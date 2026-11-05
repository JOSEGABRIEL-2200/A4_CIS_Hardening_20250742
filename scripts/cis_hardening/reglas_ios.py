"""
reglas_ios.py - Recomendaciones del CIS Cisco IOS 15 Benchmark v4.1.1 elegidas
para R1 (router) y SW1 (switch).
Asignacion 4 - Jose Gabriel Feliz Maria (2025-0742)

Cada regla tiene: como se verifica (sobre la salida de los comandos show) y
que comandos la corrigen. Los comandos que empiezan con '@' son acciones
especiales que el ejecutor maneja aparte (porque piden confirmacion o claves).
"""

import re
import binascii
from nucleo import (Regla, CUMPLE, NO_CUMPLE, EXCEPCION, tiene_linea, lineas_que,
                    bloques, interfaces_con_ip)

ACL_GESTION = "ACL-GESTION-SSH"
# Lista AAA con nombre para consola y vty. Con la lista "default" el IOS no
# muestra 'login authentication default' en la configuracion (es el valor por
# defecto), y asi ni este script ni Onyx pueden comprobar la recomendacion.
LISTA_LOGIN = "LOGIN-LOCAL"

# Comandos show que se recogen una sola vez por equipo
COMANDOS_IOS = {
    "run": "show running-config",
    "ssh": "show ip ssh",
    "rsa": "show crypto key mypubkey rsa",
    "cdp": "show cdp",
}


# ---------------------------------------------------------------------------
# Ayudas
# ---------------------------------------------------------------------------
def _ok(cond, evid_ok, evid_mal):
    return (CUMPLE, evid_ok) if cond else (NO_CUMPLE, evid_mal)


def _linea(d, patron):
    l = lineas_que(d["run"], patron)
    return l[0] if l else "no configurado"


def _bloque_linea(d, nombre):
    """Bloque de 'line con 0', 'line aux 0' o 'line vty 0 4' (todas las vty)."""
    b = bloques(d["run"], r"^line " + nombre)
    hijos = []
    for v in b.values():
        hijos.extend(v)
    return b, hijos


def _rsa_bits(salida_rsa):
    """Tamano real de la clave RSA de uso general, leyendo el 'Key Data' (DER).
    Onyx solo revisa que exista una clave; aqui se mide el modulo."""
    bloques_clave = re.split(r"% Key pair was generated at", salida_rsa)
    for bl in bloques_clave:
        if "Key name:" not in bl or ".server" in bl.split("Key name:")[1].split("\n")[0]:
            continue
        datos = bl.split("Key Data:")[-1]
        hexa = "".join(re.findall(r"\b[0-9A-F]{2,8}\b", datos))
        try:
            der = binascii.unhexlify(hexa)
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            return load_der_public_key(der).key_size
        except Exception:
            if hexa.startswith("30819F"):
                return 1024
            if hexa.startswith("30820122"):
                return 2048
            if hexa.startswith("30820222"):
                return 4096
    return 0


def _ssh_dato(d, patron, defecto=None):
    m = re.search(patron, d["ssh"], re.I)
    return m.group(1) if m else defecto


def _timeouts(hijos):
    for h in hijos:
        m = re.match(r"exec-timeout (\d+)(?: (\d+))?", h)
        if m:
            minutos, seg = int(m.group(1)), int(m.group(2) or 0)
            return minutos, seg
    return None


def _vty(d):
    """Encabezados de las lineas vty que existen (p. ej. 'line vty 0 4')."""
    return list(bloques(d["run"], r"^line vty").keys()) or ["line vty 0 4"]


def _en_vty(d, *subcomandos):
    cmds = []
    for cab in _vty(d):
        cmds.append(cab)
        cmds += [" " + s for s in subcomandos]
    return cmds


def _usuarios(d):
    return lineas_que(d["run"], r"^username \S+")


# ---------------------------------------------------------------------------
# Verificaciones y remediaciones
# ---------------------------------------------------------------------------
def v_aaa_new_model(d, c):
    return _ok(tiene_linea(d["run"], r"^aaa new-model$"), "aaa new-model", "no aaa new-model")


def r_aaa(d, c):
    return ["aaa new-model",
            "aaa authentication login default local",
            f"aaa authentication login {LISTA_LOGIN} local",
            "aaa authentication enable default enable",
            "aaa authorization exec default local"]


def v_aaa_login(d, c):
    l = lineas_que(d["run"], r"^aaa authentication login \S+ ")
    return _ok(bool(l), "; ".join(l), "sin 'aaa authentication login'")


def v_aaa_enable(d, c):
    l = lineas_que(d["run"], r"^aaa authentication enable default ")
    return _ok(bool(l), "; ".join(l), "sin 'aaa authentication enable default'")


def v_login_con(d, c):
    _, hijos = _bloque_linea(d, "con 0")
    l = [h for h in hijos if h.startswith("login authentication")]
    return _ok(bool(l), "line con 0: " + "; ".join(l),
               "line con 0 sin 'login authentication' visible en la configuracion")


def r_login_con(d, c):
    return [f"aaa authentication login {LISTA_LOGIN} local",
            "line con 0", f" login authentication {LISTA_LOGIN}"]


def v_login_vty(d, c):
    b, _ = _bloque_linea(d, "vty")
    malos = [k for k, v in b.items() if not any(h.startswith("login authentication") for h in v)]
    bien = sorted({h for v in b.values() for h in v if h.startswith("login authentication")})
    return _ok(b and not malos, "vty: " + "; ".join(bien),
               "sin 'login authentication' visible en: " + ", ".join(malos or ["line vty"]))


def r_login_vty(d, c):
    return [f"aaa authentication login {LISTA_LOGIN} local"] + _en_vty(d, f"login authentication {LISTA_LOGIN}")


def v_privilegio_1(d, c):
    malos = [u for u in _usuarios(d) if re.search(r" privilege (?!1 )\d+", u + " ")]
    evid = ", ".join(re.sub(r" (password|secret) .*", "", u) for u in malos)
    return _ok(not malos, "usuarios locales con privilegio 1", "usuarios con privilegio > 1: " + evid)


def v_transport_ssh(d, c):
    b, _ = _bloque_linea(d, "vty")
    malos = []
    for k, v in b.items():
        t = [h for h in v if h.startswith("transport input")]
        if not t or t[0] != "transport input ssh":
            malos.append(f"{k}: {t[0] if t else 'transport input (por defecto: todo)'}")
    return _ok(b and not malos, "transport input ssh en todas las vty", "; ".join(malos))


def r_transport_ssh(d, c):
    return _en_vty(d, "transport input ssh")


def v_acl_vty(d, c):
    ok = tiene_linea(d["run"], r"^ip access-list standard " + ACL_GESTION + r"$")
    return _ok(ok, f"ip access-list standard {ACL_GESTION}",
               f"no existe la ACL de gestion {ACL_GESTION} (Onyx cuenta ACL de fabrica de la imagen)")


def r_acl_vty(d, c):
    host = c["params"]["host_gestion"]
    return [f"ip access-list standard {ACL_GESTION}",
            " remark Solo la estacion de gestion entra por SSH",
            f" permit host {host}",
            " deny any log"]


def v_access_class(d, c):
    b, _ = _bloque_linea(d, "vty")
    malos = [k for k, v in b.items() if f"access-class {ACL_GESTION} in" not in v]
    return _ok(b and not malos, f"access-class {ACL_GESTION} in", "sin access-class en: " + ", ".join(malos or ["vty"]))


def r_access_class(d, c):
    return _en_vty(d, f"access-class {ACL_GESTION} in")


def _v_timeout(nombre):
    def v(d, c):
        b, hijos = _bloque_linea(d, nombre)
        if not b:
            return EXCEPCION, f"el equipo no tiene line {nombre}"
        t = _timeouts(hijos)
        if t is None:
            return NO_CUMPLE, "exec-timeout por defecto (10 min, no queda registrado en la configuracion)"
        minutos, seg = t
        bien = (minutos, seg) != (0, 0) and minutos * 60 + seg <= 600
        return _ok(bien, f"exec-timeout {minutos} {seg}", f"exec-timeout {minutos} {seg}")
    return v


def _r_timeout(linea):
    if linea == "vty":
        return lambda d, c: _en_vty(d, "exec-timeout 5 0")
    return lambda d, c: [linea, " exec-timeout 5 0"]


def v_aux_no_exec(d, c):
    b, hijos = _bloque_linea(d, "aux 0")
    if not b:
        return EXCEPCION, "el equipo no tiene line aux 0"
    return _ok("no exec" in hijos, "line aux 0: no exec", "line aux 0 permite exec")


def r_aux_no_exec(d, c):
    return ["line aux 0", " no exec", " transport input none"]


def _v_banner(tipo):
    return lambda d, c: _ok(tiene_linea(d["run"], rf"^banner {tipo} "), f"banner {tipo} configurado",
                            f"sin banner {tipo}")


def _r_banner(tipo):
    def r(d, c):
        texto = c["params"]["banner"].replace("^", "")
        return [f"banner {tipo} ^{texto} [{c['equipo']['nombre']} - {tipo}]^"]
    return r


def v_enable_secret(d, c):
    sec = tiene_linea(d["run"], r"^enable secret ")
    pw = tiene_linea(d["run"], r"^enable password ")
    if sec and not pw:
        return CUMPLE, "'enable secret' con hash y sin 'enable password'"
    return NO_CUMPLE, "usa 'enable password' (texto plano o tipo 7)" if pw else "sin 'enable secret'"


def r_enable_secret(d, c):
    return ["@ENABLE_SECRET"]


def v_pw_encryption(d, c):
    return _ok(tiene_linea(d["run"], r"^service password-encryption$"),
               "service password-encryption", "no service password-encryption")


def v_username_secret(d, c):
    malos = [u.split()[1] for u in _usuarios(d) if " secret " not in u]
    return _ok(_usuarios(d) and not malos, "todos los usuarios locales usan 'secret'",
               "usuarios con 'password' (reversible): " + ", ".join(malos))


def r_usuario(d, c):
    return ["@USUARIO"]


def v_no_snmp(d, c):
    l = lineas_que(d["run"], r"^snmp-server ")
    return _ok(not l, "SNMP deshabilitado (no se usa en esta red)", "; ".join(l))


def v_hostname(d, c):
    l = _linea(d, r"^hostname ")
    return _ok(l != "no configurado" and l not in ("hostname Router", "hostname Switch"), l, l)


def v_domain(d, c):
    l = _linea(d, r"^ip domain[ -]name ")
    return _ok(l != "no configurado", l, l)


def v_rsa(d, c):
    bits = _rsa_bits(d["rsa"])
    return _ok(bits >= 2048, f"clave RSA de {bits} bits", f"clave RSA de {bits} bits (minimo 2048)")


def r_rsa(d, c):
    return ["@RSA 2048"]


def v_ssh_timeout(d, c):
    t = int(_ssh_dato(d, r"Authentication timeout:\s*(\d+)", 120))
    return _ok(t <= 60, f"ip ssh time-out {t}", f"ip ssh time-out {t} (maximo 60)")


def v_ssh_retries(d, c):
    t = int(_ssh_dato(d, r"Authentication retries:\s*(\d+)", 3))
    return _ok(t <= 3, f"ip ssh authentication-retries {t}", f"ip ssh authentication-retries {t}")


def v_ssh_v2(d, c):
    v = _ssh_dato(d, r"version\s+([\d.]+)", "?")
    return _ok(v == "2.0", f"SSH version {v}", f"SSH version {v} (acepta SSHv1)")


def v_no_cdp(d, c):
    apagado = "not enabled" in d["cdp"].lower() or tiene_linea(d["run"], r"^no cdp run$")
    return _ok(apagado, "CDP deshabilitado", "CDP habilitado (anuncia modelo, IOS e IP a los vecinos)")


def _v_global(linea, evid_mal=None):
    return lambda d, c: _ok(tiene_linea(d["run"], "^" + re.escape(linea) + "$"), linea,
                            evid_mal or f"falta '{linea}'")


def v_no_service_dhcp(d, c):
    if c["equipo"]["rol"] == "router":
        return EXCEPCION, ("R1 es el servidor DHCP de la LAN (lo pide la red): "
                           "'no service dhcp' lo apagaria")
    return _ok(tiene_linea(d["run"], r"^no service dhcp$"), "no service dhcp", "service dhcp activo")


def v_service_pad(d, c):
    return _ok(tiene_linea(d["run"], r"^no service pad$"), "no service pad", "service pad (X.25 PAD activo)")


def v_logging_buffered(d, c):
    l = lineas_que(d["run"], r"^logging buffered \d+")
    return _ok(bool(l), l[0] if l else "", "sin tamano de 'logging buffered'")


def v_logging_console(d, c):
    return _ok(tiene_linea(d["run"], r"^logging console critical$"), "logging console critical",
               "la consola recibe todos los mensajes")


def v_logging_host(d, c):
    host = c["params"]["syslog"]
    return _ok(tiene_linea(d["run"], rf"^logging host {re.escape(host)}$"), f"logging host {host}",
               "sin servidor syslog")


def v_logging_source(d, c):
    l = lineas_que(d["run"], r"^logging source-interface ")
    return _ok(bool(l), l[0] if l else "", "sin 'logging source-interface'")


def r_logging_source(d, c):
    return [f"logging source-interface {c['equipo']['interfaz_origen_log']}"]


def v_proxy_arp(d, c):
    malos = [k.split()[1] for k, v in interfaces_con_ip(d["run"]).items() if "no ip proxy-arp" not in v]
    return _ok(not malos, "proxy-arp deshabilitado en las interfaces con IP",
               "proxy-arp activo en: " + ", ".join(malos))


def r_proxy_arp(d, c):
    cmds = []
    for k in interfaces_con_ip(d["run"]):
        cmds += [k, " no ip proxy-arp"]
    return cmds


def _cmd(*cmds):
    return lambda d, c: list(cmds)


# ---------------------------------------------------------------------------
# Lista de reglas (el orden es el orden en que se aplican)
# ---------------------------------------------------------------------------
GEST, CTRL, DATOS = "Plano de gestion", "Plano de control", "Plano de datos"

REGLAS_IOS = [
    # 1.4 Contrasenas (primero: el resto depende de que las claves sean seguras)
    Regla("1.4.1", "Set 'password' for 'enable secret'", 1, GEST,
          "'enable password' se guarda en texto o con cifrado reversible (tipo 7); 'enable secret' guarda un hash (scrypt).",
          v_enable_secret, r_enable_secret, ("router", "switch")),
    Regla("1.4.2", "Enable 'service password-encryption'", 1, GEST,
          "Evita que cualquier clave que quede en texto plano se vea en un 'show running-config' o en un respaldo.",
          v_pw_encryption, _cmd("service password-encryption"), ("router", "switch")),
    Regla("1.4.3", "Set 'username secret' for all local users", 1, GEST,
          "La clave del usuario local con 'password' se puede revertir; con 'secret' queda como hash.",
          v_username_secret, r_usuario, ("router", "switch")),
    Regla("1.2.1", "Set 'privilege 1' for local users", 1, GEST,
          "El usuario entra con privilegio minimo y tiene que usar 'enable' para administrar (minimo privilegio).",
          v_privilegio_1, r_usuario, ("router", "switch")),
    # 1.1 AAA
    Regla("1.1.1", "Enable 'aaa new-model'", 1, GEST,
          "Activa el modelo AAA para controlar quien entra, que puede hacer y dejar registro.",
          v_aaa_new_model, r_aaa, ("router", "switch")),
    Regla("1.1.2", "Enable 'aaa authentication login'", 1, GEST,
          "Define el metodo de autenticacion del login (base local; no hay servidor AAA en esta red).",
          v_aaa_login, r_aaa, ("router", "switch")),
    Regla("1.1.3", "Enable 'aaa authentication enable default'", 1, GEST,
          "El paso a modo privilegiado tambien queda bajo AAA.",
          v_aaa_enable, r_aaa, ("router", "switch")),
    Regla("1.1.4", "Set 'login authentication for 'line con 0'", 1, GEST,
          "La consola fisica tambien pide usuario y clave. Se usa la lista con nombre LOGIN-LOCAL porque "
          "IOS no muestra 'login authentication default' y asi la recomendacion queda comprobable.",
          v_login_con, r_login_con, ("router", "switch")),
    Regla("1.1.6", "Set 'login authentication for 'line vty'", 1, GEST,
          "Las lineas remotas (SSH) usan la lista AAA LOGIN-LOCAL de forma explicita y visible en la configuracion.",
          v_login_vty, r_login_vty, ("router", "switch")),
    # 1.2 Acceso
    Regla("1.2.2", "Set 'transport input ssh' for 'line vty' connections", 1, GEST,
          "Telnet viaja en texto plano (usuario y clave incluidos); solo se permite SSH.",
          v_transport_ssh, r_transport_ssh, ("router", "switch")),
    Regla("1.2.4", "Create 'access-list' for use with 'line vty'", 1, GEST,
          "Lista de los unicos equipos que pueden administrar: la estacion de gestion 10.7.42.10.",
          v_acl_vty, r_acl_vty, ("router", "switch")),
    Regla("1.2.5", "Set 'access-class' for 'line vty'", 1, GEST,
          "Aplica esa ACL a las lineas remotas; cualquier otra IP es rechazada y registrada. (Onyx solo reconoce "
          "ACL numeradas en este punto; aqui se usa una ACL con nombre, que es equivalente y mas clara.)",
          v_access_class, r_access_class, ("router", "switch")),
    Regla("1.2.3", "Set 'no exec' for 'line aux 0'", 1, GEST,
          "El puerto auxiliar no se usa: se cierra para que no sea una puerta de entrada.",
          v_aux_no_exec, r_aux_no_exec, ("router", "switch")),
    Regla("1.2.6", "Set 'exec-timeout' to less than or equal to 10 minutes for 'line aux 0'", 1, GEST,
          "Una sesion olvidada se cierra sola.",
          _v_timeout("aux 0"), _r_timeout("line aux 0"), ("router", "switch")),
    Regla("1.2.7", "Set 'exec-timeout' to less than or equal to 10 minutes 'line console 0'", 1, GEST,
          "Una sesion de consola olvidada se cierra sola.",
          _v_timeout("con 0"), _r_timeout("line con 0"), ("router", "switch")),
    Regla("1.2.8", "Set 'exec-timeout' less than or equal to 10 minutes 'line vty'", 1, GEST,
          "Una sesion SSH olvidada se cierra sola.",
          _v_timeout("vty"), _r_timeout("vty"), ("router", "switch")),
    # 1.3 Banners
    Regla("1.3.1", "Set the 'banner-text' for 'banner exec'", 1, GEST,
          "Aviso legal al entrar a la sesion.", _v_banner("exec"), _r_banner("exec"), ("router", "switch")),
    Regla("1.3.2", "Set the 'banner-text' for 'banner login'", 1, GEST,
          "Aviso antes de pedir usuario y clave.", _v_banner("login"), _r_banner("login"), ("router", "switch")),
    Regla("1.3.3", "Set the 'banner-text' for 'banner motd'", 1, GEST,
          "Mensaje del dia con la advertencia de acceso restringido.", _v_banner("motd"), _r_banner("motd"),
          ("router", "switch")),
    # 1.5 SNMP
    Regla("1.5.1", "Set 'no snmp-server' to disable SNMP when unused", 1, GEST,
          "En esta red no hay sistema de monitoreo: SNMP con 'public' solo regala informacion.",
          v_no_snmp, _cmd("no snmp-server"), ("router", "switch")),
    # 2.1 Servicios globales / SSH
    Regla("2.1.1.1.1", "Set the 'hostname'", 1, CTRL,
          "Requisito para generar la clave RSA de SSH e identificar el equipo en los registros.",
          v_hostname, None, ("router", "switch")),
    Regla("2.1.1.1.2", "Set the 'ip domain-name'", 1, CTRL,
          "Requisito para generar la clave RSA de SSH.", v_domain, None, ("router", "switch")),
    Regla("2.1.1.1.4", "Set 'seconds' for 'ip ssh timeout'", 1, CTRL,
          "Limita el tiempo que un cliente tiene para autenticarse (60 s).",
          v_ssh_timeout, _cmd("ip ssh time-out 60"), ("router", "switch")),
    Regla("2.1.1.1.5", "Set maximum value for 'ip ssh authentication-retries'", 1, CTRL,
          "Maximo 3 intentos por conexion contra fuerza bruta.",
          v_ssh_retries, _cmd("ip ssh authentication-retries 3"), ("router", "switch")),
    Regla("2.1.1.2", "Set version 2 for 'ip ssh version'", 1, CTRL,
          "SSHv1 tiene fallas conocidas; solo se acepta la version 2.",
          v_ssh_v2, _cmd("ip ssh version 2"), ("router", "switch")),
    Regla("2.1.2", "Set 'no cdp run'", 1, CTRL,
          "CDP anuncia modelo, version de IOS e IP de gestion a cualquier vecino.",
          v_no_cdp, _cmd("no cdp run"), ("router", "switch")),
    Regla("2.1.3", "Set 'no ip bootp server'", 1, CTRL,
          "Servicio viejo que no se usa y permite descargar imagenes del equipo.",
          _v_global("no ip bootp server"), _cmd("no ip bootp server"), ("router", "switch")),
    Regla("2.1.4", "Set 'no service dhcp'", 1, CTRL,
          "En el switch no hace falta el servidor/relay DHCP; en R1 es una excepcion porque es el servidor DHCP de la LAN.",
          v_no_service_dhcp, _cmd("no service dhcp"), ("router", "switch")),
    Regla("2.1.6", "Set 'service tcp-keepalives-in'", 1, CTRL,
          "Cierra las sesiones TCP entrantes que quedan colgadas.",
          _v_global("service tcp-keepalives-in"), _cmd("service tcp-keepalives-in"), ("router", "switch")),
    Regla("2.1.7", "Set 'service tcp-keepalives-out'", 1, CTRL,
          "Cierra las sesiones TCP salientes que quedan colgadas.",
          _v_global("service tcp-keepalives-out"), _cmd("service tcp-keepalives-out"), ("router", "switch")),
    Regla("2.1.8", "Set 'no service pad'", 1, CTRL,
          "El PAD de X.25 no se usa; es un servicio menos expuesto.",
          v_service_pad, _cmd("no service pad"), ("router", "switch")),
    # 2.2 Registros
    Regla("2.2.2", "Set 'buffer size' for 'logging buffered'", 1, CTRL,
          "Guarda los ultimos eventos en memoria para poder revisarlos.",
          v_logging_buffered, _cmd("logging buffered 64000"), ("router", "switch")),
    Regla("2.2.3", "Set 'logging console critical'", 1, CTRL,
          "La consola solo muestra mensajes criticos (evita saturarla).",
          v_logging_console, _cmd("logging console critical"), ("router", "switch")),
    Regla("2.2.4", "Set IP address for 'logging host'", 1, CTRL,
          "Envia los registros a un servidor syslog externo (el Kali): si atacan el equipo, el registro queda afuera.",
          v_logging_host, lambda d, c: [f"logging host {c['params']['syslog']}", "logging trap informational"],
          ("router", "switch")),
    Regla("2.2.7", "Set 'logging source interface'", 1, CTRL,
          "Los mensajes syslog salen siempre con la misma IP de origen. El CIS sugiere una Loopback; en esta red "
          "se usa la interfaz de gestion (R1: Ethernet0/1.10, SW1: Vlan99) porque no hay Loopbacks (2.4.1 es "
          "nivel 2 y no se eligio). Onyx solo acepta Loopback y por eso lo marca como no cumple.",
          v_logging_source, r_logging_source, ("router", "switch")),
    # 3.1 Plano de datos
    Regla("3.1.1", "Set 'no ip source-route'", 1, DATOS,
          "Impide que un paquete elija su propia ruta (se usa para saltarse controles).",
          _v_global("no ip source-route", "ip source-route (por defecto)"), _cmd("no ip source-route"),
          ("router", "switch")),
    Regla("3.1.2", "Set 'no ip proxy-arp'", 2, DATOS,
          "El equipo no responde ARP en nombre de otros (evita suplantaciones y fugas entre redes).",
          v_proxy_arp, r_proxy_arp, ("router", "switch")),
    # SSH con clave fuerte al final: regenera la clave del servidor SSH
    Regla("2.1.1.1.3", "Set 'modulus' to greater than or equal to 2048 for 'crypto key generate rsa'", 1, CTRL,
          "Una clave RSA de 1024 bits ya no se considera segura. (Onyx marca este punto como cumplido solo "
          "porque existe una clave; este script mide su tamano real.)",
          v_rsa, r_rsa, ("router", "switch")),
]
