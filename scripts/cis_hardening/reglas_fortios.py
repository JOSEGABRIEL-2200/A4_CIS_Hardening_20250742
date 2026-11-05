"""
reglas_fortios.py - Recomendaciones del CIS Fortinet FortiGate 7.0.x Benchmark
v1.3.0 elegidas para FGT1 (firewall perimetral).
Asignacion 4 - Jose Gabriel Feliz Maria (2025-0742)
"""

import re
from nucleo import Regla, CUMPLE, NO_CUMPLE, EXCEPCION, fgt_set, fgt_edits

COMANDOS_FGT = {
    "status": "get system status",
    "global": "show full-configuration system global",
    "interface": "show full-configuration system interface",
    "admin": "show full-configuration system admin",
    "pwpolicy": "show full-configuration system password-policy",
    "ntp": "show full-configuration system ntp",
    "autoinstall": "show full-configuration system auto-install",
    "policy": "show full-configuration firewall policy",
    "syslog": "show full-configuration log syslogd setting",
}

SERVICIOS_GESTION = {"http", "https", "ssh", "telnet", "snmp", "fgfm", "radius-acct", "ftm"}
NOMBRES_DE_FABRICA = ("FortiGate-VM64", "FortiGate", "FGVM")


def _ok(cond, bien, mal):
    return (CUMPLE, bien) if cond else (NO_CUMPLE, mal)


def _allow(texto_if):
    v = fgt_set(texto_if, "allowaccess") or ""
    return [s for s in v.replace('"', "").split() if s]


def _global(d, clave):
    return fgt_set(d["global"], clave)


def _bloque(*lineas):
    return list(lineas)


# ---------------------------------------------------------------------------
def v_wan(d, c):
    wan = c["equipo"]["puerto_wan"]
    acc = _allow(fgt_edits(d["interface"]).get(wan, ""))
    malos = sorted(set(acc) & SERVICIOS_GESTION)
    return _ok(not malos, f"{wan} allowaccess: {' '.join(acc) or 'ninguno'}",
               f"{wan} (WAN) permite administracion: {' '.join(malos)}")


def r_wan(d, c):
    wan = c["equipo"]["puerto_wan"]
    return _bloque("config system interface", f'edit "{wan}"', "set allowaccess ping", "next", "end")


def _v_global(clave, esperado, texto):
    def v(d, c):
        valor = _global(d, clave)
        return _ok(valor == esperado, f"{clave} {valor}", f"{clave} {valor} ({texto})")
    return v


def _r_global(*pares):
    def r(d, c):
        cmds = ["config system global"]
        cmds += [f"set {k} {v}" for k, v in pares]
        return cmds + ["end"]
    return r


def v_timezone(d, c):
    esperado = str(c["params"].get("zona_horaria_fgt", "")).strip('"')
    valor = (_global(d, "timezone") or "").strip('"')
    if not esperado:
        return EXCEPCION, f"timezone {valor} (sin zona definida en el inventario)"
    return _ok(valor == esperado, f"timezone {valor}", f"timezone {valor} (se espera {esperado})")


def r_timezone(d, c):
    return ["config system global", f"set timezone {c['params']['zona_horaria_fgt']}", "end"]


def v_ntp(d, c):
    sync = fgt_set(d["ntp"], "ntpsync")
    return _ok(sync == "enable", f"ntpsync {sync} ({fgt_set(d['ntp'], 'type')})", f"ntpsync {sync}")


def r_ntp(d, c):
    return ["config system ntp", "set ntpsync enable", "set type fortiguard", "end"]


def v_hostname(d, c):
    h = _global(d, "hostname") or ""
    return _ok(h and not h.startswith(NOMBRES_DE_FABRICA), f"hostname {h}", f"hostname {h} (nombre de fabrica)")


def r_hostname(d, c):
    return ["config system global", f'set hostname "{c["equipo"]["nombre"]}"', "end"]


def v_usb(d, c):
    cfg = fgt_set(d["autoinstall"], "auto-install-config")
    img = fgt_set(d["autoinstall"], "auto-install-image")
    return _ok(cfg == "disable" and img == "disable", "auto-install-config/image disable",
               f"auto-install-config {cfg}, auto-install-image {img}")


def r_usb(d, c):
    return ["config system auto-install", "set auto-install-config disable", "set auto-install-image disable", "end"]


def v_strong_crypto(d, c):
    v = _global(d, "strong-crypto")
    if v is None:
        return EXCEPCION, "la licencia de evaluacion (cifrado bajo) no tiene 'strong-crypto'"
    return _ok(v == "enable", f"strong-crypto {v}", f"strong-crypto {v}")


def v_tls_gui(d, c):
    v = _global(d, "admin-https-ssl-versions") or ""
    viejas = [x for x in v.split() if x in ("tlsv1-0", "tlsv1-1", "sslv3")]
    return _ok(v and not viejas, f"admin-https-ssl-versions {v}", f"admin-https-ssl-versions {v}")


def v_pwpolicy(d, c):
    p = d["pwpolicy"]
    status = fgt_set(p, "status")
    largo = int(fgt_set(p, "minimum-length") or 0)
    bien = status == "enable" and largo >= 8
    return _ok(bien, f"password-policy {status}, minimum-length {largo}",
               f"password-policy {status}, minimum-length {largo}")


def r_pwpolicy(d, c):
    return ["config system password-policy", "set status enable", "set apply-to admin-password",
            "set minimum-length 12", "set min-lower-case-letter 1", "set min-upper-case-letter 1",
            "set min-non-alphanumeric 1", "set min-number 1", "set expire-status enable",
            "set expire-day 90", "end"]


def v_lockout(d, c):
    th = int(_global(d, "admin-lockout-threshold") or 0)
    du = int(_global(d, "admin-lockout-duration") or 0)
    return _ok(0 < th <= 3 and du >= 900, f"threshold {th}, duration {du}s",
               f"threshold {th}, duration {du}s (CIS: 3 intentos y 900 s)")


def v_trusthost(d, c):
    malos = []
    for nombre, txt in fgt_edits(d["admin"]).items():
        th = [fgt_set(txt, f"trusthost{i}") for i in range(1, 11)]
        if all((t or "0.0.0.0 0.0.0.0") == "0.0.0.0 0.0.0.0" for t in th):
            malos.append(nombre)
    return _ok(not malos, "todos los administradores con trusted hosts",
               "administradores sin trusted hosts (entran desde cualquier IP): " + ", ".join(malos))


def r_trusthost(d, c):
    host = c["params"]["host_gestion"]
    cmds = ["config system admin"]
    for nombre in fgt_edits(d["admin"]):
        cmds += [f'edit "{nombre}"', f"set trusthost1 {host} 255.255.255.255", "next"]
    return cmds + ["end"]


def v_admintimeout(d, c):
    t = int(_global(d, "admintimeout") or 0)
    return _ok(0 < t <= 5, f"admintimeout {t} min", f"admintimeout {t} min")


def v_cifrado(d, c):
    malos = []
    for nombre, txt in fgt_edits(d["interface"]).items():
        inseguros = set(_allow(txt)) & {"http", "telnet"}
        if inseguros:
            malos.append(f"{nombre}: {' '.join(sorted(inseguros))}")
    return _ok(not malos, "solo HTTPS y SSH para administrar", "acceso sin cifrar en " + "; ".join(malos))


def r_cifrado(d, c):
    cmds = ["config system interface"]
    for nombre, txt in fgt_edits(d["interface"]).items():
        acc = _allow(txt)
        if set(acc) & {"http", "telnet"}:
            nuevo = [a for a in acc if a not in ("http", "telnet")] or ["ping"]
            cmds += [f'edit "{nombre}"', "set allowaccess " + " ".join(nuevo), "next"]
    return cmds + ["end"]


def v_puerto_admin(d, c):
    p = _global(d, "admin-sport")
    return _ok(p and p != "443", f"admin-sport {p}", f"admin-sport {p} (puerto por defecto)")


def _politicas(d):
    return fgt_edits(d["policy"])


def v_servicio_all(d, c):
    malos = [f"politica {k}" for k, v in _politicas(d).items()
             if re.search(r'^\s*set service .*"ALL"', v, re.M)]
    if not _politicas(d):
        return EXCEPCION, "sin politicas de firewall"
    return _ok(not malos, "ninguna politica usa el servicio ALL", "usan ALL: " + ", ".join(malos))


def r_servicio_all(d, c):
    cmds = ["config firewall policy"]
    for k, v in _politicas(d).items():
        if re.search(r'^\s*set service .*"ALL"', v, re.M):
            cmds += [f"edit {k}", 'set service "HTTP" "HTTPS" "DNS" "PING"', "next"]
    return cmds + ["end"]


def v_log_politicas(d, c):
    malos = [f"politica {k}" for k, v in _politicas(d).items()
             if (fgt_set(v, "logtraffic") or "utm") == "disable"]
    if not _politicas(d):
        return EXCEPCION, "sin politicas de firewall"
    return _ok(not malos, "todas las politicas registran trafico", "sin registro: " + ", ".join(malos))


def r_log_politicas(d, c):
    cmds = ["config firewall policy"]
    for k, v in _politicas(d).items():
        if (fgt_set(v, "logtraffic") or "utm") == "disable":
            cmds += [f"edit {k}", "set logtraffic all", "next"]
    return cmds + ["end"]


def v_syslog(d, c):
    st = fgt_set(d["syslog"], "status")
    srv = fgt_set(d["syslog"], "server")
    return _ok(st == "enable" and srv, f"syslog {st} -> {srv}", f"syslog {st}")


def r_syslog(d, c):
    return ["config log syslogd setting", "set status enable", f"set server {c['params']['syslog']}", "end"]


SIS, PASS, ADMIN, FW, LOG, RED = ("Configuracion del sistema", "Politica de contrasenas",
                                  "Administradores", "Politicas de firewall", "Registros", "Red")

REGLAS_FGT = [
    Regla("2.1.1", "Ensure 'Pre-Login Banner' is set", 1, SIS,
          "Aviso legal antes de iniciar sesion.",
          _v_global("pre-login-banner", "enable", "sin aviso antes del login"),
          _r_global(("pre-login-banner", "enable")), ("firewall",)),
    Regla("2.1.2", "Ensure 'Post-Login-Banner' is set", 1, SIS,
          "Aviso despues de iniciar sesion.",
          _v_global("post-login-banner", "enable", "sin aviso despues del login"),
          _r_global(("post-login-banner", "enable")), ("firewall",)),
    Regla("2.1.3", "Ensure timezone is properly configured", 1, SIS,
          "Los registros tienen que tener la hora local correcta para poder cruzarlos con los demas equipos.",
          v_timezone, r_timezone, ("firewall",)),
    Regla("2.1.4", "Ensure correct system time is configured through NTP", 1, SIS,
          "Hora sincronizada para que los registros sean confiables.",
          v_ntp, r_ntp, ("firewall",)),
    Regla("2.1.7", "Disable USB Firmware and configuration installation", 1, SIS,
          "Nadie puede cambiar el firmware o la configuracion conectando una memoria USB.",
          v_usb, r_usb, ("firewall",)),
    Regla("2.1.9", "Enable Global Strong Encryption", 1, SIS,
          "Solo cifrados fuertes en HTTPS, SSH y VPN.",
          v_strong_crypto, _r_global(("strong-crypto", "enable")), ("firewall",)),
    Regla("2.1.10", "Ensure management GUI listens on secure TLS version", 1, SIS,
          "La interfaz web no acepta TLS 1.0/1.1.",
          v_tls_gui, _r_global(("admin-https-ssl-versions", "tlsv1-2 tlsv1-3")), ("firewall",)),
    Regla("2.2.1", "Ensure 'Password Policy' is enabled", 1, PASS,
          "Claves de administrador largas y complejas (12 caracteres, mayuscula, minuscula, numero y simbolo).",
          v_pwpolicy, r_pwpolicy, ("firewall",)),
    Regla("2.2.2", "Ensure administrator password retries and lockout time are configured", 1, PASS,
          "Tras 3 intentos fallidos la cuenta se bloquea 15 minutos (contra fuerza bruta).",
          v_lockout, _r_global(("admin-lockout-threshold", "3"), ("admin-lockout-duration", "900")), ("firewall",)),
    Regla("2.4.2", "Ensure all the login accounts having specific trusted hosts enabled", 1, ADMIN,
          "El administrador solo puede entrar desde la estacion de gestion 10.7.42.10.",
          v_trusthost, r_trusthost, ("firewall",)),
    Regla("2.4.4", "Ensure idle timeout time is configured", 1, ADMIN,
          "Una sesion de administracion olvidada se cierra a los 5 minutos.",
          v_admintimeout, _r_global(("admintimeout", "5")), ("firewall",)),
    Regla("2.4.5", "Ensure only encrypted access channels are enabled", 1, ADMIN,
          "HTTP y Telnet mandan la clave en texto plano: solo HTTPS y SSH.",
          v_cifrado, r_cifrado, ("firewall",)),
    Regla("2.4.7", "Ensure default Admin ports are changed", 2, ADMIN,
          "La interfaz web pasa del 443 al 8443 para no estar en el puerto que todos escanean. "
          "(SSH se deja en 22 porque lo usan las herramientas de auditoria.)",
          v_puerto_admin, _r_global(("admin-sport", "8443")), ("firewall",)),
    Regla("1.3", "Disable all management related services on WAN port", 1, RED,
          "Nadie desde Internet puede llegar a la administracion del firewall.",
          v_wan, r_wan, ("firewall",)),
    Regla("3.2", "Ensure that policies do not use 'ALL' as Service", 1, FW,
          "La LAN solo sale por los servicios que necesita (HTTP, HTTPS, DNS y ping).",
          v_servicio_all, r_servicio_all, ("firewall",)),
    Regla("3.4", "Ensure firewall policy is logging", 1, FW,
          "Todo el trafico permitido queda registrado.",
          v_log_politicas, r_log_politicas, ("firewall",)),
    Regla("7.3.1", "Ensure Syslog is enabled (centralized logging)", 1, LOG,
          "Los registros se envian al servidor syslog (el Kali), fuera del firewall.",
          v_syslog, r_syslog, ("firewall",)),
    # El nombre va al final: al cambiarlo cambia el prompt de la sesion SSH.
    Regla("2.1.5", "Ensure hostname is set", 1, SIS,
          "Identifica el equipo en registros y en la gestion (el nombre de fabrica no dice nada).",
          v_hostname, r_hostname, ("firewall",)),
]
