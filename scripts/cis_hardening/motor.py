"""
motor.py - Conexion SSH, recoleccion, evaluacion y aplicacion de reglas.
Asignacion 4 - Jose Gabriel Feliz Maria (2025-0742)
"""

import re
import time
from nucleo import Resultado, NO_CUMPLE, ERROR, ocultar
from reglas_ios import REGLAS_IOS, COMANDOS_IOS
from reglas_fortios import REGLAS_FGT, COMANDOS_FGT

PLATAFORMAS = {
    "ios": {"netmiko": "cisco_ios", "reglas": REGLAS_IOS, "comandos": COMANDOS_IOS},
    "fortios": {"netmiko": "fortinet", "reglas": REGLAS_FGT, "comandos": COMANDOS_FGT},
}


def conectar(equipo, cred):
    from netmiko import ConnectHandler
    plat = PLATAFORMAS[equipo["tipo"]]
    datos = {
        "device_type": plat["netmiko"],
        "host": equipo["ip"],
        "port": equipo.get("puerto_ssh", 22),
        "username": equipo["usuario"],
        "password": cred["clave"],
        "fast_cli": False,
        "conn_timeout": 20,
    }
    if equipo["tipo"] == "ios":
        datos["secret"] = cred.get("enable", cred["clave"])
    conn = ConnectHandler(**datos)
    if equipo["tipo"] == "ios":
        conn.enable()
    return conn


def recolectar(conn, equipo):
    comandos = PLATAFORMAS[equipo["tipo"]]["comandos"]
    return {clave: conn.send_command(cmd, read_timeout=90) for clave, cmd in comandos.items()}


def evaluar(datos, equipo, ctx, filtro=None):
    resultados = []
    for regla in PLATAFORMAS[equipo["tipo"]]["reglas"]:
        if equipo["rol"] not in regla.roles:
            continue
        if filtro and regla.id not in filtro:
            continue
        try:
            estado, evidencia = regla.verificar(datos, ctx)
        except Exception as e:  # una regla rota no detiene el escaneo
            estado, evidencia = ERROR, f"no se pudo verificar: {e}"
        r = Resultado(regla, estado, evidencia, usuario=equipo.get("usuario", "<usuario>"))
        if estado == NO_CUMPLE and regla.remediar:
            r.comandos = regla.remediar(datos, ctx)
        resultados.append(r)
    return resultados


def plan(resultados):
    """Lista ordenada de (regla_id, comandos) sin repetir bloques iguales
    (p. ej. 1.1.1, 1.1.2 y 1.1.3 comparten el bloque AAA)."""
    vistos, salida = set(), []
    for r in resultados:
        if r.estado != NO_CUMPLE or not r.comandos:
            continue
        clave = tuple(r.comandos)
        if clave in vistos:
            continue
        vistos.add(clave)
        salida.append((r.regla.id, r.comandos))
    return salida


# ---------------------------------------------------------------------------
# Aplicacion
# ---------------------------------------------------------------------------
def _comprobar(conn, filtro, patron, que):
    """Revisa la configuracion despues de una accion delicada. Si no quedo bien,
    detiene la aplicacion antes de tocar AAA (para no dejar el equipo sin acceso).
    Ojo: IOS no muestra 'privilege 1' en el running-config porque es el valor
    por defecto, asi que se busca solo el usuario con 'secret'."""
    out = ""
    for _ in range(3):
        out = conn.send_command(f"do show running-config | include {filtro}",
                                expect_string=r"\(config[^)]*\)#", read_timeout=60)
        if re.search(patron, out, re.M):
            return
        time.sleep(2)
    raise RuntimeError(f"{que}: no quedo en la configuracion; se detiene la aplicacion "
                       "para no perder el acceso (revisar por consola)")


def _ios_especial(conn, accion, equipo, cred, log):
    conn.config_mode()
    if accion == "@ENABLE_SECRET":
        en = cred["enable"]
        out = conn.send_command_timing(f"enable algorithm-type scrypt secret {en}", last_read=2)
        if "Invalid" in out:
            conn.send_command_timing(f"enable secret {en}", last_read=2)
        _comprobar(conn, "^enable", r"^enable secret ", "enable secret")
        conn.send_command_timing("no enable password", last_read=2)
        log.append("enable algorithm-type scrypt secret <OCULTO>")
        log.append("no enable password")
    elif accion == "@USUARIO":
        u, pw = equipo["usuario"], cred["clave"]
        out = conn.send_command_timing(f"no username {u}", last_read=4)
        if "confirm" in out.lower():
            conn.send_command_timing("\n", last_read=2)
        out = conn.send_command_timing(f"username {u} privilege 1 algorithm-type scrypt secret {pw}", last_read=2)
        if "Invalid" in out:
            conn.send_command_timing(f"username {u} privilege 1 secret {pw}", last_read=2)
        _comprobar(conn, f"^username {u}", rf"^username {re.escape(u)} .*secret ", f"usuario {u}")
        log.append(f"no username {u}")
        log.append(f"username {u} privilege 1 algorithm-type scrypt secret <OCULTO>")
    elif accion.startswith("@RSA"):
        bits = accion.split()[1]
        out = conn.send_command_timing(f"crypto key generate rsa general-keys modulus {bits}", last_read=3)
        if "yes/no" in out or "replace" in out.lower():
            conn.send_command_timing("yes", last_read=8, read_timeout=180)
        log.append(f"crypto key generate rsa general-keys modulus {bits}")
    conn.exit_config_mode()


def aplicar(conn, equipo, pasos, cred):
    """Envia los comandos del plan. Devuelve el registro de lo que se hizo."""
    log = []
    if equipo["tipo"] == "ios":
        normales = []

        def enviar():
            if normales:
                conn.send_config_set(normales, cmd_verify=False, read_timeout=60)
                log.extend(ocultar(c) for c in normales)
                normales.clear()

        for _rid, cmds in pasos:
            for c in cmds:
                if c.startswith("@"):
                    enviar()
                    _ios_especial(conn, c, equipo, cred, log)
                else:
                    normales.append(c)
        enviar()
        conn.save_config()
        log.append("write memory")
    else:
        for _rid, cmds in pasos:
            conn.send_config_set(cmds, cmd_verify=False, exit_config_mode=False, read_timeout=60)
            log.extend(ocultar(c) for c in cmds)
            time.sleep(1)
    return log


def respaldo(conn, equipo):
    """Configuracion completa (con secretos tapados) para la herramienta CIS de FortiGate."""
    cmd = "show full-configuration" if equipo["tipo"] == "fortios" else "show running-config"
    return ocultar(conn.send_command(cmd, read_timeout=180))
