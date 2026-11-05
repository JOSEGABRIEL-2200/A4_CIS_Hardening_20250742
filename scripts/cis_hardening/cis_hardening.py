#!/usr/bin/env python3
"""
cis_hardening.py - Escaner de recomendaciones CIS Benchmark para R1 (router),
SW1 (switch) y FGT1 (FortiGate). Asignacion 4 - Jose Gabriel Feliz Maria (2025-0742)

Modos
  auditar   Se conecta por SSH, revisa cada recomendacion CIS elegida y genera el
            informe (HTML y JSON). No cambia nada en los equipos.
  aplicar   Audita, muestra los comandos que corrigen cada punto que no cumple,
            pide confirmacion, los aplica, vuelve a conectarse, audita otra vez y
            genera el informe con el antes y el despues.
  reglas    Lista las recomendaciones que el script sabe revisar.

Ejemplos
  python3 cis_hardening.py auditar
  python3 cis_hardening.py auditar -e R1
  python3 cis_hardening.py aplicar -e R1,SW1
  python3 cis_hardening.py aplicar -e FGT1 --reglas 1.3,2.4.2

Las claves se piden por teclado (no se ven al escribir) o se leen de variables
de entorno: CIS_CLAVE_<GRUPO> y CIS_ENABLE_<GRUPO>, donde <GRUPO> es el campo
"credencial" del inventario (p. ej. CIS_CLAVE_CISCO, CIS_CLAVE_FORTIGATE).
"""

import argparse
import getpass
import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nucleo import CUMPLE, NO_CUMPLE, EXCEPCION, ERROR, describir, ocultar, registrar_secreto  # noqa: E402
import motor     # noqa: E402
import informe   # noqa: E402

_COLORES = {CUMPLE: "32", NO_CUMPLE: "31", EXCEPCION: "33", ERROR: "35"}
_TTY = sys.stdout.isatty()


def pintar(texto, estado=None, codigo=None):
    c = codigo or _COLORES.get(estado)
    return f"\033[{c}m{texto}\033[0m" if _TTY and c else texto


# ---------------------------------------------------------------------------
# Inventario y credenciales
# ---------------------------------------------------------------------------
def cargar_inventario(ruta, filtro):
    with open(ruta, encoding="utf-8") as f:
        inv = json.load(f)
    equipos = inv["equipos"]
    if filtro:
        pedidos = {n.strip().upper() for n in filtro.split(",") if n.strip()}
        equipos = [e for e in equipos if e["nombre"].upper() in pedidos]
        faltan = pedidos - {e["nombre"].upper() for e in equipos}
        if faltan:
            sys.exit(f"No estan en el inventario: {', '.join(sorted(faltan))}")
    return inv.get("parametros", {}), equipos


def pedir_credenciales(equipos):
    """Una clave por grupo de credencial (R1 y SW1 comparten 'cisco')."""
    creds = {}
    for e in equipos:
        grupo = e.get("credencial", e["nombre"])
        if grupo in creds:
            continue
        var = grupo.upper().replace("-", "_")
        clave = os.environ.get(f"CIS_CLAVE_{var}") or getpass.getpass(
            f"Clave SSH del usuario '{e['usuario']}' ({grupo}): ")
        cred = {"clave": clave}
        if e["tipo"] == "ios":
            cred["enable"] = os.environ.get(f"CIS_ENABLE_{var}") or getpass.getpass(
                f"Clave de enable ({grupo}) [Enter = la misma]: ") or clave
        for valor in cred.values():
            registrar_secreto(valor)
        creds[grupo] = cred
    return creds


# ---------------------------------------------------------------------------
# Pantalla
# ---------------------------------------------------------------------------
def mostrar(resultados, titulo):
    res = informe.resumen(resultados)
    print(pintar(f"\n  {titulo}: {res['porcentaje']}% de cumplimiento  "
                 f"({res[CUMPLE]} cumple, {res[NO_CUMPLE]} no cumple, "
                 f"{res[EXCEPCION]} excepcion, {res[ERROR]} error)", codigo="1"))
    for r in resultados:
        evid = ocultar(r.evidencia)
        evid = evid if len(evid) <= 75 else evid[:72] + "..."
        print(f"   {r.regla.id:<10} {pintar(f'{r.estado:<10}', r.estado)} {evid}")


def mostrar_plan(pasos, usuario):
    print(pintar("\n  Comandos que se van a aplicar:", codigo="1"))
    for rid, cmds in pasos:
        print(pintar(f"   [{rid}]", codigo="36"))
        for c in describir(cmds, usuario):
            print(f"      {c}")


def clave_cumple_politica(clave):
    """La politica que aplica la regla 2.2.1 del FortiGate: 12 caracteres,
    mayuscula, minuscula, numero y simbolo."""
    return (len(clave) >= 12 and any(c.isupper() for c in clave) and any(c.islower() for c in clave)
            and any(c.isdigit() for c in clave) and any(not c.isalnum() for c in clave))


def confirmar(nombre):
    try:
        r = input(f"\n  Aplicar estos cambios en {nombre}? (s/N): ")
    except EOFError:
        return False
    return r.strip().lower() in ("s", "si", "sí", "y", "yes")


def guardar_texto(carpeta, nombre, texto):
    os.makedirs(carpeta, exist_ok=True)
    ruta = os.path.join(carpeta, nombre)
    with open(ruta, "w", encoding="utf-8", newline="\n") as f:
        f.write(ocultar(texto).replace("\r", ""))
    return ruta


# ---------------------------------------------------------------------------
# Un equipo
# ---------------------------------------------------------------------------
def auditar_equipo(conn, e, ctx, filtro, carpeta, fase):
    datos = motor.recolectar(conn, e)
    # Configuracion completa (con secretos tapados) como evidencia del informe.
    # La del FortiGate sirve tambien de entrada para Fortigate_CIS_check.
    if e["tipo"] == "fortios":
        guardar_texto(os.path.join(carpeta, "configs"), f"{e['nombre']}_{fase}.conf", motor.respaldo(conn, e))
    else:
        guardar_texto(os.path.join(carpeta, "configs"), f"{e['nombre']}_{fase}.txt", datos["run"])
    return motor.evaluar(datos, e, ctx, filtro)


def procesar(e, params, cred, modo, filtro, carpeta, pedir_ok):
    item = {k: e.get(k) for k in ("nombre", "ip", "tipo", "rol")}
    ctx = {"params": params, "equipo": e}
    print(pintar(f"\n=== {e['nombre']} ({e['ip']}) - {informe.BENCHMARKS[e['tipo']]} ===", codigo="1;34"))
    conn = None
    try:
        conn = motor.conectar(e, cred)
        antes = auditar_equipo(conn, e, ctx, filtro, carpeta, "antes")
        item["antes"] = antes
        mostrar(antes, "Antes" if modo == "aplicar" else "Estado actual")
        if modo != "aplicar":
            return item

        pasos = motor.plan(antes)
        item["aplicado"] = []
        # Si la clave actual no cumple la politica de contrasenas, el FortiGate obliga a
        # cambiarla en el siguiente inicio de sesion y el script ya no puede reconectarse.
        if e["tipo"] == "fortios" and any(rid == "2.2.1" for rid, _ in pasos) \
                and not clave_cumple_politica(cred["clave"]):
            pasos = [(rid, cmds) for rid, cmds in pasos if rid != "2.2.1"]
            print(pintar("\n  AVISO: la clave actual del admin no cumple la politica de 2.2.1 (12 caracteres, "
                         "mayuscula, minuscula, numero y simbolo). Se omite 2.2.1 para no dejar el equipo "
                         "pidiendo cambio de clave; cambiala primero y vuelve a aplicar.", EXCEPCION))
        if not pasos:
            print("\n  No hay nada que corregir en este equipo.")
            return item
        mostrar_plan(pasos, e.get("usuario"))
        if pedir_ok and not confirmar(e["nombre"]):
            print("  No se aplico ningun cambio.")
            return item

        print("\n  Aplicando...")
        item["aplicado"] = motor.aplicar(conn, e, pasos, cred)
        print("  Listo. Reconectando para la auditoria posterior...")
        conn.disconnect()
        conn = None
        time.sleep(5)
        conn = motor.conectar(e, cred)
        item["despues"] = auditar_equipo(conn, e, ctx, filtro, carpeta, "despues")
        mostrar(item["despues"], "Despues")
    except Exception as ex:  # el error queda en el informe y se sigue con el proximo equipo
        primera = (str(ex).strip().splitlines() or [""])[0]
        if "to accept" in primera:
            primera = ("conecto pero no aparecio el prompt; si el FortiGate pide cambiar la clave "
                       "(politica de contrasenas), cambiala por consola o SSH y vuelve a correr el script")
        elif isinstance(ex, EOFError):
            primera = ("el equipo cerro la conexion SSH durante la negociacion "
                       "(revisar que el puerto permita SSH y el MTU del camino)")
        item["error"] = ocultar(f"{type(ex).__name__}: {primera}")
        print(pintar(f"\n  ERROR: {item['error']}", ERROR))
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:
                pass
    return item


# ---------------------------------------------------------------------------
# Comando 'reglas'
# ---------------------------------------------------------------------------
def listar_reglas():
    for tipo, plat in motor.PLATAFORMAS.items():
        print(pintar(f"\n{informe.BENCHMARKS[tipo]}", codigo="1"))
        for r in plat["reglas"]:
            corrige = "si" if r.remediar else "solo revisa"
            print(f"  {r.id:<10} N{r.nivel}  {'/'.join(r.roles):<14} {corrige:<11} {r.titulo}")


# ---------------------------------------------------------------------------
def main():
    base = argparse.ArgumentParser(add_help=False)
    aqui = os.path.dirname(os.path.abspath(__file__))
    base.add_argument("-i", "--inventario", default=os.path.join(aqui, "inventario.json"),
                      help="archivo JSON con los equipos (por defecto: inventario.json)")
    base.add_argument("-e", "--equipos", help="solo estos equipos, separados por coma (p. ej. R1,SW1)")
    base.add_argument("-o", "--salida", default="reportes", help="carpeta de los informes (por defecto: reportes)")
    base.add_argument("--reglas", help="solo estas recomendaciones CIS, separadas por coma (p. ej. 1.2.2,1.5.1)")

    ap = argparse.ArgumentParser(description="Escaner de hardening CIS para Cisco IOS y FortiGate "
                                             "(Asignacion 4 - Jose Gabriel Feliz Maria 2025-0742)")
    sub = ap.add_subparsers(dest="modo", required=True)
    sub.add_parser("auditar", parents=[base], help="genera el informe sin aplicar nada")
    p_apl = sub.add_parser("aplicar", parents=[base], help="aplica las recomendaciones y genera el informe antes/despues")
    p_apl.add_argument("--sin-confirmar", action="store_true", help="no preguntar antes de aplicar en cada equipo")
    sub.add_parser("reglas", help="lista las recomendaciones que se revisan")
    args = ap.parse_args()

    if args.modo == "reglas":
        listar_reglas()
        return 0

    params, equipos = cargar_inventario(args.inventario, args.equipos)
    filtro = {x.strip() for x in args.reglas.split(",")} if args.reglas else None
    creds = pedir_credenciales(equipos)

    ahora = datetime.now()
    carpeta = os.path.join(args.salida, ahora.strftime("%Y%m%d_%H%M%S") + "_" + args.modo)
    n = 2
    while os.path.exists(carpeta):
        carpeta = os.path.join(args.salida, ahora.strftime("%Y%m%d_%H%M%S") + f"_{args.modo}_{n}")
        n += 1
    os.makedirs(carpeta)
    print(pintar(f"\nModo: {args.modo}  ·  Informe en: {carpeta}", codigo="1"))
    if args.modo == "auditar":
        print("Solo lectura: no se envia ningun comando de configuracion.")

    pedir_ok = args.modo == "aplicar" and not args.sin_confirmar
    resultados = []
    for e in equipos:
        cred = creds[e.get("credencial", e["nombre"])]
        resultados.append(procesar(e, params, cred, args.modo, filtro, carpeta, pedir_ok))

    datos = informe.a_dict(args.modo, ahora.strftime("%Y-%m-%d %H:%M:%S"), resultados)
    informe.guardar_json(datos, os.path.join(carpeta, "informe_cis.json"))
    informe.guardar_html(datos, os.path.join(carpeta, "informe_cis.html"))

    print(pintar("\nResumen", codigo="1"))
    for eq in datos["equipos"]:
        if "resumen_antes" not in eq:
            print(f"  {eq['nombre']:<5} {pintar('sin datos: ' + str(eq.get('error')), ERROR)}")
            continue
        txt = f"  {eq['nombre']:<5} {eq['resumen_antes']['porcentaje']:>3}%"
        if "resumen_despues" in eq:
            txt += f"  ->  {eq['resumen_despues']['porcentaje']:>3}%"
        if eq.get("error"):
            txt += "  " + pintar("(con error, ver informe)", ERROR)
        print(txt)
    print(f"\nInforme HTML: {os.path.join(carpeta, 'informe_cis.html')}")
    print(f"Informe JSON: {os.path.join(carpeta, 'informe_cis.json')}")
    return 1 if any(eq.get("error") for eq in datos["equipos"]) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nCancelado.")
        sys.exit(130)
