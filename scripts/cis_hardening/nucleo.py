"""
nucleo.py - Piezas comunes del escaner de hardening CIS.
Asignacion 4 - Jose Gabriel Feliz Maria (2025-0742)

Define la estructura de una regla, los estados posibles, el ocultado de
secretos y unas utilidades para leer configuraciones de Cisco IOS y FortiOS.
"""

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

CUMPLE = "CUMPLE"
NO_CUMPLE = "NO CUMPLE"
EXCEPCION = "EXCEPCION"      # no se aplica a este equipo, con motivo documentado
ERROR = "ERROR"              # no se pudo verificar


@dataclass
class Regla:
    """Una recomendacion del CIS Benchmark que el script sabe verificar y corregir."""
    id: str                         # numero del CIS Benchmark, p. ej. "1.1.1"
    titulo: str                     # titulo de la recomendacion
    nivel: int                      # perfil CIS: 1 o 2
    seccion: str                    # plano o seccion del benchmark
    por_que: str                    # por que se aplica en esta red
    verificar: Callable             # f(datos, ctx) -> (estado, evidencia)
    remediar: Optional[Callable] = None   # f(datos, ctx) -> lista de comandos
    roles: tuple = ("router", "switch", "firewall")


@dataclass
class Resultado:
    regla: Regla
    estado: str
    evidencia: str = ""
    comandos: list = field(default_factory=list)
    usuario: str = "<usuario>"

    def como_dict(self):
        return {
            "id": self.regla.id,
            "titulo": self.regla.titulo,
            "nivel": self.regla.nivel,
            "seccion": self.regla.seccion,
            "estado": self.estado,
            "evidencia": ocultar(self.evidencia),
            "por_que": self.regla.por_que,
            "remediacion": describir(self.comandos, self.usuario),
        }


def describir(cmds, usuario="<usuario>"):
    """Traduce las acciones especiales '@...' a los comandos reales que se
    envian (con las claves tapadas), para el plan y los informes."""
    salida = []
    for c in cmds:
        if c == "@ENABLE_SECRET":
            salida += ["enable algorithm-type scrypt secret <OCULTO>", "no enable password"]
        elif c == "@USUARIO":
            salida += [f"no username {usuario}",
                       f"username {usuario} privilege 1 algorithm-type scrypt secret <OCULTO>"]
        elif c.startswith("@RSA"):
            salida.append(f"crypto key generate rsa general-keys modulus {c.split()[1]}")
        else:
            salida.append(ocultar(c))
    return salida


# ---------------------------------------------------------------------------
# Ocultar secretos (nada de claves en informes, pantalla ni repositorio)
# ---------------------------------------------------------------------------
# El orden importa: primero los formatos de FortiOS (ENC / set password) y
# despues los de Cisco IOS.
_PATRONES_SECRETOS = [
    # Claves privadas PEM (los certificados locales del FortiGate las traen en la configuracion)
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "<OCULTO>"),
    (re.compile(r"(\bENC[ \t]+)(\S+)"), r"\1<OCULTO>"),
    (re.compile(r"(\bset[ \t]+(?:password|passwd|psksecret|ppk-secret|auth-pwd|priv-pwd|secret|key|private-key)[ \t]+)(.+)", re.I),
     r"\1<OCULTO>"),
    (re.compile(r"(\b(?:password|secret)[ \t]+)(\d[ \t]+)?(?!<OCULTO>)(\S+)", re.I), r"\1\2<OCULTO>"),
    (re.compile(r"(\bkey[ \t]+)(\d[ \t]+)(\S+)", re.I), r"\1\2<OCULTO>"),
    (re.compile(r"(\bkey-string[ \t]+)(\d[ \t]+)?(\S+)", re.I), r"\1\2<OCULTO>"),
    (re.compile(r"(\bcommunity[ \t]+)(?!<OCULTO>)(\S+)", re.I), r"\1<OCULTO>"),
]
_SECRETOS_EXTRA = set()   # valores reales a tapar (claves escritas en la sesion)


def registrar_secreto(valor):
    # Claves muy cortas no se registran para no tapar palabras comunes del informe
    if valor and len(valor) >= 6:
        _SECRETOS_EXTRA.add(valor)


def ocultar(texto):
    if not texto:
        return texto
    for patron, reemplazo in _PATRONES_SECRETOS:
        texto = patron.sub(reemplazo, texto)
    for valor in _SECRETOS_EXTRA:
        texto = texto.replace(valor, "<OCULTO>")
    return texto


# ---------------------------------------------------------------------------
# Lectura de configuracion Cisco IOS
# ---------------------------------------------------------------------------
def lineas(run):
    return [l.rstrip() for l in run.splitlines()]


def tiene_linea(run, patron):
    """True si alguna linea global (sin sangria) coincide con el patron (regex)."""
    rx = re.compile(patron)
    return any(rx.search(l) for l in lineas(run) if l and not l.startswith(" "))


def lineas_que(run, patron, globales=True):
    rx = re.compile(patron)
    return [l for l in lineas(run) if rx.search(l) and (not globales or not l.startswith(" "))]


def bloques(run, encabezado):
    """Devuelve {linea_encabezado: [lineas hijas]} para cada bloque cuyo
    encabezado coincide con el regex (p. ej. r'^line vty', r'^interface ')."""
    rx = re.compile(encabezado)
    salida, actual = {}, None
    for l in lineas(run):
        if l and not l.startswith(" "):
            actual = l if rx.search(l) else None
            if actual:
                salida[actual] = []
        elif actual is not None and l.strip() and l.strip() != "!":
            salida[actual].append(l.strip())
    return salida


def interfaces_con_ip(run):
    """Interfaces que tienen direccion IP (donde aplican proxy-arp, etc.)."""
    return {k: v for k, v in bloques(run, r"^interface ").items()
            if any(h.startswith("ip address ") for h in v)
            and not any(h == "shutdown" for h in v)}


# ---------------------------------------------------------------------------
# Lectura de configuracion FortiOS
# ---------------------------------------------------------------------------
def fgt_set(texto, clave):
    """Valor del primer 'set <clave> <valor>' (sin comillas) o None."""
    m = re.search(r"^\s*set\s+" + re.escape(clave) + r"\s+(.+?)\s*$", texto, re.M)
    if not m:
        return None
    return m.group(1).strip().strip('"')


def fgt_edits(texto):
    """Divide un bloque 'config ...' en {nombre_edit: texto_del_edit}."""
    salida, actual, buf, prof = {}, None, [], 0
    for l in texto.splitlines():
        s = l.strip()
        if actual is None:
            m = re.match(r'^edit\s+"?([^"]+?)"?$', s)
            if m:
                actual, buf, prof = m.group(1), [], 0
            continue
        if s.startswith("config "):
            prof += 1
        elif s == "end" and prof > 0:
            prof -= 1
        elif s == "next" and prof == 0:
            salida[actual] = "\n".join(buf)
            actual = None
            continue
        buf.append(l)
    if actual is not None:
        salida[actual] = "\n".join(buf)
    return salida
