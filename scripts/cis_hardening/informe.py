"""
informe.py - Informes HTML y JSON del escaner de hardening CIS.
Asignacion 4 - Jose Gabriel Feliz Maria (2025-0742)
"""

import html
import json
from nucleo import CUMPLE, NO_CUMPLE, EXCEPCION, ERROR, ocultar

BENCHMARKS = {
    "ios": "CIS Cisco IOS 15 Benchmark v4.1.1",
    "fortios": "CIS Fortinet FortiGate 7.0.x Benchmark v1.3.0",
}


def resumen(resultados):
    c = {CUMPLE: 0, NO_CUMPLE: 0, EXCEPCION: 0, ERROR: 0}
    for r in resultados:
        c[r["estado"] if isinstance(r, dict) else r.estado] += 1
    evaluadas = c[CUMPLE] + c[NO_CUMPLE]
    c["porcentaje"] = round(100 * c[CUMPLE] / evaluadas) if evaluadas else 0
    return c


def a_dict(modo, fecha, equipos):
    """equipos: lista de dicts {nombre, ip, tipo, rol, antes, despues?, aplicado?, error?}"""
    salida = {"modo": modo, "fecha": fecha, "equipos": []}
    for e in equipos:
        item = {k: e.get(k) for k in ("nombre", "ip", "tipo", "rol", "error")}
        item["benchmark"] = BENCHMARKS[e["tipo"]]
        for fase in ("antes", "despues"):
            if e.get(fase) is not None:
                item[fase] = [r.como_dict() for r in e[fase]]
                item[f"resumen_{fase}"] = resumen(item[fase])
        if e.get("aplicado") is not None:
            item["comandos_aplicados"] = [ocultar(c) for c in e["aplicado"]]
        salida["equipos"].append(item)
    return salida


def guardar_json(datos, ruta):
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)


_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1f2937;--muted:#6b7280;--ok:#15803d;--okbg:#dcfce7;--bad:#b91c1c;
--badbg:#fee2e2;--exc:#92400e;--excbg:#fef3c7;--line:#e5e7eb;--acc:#1d4ed8}
@media (prefers-color-scheme:dark){:root{--bg:#0f172a;--card:#111827;--ink:#e5e7eb;--muted:#9ca3af;--ok:#4ade80;
--okbg:#14532d;--bad:#f87171;--badbg:#7f1d1d;--exc:#fbbf24;--excbg:#78350f;--line:#374151;--acc:#93c5fd}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,Segoe UI,Arial,sans-serif}
main{max-width:1150px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 8px}
.sub{color:var(--muted);margin:0 0 18px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:12px 0}
.kpis{display:flex;flex-wrap:wrap;gap:10px}.kpi{flex:1 1 80px;border:1px solid var(--line);border-radius:8px;padding:10px}
.kpi b{display:block;font-size:22px}.kpi span{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 8px;border-top:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}.est{font-weight:700;border-radius:6px;padding:2px 6px;white-space:nowrap;display:inline-block}
.CUMPLE{color:var(--ok);background:var(--okbg)}.NO{color:var(--bad);background:var(--badbg)}.EXCEPCION,.ERROR{color:var(--exc);background:var(--excbg)}
code,pre{font-family:ui-monospace,Consolas,monospace;font-size:12px}pre{white-space:pre-wrap;margin:0}
.porque{color:var(--muted);font-size:12px}.wrap{overflow-x:auto}
.grupos{display:flex;flex-wrap:wrap;gap:16px}.grupo{flex:1 1 320px}.grupo h3{font-size:13px;margin:0 0 8px;color:var(--muted);
text-transform:uppercase;letter-spacing:.04em}.big{font-weight:700}
"""


def _badge(estado):
    clase = "NO" if estado == NO_CUMPLE else estado
    return f'<span class="est {clase}">{html.escape(estado)}</span>'


def _kpis(res, titulo):
    return (f'<div class="grupo"><h3>{titulo}</h3><div class="kpis">'
            f'<div class="kpi"><b>{res["porcentaje"]}%</b><span>cumplimiento</span></div>'
            f'<div class="kpi"><b>{res[CUMPLE]}</b><span>cumple</span></div>'
            f'<div class="kpi"><b>{res[NO_CUMPLE]}</b><span>no cumple</span></div>'
            f'<div class="kpi"><b>{res[EXCEPCION]}</b><span>excepcion</span></div>'
            f'<div class="kpi"><b>{res[ERROR]}</b><span>error</span></div></div></div>')


def _tabla_resumen(datos):
    esc = html.escape
    hay_despues = any("resumen_despues" in e for e in datos["equipos"])
    filas = []
    for e in datos["equipos"]:
        if "resumen_antes" not in e:
            filas.append(f"<tr><td>{esc(e['nombre'])}</td><td>{esc(e['rol'])}</td>"
                         f"<td colspan='3'>{esc(str(e.get('error')))}</td></tr>")
            continue
        a = e["resumen_antes"]
        fila = (f"<tr><td class='big'>{esc(e['nombre'])}</td><td>{esc(e['rol'])}</td>"
                f"<td>{esc(e['benchmark'])}</td><td class='big'>{a['porcentaje']}%</td>")
        if hay_despues:
            d = e.get("resumen_despues")
            fila += f"<td class='big'>{str(d['porcentaje']) + '%' if d else '—'}</td>"
        filas.append(fila + "</tr>")
    cab = "<th>Antes</th><th>Despues</th>" if hay_despues else "<th>Cumplimiento</th>"
    return ("<div class='card wrap'><table><tr><th>Equipo</th><th>Rol</th><th>Benchmark</th>"
            f"{cab}</tr>{''.join(filas)}</table>"
            "<p class='porque'>Cumplimiento = cumple / (cumple + no cumple). Las excepciones documentadas "
            "no cuentan.</p></div>")


def guardar_html(datos, ruta):
    esc = html.escape
    modo_txt = ("Auditoria (solo lectura, sin aplicar reglas)" if datos["modo"] == "auditar"
                else "Aplicacion de reglas con informe antes/despues")
    partes = [f"<!doctype html><html lang='es'><head><meta charset='utf-8'>"
              f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
              f"<title>Informe CIS - {esc(datos['fecha'])}</title><style>{_CSS}</style></head><body><main>",
              "<h1>Informe de hardening CIS</h1>",
              f"<p class='sub'>{esc(modo_txt)} · {esc(datos['fecha'])} · Asignacion 4 · Jose Gabriel Feliz Maria (2025-0742)</p>",
              _tabla_resumen(datos)]
    for e in datos["equipos"]:
        partes.append(f"<h2>{esc(e['nombre'])} · {esc(e['ip'])} · {esc(e['rol'])}</h2>")
        partes.append(f"<p class='sub'>{esc(e['benchmark'])}</p>")
        if e.get("error"):
            partes.append(f"<div class='card'><b>Error:</b> {esc(e['error'])}</div>")
        if "antes" not in e:
            continue
        partes.append("<div class='card'><div class='grupos'>")
        partes.append(_kpis(e["resumen_antes"], "Antes" if "despues" in e else "Estado actual"))
        if "despues" in e:
            partes.append(_kpis(e["resumen_despues"], "Despues"))
        partes.append("</div></div>")
        despues = {r["id"]: r for r in e.get("despues", [])}
        cab = "<th>Antes</th><th>Despues</th>" if despues else "<th>Estado</th>"
        partes.append(f"<div class='card wrap'><table><tr><th>CIS</th><th>Recomendacion</th><th>Nivel</th>{cab}"
                      "<th>Evidencia</th><th>Remediacion</th></tr>")
        for r in e["antes"]:
            d = despues.get(r["id"])
            if d and d["evidencia"] != r["evidencia"]:
                evid = f"<b>antes:</b> {esc(r['evidencia'])}<br><b>despues:</b> {esc(d['evidencia'])}"
            else:
                evid = esc(r["evidencia"])
            celdas = _badge(r["estado"]) + (f"</td><td>{_badge(d['estado'])}" if d else "")
            rem = "<br>".join(esc(c) for c in r["remediacion"]) or "—"
            partes.append(
                f"<tr><td><code>{esc(r['id'])}</code></td><td>{esc(r['titulo'])}"
                f"<div class='porque'>{esc(r['por_que'])}</div></td><td>{r['nivel']}</td><td>{celdas}</td>"
                f"<td><code>{evid}</code></td><td><code>{rem}</code></td></tr>")
        partes.append("</table></div>")
        if e.get("comandos_aplicados"):
            partes.append("<div class='card'><b>Comandos aplicados</b><pre>"
                          + esc("\n".join(e["comandos_aplicados"])) + "</pre></div>")
        elif datos["modo"] == "aplicar" and "comandos_aplicados" in e:
            partes.append("<div class='card'><b>No se aplicaron cambios en este equipo.</b></div>")
    partes.append("</main></body></html>")
    with open(ruta, "w", encoding="utf-8") as f:
        f.write("\n".join(partes))
