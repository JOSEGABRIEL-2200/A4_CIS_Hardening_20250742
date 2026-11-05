"""Genera diagramas/topologia_a4_cis_hardening.png (Asignacion 4 - Jose Gabriel Feliz Maria 2025-0742)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Ellipse

fig, ax = plt.subplots(figsize=(17, 14), dpi=150)
ax.set_xlim(0, 170); ax.set_ylim(-6, 140); ax.axis("off")
fig.patch.set_facecolor("white")

INK = "#1f2937"; MUTED = "#6b7280"
C_FGT = "#c2410c"; C_CIS = "#0f766e"; C_KALI = "#1d4ed8"; C_SSH = "#2563eb"; C_LOG = "#7c3aed"; C_NET = "#64748b"


def box(x, y, w, h, title, lines, color, fs=9.0, tfs=12):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.5,rounding_size=1.8",
                                linewidth=2, edgecolor=color, facecolor="white", zorder=3))
    ax.text(x + w / 2, y + h - 3.0, title, ha="center", va="center", fontsize=tfs, fontweight="bold",
            color=color, zorder=4)
    for i, t in enumerate(lines):
        ax.text(x + w / 2, y + h - 6.9 - i * 3.1, t, ha="center", va="center", fontsize=fs,
                color=INK, family="DejaVu Sans Mono", zorder=4)


def link(p1, p2, label=None, off=(0, 0), fs=8.6):
    ax.plot([p1[0], p2[0]], [p1[1], p2[1]], color=INK, lw=2.2, zorder=2, solid_capstyle="round")
    if label:
        ax.text((p1[0] + p2[0]) / 2 + off[0], (p1[1] + p2[1]) / 2 + off[1], label, ha="left", va="center",
                fontsize=fs, color=MUTED, zorder=5, bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none"))


def flow(p1, p2, color, rad=0.0):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle="-|>", mutation_scale=16, color=color, lw=2.2,
                                 ls=(0, (5, 3)), connectionstyle=f"arc3,rad={rad}", zorder=1))


ax.text(85, 136, "Asignación 4 — Hardening con CIS Benchmark (router, switch y firewall)",
        ha="center", fontsize=17, fontweight="bold", color=INK)
ax.text(85, 132.2, "Jose Gabriel Feliz Maria · Matrícula 2025-0742 · Seguridad de Redes (ITLA)",
        ha="center", fontsize=10.5, color=MUTED)

# Internet
ax.add_patch(Ellipse((85, 122), 34, 9, facecolor="#f1f5f9", edgecolor=C_NET, lw=2, zorder=3))
ax.text(85, 122, "INTERNET (Cloud0)", ha="center", va="center", fontsize=11, fontweight="bold", color=C_NET, zorder=4)

box(55, 92, 60, 22, "FGT1 — FortiGate VM (firewall)", [
    "port1  DHCP (WAN)  ->  Internet",
    "port2  10.7.42.146/30  ->  R1",
    "CIS FortiGate 7.0.x Benchmark v1.3.0",
    "gestion solo desde 10.7.42.10"], C_FGT, tfs=11.5)

box(55, 56, 60, 26, "R1 — Cisco IOL 15.7 (router)", [
    "e0/0     10.7.42.145/30  WAN-FGT1",
    "e0/1.10  10.7.42.1/25    VLAN 10 LAN",
    "e0/1.99  10.7.42.137/29  VLAN 99 GESTION",
    "servidor DHCP · reserva 10.7.42.10",
    "CIS Cisco IOS 15 Benchmark v4.1.1"], C_CIS, tfs=11.5)

box(55, 27, 60, 19, "SW1 — Cisco IOL L2 15.2 (switch)", [
    "e0/0 trunk 10,99 -> R1 e0/1",
    "e0/1 VLAN 10 -> Net-AUDITOR",
    "Vlan99  10.7.42.138/29"], C_CIS, tfs=11.5)

box(46, 2, 78, 17, "NET-AUDITOR — Kali (estación de gestión)", [
    "eth1  10.7.42.10/25 (DHCP con reserva) · Cloud1",
    "Onyx · cis_hardening.py · Fortigate_CIS_check",
    "receptor syslog (UDP 514)"], C_KALI, fs=8.8, tfs=11.5)

link((85, 117.5), (85, 114.5))
link((85, 92), (85, 82.5), "port2 – e0/0 (10.7.42.144/30)", off=(2, 0))
link((85, 56), (85, 46.5), "e0/1 – e0/0 (trunk 10, 99)", off=(2, 0))
link((85, 27), (85, 19.5), "e0/1 (VLAN 10)", off=(2, 0))

# Flujos de gestion (SSH) y registros (syslog)
flow((48, 12), (54, 98), C_SSH, rad=-0.35)
flow((48, 10), (54, 66), C_SSH, rad=-0.30)
flow((48, 8), (54, 34), C_SSH, rad=-0.25)
flow((116, 98), (122, 12), C_LOG, rad=-0.35)
flow((116, 66), (122, 10), C_LOG, rad=-0.30)
flow((116, 34), (122, 8), C_LOG, rad=-0.25)

ax.text(14, 62, "SSH de auditoría\ny hardening\n(solo 10.7.42.10)", ha="center", va="center", fontsize=10,
        color=C_SSH, fontweight="bold")
ax.text(156, 62, "Syslog\n(UDP 514)\nhacia el Kali", ha="center", va="center", fontsize=10,
        color=C_LOG, fontweight="bold")

ax.text(85, -4, "Direccionamiento: 10.7.42.0/24 (de la matrícula 2025-0742) · LAN /25 · gestión /29 · enlace WAN /30",
        ha="center", fontsize=9.5, color=MUTED)

plt.savefig("topologia_a4_cis_hardening.png", bbox_inches="tight", facecolor="white")
print("ok")
