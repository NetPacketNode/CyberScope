from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .core import DomainResult, HostResult, ScanError

STYLE = """
body{font-family:Segoe UI,system-ui,sans-serif;background:#0c0a0a;color:#f3e9e9;margin:0;padding:2rem}
h1{color:#ff4d4d;margin-top:0}h2{color:#ff8a8a;border-bottom:1px solid #3a2222;padding-bottom:.4rem}
table{width:100%;border-collapse:collapse;margin-bottom:2rem}
th,td{text-align:left;padding:.5rem .7rem;border-bottom:1px solid #2a1c1c}
th{color:#a88a8a;font-weight:500}td.mono{font-family:Consolas,monospace}
.meta{color:#a88a8a;font-size:.9rem;margin-bottom:2rem}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:2rem}
.card{background:#171212;border:1px solid #2a1c1c;border-radius:12px;padding:1rem 1.2rem}
.card b{display:block;font-size:2rem;color:#ff4d4d}.card span{color:#a88a8a;font-size:.85rem}
.bar{display:grid;grid-template-columns:9rem 1fr 3rem;gap:.6rem;align-items:center;margin:.35rem 0;font-family:Consolas,monospace;font-size:.9rem}
.bar i{display:block;height:10px;border-radius:6px;background:linear-gradient(90deg,#ff3b3b,#ff9466)}
"""


def _summary(hosts: list[HostResult], domains: list[DomainResult]) -> str:
    services = Counter(p.service or "unknown" for h in hosts for p in h.ports)
    open_total = sum(services.values())
    cards = (
        f'<div class="card"><b>{len(hosts)}</b><span>живых хостов</span></div>'
        f'<div class="card"><b>{open_total}</b><span>открытых портов</span></div>'
        f'<div class="card"><b>{len(domains)}</b><span>поддоменов</span></div>'
    )
    top = services.most_common(8)
    peak = top[0][1] if top else 1
    bars = "".join(
        f'<div class="bar"><span>{html.escape(name)}</span>'
        f'<i style="width:{count / peak * 100:.0f}%"></i><span>{count}</span></div>'
        for name, count in top
    )
    chart = f"<h2>Сервисы</h2>{bars}" if bars else ""
    return f'<div class="cards">{cards}</div>{chart}'


def _table(headers: tuple[str, ...], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f'<td class="mono">{html.escape(cell)}</td>' for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def to_json(target: str, hosts: list[HostResult], domains: list[DomainResult]) -> str:
    payload = {
        "target": target,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hosts": [
            {
                "address": h.address,
                "hostname": h.hostname,
                "ports": [asdict(p) for p in h.ports],
            }
            for h in hosts
        ],
        "subdomains": [asdict(d) for d in domains],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def to_pdf(target: str, hosts: list[HostResult], domains: list[DomainResult], path: str) -> None:
    try:
        from fpdf import FPDF
    except ImportError as exc:
        raise ScanError("для --pdf установите fpdf2: pip install fpdf2") from exc
    font_path = Path(r"C:\Windows\Fonts\arial.ttf")
    if not font_path.exists():
        raise ScanError("шрифт arial.ttf не найден, PDF с кириллицей не создать")

    pdf = FPDF()
    pdf.add_page()
    pdf.add_font("Arial", "", str(font_path))
    pdf.set_font("Arial", size=16)
    pdf.cell(0, 10, "CyberScope", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Arial", size=10)
    pdf.cell(0, 6, f"Цель: {target}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Хостов: {len(hosts)}, поддоменов: {len(domains)}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, "Открытые порты", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Arial", size=9)
    for host in hosts:
        for p in host.ports:
            line = f"{host.address}  {p.number}/{p.proto}  {p.service or '-'}  {p.product or '-'}"
            pdf.cell(0, 5, line, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, "Поддомены", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Arial", size=9)
    for d in domains:
        pdf.cell(0, 5, f"{d.name}  {', '.join(d.addresses)}", new_x="LMARGIN", new_y="NEXT")

    pdf.output(path)


def render_html(target: str, hosts: list[HostResult], domains: list[DomainResult]) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    host_rows = [
        [h.address, h.hostname or "-", str(p.number), p.proto, p.service or "-", p.product or "-"]
        for h in hosts
        for p in h.ports
    ]
    domain_rows = [[d.name, ", ".join(d.addresses)] for d in domains]
    sections = [
        f"<h2>Открытые порты ({len(host_rows)})</h2>",
        _table(("Хост", "Имя", "Порт", "Протокол", "Сервис", "Продукт"), host_rows)
        if host_rows else "<p>Открытых портов не найдено.</p>",
        f"<h2>Поддомены ({len(domain_rows)})</h2>",
        _table(("Имя", "Адреса"), domain_rows)
        if domain_rows else "<p>Поддомены не найдены.</p>",
    ]
    return (
        "<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\">"
        f"<title>CyberScope: {html.escape(target)}</title><style>{STYLE}</style></head><body>"
        f"<h1>CyberScope</h1><div class=\"meta\">Цель: {html.escape(target)} · {generated}</div>"
        + _summary(hosts, domains)
        + "".join(sections)
        + "</body></html>"
    )
