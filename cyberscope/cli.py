from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core import (
    DEFAULT_SUBDOMAINS,
    ScanError,
    enumerate_subdomains,
    load_wordlist,
    parse_nmap_xml,
    run_nmap,
    validate_ports,
    validate_target,
)
from .report import render_html, to_json, to_pdf


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberscope",
        description="Разведка: Nmap + перебор поддоменов, HTML-отчёт. Только для авторизованных целей.",
    )
    parser.add_argument("target", nargs="?", help="IP, CIDR или имя хоста")
    parser.add_argument("--serve", action="store_true", help="запустить веб-дашборд на 127.0.0.1")
    parser.add_argument("--port", type=int, default=8765, help="порт дашборда")
    parser.add_argument("--domain", help="домен для перебора поддоменов")
    parser.add_argument("--ports", default="1-1000", help="порты для Nmap, например 22,80,443 или 1-1000")
    parser.add_argument("--out", default="report.html", help="путь к HTML-отчёту")
    parser.add_argument("--json", dest="json_out", help="путь для экспорта результатов в JSON")
    parser.add_argument("--pdf", dest="pdf_out", help="путь для PDF-отчёта (нужен fpdf2)")
    parser.add_argument("--wordlist", help="файл с метками поддоменов, по одной в строке")
    parser.add_argument(
        "--i-have-permission",
        action="store_true",
        dest="permitted",
        help="подтверждаю наличие письменного разрешения на тестирование цели",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.serve:
        from .web import serve
        serve(args.port)
        return 0
    if not args.target:
        parser.error("укажите цель или --serve")
    if not args.permitted:
        print("Отказ: укажите --i-have-permission, подтвердив разрешение на тестирование.", file=sys.stderr)
        return 2
    try:
        target = validate_target(args.target)
        ports = validate_ports(args.ports)
        hosts = parse_nmap_xml(run_nmap(target, ports))
        domains = []
        if args.domain:
            labels = load_wordlist(args.wordlist) if args.wordlist else DEFAULT_SUBDOMAINS
            domains = enumerate_subdomains(validate_target(args.domain), labels)
        out = Path(args.out)
        out.write_text(render_html(target, hosts, domains), encoding="utf-8")
        if args.json_out:
            Path(args.json_out).write_text(to_json(target, hosts, domains), encoding="utf-8")
        if args.pdf_out:
            to_pdf(target, hosts, domains, args.pdf_out)
    except ScanError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1

    open_ports = sum(len(h.ports) for h in hosts)
    print(f"Хостов: {len(hosts)}, открытых портов: {open_ports}, поддоменов: {len(domains)}")
    print(f"Отчёт: {out.resolve()}")
    return 0
