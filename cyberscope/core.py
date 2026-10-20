from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.IGNORECASE)
PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
DEFAULT_SUBDOMAINS = (
    "www", "mail", "api", "dev", "test", "staging", "admin", "vpn",
    "ftp", "ns1", "ns2", "portal", "git", "blog", "shop",
)


class ScanError(Exception):
    pass


@dataclass(frozen=True)
class Port:
    number: int
    proto: str
    service: str
    product: str


@dataclass
class HostResult:
    address: str
    hostname: str | None = None
    ports: list[Port] = field(default_factory=list)


@dataclass
class DomainResult:
    name: str
    addresses: list[str]


def validate_target(target: str) -> str:
    target = target.strip()
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    if HOST_RE.match(target):
        return target.lower()
    raise ScanError(f"некорректная цель: {target!r}")


def validate_ports(ports: str) -> str:
    if not PORTS_RE.match(ports):
        raise ScanError(f"некорректный список портов: {ports!r}")
    return ports


def run_nmap(target: str, ports: str, timeout: int = 900) -> str:
    exe = shutil.which("nmap")
    if exe is None:
        raise ScanError("nmap не найден в PATH, установите Nmap")
    cmd = [exe, "-sV", "-T4", "-Pn", "-p", ports, "-oX", "-", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"nmap превысил таймаут {timeout} с") from exc
    if proc.returncode != 0:
        raise ScanError(proc.stderr.strip() or "nmap завершился с ошибкой")
    return proc.stdout


def _service_product(svc: ET.Element | None) -> str:
    if svc is None:
        return ""
    return " ".join(part for part in (svc.get("product", ""), svc.get("version", "")) if part)


def parse_nmap_xml(xml_text: str) -> list[HostResult]:
    root = ET.fromstring(xml_text)
    hosts: list[HostResult] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        address = next(
            (a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")),
            None,
        )
        if address is None:
            continue
        name_el = host.find("hostnames/hostname")
        ports: list[Port] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            ports.append(Port(
                number=int(port.get("portid", "0")),
                proto=port.get("protocol", ""),
                service=svc.get("name", "") if svc is not None else "",
                product=_service_product(svc),
            ))
        hosts.append(HostResult(
            address=address,
            hostname=name_el.get("name") if name_el is not None else None,
            ports=ports,
        ))
    return hosts


LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def load_wordlist(path: str) -> tuple[str, ...]:
    try:
        with open(path, encoding="utf-8") as fh:
            lines = [line.strip().lower() for line in fh]
    except OSError as exc:
        raise ScanError(f"не удалось прочитать вордлист: {exc}") from exc
    labels = tuple(dict.fromkeys(l for l in lines if l and not l.startswith("#")))
    bad = [l for l in labels if not LABEL_RE.match(l)]
    if bad:
        raise ScanError(f"некорректные метки в вордлисте: {', '.join(bad[:5])}")
    if not labels:
        raise ScanError("вордлист пуст")
    return labels


def enumerate_subdomains(domain: str, labels: tuple[str, ...] = DEFAULT_SUBDOMAINS, workers: int = 20) -> list[DomainResult]:
    def resolve(label: str) -> DomainResult | None:
        name = f"{label}.{domain}"
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except OSError:
            return None
        return DomainResult(name=name, addresses=sorted({info[4][0] for info in infos}))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return [r for r in pool.map(resolve, labels) if r is not None]
