from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core import (
    DEFAULT_SUBDOMAINS,
    DomainResult,
    HostResult,
    ScanError,
    enumerate_subdomains,
    parse_nmap_xml,
    run_nmap,
    validate_ports,
    validate_target,
)

MAX_BODY = 4096


@dataclass
class Job:
    state: str = "idle"
    target: str = ""
    error: str = ""
    hosts: list[HostResult] = field(default_factory=list)
    domains: list[DomainResult] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "state": self.state,
                "target": self.target,
                "error": self.error,
                "hosts": [
                    {"address": h.address, "hostname": h.hostname, "ports": [asdict(p) for p in h.ports]}
                    for h in self.hosts
                ],
                "subdomains": [asdict(d) for d in self.domains],
            }

    def start(self, target: str, ports: str, domain: str | None) -> bool:
        with self.lock:
            if self.state == "running":
                return False
            self.state, self.target, self.error = "running", target, ""
            self.hosts, self.domains = [], []
        threading.Thread(target=self._run, args=(target, ports, domain), daemon=True).start()
        return True

    def _run(self, target: str, ports: str, domain: str | None) -> None:
        try:
            hosts = parse_nmap_xml(run_nmap(target, ports))
            domains = enumerate_subdomains(domain, DEFAULT_SUBDOMAINS) if domain else []
        except ScanError as exc:
            self._finish("error", error=str(exc))
            return
        except Exception as exc:
            self._finish("error", error=f"внутренняя ошибка: {exc}")
            return
        with self.lock:
            self.hosts, self.domains = hosts, domains
        self._finish("done")

    def _finish(self, state: str, error: str = "") -> None:
        with self.lock:
            self.state, self.error = state, error


def make_handler(job: Job) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/":
                self._send(200, "text/html; charset=utf-8", DASHBOARD_HTML.encode("utf-8"))
            elif self.path == "/api/status":
                self._json(200, job.snapshot())
            else:
                self._json(404, {"error": "не найдено"})

        def do_POST(self) -> None:
            if self.path != "/api/scan":
                self._json(404, {"error": "не найдено"})
                return
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                self._json(415, {"error": "ожидается application/json"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._json(400, {"error": "некорректный Content-Length"})
                return
            if not 0 <= length <= MAX_BODY:
                self._json(413, {"error": "слишком большой запрос"})
                return
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "некорректный JSON"})
                return
            if not isinstance(body, dict) or body.get("permission") is not True:
                self._json(403, {"error": "подтвердите письменное разрешение на тестирование"})
                return
            try:
                target = validate_target(str(body.get("target", "")))
                ports = validate_ports(str(body.get("ports") or "1-1000"))
                domain = validate_target(str(body["domain"])) if body.get("domain") else None
            except ScanError as exc:
                self._json(400, {"error": str(exc)})
                return
            if not job.start(target, ports, domain):
                self._json(409, {"error": "сканирование уже выполняется"})
                return
            self._json(202, {"started": True})

        def _json(self, status: int, payload: dict) -> None:
            self._send(status, "application/json; charset=utf-8", json.dumps(payload, ensure_ascii=False).encode("utf-8"))

        def _send(self, status: int, ctype: str, data: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def make_server(port: int, job: Job | None = None) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(job or Job()))


def serve(port: int = 8765) -> None:
    server = make_server(port)
    print(f"CyberScope: http://127.0.0.1:{port}  (Ctrl+C для остановки)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberScope</title>
<style>
:root{--bg:#0c0a0a;--card:#171212;--line:#2a1c1c;--text:#f3e9e9;--muted:#a88a8a;--acc:#ff4d4d}
*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI,system-ui,sans-serif;background:var(--bg);color:var(--text);padding:2rem}
h1{margin:0 0 .3rem;color:var(--acc)}
h2{color:#ff8a8a;font-size:1.1rem;border-bottom:1px solid var(--line);padding-bottom:.4rem;margin-top:2rem}
.sub{color:var(--muted);margin-bottom:1.5rem}
form{display:grid;grid-template-columns:2fr 1.5fr 1fr auto;gap:.6rem;align-items:center;background:var(--card);border:1px solid var(--line);padding:1rem;border-radius:12px}
input[type=text]{background:#0c0808;border:1px solid var(--line);color:var(--text);padding:.6rem .8rem;border-radius:8px;font:inherit}
input:focus{outline:none;border-color:var(--acc)}
label.perm{grid-column:1/-1;color:var(--muted);font-size:.9rem}
button{background:linear-gradient(120deg,#ff3b3b,#ff9466);color:#fff;border:0;padding:.7rem 1.4rem;border-radius:8px;font-weight:700;cursor:pointer}
button:disabled{opacity:.5;cursor:default}
#status{margin:1rem 0;font-family:Consolas,monospace;color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1rem 1.2rem}
.card b{display:block;font-size:2rem;color:var(--acc)}.card span{color:var(--muted);font-size:.85rem}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:.5rem .7rem;border-bottom:1px solid var(--line);font-family:Consolas,monospace;font-size:.9rem}
th{color:var(--muted);font-weight:500;font-family:Segoe UI,sans-serif}
.bar{display:grid;grid-template-columns:9rem 1fr 3rem;gap:.6rem;align-items:center;margin:.35rem 0;font-family:Consolas,monospace;font-size:.9rem}
.bar i{display:block;height:10px;border-radius:6px;background:linear-gradient(90deg,#ff3b3b,#ff9466);transition:width .6s}
.err{color:#ff7a7a}
@media(max-width:700px){form{grid-template-columns:1fr}.cards{grid-template-columns:1fr}}
</style>
</head>
<body>
<h1>CyberScope</h1>
<div class="sub">Разведка по авторизованным целям. Сервер доступен только с этого компьютера.</div>
<form id="scan-form">
  <input type="text" id="target" placeholder="IP, CIDR или хост, например 192.168.1.10" required>
  <input type="text" id="domain" placeholder="домен для поддоменов (необязательно)">
  <input type="text" id="ports-in" placeholder="порты, 1-1000" value="1-1000">
  <button type="submit" id="go">Сканировать</button>
  <label class="perm"><input type="checkbox" id="perm"> У меня есть письменное разрешение на тестирование этой цели</label>
</form>
<div id="status">Ожидание запуска</div>
<div class="cards">
  <div class="card"><b id="hosts-n">0</b><span>живых хостов</span></div>
  <div class="card"><b id="open-n">0</b><span>открытых портов</span></div>
  <div class="card"><b id="subs-n">0</b><span>поддоменов</span></div>
</div>
<h2>Сервисы</h2>
<div id="bars"></div>
<h2>Открытые порты</h2>
<table><thead><tr><th>Хост</th><th>Имя</th><th>Порт</th><th>Протокол</th><th>Сервис</th><th>Продукт</th></tr></thead><tbody id="ports-tbody"></tbody></table>
<h2>Поддомены</h2>
<table><thead><tr><th>Имя</th><th>Адреса</th></tr></thead><tbody id="subs-tbody"></tbody></table>
<script>
const $ = s => document.querySelector(s);
function fill(tbody, rows) {
  tbody.replaceChildren(...rows.map(r => {
    const tr = document.createElement('tr');
    r.forEach(v => { const td = document.createElement('td'); td.textContent = v; tr.appendChild(td); });
    return tr;
  }));
}
function renderBars(counts) {
  const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const peak = top.length ? top[0][1] : 1;
  $('#bars').replaceChildren(...top.map(([name, n]) => {
    const row = document.createElement('div');
    row.className = 'bar';
    const label = document.createElement('span'); label.textContent = name;
    const fillBar = document.createElement('i'); fillBar.style.width = (n / peak * 100) + '%';
    const count = document.createElement('span'); count.textContent = n;
    row.append(label, fillBar, count);
    return row;
  }));
}
const STATES = { idle: 'Ожидание запуска', running: 'Сканирование', done: 'Готово' };
async function poll() {
  try {
    const s = await (await fetch('/api/status')).json();
    const text = s.state === 'error' ? 'Ошибка: ' + s.error
      : s.state === 'running' ? 'Сканирование: ' + s.target + '…'
      : s.state === 'done' ? 'Готово: ' + s.target
      : STATES.idle;
    $('#status').textContent = text;
    $('#status').className = s.state === 'error' ? 'err' : '';
    const rows = s.hosts.flatMap(h => h.ports.map(p => [h.address, h.hostname || '-', String(p.number), p.proto, p.service || '-', p.product || '-']));
    fill($('#ports-tbody'), rows);
    fill($('#subs-tbody'), s.subdomains.map(d => [d.name, d.addresses.join(', ')]));
    $('#hosts-n').textContent = s.hosts.length;
    $('#open-n').textContent = rows.length;
    $('#subs-n').textContent = s.subdomains.length;
    const counts = {};
    rows.forEach(r => { counts[r[4]] = (counts[r[4]] || 0) + 1; });
    renderBars(counts);
    $('#go').disabled = s.state === 'running';
  } catch (e) {
    $('#status').textContent = 'Нет связи с сервером';
  }
}
$('#scan-form').addEventListener('submit', async e => {
  e.preventDefault();
  const body = {
    target: $('#target').value.trim(),
    domain: $('#domain').value.trim() || null,
    ports: $('#ports-in').value.trim() || '1-1000',
    permission: $('#perm').checked
  };
  const r = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) alert((await r.json()).error);
  poll();
});
setInterval(poll, 1500);
poll();
</script>
</body>
</html>
"""
