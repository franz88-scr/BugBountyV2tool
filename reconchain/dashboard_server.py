"""
reconchain.dashboard_server — live web dashboard with SSE streaming.

Starts an embedded HTTP server that serves a single-page dashboard with
real-time updates via Server-Sent Events. Subscribes to the event bus
for live phase progress, finding alerts, and resource monitoring.

Usage:
    from reconchain.dashboard_server import start_dashboard

    # In pipeline.py, after event bus is set up:
    start_dashboard(host, port)
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
from http import HTTPStatus
from pathlib import Path
from typing import Any, Dict, List

from reconchain.events import bus
from reconchain.utils import log

_dashboard_clients: List[asyncio.Queue] = []
_dashboard_clients_lock = threading.Lock()
_dashboard_loop: asyncio.AbstractEventLoop | None = None
_server_started = False


async def _sse_handler(request: Any) -> None:
    """Handle an SSE client connection."""
    queue: asyncio.Queue = asyncio.Queue()
    with _dashboard_clients_lock:
        _dashboard_clients.append(queue)
    try:
        response = request.response
        response.status = HTTPStatus.OK
        response.content_type = "text/event-stream"
        response.headers["Cache-Control"] = "no-cache"
        response.headers["Connection"] = "keep-alive"
        response.headers["Access-Control-Allow-Origin"] = "*"

        # Send initial state
        initial = json.dumps({
            "type": "init",
            "data": {"message": "connected", "ts": time.time()},
        })
        response.write(f"data: {initial}\n\n".encode())

        # Stream events
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30)
                response.write(event.encode())
            except asyncio.TimeoutError:
                # Send keepalive
                response.write(b": keepalive\n\n")
    except (ConnectionError, OSError, asyncio.CancelledError):
        pass
    finally:
        with _dashboard_clients_lock:
            if queue in _dashboard_clients:
                _dashboard_clients.remove(queue)


async def _broadcast(event_type: str, data: Dict[str, Any]) -> None:
    """Broadcast an event to all connected SSE clients."""
    payload = json.dumps({"type": event_type, "data": data})
    message = f"data: {payload}\n\n"
    with _dashboard_clients_lock:
        clients_snapshot = list(_dashboard_clients)
    dead: List[asyncio.Queue] = []
    for q in clients_snapshot:
        try:
            q.put_nowait(message)
        except asyncio.QueueFull:
            dead.append(q)
    if dead:
        with _dashboard_clients_lock:
            for d in dead:
                try:
                    _dashboard_clients.remove(d)
                except ValueError:
                    pass


def _setup_event_subscriptions() -> None:
    """Subscribe to the event bus and forward events to SSE clients."""
    loop = _dashboard_loop

    def _schedule_broadcast(event_type: str, data: Dict[str, Any]) -> None:
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(
                asyncio.ensure_future,
                _broadcast(event_type, data),
            )

    def on_phase_start(event: Any) -> None:
        _schedule_broadcast("phase.start", event.data)

    def on_phase_complete(event: Any) -> None:
        _schedule_broadcast("phase.complete", event.data)

    def on_phase_fail(event: Any) -> None:
        _schedule_broadcast("phase.fail", event.data)

    def on_finding(event: Any) -> None:
        _schedule_broadcast("finding.new", event.data)

    def on_progress(event: Any) -> None:
        _schedule_broadcast("scan.progress", event.data)

    def on_resource(event: Any) -> None:
        _schedule_broadcast("resource.update", event.data)

    def on_scan_complete(event: Any) -> None:
        _schedule_broadcast("scan.complete", event.data)

    bus.subscribe("phase.start", on_phase_start)
    bus.subscribe("phase.complete", on_phase_complete)
    bus.subscribe("phase.fail", on_phase_fail)
    bus.subscribe("finding.new", on_finding)
    bus.subscribe("scan.progress", on_progress)
    bus.subscribe("resource.update", on_resource)
    bus.subscribe("scan.complete", on_scan_complete)


_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconChain Live Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--fg:#c9d1d9;--fg2:#8b949e;--acc:#58a6ff;--ok:#3fb950;--warn:#d29922;--err:#f85149;--purple:#d2a8ff;--orange:#f0883e}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',monospace;font-size:13px}
.header{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:16px}
.header h1{font-size:15px;color:var(--acc);font-weight:600}
.header .dot{width:8px;height:8px;border-radius:50%;background:var(--ok);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.header .status{color:var(--fg2);font-size:12px;margin-left:auto}
.grid{display:grid;grid-template-columns:1fr 320px;gap:1px;background:var(--border);min-height:calc(100vh - 44px)}
.col{background:var(--bg);padding:12px;overflow-y:auto}
.stats-bar{display:grid;grid-template-columns:repeat(6,1fr);gap:1px;background:var(--border)}
.stat{background:var(--surface);padding:12px;text-align:center}
.stat .num{font-size:24px;font-weight:700}
.stat .label{font-size:11px;color:var(--fg2);margin-top:2px}
.stat.critical .num{color:var(--err)}
.stat.high .num{color:var(--orange)}
.stat.medium .num{color:var(--warn)}
.stat.low .num{color:var(--fg2)}
.stat.total .num{color:var(--acc)}
.stat.phases .num{color:var(--purple)}
.section{margin-bottom:16px}
.section h3{font-size:12px;color:var(--fg2);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid var(--border)}
.phase-list{max-height:240px;overflow-y:auto}
.phase{display:flex;align-items:center;gap:8px;padding:3px 0;font-size:12px}
.phase .icon{width:14px;text-align:center}
.phase .name{color:var(--fg2);flex:1}
.phase .time{color:var(--fg2);font-size:11px}
.phase.done .icon{color:var(--ok)}
.phase.running .icon{color:var(--acc);animation:pulse 1s infinite}
.phase.failed .icon{color:var(--err)}
.phase.pending .icon{color:var(--fg2)}
.finding-ticker{max-height:360px;overflow-y:auto}
.finding{padding:6px 8px;border-bottom:1px solid var(--border);font-size:12px;animation:fadeIn .3s}
.finding:hover{background:var(--surface)}
.finding .sev{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px}
.finding .sev.critical{background:var(--err)}
.finding .sev.high{background:var(--orange)}
.finding .sev.medium{background:var(--warn)}
.finding .sev.low{background:var(--fg2)}
.finding .text{color:var(--fg)}
.finding .meta{color:var(--fg2);font-size:11px;margin-top:2px}
@keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
.gauge{margin:4px 0}
.gauge .label{font-size:11px;color:var(--fg2);display:flex;justify-content:space-between}
.gauge .bar{height:6px;background:var(--border);border-radius:3px;overflow:hidden;margin-top:2px}
.gauge .fill{height:100%;border-radius:3px;transition:width .5s ease}
.search{width:100%;background:var(--surface);border:1px solid var(--border);color:var(--fg);padding:6px 10px;border-radius:6px;font-size:12px;margin-bottom:8px}
</style>
</head>
<body>
<div class="header">
  <div class="dot" id="conn-dot"></div>
  <h1>&#9881; ReconChain Live Dashboard</h1>
  <span class="status" id="conn-status">Connecting...</span>
</div>
<div class="stats-bar" id="stats-bar">
  <div class="stat total"><div class="num" id="s-total">0</div><div class="label">TOTAL</div></div>
  <div class="stat critical"><div class="num" id="s-critical">0</div><div class="label">CRITICAL</div></div>
  <div class="stat high"><div class="num" id="s-high">0</div><div class="label">HIGH</div></div>
  <div class="stat medium"><div class="num" id="s-medium">0</div><div class="label">MEDIUM</div></div>
  <div class="stat low"><div class="num" id="s-low">0</div><div class="label">LOW/INFO</div></div>
  <div class="stat phases"><div class="num" id="s-phases">0/0</div><div class="label">PHASES</div></div>
</div>
<div class="grid">
  <div class="col">
    <div class="section">
      <h3>Phase Progress</h3>
      <div class="phase-list" id="phases"></div>
    </div>
    <div class="section">
      <h3>Resource Monitor</h3>
      <div class="gauge"><div class="label"><span>CPU</span><span id="cpu-val">0%</span></div><div class="bar"><div class="fill" id="cpu-bar" style="width:0;background:var(--acc)"></div></div></div>
      <div class="gauge"><div class="label"><span>RAM</span><span id="ram-val">0%</span></div><div class="bar"><div class="fill" id="ram-bar" style="width:0;background:var(--purple)"></div></div></div>
      <div class="gauge"><div class="label"><span>Concurrency</span><span id="conc-val">0</span></div><div class="bar"><div class="fill" id="conc-bar" style="width:0;background:var(--ok)"></div></div></div>
    </div>
    <div class="section">
      <h3>AI Analysis</h3>
      <div id="ai-panel" style="color:var(--fg2);font-size:12px;padding:4px 0">Waiting for scan completion...</div>
    </div>
  </div>
  <div class="col">
    <h3 style="font-size:12px;color:var(--fg2);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Findings</h3>
    <input class="search" placeholder="Filter findings..." id="search" oninput="filterFindings()" />
    <div class="finding-ticker" id="findings"></div>
  </div>
</div>
<script>
let phases={}, findings=[], findingsRaw=[], sevCounts={critical:0,high:0,medium:0,low:0};
let totalPhases=0, donePhases=0;

function updateStats(){
  document.getElementById('s-total').textContent=findings.length;
  document.getElementById('s-critical').textContent=sevCounts.critical;
  document.getElementById('s-high').textContent=sevCounts.high;
  document.getElementById('s-medium').textContent=sevCounts.medium;
  document.getElementById('s-low').textContent=sevCounts.low;
  document.getElementById('s-phases').textContent=donePhases+'/'+totalPhases;
}

function guessSeverity(text){
  var t=text.toLowerCase();
  if(/rce|critical|remote code|sql injection/.test(t))return'critical';
  if(/xss|ssrf|lfi|idor|sqli|high/.test(t))return'high';
  if(/medium|redirect|cors|open redirect/.test(t))return'medium';
  return'low';
}

function renderPhases(){
  var el=document.getElementById('phases');
  var html='';
  var sorted=Object.entries(phases).sort((a,b)=>{
    var order={running:0,failed:1,done:2,pending:3};
    return(order[a[1].status]||3)-(order[b[1].status]||3);
  });
  for(var[name,s]of sorted){
    var icon=s.status==='done'?'&#10003;':s.status==='running'?'&#9679;':s.status==='failed'?'&#10007;':'&#9675;';
    var timeStr=s.elapsed?s.elapsed+'s':'';
    html+='<div class="phase '+s.status+'"><span class="icon">'+icon+'</span><span class="name">'+escapeHtml(name)+'</span><span class="time">'+escapeHtml(String(timeStr))+'</span></div>';
  }
  el.innerHTML=html;
}

function renderFindings(){
  var el=document.getElementById('findings');
  var q=document.getElementById('search').value.toLowerCase();
  var filtered=findingsRaw.filter(f=>!q||f.text.toLowerCase().includes(q)||f.severity.includes(q));
  var html='';
  for(var f of filtered.slice(-100).reverse()){
    html+='<div class="finding"><span class="sev '+f.severity+'"></span><span class="text">'+escapeHtml(f.text.substring(0,120))+'</span><div class="meta">'+escapeHtml(f.source)+' &middot; '+escapeHtml(f.severity.toUpperCase())+'</div></div>';
  }
  el.innerHTML=html;
}

function filterFindings(){renderFindings()}

function escapeHtml(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

function connect(){
  var es=new EventSource('/events');
  es.onopen=function(){
    document.getElementById('conn-dot').style.background='var(--ok)';
    document.getElementById('conn-status').textContent='Connected';
  };
  es.onerror=function(){
    document.getElementById('conn-dot').style.background='var(--err)';
    document.getElementById('conn-status').textContent='Reconnecting...';
  };
  es.addEventListener('phase.start',function(e){
    var d=JSON.parse(e.data);
    phases[d.phase]={status:'running',start:d.ts||Date.now()/1000};
    totalPhases=Object.keys(phases).length;
    renderPhases();updateStats();
  });
  es.addEventListener('phase.complete',function(e){
    var d=JSON.parse(e.data);
    if(phases[d.phase]){
      phases[d.phase].status='done';
      phases[d.phase].elapsed=d.elapsed?d.elapsed.toFixed(1):'';
    }
    donePhases=Object.values(phases).filter(p=>p.status==='done'||p.status==='failed').length;
    renderPhases();updateStats();
  });
  es.addEventListener('phase.fail',function(e){
    var d=JSON.parse(e.data);
    if(phases[d.phase])phases[d.phase].status='failed';
    donePhases=Object.values(phases).filter(p=>p.status==='done'||p.status==='failed').length;
    renderPhases();updateStats();
  });
  es.addEventListener('finding.new',function(e){
    var d=JSON.parse(e.data);
    var sev=d.severity||guessSeverity(d.text||d.finding||'');
    sevCounts[sev]=(sevCounts[sev]||0)+1;
    findingsRaw.push({text:d.text||d.finding||JSON.stringify(d),severity:sev,source:d.source||d.phase||''});
    renderFindings();updateStats();
  });
  es.addEventListener('scan.progress',function(e){
    var d=JSON.parse(e.data);
    document.getElementById('s-phases').textContent=(d.completed||donePhases)+'/'+(d.total||totalPhases);
  });
  es.addEventListener('resource.update',function(e){
    var d=JSON.parse(e.data);
    if(d.cpu!==undefined){
      document.getElementById('cpu-val').textContent=d.cpu.toFixed(0)+'%';
      document.getElementById('cpu-bar').style.width=d.cpu+'%';
      document.getElementById('cpu-bar').style.background=d.cpu>80?'var(--err)':d.cpu>60?'var(--warn)':'var(--acc)';
    }
    if(d.ram!==undefined){
      document.getElementById('ram-val').textContent=d.ram.toFixed(0)+'%';
      document.getElementById('ram-bar').style.width=d.ram+'%';
    }
    if(d.concurrency!==undefined){
      document.getElementById('conc-val').textContent=d.concurrency;
      document.getElementById('conc-bar').style.width=Math.min(100,d.concurrency*10)+'%';
    }
  });
  es.addEventListener('scan.complete',function(e){
    document.getElementById('ai-panel').innerHTML='<span style="color:var(--ok)">&#10003; Scan complete</span><br><span>Check ai_triage.json for AI analysis</span>';
  });
}

connect();
</script>
</body>
</html>"""


async def _handle_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle a single HTTP request."""
    try:
        data = await asyncio.wait_for(reader.readline(), timeout=10)
        request_line = data.decode().strip()
        if not request_line:
            writer.close()
            return

        parts = request_line.split()
        method = parts[0] if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        # Read headers
        while True:
            header_line = await reader.readline()
            if header_line == b"\r\n" or not header_line:
                break

        # Handle CORS preflight
        if method == "OPTIONS":
            writer.write(
                b"HTTP/1.1 204 No Content\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                b"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                b"Access-Control-Allow-Headers: Content-Type\r\n"
                b"\r\n"
            )
            await writer.drain()
            writer.close()
            return

        # Route requests
        if path == "/events":
            # SSE endpoint — use streaming response
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/event-stream\r\n"
                b"Cache-Control: no-cache\r\n"
                b"Connection: keep-alive\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                b"\r\n"
            )
            await writer.drain()

            queue: asyncio.Queue = asyncio.Queue()
            with _dashboard_clients_lock:
                _dashboard_clients.append(queue)
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=30)
                        writer.write(event.encode())
                        await writer.drain()
                    except asyncio.TimeoutError:
                        writer.write(b": keepalive\n\n")
                        await writer.drain()
                    except (ConnectionError, OSError):
                        break
            finally:
                with _dashboard_clients_lock:
                    if queue in _dashboard_clients:
                        _dashboard_clients.remove(queue)
            return

        elif path == "/":
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Cache-Control: no-cache\r\n"
                b"\r\n"
                + _DASHBOARD_HTML.encode()
            )
            await writer.drain()

        elif path == "/api/state":
            # Return current scan state as JSON

            state = {}
            state_file = Path("state.json")
            if state_file.exists():
                try:
                    state = json.loads(state_file.read_text())
                except Exception:
                    pass

            body = json.dumps(state).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                b"\r\n" + body
            )
            await writer.drain()

        else:
            writer.write(b"HTTP/1.1 404 Not Found\r\n\r\n")
            await writer.drain()

    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _run_server(host: str, port: int) -> None:
    """Run the HTTP server."""
    global _dashboard_loop
    _dashboard_loop = asyncio.get_running_loop()
    _setup_event_subscriptions()
    server = await asyncio.start_server(_handle_request, host, port)
    log("ok", f"ok: dashboard server running at http://{host}:{port}")
    async with server:
        await server.serve_forever()


def start_dashboard_thread(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Start the dashboard server in a background thread.

    Call this from pipeline.py or the main async loop.
    """
    global _server_started
    if _server_started:
        return
    _server_started = True

    def _thread() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run_server(host, port))
        except Exception as exc:
            log("err", f"err: dashboard server failed: {exc}")

    t = Thread(target=_thread, daemon=True, name="reconchain-dashboard")
    t.start()
    log("ok", f"ok: dashboard thread started on {host}:{port}")


def start_dashboard(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    """Start dashboard and optionally open browser."""
    start_dashboard_thread(host, port)
    if open_browser:
        import webbrowser

        try:
            webbrowser.open(f"http://{host}:{port}")
        except Exception:
            pass
