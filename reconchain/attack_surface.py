"""
reconchain.attack_surface — attack surface graph data generation + interactive HTML visualization.

Builds a graph of hosts, ports, technologies, URLs, and vulnerabilities from
scan artifacts, then generates an interactive HTML visualization using vanilla JS
Canvas (no external dependencies).

Usage:
    from reconchain.attack_surface import build_graph, write_attack_surface_html

    graph = build_graph(outdir)
    write_attack_surface_html(outdir, domain, graph)
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from reconchain.artifacts import ARTIFACTS
from reconchain.utils import ensure, log, read_lines


def _hash_id(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()[:8]


def _classify_host(hostname: str) -> str:
    if hostname.startswith("169.254."):
        return "cloud-metadata"
    if any(x in hostname for x in ["amazonaws", "cloudfront", "s3.", "azure", "googleapis"]):
        return "cloud"
    if any(x in hostname for x in ["github", "gitlab", "bitbucket"]):
        return "vcs"
    return "host"


def build_graph(outdir: Path) -> Dict[str, Any]:
    """Build a graph data structure from scan artifacts."""
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, str]] = []

    def add_node(nid: str, ntype: str, label: str, **extra: Any) -> None:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "label": label, **extra}

    def add_edge(src: str, dst: str, rel: str) -> None:
        edges.append({"source": src, "target": dst, "relation": rel})

    # --- Load host/resolution/port/tech/URL artifacts from registry ---
    _recon_keys = {"live_hosts", "resolved", "open_ports", "tech", "urls"}
    _recon_lookups = {a.key: a for a in ARTIFACTS if a.key in _recon_keys}

    _hosts_art = _recon_lookups.get("live_hosts")
    if _hosts_art:
        hosts_file = outdir / _hosts_art.filename
        if hosts_file.exists():
            for host in read_lines(hosts_file):
                host = host.strip()
                if not host:
                    continue
                nid = f"h-{_hash_id(host)}"
                htype = _classify_host(host)
                add_node(nid, "host", host, subtype=htype)

    _resolved_art = _recon_lookups.get("resolved")
    if _resolved_art:
        resolved_file = outdir / _resolved_art.filename
        if resolved_file.exists():
            for line in read_lines(resolved_file):
                parts = line.strip().split()
                if len(parts) >= 2:
                    hostname, ip = parts[0], parts[1]
                    hnid = f"h-{_hash_id(hostname)}"
                    ipnid = f"ip-{_hash_id(ip)}"
                    add_node(ipnid, "ip", ip)
                    if hnid in nodes:
                        add_edge(hnid, ipnid, "resolves_to")

    _ports_art = _recon_lookups.get("open_ports")
    if _ports_art:
        ports_file = outdir / _ports_art.filename
        if ports_file.exists():
            for line in read_lines(ports_file):
                parts = line.strip().split()
                if len(parts) >= 2:
                    ip = parts[0]
                    port_proto = parts[1]
                    port_num = port_proto.split("/")[0] if "/" in port_proto else port_proto
                    ipnid = f"ip-{_hash_id(ip)}"
                    pnid = f"port-{_hash_id(ip + port_num)}"
                    add_node(pnid, "port", f":{port_num}", parent_ip=ip)
                    add_edge(ipnid, pnid, "serves_on")

    _tech_art = _recon_lookups.get("tech")
    if _tech_art:
        tech_file = outdir / _tech_art.filename
        if tech_file.exists():
            for line in read_lines(tech_file):
                tech = line.strip()
                if not tech:
                    continue
                tnid = f"tech-{_hash_id(tech)}"
                add_node(tnid, "technology", tech)

    _urls_art = _recon_lookups.get("urls")
    if _urls_art:
        urls_file = outdir / _urls_art.filename
        if urls_file.exists():
            url_count = 0
            for line in read_lines(urls_file):
                url = line.strip()
                if not url or url_count > 200:
                    break
                url_count += 1

                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname or ""
                except Exception:
                    continue
                hnid = f"h-{_hash_id(hostname)}"
                uid = f"url-{_hash_id(url)}"
                add_node(uid, "url", url[:80])
                if hnid in nodes:
                    add_edge(hnid, uid, "serves_url")

    # --- Vulnerability nodes from artifact registry ---
    for art in ARTIFACTS:
        if not art.vuln_type:
            continue
        fpath = outdir / art.filename
        if not fpath.exists():
            continue
        for line in read_lines(fpath):
            finding = line.strip()
            if not finding:
                continue
            vid = f"vuln-{_hash_id(finding)}"
            add_node(vid, "vuln", finding[:80], severity=_guess_severity(finding), vuln_type=art.vuln_type)

            # Try to link to a host
            try:
                if finding.startswith("http"):
                    parsed = urlparse(finding)
                    hnid = f"h-{_hash_id(parsed.hostname or '')}"
                    if hnid in nodes:
                        add_edge(hnid, vid, "has_vuln")
            except Exception:
                pass

    # --- Exploit chains ---
    chains_file = outdir / "exploit_chains.json"
    if chains_file.exists():
        try:
            chains = json.loads(chains_file.read_text())
            for chain in chains:
                cid = f"chain-{_hash_id(chain.get('name', ''))}"
                add_node(cid, "chain", chain.get("name", "exploit chain"),
                         severity=chain.get("severity", "high"),
                         impact=chain.get("impact", ""),
                         steps=chain.get("steps", []))
                for step in chain.get("steps", []):
                    finding = step.get("finding", "")
                    vid = f"vuln-{_hash_id(finding)}"
                    if vid in nodes:
                        add_edge(vid, cid, "part_of_chain")
        except Exception:
            pass

    return {"nodes": list(nodes.values()), "edges": edges}


def _guess_severity(text: str) -> str:
    t = text.lower()
    if any(w in t for w in ["rce", "critical", "remote code", "sql injection"]):
        return "critical"
    if any(w in t for w in ["xss", "ssrf", "lfi", "idor", "high", "sqli"]):
        return "high"
    if any(w in t for w in ["medium", "redirect", "cors", "open redirect"]):
        return "medium"
    if any(w in t for w in ["low", "info", "clickjack", "information"]):
        return "low"
    return "info"


def write_attack_surface_json(outdir: Path, domain: str, graph: Dict[str, Any]) -> Path:
    out = ensure(outdir / "attack_surface.json")
    out.write_text(json.dumps(graph, indent=2, default=str))
    log("ok", f"ok: attack surface graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")
    return out


def write_attack_surface_html(outdir: Path, domain: str, graph: Dict[str, Any]) -> Path:
    """Generate an interactive HTML visualization of the attack surface graph."""
    graph_json = json.dumps(graph, default=str)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Attack Surface — {domain}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; overflow: hidden; }}
#toolbar {{ position: fixed; top: 0; left: 0; right: 0; height: 48px; background: #161b22; border-bottom: 1px solid #30363d; display: flex; align-items: center; padding: 0 16px; z-index: 10; gap: 12px; }}
#toolbar h1 {{ font-size: 14px; color: #58a6ff; font-weight: 600; }}
#toolbar .stats {{ font-size: 12px; color: #8b949e; margin-left: auto; }}
#toolbar input {{ background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 4px 10px; border-radius: 6px; font-size: 12px; width: 200px; }}
#legend {{ position: fixed; bottom: 16px; left: 16px; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px; z-index: 10; font-size: 12px; }}
#legend .item {{ display: flex; align-items: center; gap: 8px; margin: 4px 0; }}
#legend .dot {{ width: 10px; height: 10px; border-radius: 50%; }}
#info {{ position: fixed; top: 48px; right: 0; width: 320px; bottom: 0; background: #161b22; border-left: 1px solid #30363d; padding: 16px; z-index: 10; overflow-y: auto; display: none; font-size: 13px; }}
#info h3 {{ color: #58a6ff; margin-bottom: 8px; }}
#info .field {{ margin: 4px 0; }}
#info .label {{ color: #8b949e; }}
canvas {{ display: block; cursor: grab; }}
canvas:active {{ cursor: grabbing; }}
</style>
</head>
<body>
<div id="toolbar">
  <h1>&#9776; {domain} — Attack Surface</h1>
  <input type="text" id="search" placeholder="Filter nodes..." />
  <span class="stats" id="stats"></span>
</div>
<div id="legend">
  <div class="item"><span class="dot" style="background:#58a6ff"></span> Host</div>
  <div class="item"><span class="dot" style="background:#7ee787"></span> IP</div>
  <div class="item"><span class="dot" style="background:#d2a8ff"></span> Port</div>
  <div class="item"><span class="dot" style="background:#ffa657"></span> Technology</div>
  <div class="item"><span class="dot" style="background:#79c0ff"></span> URL</div>
  <div class="item"><span class="dot" style="background:#f85149"></span> Vulnerability</div>
  <div class="item"><span class="dot" style="background:#f0883e"></span> Exploit Chain</div>
  <div class="item"><span class="dot" style="background:#3fb950"></span> Cloud</div>
</div>
<div id="info"><div id="info-content"></div></div>
<canvas id="c"></canvas>
<script>
const GRAPH = {graph_json};

const COLORS = {{
  host: '#58a6ff', ip: '#7ee787', port: '#d2a8ff', technology: '#ffa657',
  url: '#79c0ff', vuln: '#f85149', chain: '#f0883e'
}};
const SEVERITY_COLORS = {{ critical: '#f85149', high: '#f0883e', medium: '#d29922', low: '#8b949e', info: '#8b949e' }};

const canvas = document.getElementById('c');
const ctx = canvas.getContext('2d');
const infoPanel = document.getElementById('info');
const infoContent = document.getElementById('info-content');
const statsEl = document.getElementById('stats');
const searchEl = document.getElementById('search');

let W, H;
function resize() {{
  W = canvas.width = window.innerWidth;
  H = canvas.height = window.innerHeight;
}}
resize();
window.addEventListener('resize', resize);

// Initialize positions
const nodes = GRAPH.nodes.map((n, i) => {{
  const angle = (i / GRAPH.nodes.length) * Math.PI * 2;
  const r = Math.min(W, H) * 0.3;
  return {{
    ...n,
    x: W/2 + Math.cos(angle) * r + (Math.random() - 0.5) * 100,
    y: H/2 + Math.sin(angle) * r + (Math.random() - 0.5) * 100,
    vx: 0, vy: 0,
    radius: n.type === 'host' ? 8 : n.type === 'vuln' ? 7 : n.type === 'chain' ? 10 : 5,
    visible: true
  }};
}});

const nodeMap = {{}};
nodes.forEach(n => nodeMap[n.id] = n);

const edges = GRAPH.edges.map(e => ({{
  source: nodeMap[e.source],
  target: nodeMap[e.target],
  relation: e.relation
}})).filter(e => e.source && e.target);

// Force simulation
const K = 0.0005;
const REPULSION = 5000;
const DAMPING = 0.9;
const CENTER_GRAVITY = 0.01;

function step() {{
  for (let i = 0; i < nodes.length; i++) {{
    const a = nodes[i];
    if (!a.visible) continue;
    let fx = 0, fy = 0;
    // Repulsion
    for (let j = 0; j < nodes.length; j++) {{
      if (i === j || !nodes[j].visible) continue;
      const b = nodes[j];
      let dx = a.x - b.x, dy = a.y - b.y;
      let dist = Math.sqrt(dx*dx + dy*dy) || 1;
      let f = REPULSION / (dist * dist);
      fx += (dx / dist) * f;
      fy += (dy / dist) * f;
    }}
    // Edge attraction
    edges.forEach(e => {{
      if (e.source === a) {{
        fx += (e.target.x - a.x) * K * 3;
        fy += (e.target.y - a.y) * K * 3;
      }} else if (e.target === a) {{
        fx += (e.source.x - a.x) * K * 3;
        fy += (e.source.y - a.y) * K * 3;
      }}
    }});
    // Center gravity
    fx += (W/2 - a.x) * CENTER_GRAVITY;
    fy += (H/2 - a.y) * CENTER_GRAVITY;
    a.vx = (a.vx + fx) * DAMPING;
    a.vy = (a.vy + fy) * DAMPING;
    a.x += a.vx;
    a.y += a.vy;
    a.x = Math.max(20, Math.min(W - 20, a.x));
    a.y = Math.max(60, Math.min(H - 20, a.y));
  }}
}}

let zoom = 1, panX = 0, panY = 0;
let dragging = null, dragOffX = 0, dragOffY = 0;
let mouseX = 0, mouseY = 0;
let hoveredNode = null;

canvas.addEventListener('mousedown', e => {{
  const wx = (e.clientX - panX) / zoom, wy = (e.clientY - panY) / zoom;
  for (const n of nodes) {{
    if (!n.visible) continue;
    const dx = n.x - wx, dy = n.y - wy;
    if (dx*dx + dy*dy < (n.radius + 4) ** 2) {{
      dragging = n;
      dragOffX = dx; dragOffY = dy;
      return;
    }}
  }}
}});

canvas.addEventListener('mousemove', e => {{
  mouseX = e.clientX; mouseY = e.clientY;
  if (dragging) {{
    dragging.x = (e.clientX - panX) / zoom - dragOffX;
    dragging.y = (e.clientY - panY) / zoom - dragOffY;
    dragging.vx = 0; dragging.vy = 0;
  }}
  // Hover detection
  const wx = (e.clientX - panX) / zoom, wy = (e.clientY - panY) / zoom;
  hoveredNode = null;
  for (const n of nodes) {{
    if (!n.visible) continue;
    const dx = n.x - wx, dy = n.y - wy;
    if (dx*dx + dy*dy < (n.radius + 4) ** 2) {{ hoveredNode = n; break; }}
  }}
  canvas.style.cursor = hoveredNode ? 'pointer' : (dragging ? 'grabbing' : 'grab');
}});

canvas.addEventListener('mouseup', () => {{ dragging = null; }});

canvas.addEventListener('click', e => {{
  if (hoveredNode) {{
    showInfo(hoveredNode);
  }} else {{
    infoPanel.style.display = 'none';
  }}
}});

canvas.addEventListener('wheel', e => {{
  e.preventDefault();
  const factor = e.deltaY > 0 ? 0.9 : 1.1;
  zoom *= factor;
  zoom = Math.max(0.1, Math.min(5, zoom));
  panX = e.clientX - (e.clientX - panX) * factor;
  panY = e.clientY - (e.clientY - panY) * factor;
}});

searchEl.addEventListener('input', () => {{
  const q = searchEl.value.toLowerCase();
  let count = 0;
  nodes.forEach(n => {{
    n.visible = !q || n.label.toLowerCase().includes(q) || n.type.includes(q);
    if (n.visible) count++;
  }});
  statsEl.textContent = count + '/' + nodes.length + ' nodes';
}});

function showInfo(n) {{
  infoPanel.style.display = 'block';
  let html = '<h3>' + n.label + '</h3>';
  html += '<div class="field"><span class="label">Type:</span> ' + n.type + '</div>';
  if (n.subtype) html += '<div class="field"><span class="label">Subtype:</span> ' + n.subtype + '</div>';
  if (n.severity) {{
    const c = SEVERITY_COLORS[n.severity] || '#8b949e';
    html += '<div class="field"><span class="label">Severity:</span> <span style="color:'+c+'">' + n.severity + '</span></div>';
  }}
  if (n.vuln_type) html += '<div class="field"><span class="label">Vuln Type:</span> ' + n.vuln_type + '</div>';
  if (n.impact) html += '<div class="field"><span class="label">Impact:</span> ' + n.impact + '</div>';
  if (n.steps) {{
    html += '<div class="field"><span class="label">Chain Steps:</span></div>';
    n.steps.forEach((s, i) => {{
      html += '<div style="margin-left:12px;color:#c9d1d9">' + (i+1) + '. ' + (s.finding || s) + '</div>';
    }});
  }}
  // Connected nodes
  const connected = edges.filter(e => e.source === n || e.target === n)
    .map(e => e.source === n ? e.target : e.source);
  if (connected.length) {{
    html += '<div class="field" style="margin-top:8px"><span class="label">Connected to:</span></div>';
    connected.slice(0, 10).forEach(cn => {{
      html += '<div style="margin-left:12px;color:#8b949e">• ' + cn.label + '</div>';
    }});
    if (connected.length > 10) html += '<div style="margin-left:12px;color:#8b949e">... and ' + (connected.length - 10) + ' more</div>';
  }}
  infoContent.innerHTML = html;
}}

function draw() {{
  ctx.clearRect(0, 0, W, H);
  ctx.save();
  ctx.translate(panX, panY);
  ctx.scale(zoom, zoom);

  // Edges
  edges.forEach(e => {{
    if (!e.source.visible || !e.target.visible) return;
    ctx.beginPath();
    ctx.moveTo(e.source.x, e.source.y);
    ctx.lineTo(e.target.x, e.target.y);
    ctx.strokeStyle = e.relation === 'has_vuln' ? 'rgba(248,81,73,0.2)' :
                      e.relation === 'part_of_chain' ? 'rgba(240,136,62,0.3)' :
                      'rgba(139,148,158,0.1)';
    ctx.lineWidth = e.relation === 'has_vuln' ? 1.5 : 0.8;
    ctx.stroke();
  }});

  // Nodes
  nodes.forEach(n => {{
    if (!n.visible) return;
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
    let color = COLORS[n.type] || '#8b949e';
    if (n.type === 'vuln' && n.severity) color = SEVERITY_COLORS[n.severity] || color;
    ctx.fillStyle = color;
    ctx.fill();

    if (n === hoveredNode) {{
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 2;
      ctx.stroke();
    }}

    // Label for larger nodes
    if ((n.type === 'host' || n.type === 'vuln' || n.type === 'chain') && zoom > 0.5) {{
      ctx.fillStyle = '#c9d1d9';
      ctx.font = '10px monospace';
      ctx.fillText(n.label.substring(0, 30), n.x + n.radius + 3, n.y + 3);
    }}
  }});

  ctx.restore();
  statsEl.textContent = nodes.filter(n => n.visible).length + '/' + nodes.length + ' nodes';

  step();
  requestAnimationFrame(draw);
}}

draw();
</script>
</body>
</html>"""

    out = ensure(outdir / "attack_surface.html")
    out.write_text(html)
    log("ok", f"ok: attack surface HTML written to {out}")
    return out
