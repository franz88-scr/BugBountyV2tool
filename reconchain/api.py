"""Lightweight REST API for querying scan findings.

Zero external dependencies — uses Python stdlib http.server + asyncio.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from reconchain.config import __version__
from reconchain.utils import log


_api_server: Optional[HTTPServer] = None
_api_thread: Optional[threading.Thread] = None
_outdir: Optional[Path] = None


def _json_response(handler: BaseHTTPRequestHandler, data: Any, status: int = 200) -> None:
    body = json.dumps(data, default=str, indent=2).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "http://localhost:8765")
    handler.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.end_headers()
    handler.wfile.write(body)


def _error_response(handler: BaseHTTPRequestHandler, message: str, status: int = 404) -> None:
    _json_response(handler, {"error": message, "status": status}, status)


class ReconChainAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the ReconChain findings API."""

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "http://localhost:8765")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        if path == "/api/v1/health":
            self._handle_health()
        elif path == "/api/v1/summary":
            self._handle_summary()
        elif path == "/api/v1/findings":
            self._handle_findings(params)
        elif path == "/api/v1/findings/by-severity":
            self._handle_findings_by_severity()
        elif path == "/api/v1/findings/by-phase":
            self._handle_findings_by_phase()
        elif path == "/api/v1/findings/by-type":
            self._handle_findings_by_type()
        elif path == "/api/v1/coverage":
            self._handle_coverage()
        elif path == "/api/v1/artifacts":
            self._handle_artifacts()
        else:
            _error_response(self, f"Unknown endpoint: {path}", 404)

    def _handle_health(self) -> None:
        _json_response(self, {
            "status": "ok",
            "version": __version__,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        })

    def _handle_summary(self) -> None:
        if not _outdir or not _outdir.exists():
            _error_response(self, "No scan output directory", 404)
            return
        summary_file = _outdir / "summary.json"
        risk_file = _outdir / "risk_score.json"
        data: Dict[str, Any] = {}
        if summary_file.exists():
            try:
                data = json.loads(summary_file.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                data = {}
        if risk_file.exists():
            try:
                data["risk_score"] = json.loads(risk_file.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                pass
        _json_response(self, data)

    def _handle_findings(self, params: Dict[str, list]) -> None:
        if not _outdir or not _outdir.exists():
            _error_response(self, "No scan output directory", 404)
            return
        from reconchain.finding import FindingStore
        store = FindingStore(_outdir)
        findings = store.load()

        severity = params.get("severity", [None])[0]
        phase = params.get("phase", [None])[0]
        vuln_type = params.get("vuln_type", [None])[0]
        host = params.get("host", [None])[0]
        try:
            limit = min(int(params.get("limit", ["500"])[0]), 10000)
            offset = max(0, int(params.get("offset", ["0"])[0]))
        except (ValueError, TypeError):
            _error_response(self, "Invalid limit/offset parameter", 400)
            return

        if severity:
            findings = [f for f in findings if f.severity == severity]
        if phase:
            findings = [f for f in findings if f.phase == phase]
        if vuln_type:
            findings = [f for f in findings if f.vuln_type == vuln_type]
        if host:
            findings = [f for f in findings if f.host == host]

        total = len(findings)
        findings = findings[offset:offset + limit]

        _json_response(self, {
            "total": total,
            "offset": offset,
            "limit": limit,
            "findings": [f.to_dict() for f in findings],
        })

    def _handle_findings_by_severity(self) -> None:
        if not _outdir or not _outdir.exists():
            _error_response(self, "No scan output directory", 404)
            return
        from reconchain.finding import FindingStore
        store = FindingStore(_outdir)
        by_sev = store.by_severity()
        _json_response(self, {
            severity: {
                "count": len(findings),
                "findings": [f.to_dict() for f in findings],
            }
            for severity, findings in by_sev.items()
        })

    def _handle_findings_by_phase(self) -> None:
        if not _outdir or not _outdir.exists():
            _error_response(self, "No scan output directory", 404)
            return
        from reconchain.finding import FindingStore
        store = FindingStore(_outdir)
        by_phase = store.by_phase()
        _json_response(self, {
            phase: {
                "count": len(findings),
                "findings": [f.to_dict() for f in findings[:50]],
            }
            for phase, findings in sorted(by_phase.items())
        })

    def _handle_findings_by_type(self) -> None:
        if not _outdir or not _outdir.exists():
            _error_response(self, "No scan output directory", 404)
            return
        from reconchain.finding import FindingStore
        store = FindingStore(_outdir)
        by_type = store.by_vuln_type()
        _json_response(self, {
            vt: {
                "count": len(findings),
                "findings": [f.to_dict() for f in findings[:50]],
            }
            for vt, findings in sorted(by_type.items())
        })

    def _handle_coverage(self) -> None:
        if not _outdir or not _outdir.exists():
            _error_response(self, "No scan output directory", 404)
            return
        from reconchain.artifacts import get_coverage, get_artifact_keys
        from reconchain.config import VALID_PHASES
        coverage = get_coverage(_outdir, sorted(VALID_PHASES))
        _json_response(self, coverage)

    def _handle_artifacts(self) -> None:
        if not _outdir or not _outdir.exists():
            _error_response(self, "No scan output directory", 404)
            return
        from reconchain.artifacts import ARTIFACTS
        from reconchain.utils import count_nonblank
        result = []
        for art in ARTIFACTS:
            p = _outdir / art.filename
            if p.exists():
                result.append({
                    "key": art.key,
                    "filename": art.filename,
                    "display_name": art.display_name,
                    "phase": art.phase,
                    "vuln_type": art.vuln_type,
                    "severity_hint": art.severity_hint,
                    "count": count_nonblank(p),
                    "size_bytes": p.stat().st_size,
                })
        _json_response(self, {"artifacts": result, "total": len(result)})


def start_api_server(
    outdir: Path,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> int:
    """Start the API server. Returns the actual port used."""
    global _api_server, _api_thread, _outdir
    _outdir = outdir

    _api_server = HTTPServer((host, port), ReconChainAPIHandler)
    actual_port = _api_server.server_address[1]

    _api_thread = threading.Thread(
        target=_api_server.serve_forever,
        name="reconchain-api",
        daemon=True,
    )
    _api_thread.start()
    log("ok", f"API server started on http://{host}:{actual_port}")
    log("ok", f"  GET http://{host}:{actual_port}/api/v1/health")
    log("ok", f"  GET http://{host}:{actual_port}/api/v1/findings")
    log("ok", f"  GET http://{host}:{actual_port}/api/v1/summary")
    return actual_port


def stop_api_server() -> None:
    global _api_server, _api_thread
    if _api_server:
        _api_server.shutdown()
        _api_server = None
    _api_thread = None
