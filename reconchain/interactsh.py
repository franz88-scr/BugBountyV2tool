"""Out-of-band (OOB) interaction tracking via interactsh-client with HTTP webhook support."""
from __future__ import annotations
import asyncio
import contextlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from reconchain.process import _wait_proc, _proxify_cmd
from reconchain.utils import ensure, log


_INSTANCE_CALLBACKS: Dict[int, List[Dict[str, Any]]] = {}
_INSTANCE_HOOKS: Dict[int, Optional[Callable[[Dict[str, Any]], None]]] = {}
_INSTANCE_SECRETS: Dict[int, str] = {}
_INSTANCE_LOCK = threading.Lock()


def _make_callback_handler(instance_id: int) -> type:
    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            max_body = 1 * 1024 * 1024  # 1 MB limit
            if length > max_body:
                self.send_response(413)
                self.end_headers()
                self.wfile.write(b"request body too large")
                return
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = {"raw": body.decode("utf-8", errors="replace")}
            with _INSTANCE_LOCK:
                secret = _INSTANCE_SECRETS.get(instance_id)
            if secret:
                token = self.headers.get("X-Reconchain-Token", "")
                if not data.get("_token") and token != secret:
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b"forbidden")
                    return
            data["_path"] = self.path
            data["_method"] = "POST"
            data["_ts"] = time.time()
            with _INSTANCE_LOCK:
                cb_list = _INSTANCE_CALLBACKS.get(instance_id)
                if cb_list is not None:
                    cb_list.append(data)
                hook = _INSTANCE_HOOKS.get(instance_id)
            if hook:
                hook(data)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def do_GET(self) -> None:
            data = {"_path": self.path, "_method": "GET", "_ts": time.time()}
            with _INSTANCE_LOCK:
                cb_list = _INSTANCE_CALLBACKS.get(instance_id)
                if cb_list is not None:
                    cb_list.append(data)
                hook = _INSTANCE_HOOKS.get(instance_id)
            if hook:
                hook(data)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, msg_format: str, *args: Any) -> None:
            pass
    return _Handler


class Interactsh:
    """OOB collector with interactsh-client + optional local HTTP webhook server."""

    _next_id: int = 0

    def __init__(self, outdir: Path) -> None:
        self.outdir = outdir
        self.proc: Optional[subprocess.Popen] = None
        self.domain: Optional[str] = None
        self.log = ensure(outdir / "logs" / "interactsh.log")
        self._log_fh = None
        self._start_pos = 0
        self._httpd: Optional[HTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._webhook_port: Optional[int] = None
        self._local_callbacks: List[Dict[str, Any]] = []
        Interactsh._next_id += 1
        self._instance_id = Interactsh._next_id
        _INSTANCE_CALLBACKS[self._instance_id] = self._local_callbacks
        _INSTANCE_HOOKS[self._instance_id] = None
        import secrets
        self._webhook_secret = secrets.token_hex(16)
        _INSTANCE_SECRETS[self._instance_id] = self._webhook_secret

    @property
    def available(self) -> bool:
        return shutil.which("interactsh-client") is not None

    def start_webhook(self, port: int = 0) -> Optional[int]:
        if self._httpd is not None:
            return self._webhook_port
        try:
            handler_cls = _make_callback_handler(self._instance_id)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port or 0))
            self._webhook_port = sock.getsockname()[1]
            self._httpd = HTTPServer(("127.0.0.1", self._webhook_port), handler_cls, bind_and_activate=False)
            self._httpd.socket = sock
            self._httpd.server_address = sock.getsockname()
            self._httpd.server_bind = lambda: None
            self._httpd.server_activate()
            self._http_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            self._http_thread.start()
            log("info", f"OOB webhook listening on port {self._webhook_port} (token required)")
            return self._webhook_port
        except Exception as e:
            log("warn", f"OOB webhook start failed: {e}")
            return None

    def stop_webhook(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            if self._http_thread is not None:
                self._http_thread.join(timeout=5)
            self._httpd = None
            self._http_thread = None
            self._webhook_port = None

    def _kill_proc(self) -> None:
        if self._log_fh is not None:
            with contextlib.suppress(Exception):
                self._log_fh.close()
            self._log_fh = None
        if not self.proc:
            return
        if self.proc.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                self.proc.send_signal(signal.SIGINT)
            if _wait_proc(self.proc, 10):
                return
            self.proc.kill()
            _wait_proc(self.proc, 5)

    async def start(self) -> bool:
        if not self.available:
            log("warn", "interactsh-client not found; OOB phase will be empty")
            return False
        token = os.environ.get("INTERACTSH_TOKEN")
        ensure(self.log)
        self.log.write_text("")
        cmd = ["interactsh-client", "-v"]
        if token:
            cmd += ["-t", token]
        from reconchain.process import _PIPELINE_CFG
        if _PIPELINE_CFG.proxy:
            cmd += ["-proxy", _PIPELINE_CFG.proxy]
        cmd = _proxify_cmd(cmd)
        try:
            self._log_fh = self.log.open("ab")
            self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=self._log_fh, stderr=subprocess.STDOUT)
            self._start_pos = self.log.stat().st_size
            await asyncio.sleep(0.5)
        except FileNotFoundError:
            if self._log_fh is not None:
                self._log_fh.close()
                self._log_fh = None
            return False
        except Exception as e:
            log("err", f"interactsh start failed: {e}")
            self._kill_proc()
            return False
        deadline = time.monotonic() + 90
        try:
            while time.monotonic() < deadline:
                if self.proc.poll() is not None:
                    _tail = ""
                    try:
                        with self.log.open("rb") as fh:
                            raw = fh.read()
                            _tail = raw.decode("utf-8", errors="replace")[-2000:]
                    except OSError:
                        pass
                    log("warn", f"interactsh-client exited prematurely (rc={self.proc.returncode})")
                    if _tail.strip():
                        for _ln in _tail.strip().splitlines()[-10:]:
                            log("warn", f"  interactsh: {_ln}")
                    return False
                try:
                    with self.log.open("rb") as fh:
                        fh.seek(self._start_pos)
                        txt = fh.read().decode("utf-8", errors="ignore")
                except FileNotFoundError:
                    txt = ""
                for ln in txt.splitlines():
                    clean = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", ln).strip()
                    if "Domain" in clean and ":" in clean:
                        cand = clean.split(":", 1)[1].strip()
                        if cand and "." in cand and " " not in cand:
                            self.domain = cand
                            log("ok", f"interactsh domain: {self.domain}")
                            return True
                    if re.search(r"[a-zA-Z0-9-]+\.oast\.[a-z]+", clean):
                        cand = clean.split()[-1].strip()
                        if cand and "." in cand and " " not in cand:
                            self.domain = cand
                            log("ok", f"interactsh domain: {self.domain}")
                            return True
                await asyncio.sleep(1)
        except Exception:
            self._kill_proc()
            raise
        log("warn", "interactsh did not announce a domain in time")
        return False

    def stop(self) -> Path:
        out = ensure(self.outdir / "oast" / "callbacks.txt")
        self._kill_proc()
        events: list[dict] = []
        try:
            with self.log.open("r", errors="ignore") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln.startswith("{") and '"protocol"' in ln:
                        with contextlib.suppress(json.JSONDecodeError):
                            ev = json.loads(ln)
                            events.append({
                                "ts": ev.get("timestamp"),
                                "proto": ev.get("protocol"),
                                "id": ev.get("unique-id"),
                                "from": ev.get("remote-address"),
                                "domain": self.domain,
                            })
        except FileNotFoundError:
            pass
        for cb in self._local_callbacks:
            events.append({
                "ts": cb.get("_ts"),
                "proto": "http",
                "id": cb.get("_path", ""),
                "from": cb.get("_path", ""),
                "domain": self.domain or "webhook",
                "raw": cb,
            })
        with out.open("w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
        log("ok", f"interactsh: {len(events)} OOB callback(s) captured ({len(self._local_callbacks)} from webhook)")
        self.stop_webhook()
        # Clean up global callback/hook registries to prevent memory leak
        with _INSTANCE_LOCK:
            _INSTANCE_CALLBACKS.pop(self._instance_id, None)
            _INSTANCE_HOOKS.pop(self._instance_id, None)
            _INSTANCE_SECRETS.pop(self._instance_id, None)
        return out
