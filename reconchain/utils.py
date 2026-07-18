"""Utility functions: file I/O, logging, validation, proxy config."""
from __future__ import annotations
import concurrent.futures
import contextlib
import hashlib
import json
import os
import re
import struct
import sys
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

from reconchain.config import _HOSTNAME_RE

_re = re

_HOSTNAME_RE = _HOSTNAME_RE
_MERGE_LOCK = threading.Lock()

# Bounded thread pool for HTTP requests — replaces unbounded thread-per-request.
# 24 workers: HTTP is pure I/O, threads are cheap (~1MB each), caps total RAM.
_http_pool = concurrent.futures.ThreadPoolExecutor(max_workers=24, thread_name_prefix="rc-http")

# Ensure pool threads are daemon so Python doesn't hang at exit waiting for
# in-flight HTTP requests (which may have long socket timeouts).
import atexit as _atexit
def _shutdown_http_pool() -> None:
    _http_pool.shutdown(wait=False)
_atexit.register(_shutdown_http_pool)


# ── HTTP Response Cache ────────────────────────────────────────────
# LRU cache for GET responses to avoid redundant network I/O across phases.
# Keyed by (url, method). Entries expire after TTL seconds.

class _HTTPResponseCache:
    """Thread-safe LRU cache for HTTP GET responses.

    Avoids redundant fetches when multiple phases probe the same URL
    (e.g. CORS check, header leak check, redirect check).
    """

    def __init__(self, max_size: int = 2048, ttl: int = 300) -> None:
        self._max_size = max_size
        self._ttl = ttl
        self._cache: Dict[str, Tuple[float, int, bytes]] = {}  # key -> (ts, status, body)
        self._lock = threading.Lock()

    def _key(self, url: str, method: str = "GET") -> str:
        return f"{method}:{url}"

    def get(self, url: str, method: str = "GET") -> Optional[Tuple[int, bytes]]:
        key = self._key(url, method)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            ts, status, body = entry
            if time.monotonic() - ts > self._ttl:
                del self._cache[key]
                return None
            return status, body

    def put(self, url: str, status: int, body: bytes, method: str = "GET") -> None:
        key = self._key(url, method)
        with self._lock:
            if len(self._cache) >= self._max_size:
                # Evict oldest 25%
                evict_count = max(1, self._max_size // 4)
                sorted_keys = sorted(
                    self._cache.keys(),
                    key=lambda k: self._cache[k][0],
                )
                for k in sorted_keys[:evict_count]:
                    self._cache.pop(k, None)
            self._cache[key] = (time.monotonic(), status, body)

    def invalidate(self) -> None:
        with self._lock:
            self._cache.clear()


_http_response_cache = _HTTPResponseCache()


def get_http_cache() -> _HTTPResponseCache:
    return _http_response_cache


# ── DNS Resolution Cache ──────────────────────────────────────────
# Caches DNS lookup results to avoid redundant getaddrinfo calls.

class _DNSCache:
    """Thread-safe DNS resolution cache with TTL."""

    def __init__(self, max_size: int = 4096, ttl: int = 600) -> None:
        self._max_size = max_size
        self._ttl = ttl
        self._cache: Dict[str, Tuple[float, Set[str]]] = {}  # host -> (ts, resolved_ips)
        self._lock = threading.Lock()

    def get(self, host: str) -> Optional[Set[str]]:
        with self._lock:
            entry = self._cache.get(host)
            if entry is None:
                return None
            ts, ips = entry
            if time.monotonic() - ts > self._ttl:
                del self._cache[host]
                return None
            return ips

    def put(self, host: str, ips: Set[str]) -> None:
        with self._lock:
            if len(self._cache) >= self._max_size:
                evict_count = max(1, self._max_size // 4)
                sorted_keys = sorted(
                    self._cache.keys(),
                    key=lambda k: self._cache[k][0],
                )
                for k in sorted_keys[:evict_count]:
                    self._cache.pop(k, None)
            self._cache[host] = (time.monotonic(), ips)

    def invalidate(self) -> None:
        with self._lock:
            self._cache.clear()


_dns_cache = _DNSCache()


def get_dns_cache() -> _DNSCache:
    return _dns_cache


def _is_valid_hostname(s: str) -> bool:
    if not s:
        return False
    s = s.rstrip(".").lower()
    if "." not in s or any(c.isspace() or c in "[]()<>{}" for c in s):
        return False
    # Reject IP addresses (octets look like valid hostname labels)
    try:
        import ipaddress
        ipaddress.ip_address(s)
        return False
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(s))

def _is_under_domain(host: str, domain: str) -> bool:
    h = host.rstrip(".").lower()
    d = domain.rstrip(".").lower()
    return h == d or h.endswith("." + d)

def _target_token(line: str) -> str:
    token = line.strip().split()[0] if line.strip() else ""
    token = token.rstrip(".")
    if not _is_valid_hostname(token) and not token.startswith("http"):
        return ""
    return token

def _target_lines(path: Path) -> List[str]:
    return [t for line in read_lines(path) if (t := _target_token(line))]

def _write_target_tokens(src: Path, dst: Path) -> int:
    seen: Set[str] = set()
    for token in _target_lines(src):
        if token not in seen:
            seen.add(token)
    if not seen:
        log("warn", f"_write_target_tokens: no valid tokens found in {src.name}")
        ensure(dst).write_text("")
    else:
        ensure(dst).write_text("\n".join(sorted(seen)) + "\n")
    return len(seen)


def write_findings(path: Path, findings: List[str], phase_id: str = "") -> Dict[str, Any]:
    """Write findings to a file only when non-empty. Returns result dict."""
    if not findings:
        if path.exists():
            path.unlink()
        if not phase_id:
            return {"count": 0}
        return {phase_id: str(path), "count": 0}
    ensure(path).write_text("\n".join(findings) + "\n")
    log("ok", f"{phase_id}: {len(findings)} findings -> {path}" if phase_id else f"{len(findings)} findings -> {path}")
    if not phase_id:
        return {"count": len(findings)}
    return {phase_id: str(path), "count": len(findings)}


def _load_live_hosts(outdir: Path, domain: str = "") -> List[str]:
    """Load non-404 hosts from hosts.txt, optionally scoped to a domain.
    Returns only the host portion (no scheme, no status tags), deduplicated.
    If domain is provided, only returns hosts that are subdomains of (or equal to) that domain.
    If domain is empty, tries to extract it from the outdir path (e.g. ./out/example.com/)."""
    hosts_file = outdir / "hosts.txt"
    if not hosts_file.exists():
        return []
    if not domain:
        # Try to extract domain from outdir path (e.g. ./out/example.com/)
        parts = outdir.resolve().parts
        for i, p in enumerate(parts):
            if p == "out" and i + 1 < len(parts):
                domain = parts[i + 1]
                break
        if not domain:
            log("warn", "_load_live_hosts: could not auto-detect domain from path; "
                "returning unscoped host list. Pass domain= explicitly.")
    seen: Set[str] = set()
    live: List[str] = []
    for ln in read_lines(hosts_file):
        ln = ln.strip()
        if not ln:
            continue
        tokens = ln.split()
        if len(tokens) >= 2 and tokens[1] == "[404]":
            continue
        host = tokens[0] if tokens else ln
        host = host.rstrip("/")
        if host.startswith("http://") or host.startswith("https://"):
            host = urllib.parse.urlparse(host).hostname or host
        if not host:
            continue
        if domain and not _is_under_domain(host, domain):
            continue
        if host not in seen:
            seen.add(host)
            live.append(host)
    return live

def _color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

C = {
    "r": "\033[0m" if _color() else "",
    "d": "\033[2m" if _color() else "",
    "g": "\033[32m" if _color() else "",
    "y": "\033[33m" if _color() else "",
    "b": "\033[34m" if _color() else "",
    "c": "\033[36m" if _color() else "",
    "m": "\033[35m" if _color() else "",
    "red": "\033[31m" if _color() else "",
}
LVL = {"info": C["c"], "ok": C["g"], "warn": C["y"], "err": C["red"], "skip": C["d"]}

def disable_color() -> None:
    global LVL, C
    C = {k: "" for k in C}
    LVL = {k: "" for k in LVL}

_active_progress: Optional["Progress"] = None
_active_progress_lock = threading.Lock()

def log(lvl: str, msg: str) -> None:
    text = f"{LVL.get(lvl, '')}[{lvl[0].upper() if lvl else '?'}]{C['r']} {msg}"
    with _active_progress_lock:
        prog = _active_progress
    if prog and prog._enabled and sys.stderr.isatty():
        prog._write_above(text)
    else:
        _log_write(text)

_log_write = print
_tqdm_available = False
try:
    from tqdm import tqdm as _real_tqdm
    _log_write = _real_tqdm.write
    _tqdm_available = True
    tqdm = _real_tqdm
except ImportError:
    class tqdm:
        _global_pos = 0
        def __init__(self, *args: Any, total: Optional[int] = None, desc: Optional[str] = None, **kwargs: Any) -> None:
            self.total = total
            self.desc = desc
            self._n = 0
            self._closed = False
        def update(self, n: int = 1) -> None:
            self._n += n
            if self.desc:
                print(f"  [{self._n}/{self.total}] {self.desc}", flush=True)
        def set_description(self, desc: Optional[str] = None, refresh: bool = True) -> None:
            if desc != self.desc:
                self.desc = desc
                if not self._closed:
                    print(f"  [{self._n}/{self.total}] {desc}", flush=True)
        def close(self) -> None:
            self._closed = True
        @classmethod
        def write(cls, msg: str = "", *args: Any, **kwargs: Any) -> None:
            print(msg, flush=True)

def _auto_detect_proxy() -> str:
    for var in ("ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "PROXY",
                "all_proxy", "https_proxy", "http_proxy", "proxy"):
        val = os.environ.get(var, "")
        if val:
            return val
    return ""

def _set_proxy_env(proxy: str) -> None:
    from reconchain.process import _ENV_LOCK
    _PROXY_VARS = ["ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy",
                   "HTTP_PROXY", "http_proxy", "PROXY"]
    with _ENV_LOCK:
        if not proxy:
            for v in _PROXY_VARS:
                os.environ.pop(v, None)
            return
        for v in _PROXY_VARS:
            os.environ[v] = proxy

def _auto_detect_cookies(outdir: Optional[Path] = None, fix_permissions: bool = True) -> str:
    val = os.environ.get("COOKIE", "")
    if val:
        return val
    if outdir:
        cookie_file = outdir / "cookies.txt"
        if cookie_file.exists():
            try:
                mode = cookie_file.stat().st_mode & 0o777
                if mode & 0o077:
                    if fix_permissions:
                        log("warn", f"cookies.txt has overly permissive permissions ({oct(mode)}); fixing to 0o600")
                        try:
                            cookie_file.chmod(0o600)
                        except OSError:
                            log("warn", f"could not fix permissions on {cookie_file}")
                    else:
                        log("warn", f"cookies.txt has overly permissive permissions ({oct(mode)}); consider: chmod 600 {cookie_file}")
            except OSError:
                pass
            return _sanitize_header_value(cookie_file.read_text(encoding="utf-8", errors="ignore").strip())
    else:
        cookie_file = Path("cookies.txt")
        if cookie_file.exists():
            log("warn", "cookies.txt found in CWD — use --cookie or COOKIE env var instead")
            try:
                mode = cookie_file.stat().st_mode & 0o777
                if mode & 0o077:
                    if fix_permissions:
                        log("warn", f"CWD cookies.txt has overly permissive permissions ({oct(mode)}); fixing to 0o600")
                        try:
                            cookie_file.chmod(0o600)
                        except OSError:
                            log("warn", f"could not fix permissions on {cookie_file}")
                    else:
                        log("warn", f"CWD cookies.txt has overly permissive permissions ({oct(mode)}); consider: chmod 600 {cookie_file}")
            except OSError:
                pass
            return _sanitize_header_value(cookie_file.read_text(encoding="utf-8", errors="ignore").strip())
    return ""

def _sanitize_header_value(v: str) -> str:
    v = v.translate({ord(c): ord(" ") for c in "\r\n\t\x00\x0b\x0c"})
    return v.strip()

def _validate_cookie(value: str) -> str:
    """Validate and sanitize a cookie string. Raises InvalidCookieError on empty result."""
    from reconchain.exceptions import InvalidCookieError
    value = _sanitize_header_value(value)
    if not value:
        raise InvalidCookieError("cookie string is empty after sanitization")
    # Strip leading '--' fragments that could inject CLI arguments
    while value.startswith("--"):
        value = value[2:].lstrip()
    parts = [p.strip() for p in value.split(";") if p.strip()]
    for part in parts:
        if "=" not in part:
            log("warn", f"cookie part '{part[:40]}' does not look like name=value format")
    return value

def parse_set_cookie_headers(headers) -> list:
    """Extract all Set-Cookie header values from an http.client.HTTPMessage or string."""
    if hasattr(headers, "get_all"):
        return headers.get_all("Set-Cookie") or []
    result = []
    for h in str(headers).split("\n"):
        if h.lower().startswith("set-cookie:"):
            result.append(h.split(":", 1)[1].strip())
    return result

def _extra_headers_dict() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    cookie = os.environ.get("COOKIE", "")
    if cookie:
        headers["Cookie"] = _sanitize_header_value(cookie)
    headers_raw = os.environ.get("EXTRA_HEADERS", "")
    if headers_raw:
        for hdr in headers_raw.split("\n"):
            hdr = hdr.strip()
            if hdr and ":" in hdr:
                k, v = hdr.split(":", 1)
                headers[k.strip()] = _sanitize_header_value(v.strip())
    try:
        from reconchain.process import _PIPELINE_CFG as cfg
        if getattr(cfg, "auth_bearer", ""):
            headers["Authorization"] = f"Bearer {cfg.auth_bearer}"
        if getattr(cfg, "auth_api_key", ""):
            header_name = getattr(cfg, "auth_api_key_header", "X-API-Key")
            headers[header_name] = cfg.auth_api_key
        if getattr(cfg, "auth_basic", ""):
            import base64
            encoded = base64.b64encode(cfg.auth_basic.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
    except Exception:
        pass
    return headers

def _extra_http_args() -> List[str]:
    args: List[str] = []
    cookie = os.environ.get("COOKIE", "")
    if cookie:
        args += ["-H", f"Cookie: {_sanitize_header_value(cookie)}"]
    headers_raw = os.environ.get("EXTRA_HEADERS", "")
    if headers_raw:
        for h in headers_raw.split("\n"):
            h = h.strip()
            if h and ":" in h:
                k, v = h.split(":", 1)
                safe_h = f"{k.strip()}: {_sanitize_header_value(v.strip())}"
                args += ["-H", safe_h]
    return args

_original_socket_class = None
_SOCKS_PATCH_LOCK = threading.Lock()

def _patch_socks(proxy: str) -> bool:
    """Globally patch socket to route through SOCKS proxy via PySocks."""
    global _socks_patched, _original_socket_class
    with _SOCKS_PATCH_LOCK:
        import socket as _sk
        if _original_socket_class is None:
            _original_socket_class = _sk.socket
        try:
            import socks as _socks
            _parsed = urllib.parse.urlparse(proxy)
            _pt = _socks.SOCKS5 if _parsed.scheme.startswith("socks5") else _socks.SOCKS4
            _socks.set_default_proxy(_pt, _parsed.hostname, _parsed.port or 1080)
            _socks.wrap_module(_sk)
            _socks_patched = True
            return True
        except ImportError:
            log("warn", "PySocks not installed; SOCKS proxy won't work for Python HTTP. Run: pip install pysocks")
            return False
        except Exception as _e:
            log("warn", f"SOCKS patch failed: {_e}")
            return False

def _unpatch_socks() -> None:
    """Restore original socket class after SOCKS patching."""
    global _socks_patched, _original_socket_class
    with _SOCKS_PATCH_LOCK:
        if _socks_patched and _original_socket_class is not None:
            import socket as _sk
            _sk.socket = _original_socket_class
            _socks_patched = False

_socks_patched: bool = False

def _ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def _get_urlopener() -> Callable[..., Any]:
    from reconchain.process import _PIPELINE_CFG
    ctx = _ssl_context()
    proxy = _PIPELINE_CFG.proxy or os.environ.get("PROXY", "")
    if proxy:
        if proxy.startswith(("http://", "https://")):
            handler = urllib.request.ProxyHandler({
                "http": proxy,
                "https": proxy,
            })
            opener = urllib.request.build_opener(handler)
            return lambda *a, **kw: opener.open(*a, **{k: v for k, v in kw.items() if k != "context"})
        if proxy.startswith(("socks4://", "socks5://", "socks5h://", "socks4a://")):
            try:
                from sockshandler import SocksiPyHandler
                import socks as _socks
                _parsed = urllib.parse.urlparse(proxy)
                _pt = _socks.SOCKS5 if _parsed.scheme.startswith("socks5") else _socks.SOCKS4
                _handler = SocksiPyHandler(_pt, _parsed.hostname, _parsed.port or 1080)
                _opener = urllib.request.build_opener(_handler)
                return lambda *a, **kw: _opener.open(*a, **{k: v for k, v in kw.items() if k != "context"})
            except ImportError:
                with _SOCKS_PATCH_LOCK:
                    global _socks_patched
                    if not _socks_patched:
                        _socks_patched = _patch_socks(proxy)
    return lambda *a, **kw: urllib.request.urlopen(*a, **{**kw, "context": ctx})

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def _get_no_redirect_urlopener() -> Callable[..., Any]:
    from reconchain.process import _PIPELINE_CFG
    ctx = _ssl_context()
    proxy = _PIPELINE_CFG.proxy or os.environ.get("PROXY", "")
    if proxy:
        if proxy.startswith(("http://", "https://")):
            handler = urllib.request.ProxyHandler({
                "http": proxy,
                "https": proxy,
            })
            opener = urllib.request.build_opener(_NoRedirectHandler, handler)
            return lambda *a, **kw: opener.open(*a, **{k: v for k, v in kw.items() if k != "context"})
        if proxy.startswith(("socks4://", "socks5://", "socks5h://", "socks4a://")):
            try:
                from sockshandler import SocksiPyHandler
                import socks as _socks
                _parsed = urllib.parse.urlparse(proxy)
                _pt = _socks.SOCKS5 if _parsed.scheme.startswith("socks5") else _socks.SOCKS4
                _handler = SocksiPyHandler(_pt, _parsed.hostname, _parsed.port or 1080)
                _opener = urllib.request.build_opener(_NoRedirectHandler, _handler)
                return lambda *a, **kw: _opener.open(*a, **{k: v for k, v in kw.items() if k != "context"})
            except ImportError:
                with _SOCKS_PATCH_LOCK:
                    global _socks_patched
                    if not _socks_patched:
                        _socks_patched = _patch_socks(proxy)
    opener = urllib.request.build_opener(_NoRedirectHandler)
    return lambda *a, **kw: opener.open(*a, **{**kw, "context": ctx})

async def _async_urlopen(urlopen_func: Any, req: urllib.request.Request, timeout: int = 10) -> Tuple[int, Any, bytes]:
    import asyncio
    _resp_holder: List[Any] = [None]
    def _fetch() -> Tuple[int, Any, bytes]:
        resp = urlopen_func(req, timeout=timeout)
        _resp_holder[0] = resp
        try:
            data = resp.read()
            status = resp.status
            headers = resp.headers
            return (status, headers, data)
        finally:
            with contextlib.suppress(Exception):
                resp.close()
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_http_pool, _fetch),
            timeout=timeout + 5,
        )
    except (asyncio.TimeoutError, Exception):
        resp = _resp_holder[0]
        if resp is not None:
            with contextlib.suppress(Exception):
                resp.close()
        raise

_no_redirect_urlopener_cache: Optional[Callable] = None
_no_redirect_urlopener_cache_proxy: str = ""  # tracks which proxy the cache was built for
_urlopener_cache_lock = threading.Lock()  # protects urlopener cache check-and-build

def invalidate_urlopener_cache() -> None:
    """Invalidate the cached opener when proxy state changes."""
    global _no_redirect_urlopener_cache, _no_redirect_urlopener_cache_proxy
    with _urlopener_cache_lock:
        _no_redirect_urlopener_cache = None
        _no_redirect_urlopener_cache_proxy = ""

async def _async_urlopen_no_redirect(urlopen_func: Any, req: urllib.request.Request, timeout: int = 10) -> Tuple[int, Any, bytes]:
    global _no_redirect_urlopener_cache, _no_redirect_urlopener_cache_proxy
    from reconchain.process import _PIPELINE_CFG
    current_proxy = _PIPELINE_CFG.proxy or ""
    with _urlopener_cache_lock:
        if _no_redirect_urlopener_cache is None or _no_redirect_urlopener_cache_proxy != current_proxy:
            _no_redirect_urlopener_cache = _get_no_redirect_urlopener()
            _no_redirect_urlopener_cache_proxy = current_proxy
        opener = _no_redirect_urlopener_cache
    return await _async_urlopen(opener, req, timeout=timeout)

async def _throttle() -> None:
    import asyncio
    from reconchain.process import _PIPELINE_CFG
    delay = _PIPELINE_CFG.delay
    if delay > 0:
        await asyncio.sleep(delay)

async def _throttle_rate() -> None:
    import asyncio
    from reconchain.process import _PIPELINE_CFG
    delay = _PIPELINE_CFG.delay
    rate = _PIPELINE_CFG.rate_limit
    if rate > 0:
        await asyncio.sleep(1.0 / rate)
    elif delay > 0:
        await asyncio.sleep(delay)

def _throttle_sync() -> None:
    import time
    from reconchain.process import _PIPELINE_CFG
    delay = _PIPELINE_CFG.delay
    if delay > 0:
        time.sleep(delay)

def ensure(p: Path) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_dir():
        raise IsADirectoryError(f"{p} is a directory, expected a file")
    return p

def _existing_artifacts(d: Dict[str, str]) -> Dict[str, str]:
    return {k: v for k, v in d.items() if Path(v).exists()}

def read_lines(p: Path, max_lines: int = 0) -> List[str]:
    if not p.is_file():
        return []
    lines: List[str] = []
    with p.open(errors="ignore") as f:
        for ln in f:
            ln = ln.strip()
            if ln and not ln.lstrip().startswith("#"):
                lines.append(ln)
                if max_lines and len(lines) >= max_lines:
                    break
    return lines

def iter_lines(p: Path) -> Iterator[str]:
    if not p.is_file():
        return
    with p.open(errors="ignore") as f:
        for ln in f:
            ln = ln.strip()
            if ln and not ln.lstrip().startswith("#"):
                yield ln

def count_nonblank(p: Path) -> int:
    if not p.is_file():
        return 0
    count = 0
    with p.open(errors="ignore") as f:
        for ln in f:
            if ln.strip():
                count += 1
    return count

def merge_unique(srcs: List[Path], dst: Path, validator: Optional[Callable[[str], bool]] = None) -> int:
    seen: Dict[str, None] = {}
    if dst.exists():
        try:
            with dst.open(errors="ignore") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    if validator is not None and not validator(ln):
                        continue
                    seen[ln] = None
        except (OSError, IOError):
            pass
    for s in srcs:
        if not s:
            continue
        try:
            with s.open(errors="ignore") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    if validator is not None and not validator(ln):
                        continue
                    if ln not in seen:
                        seen[ln] = None
        except (OSError, IOError):
            continue
    if not seen:
        return 0
    ensure(dst)
    import tempfile
    fd, tmp_path = tempfile.mkstemp(dir=dst.parent, suffix=".merge_tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(sorted(seen)) + "\n")
        os.replace(tmp_path, dst)
    except Exception:
        with contextlib.suppress(Exception):
            os.unlink(tmp_path)
        raise
    return len(seen)


def merge_unique_incremental(srcs: List[Path], dst: Path, validator: Optional[Callable[[str], bool]] = None) -> int:
    """Streaming merge: reads dst to build seen set, then appends only new lines from srcs.
    Avoids re-sorting the entire output on every call."""
    with _MERGE_LOCK:
        seen: Set[str] = set()
        if dst.exists():
            try:
                with dst.open(errors="ignore") as f:
                    for ln in f:
                        ln = ln.strip()
                        if ln and not ln.startswith("#"):
                            if validator is None or validator(ln):
                                seen.add(ln)
            except (OSError, IOError):
                pass
        new_lines: List[str] = []
        for s in srcs:
            if not s:
                continue
            try:
                with s.open(errors="ignore") as f:
                    for ln in f:
                        ln = ln.strip()
                        if not ln or ln.startswith("#"):
                            continue
                        if validator is not None and not validator(ln):
                            continue
                        if ln not in seen:
                            seen.add(ln)
                            new_lines.append(ln)
            except (OSError, IOError):
                continue
        if not new_lines:
            return 0
        ensure(dst)
        with dst.open("a") as f:
            f.write("\n".join(new_lines) + "\n")
    return len(new_lines)

def merge_unique_str(entry: str, dst: Path) -> bool:
    with _MERGE_LOCK:
        seen: Set[str] = set()
        if dst.exists():
            try:
                with dst.open(errors="ignore") as f:
                    for ln in f:
                        ln = ln.strip()
                        if ln:
                            seen.add(ln)
            except (OSError, IOError):
                pass
        if entry in seen:
            return False
        seen.add(entry)
        ensure(dst)
        import tempfile
        fd, tmp_path = tempfile.mkstemp(dir=dst.parent, suffix=".merge_tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(sorted(seen)) + "\n")
            os.replace(tmp_path, dst)
        except Exception:
            with contextlib.suppress(Exception):
                os.unlink(tmp_path)
            raise
        return True

def _downsample_file(path: Path, n: int = 1) -> None:
    if not path.is_file():
        return
    import tempfile
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".ds_tmp")
    try:
        written = 0
        too_many = False
        with path.open(encoding="utf-8", errors="ignore") as src, os.fdopen(fd, "w", encoding="utf-8") as dst:
            for ln in src:
                if ln.strip() and not ln.lstrip().startswith("#"):
                    if written < n:
                        dst.write(ln if ln.endswith("\n") else ln + "\n")
                    written += 1
                    if written > n:
                        too_many = True
        if too_many:
            os.replace(tmp_path, path)
        else:
            os.unlink(tmp_path)
    except Exception:
        with contextlib.suppress(Exception):
            os.unlink(tmp_path)
        raise

def safe_suffix(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()[:16]

def _safe_name(s: str, maxlen: int = 80) -> str:
    safe = (
        s.replace("/", "_").replace("\\", "_").replace(":", "_")
        .replace("?", "_").replace("*", "_").replace('"', "_")
        .replace("<", "_").replace(">", "_").replace("|", "_")
        .replace("&", "_").replace("=", "_").replace("#", "_")
        .replace("%", "_").replace("\n", "").replace("\r", "")
        .replace("\x00", "").replace("'", "_").replace("`", "_")
        .replace("$", "_").replace(";", "_").replace("!", "_")
    )
    # Collapse path traversal components
    while ".." in safe:
        safe = safe.replace("..", "_")
    # Strip leading dots and hyphens (Windows hidden files / reserved names)
    safe = safe.lstrip(".-")
    return safe[:maxlen]

def read_jsonl(p: Path) -> List[Any]:
    if not p.exists():
        return []
    out: List[Any] = []
    try:
        size = p.stat().st_size
    except OSError:
        return []
    with p.open(errors="ignore") as f:
        first = f.readline().strip()
        if first.startswith("{"):
            try:
                out.append(json.loads(first))
            except json.JSONDecodeError:
                pass
            for ln in f:
                ln = ln.strip()
                if not ln or not ln.startswith("{"):
                    continue
                try:
                    out.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
            if out:
                return out
        # Fallback: only read entire file if it's small (< 10MB)
        if size > 10 * 1024 * 1024:
            log("warn", f"read_jsonl: {p.name} is {size // 1024}KB, returning partial results only")
            return out
        f.seek(0)
        raw = f.read()
        f.close()
    if not raw:
        return []
    try:
        d = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return d if isinstance(d, list) else [d]

def _extract_urls_from_ffuf_json(p: Path) -> List[str]:
    out: List[str] = []
    if not p.exists():
        return out
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return out
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return out
    for r in results:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        status = r.get("status")
        if url and status is not None:
            out.append(f"{status}\t{url}")
    return out

def _merge_dnsx_output(src: Path, hosts_out: Path, full_out: Path) -> int:
    seen_hosts: Set[str] = set()
    seen_full_lines: Set[str] = set()
    if hosts_out.exists():
        for h in read_lines(hosts_out):
            if h.strip():
                seen_hosts.add(h.strip().lower())
    if full_out.exists():
        for ln in read_lines(full_out):
            line = ln.strip()
            if line:
                seen_full_lines.add(line)
                host = line.split()[0].rstrip(".").lower()
                seen_hosts.add(host)
    new_lines: List[str] = []
    for ln in read_lines(src):
        ln = ln.strip()
        if not ln or ln.lstrip().startswith("#"):
            continue
        if ln in seen_full_lines:
            continue
        host = ln.split()[0].rstrip(".")
        if _is_valid_hostname(host):
            seen_full_lines.add(ln)
            seen_hosts.add(host.lower())
            new_lines.append(ln)
    if new_lines:
        with full_out.open("a") as f:
            # Ensure file ends with newline before appending
            if full_out.exists() and full_out.stat().st_size > 0:
                f.seek(0, 2)  # Seek to end
                f.seek(f.tell() - 1)  # Seek to last byte
                if f.read(1) != b"\n":
                    f.write(b"\n")
            f.write("\n".join(new_lines) + "\n")
        hosts_out.write_text("\n".join(sorted(seen_hosts)) + "\n")
    return len(new_lines)

def _dedupe_by_host_path(urls: List[str]) -> List[str]:
    seen: Set[Tuple[str, str, str]] = set()
    result: List[str] = []
    for u in urls:
        parsed = urllib.parse.urlparse(u)
        key = (parsed.scheme, parsed.hostname or "", parsed.path.rstrip("/"))
        if key not in seen:
            seen.add(key)
            result.append(u)
    return result

def _dedupe_by_host_params(urls: List[str]) -> List[str]:
    seen: Set[Tuple[str, str, str, str]] = set()
    result: List[str] = []
    for u in urls:
        parsed = urllib.parse.urlparse(u)
        qs = frozenset(urllib.parse.parse_qs(parsed.query))
        key = (parsed.scheme, parsed.hostname or "", parsed.path.rstrip("/"), str(sorted(qs)))
        if key not in seen:
            seen.add(key)
            result.append(u)
    return result

def _parse_httpx_tech(src: Path, dst: Path) -> int:
    seen: Set[str] = set()
    for line in read_lines(src):
        line = line.strip()
        if not line:
            continue
        url = line.split()[0]
        brackets = re.findall(r"\[.*?\]", line)
        if len(brackets) >= 3:
            status = brackets[0]
            title = brackets[1]
            tech = brackets[2]
            entry = f"{url} {status} {title} {tech}".rstrip()
            if entry not in seen:
                seen.add(entry)
    if seen:
        ensure(dst).write_text("\n".join(sorted(seen)) + "\n")
    return len(seen)

def _mmh3_hash(data: bytes) -> int:
    seed = 0
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    r1 = 15
    r2 = 13
    m = 5
    n = 0xE6546B64
    h = seed
    length = len(data)
    nblocks = length // 4
    for i in range(nblocks):
        k = struct.unpack_from("<I", data, i * 4)[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << r1) | (k >> (32 - r1))) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << r2) | (h >> (32 - r2))) & 0xFFFFFFFF
        h = (h * m + n) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k = 0
    tail_len = length & 3
    if tail_len == 3:
        k ^= tail[2] << 16
    if tail_len >= 2:
        k ^= tail[1] << 8
    if tail_len >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << r1) | (k >> (32 - r1))) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h if h < 0x80000000 else h - 0x100000000

def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )

def md_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

class Progress:
    def __init__(self, phases: List[str], stages: Optional[List[List[str]]] = None):
        from reconchain.phases import _PHASE_WEIGHTS
        self.phases = phases
        self.phase_set = set(phases)
        self._weight_done = 0
        self._completed = 0
        self._total_weight = sum(_PHASE_WEIGHTS.get(p, 1) for p in phases)
        self._enabled = sys.stderr.isatty()
        self._last_bar = ""
        self._draw_lock = threading.Lock()  # serializes terminal writes
        global _active_progress
        with _active_progress_lock:
            _active_progress = self

    def _fmt_bar(self) -> str:
        from reconchain.phases import _PHASE_WEIGHTS
        if self._total_weight == 0:
            return ""
        pct = min(100.0, (self._weight_done / self._total_weight) * 100)
        w = int(40 * self._weight_done / self._total_weight)
        bar = "█" * w + "░" * (40 - w)
        return f"[{pct:5.1f}%] {bar}  {self._completed}/{len(self.phases)}  {self.phases[self._completed - 1] if 0 < self._completed <= len(self.phases) else ''}"

    def _draw(self):
        """Redraw the progress bar on the bottom line of the terminal."""
        if not self._enabled:
            return
        bar = self._fmt_bar()
        if bar == self._last_bar:
            return
        with self._draw_lock:
            self._last_bar = bar
            sys.stderr.write(f"\033[999;0H\033[K{bar}")
            sys.stderr.flush()

    def _write_above(self, text: str):
        """Write a log line above the progress bar."""
        if not self._enabled:
            return
        with self._draw_lock:
            sys.stderr.write(f"\033[999;0H\033[K{text}\n\033[999;0H\033[K{self._last_bar}")
            sys.stderr.flush()

    def next(self, name: str):
        from reconchain.phases import _PHASE_WEIGHTS
        w = _PHASE_WEIGHTS.get(name, 1)
        self._weight_done += w
        self._completed += 1
        self._draw()

    def close(self):
        global _active_progress
        with _active_progress_lock:
            _active_progress = None
        if self._enabled:
            sys.stderr.write(f"\033[999;0H\033[K")
            sys.stderr.flush()
        self._last_bar = ""


class ScanStatus:
    """Lightweight progress persistence for terminal-reconnect support."""
    _CONTAINER_ID = os.environ.get("HOSTNAME", "")[:8] or os.urandom(4).hex()
    _SCAN_STATUS_DIR = Path(
        os.environ.get("XDG_RUNTIME_DIR") or os.environ.get("TMPDIR") or "/tmp"
    ) / f"reconchain_status_{os.getuid()}_{_CONTAINER_ID}"
    _write_lock = threading.Lock()

    def __init__(self, domain: str, outdir: Path) -> None:
        self.domain = domain
        self.outdir = outdir
        self._data_lock = threading.Lock()  # protects _data mutations
        self._SCAN_STATUS_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(self._SCAN_STATUS_DIR), 0o700)
        except OSError:
            pass
        self._path = self._SCAN_STATUS_DIR / f"{domain.replace('.', '_')}.json"
        self._data: Dict[str, Any] = {
            "domain": domain,
            "outdir": str(outdir),
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "phase": "",
            "phase_progress": "",
            "completed_phases": [],
            "running_phases": [],
            "total_phases": 0,
            "errors": [],
            "missing_tools": [],
        }
        self._dirty = False
        self._last_write = 0.0
        self._write()

    def _write(self) -> None:
        """Mark dirty and flush at most once per second to reduce disk I/O."""
        self._dirty = True
        now = time.monotonic()
        if now - self._last_write < 1.0:
            return
        self._flush()

    def _flush(self) -> None:
        """Actually write status to disk."""
        self._dirty = False
        self._last_write = time.monotonic()
        with self._write_lock:
            with self._data_lock:
                self._data["updated_at"] = datetime.now().isoformat(timespec="seconds")
                data_snapshot = dict(self._data)
                data_snapshot["completed_phases"] = list(self._data["completed_phases"])
                data_snapshot["running_phases"] = list(self._data["running_phases"])
                data_snapshot["errors"] = list(self._data["errors"])
            try:
                self._SCAN_STATUS_DIR.mkdir(parents=True, exist_ok=True)
                if self._path.is_symlink():
                    real = self._path.resolve()
                    if not real.is_relative_to(self._SCAN_STATUS_DIR):
                        self._path.unlink()
                import tempfile
                fd, tmp_path = tempfile.mkstemp(dir=self._SCAN_STATUS_DIR, suffix=".tmp")
                with os.fdopen(fd, "w") as f:
                    json.dump(data_snapshot, f, indent=2, default=str)
                os.replace(tmp_path, self._path)
                if self._path.is_symlink():
                    real = self._path.resolve()
                    if not real.is_relative_to(self._SCAN_STATUS_DIR):
                        self._path.unlink()
            except Exception as exc:
                log("err", f"ScanStatus write failed: {exc}")
                with self._data_lock:
                    self._data.setdefault("write_errors", []).append(str(exc))

    def set_phase(self, name: str) -> None:
        with self._data_lock:
            self._data["phase"] = name
            self._data["phase_progress"] = ""
        self._write()

    def set_progress(self, msg: str) -> None:
        with self._data_lock:
            self._data["phase_progress"] = msg
        self._write()

    def add_completed(self, name: str) -> None:
        with self._data_lock:
            if name not in self._data["completed_phases"]:
                self._data["completed_phases"].append(name)
            if name in self._data["running_phases"]:
                self._data["running_phases"].remove(name)
        self._write()

    def add_running(self, name: str) -> None:
        with self._data_lock:
            if name not in self._data["running_phases"]:
                self._data["running_phases"].append(name)
        self._write()

    def set_total(self, n: int) -> None:
        with self._data_lock:
            self._data["total_phases"] = n
        self._write()

    def add_error(self, err: str) -> None:
        with self._data_lock:
            self._data["errors"].append(err)
            if len(self._data["errors"]) > 1000:
                self._data["errors"] = self._data["errors"][-500:]
        self._write()

    def set_missing(self, tools: List[str]) -> None:
        with self._data_lock:
            self._data["missing_tools"] = sorted(set(tools))
        self._write()

    def close(self) -> None:
        with self._data_lock:
            self._data["status"] = "completed"
            self._data["updated_at"] = datetime.now().isoformat(timespec="seconds")
            if self._data.get("running_phases"):
                for name in self._data["running_phases"]:
                    if name not in self._data["completed_phases"]:
                        self._data["completed_phases"].append(name)
                self._data["running_phases"] = []
            self._dirty = False
        self._flush()

    @classmethod
    def load(cls, domain: str) -> Optional[Dict[str, Any]]:
        path = cls._SCAN_STATUS_DIR / f"{domain.replace('.', '_')}.json"
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            except (json.JSONDecodeError, ValueError):
                pass
        return None

    @classmethod
    def list_active(cls) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not cls._SCAN_STATUS_DIR.exists():
            return results
        for f in sorted(cls._SCAN_STATUS_DIR.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
                if data.get("status") != "completed":
                    results.append(data)
            except Exception:
                continue
        return results


# ── Atomic write helpers ──────────────────────────────────────────────────────

def atomic_write_json(path: Path, payload: Any) -> None:
    """Atomically write JSON to a file using tmp + rename."""
    import tempfile
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2, default=str)
        os.replace(tmp_path, path)
    except Exception:
        with contextlib.suppress(Exception):
            os.unlink(tmp_path)
        raise


def atomic_write_text(path: Path, content: str) -> None:
    """Atomically write text to a file using tmp + rename."""
    import tempfile
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp_path, path)
    except Exception:
        with contextlib.suppress(Exception):
            os.unlink(tmp_path)
        raise
