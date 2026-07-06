"""Utility functions: file I/O, logging, validation, proxy config."""
from __future__ import annotations
import contextlib
import hashlib
import json
import os
import re
import struct
import sys
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

from reconchain.config import _HOSTNAME_RE

_re = re

_HOSTNAME_RE = _HOSTNAME_RE

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
    return [_target_token(line) for line in read_lines(path) if _target_token(line)]

def _write_target_tokens(src: Path, dst: Path) -> int:
    seen: Set[str] = set()
    for token in _target_lines(src):
        if token not in seen:
            seen.add(token)
    ensure(dst).write_text("\n".join(sorted(seen)) + "\n")
    return len(seen)

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

def log(lvl: str, msg: str) -> None:
    _log_write(f"{LVL[lvl]}[{lvl[0].upper()}]{C['r']} {msg}")

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
    _PROXY_VARS = ["ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy",
                   "HTTP_PROXY", "http_proxy", "PROXY"]
    if not proxy:
        for v in _PROXY_VARS:
            os.environ.pop(v, None)
        return
    for v in _PROXY_VARS:
        os.environ[v] = proxy

def _auto_detect_cookies() -> str:
    val = os.environ.get("COOKIE", "")
    if val:
        return val
    cookie_file = Path("cookies.txt")
    if cookie_file.exists():
        return cookie_file.read_text(encoding="utf-8", errors="ignore").strip()
    return ""

def _extra_headers_dict() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    cookie = os.environ.get("COOKIE", "")
    if cookie:
        headers["Cookie"] = cookie
    headers_raw = os.environ.get("EXTRA_HEADERS", "")
    if headers_raw:
        for hdr in headers_raw.split("\n"):
            hdr = hdr.strip()
            if hdr and ":" in hdr:
                k, v = hdr.split(":", 1)
                headers[k.strip()] = v.strip()
    return headers

def _extra_http_args() -> List[str]:
    args: List[str] = []
    cookie = os.environ.get("COOKIE", "")
    if cookie:
        args += ["-H", f"Cookie: {cookie.replace(chr(13), '').replace(chr(10), ' ')}"]
    headers_raw = os.environ.get("EXTRA_HEADERS", "")
    if headers_raw:
        for h in headers_raw.replace(chr(13), "").split("\n"):
            h = h.strip()
            if h:
                args += ["-H", h]
    return args

def _patch_socks(proxy: str) -> bool:
    """Globally patch socket to route through SOCKS proxy via PySocks."""
    import socket as _sk
    try:
        import socks as _socks
        _parsed = urllib.parse.urlparse(proxy)
        _pt = _socks.SOCKS5 if _parsed.scheme.startswith("socks5") else _socks.SOCKS4
        _socks.set_default_proxy(_pt, _parsed.hostname, _parsed.port or 1080)
        _socks.wrap_module(_sk)
        return True
    except ImportError:
        log("warn", "PySocks not installed; SOCKS proxy won't work for Python HTTP. Run: pip install pysocks")
        return False
    except Exception as _e:
        log("warn", f"SOCKS patch failed: {_e}")
        return False

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
            return lambda *a, **kw: opener.open(*a, **{**kw, "context": ctx})
        if proxy.startswith(("socks4://", "socks5://", "socks5h://", "socks4a://")):
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
            return lambda *a, **kw: opener.open(*a, **{**kw, "context": ctx})
        if proxy.startswith(("socks4://", "socks5://", "socks5h://", "socks4a://")):
            global _socks_patched
            if not _socks_patched:
                _socks_patched = _patch_socks(proxy)
    opener = urllib.request.build_opener(_NoRedirectHandler)
    return lambda *a, **kw: opener.open(*a, **{**kw, "context": ctx})

async def _async_urlopen(urlopen_func: Any, req: urllib.request.Request, timeout: int = 10) -> Tuple[int, Any, bytes]:
    import asyncio
    def _fetch() -> Tuple[int, Any, bytes]:
        with urlopen_func(req, timeout=timeout) as resp:
            return (resp.status, resp.headers, resp.read())
    return await asyncio.wait_for(asyncio.to_thread(_fetch), timeout=timeout + 5)

async def _async_urlopen_no_redirect(urlopen_func: Any, req: urllib.request.Request, timeout: int = 10) -> Tuple[int, Any, bytes]:
    _no_redirect_urlopen = _get_no_redirect_urlopener()
    return await _async_urlopen(_no_redirect_urlopen, req, timeout=timeout)

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

def read_lines(p: Path) -> List[str]:
    if not p.is_file():
        return []
    return [
        ln.strip()
        for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]

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
    return sum(1 for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip())

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
    tmp = dst.with_suffix(dst.suffix + ".merge_tmp")
    try:
        tmp.write_text("\n".join(sorted(seen)) + "\n")
        os.replace(tmp, dst)
    except Exception:
        with contextlib.suppress(Exception):
            tmp.unlink(missing_ok=True)
        raise
    return len(seen)

def merge_unique_str(entry: str, dst: Path) -> bool:
    seen: Dict[str, None] = {}
    if dst.exists():
        try:
            with dst.open(errors="ignore") as f:
                for ln in f:
                    ln = ln.strip()
                    if ln:
                        seen[ln] = None
        except (OSError, IOError):
            pass
    if entry not in seen:
        with dst.open("a") as f:
            f.write(entry + "\n")
        return True
    return False

def _downsample_file(path: Path, n: int = 1) -> None:
    if not path.is_file():
        return
    count = 0
    try:
        with path.open(encoding="utf-8", errors="ignore") as f:
            for ln in f:
                if ln.strip() and not ln.lstrip().startswith("#"):
                    count += 1
                    if count > n:
                        break
    except (OSError, IOError):
        return
    if count <= n:
        return
    tmp = path.with_suffix(path.suffix + ".ds_tmp")
    try:
        with path.open(encoding="utf-8", errors="ignore") as src, tmp.open("w", encoding="utf-8") as dst:
            written = 0
            for ln in src:
                if ln.strip() and not ln.lstrip().startswith("#"):
                    dst.write(ln if ln.endswith("\n") else ln + "\n")
                    written += 1
                    if written >= n:
                        break
        os.replace(tmp, path)
    except Exception:
        with contextlib.suppress(Exception):
            tmp.unlink(missing_ok=True)
        raise

def safe_suffix(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()[:12]

def _safe_name(s: str, maxlen: int = 80) -> str:
    safe = (
        s.replace("/", "_").replace(":", "_").replace("?", "_")
        .replace("&", "_").replace("=", "_").replace("#", "_")
        .replace("%", "_").replace("\n", "").replace("\r", "")
    )
    return safe[:maxlen]

def read_jsonl(p: Path) -> List[Any]:
    if not p.exists():
        return []
    out: List[Any] = []
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
        f.seek(0)
        raw = f.read()
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
    return h

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
        self.stages = stages or []
        self._weight_done = 0
        self._completed = 0
        self._total_weight = sum(_PHASE_WEIGHTS.get(p, 1) for p in phases)
        self.bar = tqdm(total=self._total_weight, desc="Scan", position=0)

    def next(self, name: str):
        from reconchain.phases import _PHASE_WEIGHTS
        w = _PHASE_WEIGHTS.get(name, 1)
        self._weight_done += w
        self._completed += 1
        if self.bar.total == 0:
            return
        stage_idx = 0
        if self.stages:
            seen = 0
            for i, stage in enumerate(self.stages):
                seen += sum(1 for p in stage if p in self.phase_set)
                if self._completed <= seen:
                    stage_idx = i
                    break
        pct = min(100.0, (self._weight_done / self.bar.total) * 100)
        stage_info = f"Stage {stage_idx + 1}/{len(self.stages)} " if self.stages else ""
        self.bar.set_description(f"{stage_info}[{pct:.0f}%] {name}")
        self.bar.update(w)

    def close(self):
        self.bar.close()


class ScanStatus:
    """Lightweight progress persistence for terminal-reconnect support."""
    _SCAN_STATUS_DIR = Path(
        os.environ.get("XDG_RUNTIME_DIR") or os.environ.get("TMPDIR") or "/tmp"
    ) / "reconchain_status"
    _write_lock = threading.Lock()

    def __init__(self, domain: str, outdir: Path) -> None:
        self.domain = domain
        self.outdir = outdir
        self._SCAN_STATUS_DIR.mkdir(parents=True, exist_ok=True)
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
        self._write()

    def _write(self) -> None:
        with self._write_lock:
            self._data["updated_at"] = datetime.now().isoformat(timespec="seconds")
            try:
                self._SCAN_STATUS_DIR.mkdir(parents=True, exist_ok=True)
                tmp = self._path.with_suffix(self._path.suffix + ".tmp")
                tmp.write_text(json.dumps(self._data, indent=2, default=str))
                os.replace(tmp, self._path)
            except Exception as exc:
                log("err", f"ScanStatus write failed: {exc}")
                self._data.setdefault("write_errors", []).append(str(exc))

    def set_phase(self, name: str) -> None:
        self._data["phase"] = name
        self._data["phase_progress"] = ""
        self._write()

    def set_progress(self, msg: str) -> None:
        self._data["phase_progress"] = msg
        self._write()

    def add_completed(self, name: str) -> None:
        if name not in self._data["completed_phases"]:
            self._data["completed_phases"].append(name)
        if name in self._data["running_phases"]:
            self._data["running_phases"].remove(name)
        self._write()

    def add_running(self, name: str) -> None:
        if name not in self._data["running_phases"]:
            self._data["running_phases"].append(name)
        self._write()

    def set_total(self, n: int) -> None:
        self._data["total_phases"] = n
        self._write()

    def add_error(self, err: str) -> None:
        self._data["errors"].append(err)
        self._write()

    def set_missing(self, tools: List[str]) -> None:
        self._data["missing_tools"] = sorted(set(tools))
        self._write()

    def close(self) -> None:
        self._data["status"] = "completed"
        self._data["updated_at"] = datetime.now().isoformat(timespec="seconds")
        if not self._write_lock.acquire(blocking=False):
            return
        try:
            try:
                self._SCAN_STATUS_DIR.mkdir(parents=True, exist_ok=True)
                tmp = self._path.with_suffix(self._path.suffix + ".tmp")
                tmp.write_text(json.dumps(self._data, indent=2, default=str))
                os.replace(tmp, self._path)
            except Exception as exc:
                log("err", f"ScanStatus close failed: {exc}")
        finally:
            self._write_lock.release()
        with contextlib.suppress(Exception):
            self._path.unlink(missing_ok=True)

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
