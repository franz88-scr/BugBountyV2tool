"""Shared constants and helper functions for all phase modules."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import fnmatch
import hashlib
import json
import math
import os
import random
import re
import shlex
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from reconchain.config import _SAFE_HOST, VALID_PHASES
from reconchain.interactsh import Interactsh
from reconchain.process import (
    _ENV_LOCK,
    _JOB_SEM,
    _PIPELINE_CFG,
    _USE_PROXYCHAINS,
    _maybe_timeout,
    _proxify_cmd,
    _run,
    _update_nuclei_templates,
    run_parallel,
)
from reconchain.tools import Tools
from reconchain.utils import (
    _async_urlopen,
    _async_urlopen_no_redirect,
    _dedupe_by_host_params,
    _dedupe_by_host_path,
    _existing_artifacts,
    _extra_headers_dict,
    _extra_http_args,
    _extract_urls_from_ffuf_json,
    _get_no_redirect_urlopener,
    _get_urlopener,
    _is_under_domain,
    _is_valid_hostname,
    _load_live_hosts,
    _merge_dnsx_output,
    _mmh3_hash,
    _parse_httpx_tech,
    _safe_name,
    _throttle_rate,
    _write_target_tokens,
    count_nonblank,
    ensure,
    iter_lines,
    log,
    merge_unique,
    merge_unique_incremental,
    merge_unique_str,
    parse_set_cookie_headers,
    read_jsonl,
    read_lines,
    safe_suffix,
    write_findings,
)

__all__ = [
    # stdlib re-exports
    "asyncio", "base64", "contextlib", "fnmatch", "hashlib", "json", "math",
    "os", "random", "re", "shlex", "shutil", "socket", "subprocess", "time",
    "urllib", "datetime", "Path",
    # typing
    "Any", "Dict", "List", "Optional", "Set", "Tuple",
    # reconchain.config
    "VALID_PHASES", "_SAFE_HOST",
    # reconchain.process
    "_ENV_LOCK", "_maybe_timeout", "_USE_PROXYCHAINS", "run_parallel",
    "_PIPELINE_CFG", "_run", "_proxify_cmd", "_update_nuclei_templates",
    "_JOB_SEM",
    # reconchain.tools
    "Tools",
    # reconchain.utils (public)
    "ensure", "log", "read_lines", "iter_lines", "read_jsonl", "count_nonblank",
    "merge_unique", "merge_unique_incremental", "merge_unique_str",
    "parse_set_cookie_headers",
    "safe_suffix", "_safe_name", "write_findings", "_load_live_hosts",
    # reconchain.utils (underscored, needed by phases)
    "_is_valid_hostname", "_is_under_domain", "_existing_artifacts",
    "_get_urlopener", "_get_no_redirect_urlopener",
    "_write_target_tokens",
    "_extra_headers_dict", "_extra_http_args",
    "_async_urlopen", "_async_urlopen_no_redirect",
    "_dedupe_by_host_path", "_dedupe_by_host_params",
    "_parse_httpx_tech",
    "_mmh3_hash",
    "_extract_urls_from_ffuf_json", "_merge_dnsx_output",
    "_throttle_rate",
    # reconchain.interactsh
    "Interactsh",
    # locals
    "MAX_RECV",
    "_rate_limit_args",
    "_SCOPE_FILE", "_SCOPE_PATTERNS", "PhaseSet",
    "_DEFAULT_RESOLVERS", "_ensure_resolver_file",
    "_PROXY_CLEAR_VARS", "_run_cmd_clear_proxy",
    "_extract_headers", "_request", "_norm_line",
    "_STATIC_EXT", "_is_static_url",
    "_SKIP_PARAMS", "_TOKEN_PARAM_RE",
    "_normalize_url", "_dedupe_by_normalized_url",
]

MAX_RECV = 1_000_000


def _rate_limit_args(tool: str) -> List[str]:
    """Return rate-limit CLI flags for a tool based on _PIPELINE_CFG."""
    rl = getattr(_PIPELINE_CFG, "rate_limit", 0)
    if not rl:
        return []
    delay = getattr(_PIPELINE_CFG, "delay", 0.0)
    if tool == "httpx":
        return ["-rate-limit", str(rl)]
    if tool == "katana":
        return ["-rate-limit", str(rl)]
    if tool == "nuclei":
        return ["-rl", str(rl)]
    if tool == "ffuf":
        return ["-rate", str(rl)]
    if tool == "httprobe":
        return ["-c", str(max(5, min(rl, 50)))]
    if tool == "gau":
        return ["--threads", str(max(1, min(rl, 10)))]
    return []


# Phase-level globals
_SCOPE_FILE: Optional[Path] = None
_SCOPE_PATTERNS: List[str] = []
PhaseSet = Set[str]

_DEFAULT_RESOLVERS = [
    "1.1.1.1:53",
    "1.0.0.1:53",
    "8.8.8.8:53",
    "8.8.4.4:53",
    "9.9.9.9:53",
    "149.112.112.112:53",
    "208.67.222.222:53",
    "208.67.220.220:53",
    "185.228.168.9:53",
    "185.228.169.9:53",
    "76.76.19.19:53",
    "76.223.122.150:53",
]

def _ensure_resolver_file(path: Path) -> bool:
    """Create a default resolver file if it doesn't exist. Returns True if ready."""
    if path.exists():
        return True
    ensure(path)
    path.write_text("\n".join(_DEFAULT_RESOLVERS) + "\n")
    log("info", f"created default resolver list at {path} ({len(_DEFAULT_RESOLVERS)} resolvers)")
    return True

_PROXY_CLEAR_VARS = ["ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy",
                     "HTTP_PROXY", "http_proxy", "PROXY"]

async def _run_cmd_clear_proxy(cmd: List[str], timeout: int = 10) -> Tuple[int, bytes, bytes]:
    """Run a subprocess command after clearing proxy env vars, with resource limits."""
    from reconchain.process import _run_limited
    clean_env = {k: v for k, v in os.environ.items() if k not in _PROXY_CLEAR_VARS}
    sem = _JOB_SEM
    async def _do_run():
        return await _run_limited(
            cmd, timeout=timeout,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=clean_env,
        )
    if sem is not None:
        async with sem:
            return await _do_run()
    return await _do_run()

def _extract_headers(s: str) -> Dict[str, str]:
    heads: Dict[str, str] = {}
    for ln in s.splitlines():
        if ":" in ln:
            k, v = ln.split(":", 1)
            heads[k.strip().lower()] = v.strip()
    return heads

def _request(host: str, path: str, timeout: int = 10) -> bytes:
    opener = _get_urlopener()
    url = host.rstrip("/") + "/" + path.lstrip("/")
    if not url.startswith("http"):
        url = "https://" + url
    try:
        resp = opener.open(url, timeout=timeout)
        data = resp.read(MAX_RECV)
        return data
    except Exception:
        pass
    return b""

def _norm_line(raw: str) -> str:
    raw = raw.strip()
    while raw.startswith("//"):
        raw = raw[2:]
    while raw.count("//") > 1:
        raw = raw.replace("//", "/")
    return raw.rstrip("/")

_STATIC_EXT = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".webp", ".gif", ".pdf",
    ".json", ".xml", ".map", ".txt",
})

def _is_static_url(url: str) -> bool:
    path = urllib.parse.urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXT)


_SKIP_PARAMS = frozenset({"v", "ver", "version", "id", "_", "t"})

_TOKEN_PARAM_RE = re.compile(
    r"^(?:"
    r"[0-9a-fA-F]{8,}"
    r"|[0-9a-fA-F-]{36}"
    r"|[A-Za-z0-9+/=]{12,}"
    r"|[A-Za-z0-9_-]{12,}"
    r")$"
)
def _normalize_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    norm_qs: Dict[str, List[str]] = {}
    for k in sorted(qs):
        vals = []
        for v in qs[k]:
            if _TOKEN_PARAM_RE.match(v):
                vals.append("_TOKEN_")
            else:
                vals.append(v)
        norm_qs[k] = vals
    new_qs = urllib.parse.urlencode(norm_qs, doseq=True)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", new_qs, "")
    )

def _dedupe_by_normalized_url(urls: List[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for u in urls:
        norm = _normalize_url(u)
        if norm not in seen:
            seen.add(norm)
            result.append(u)
    return result
