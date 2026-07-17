"""Vulnerability scanning phases: nuclei, TLS/CMS fingerprinting, OOB, dependency CVE."""
from reconchain.phases.helpers import *


async def phase_09_VULNSCAN(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"09-VULNSCAN"}:
        return {}
    _f1_out = outdir / "nuclei_combined.txt"
    if _f1_out.exists() and not force:
        return {"09-VULNSCAN": str(_f1_out), "count": count_nonblank(_f1_out)}
    log("info", "Phase 09-VULNSCAN: nuclei (full) + tech-scanner (sequential)")
    hosts = outdir / "host_targets.txt"
    if not hosts.exists() or not read_lines(hosts):
        raw_hosts = outdir / "hosts.txt"
        if raw_hosts.exists() and read_lines(raw_hosts):
            _write_target_tokens(raw_hosts, hosts)
    if not hosts.exists() or not read_lines(hosts):
        hosts = outdir / "resolved.txt"
    if not hosts.exists() or not read_lines(hosts):
        log("warn", "09-VULNSCAN: no hosts; skipping")
        return {"09-VULNSCAN": str(outdir / "nuclei_combined.txt"), "count": 0}
    _proxy_opt = []
    if _PIPELINE_CFG.proxy:
        _proxy_opt = ["-proxy", _PIPELINE_CFG.proxy]
    if t.has("nuclei"):
        nuclei_base = [
            "nuclei", "-silent", "-l", str(hosts),
            "-timeout", "30", "-max-host-error", "10",
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ] + _extra_http_args()
        if _PIPELINE_CFG.rate_limit:
            nuclei_base += ["-rl", str(_PIPELINE_CFG.rate_limit)]
        nuclei_base += ["-bs", "25"]
        nuclei_tags = ["cves", "exposures", "misconfig", "vulnerabilities"]
        if _PIPELINE_CFG.nuclei_exclude_tags:
            nuclei_base += ["-et", _PIPELINE_CFG.nuclei_exclude_tags]
        # STEP 1: nuclei CVE scan
        await run_parallel([(
            "nuclei-cves",
            nuclei_base
            + ["-tags", ",".join(nuclei_tags), "-severity", "low,medium,high,critical",
               "-o", str(outdir / "nuclei.txt")]
            + _proxy_opt,
            3600,
        )], outdir)
        # STEP 2: tech-scanner
        await run_parallel([(
            "tech-scanner",
            nuclei_base
            + ["-t", "http/technologies",
               "-o", str(outdir / "tech.txt")]
            + _proxy_opt,
            3600,
        )], outdir)
        # STEP 3: headless scan (optional, needs Chrome)
        _has_browser = any(
            shutil.which(b) for b in
            ("google-chrome", "chromium-browser", "chromium", "chrome", "google-chrome-stable")
        )
        if _has_browser:
            await run_parallel([(
                "nuclei-headless",
                nuclei_base
                + ["-headless", "-ho", "--headless=new,--no-sandbox,--disable-gpu", "-tags", "headless", "-severity", "medium,high,critical",
                   "-o", str(outdir / "nuclei_headless.txt")]
                + _proxy_opt,
                3600,
            )], outdir)
        else:
            log("info", "nuclei-headless: no Chrome/Chromium found; skipping")
    n = merge_unique(
        [outdir / "nuclei.txt", outdir / "nuclei_headless.txt", outdir / "tech.txt"],
        outdir / "nuclei_combined.txt",
    )
    comb = outdir / "nuclei_combined.txt"
    if comb.exists():
        lines = read_lines(comb)
        deduped: List[str] = []
        waf_seen: Set[str] = set()
        for ln in lines:
            if "waf-detect" in ln:
                parts2 = ln.strip().split()
                host_part = parts2[-1] if parts2 else ""
                host_part = host_part.replace("http://", "").replace("https://", "")
                norm = f"waf-detect:{host_part}"
                if norm in waf_seen:
                    continue
                waf_seen.add(norm)
            deduped.append(ln)
        if len(deduped) != len(lines):
            comb.write_text("\n".join(deduped) + "\n")
            n = len(deduped)
    return {"09-VULNSCAN": str(outdir / "nuclei_combined.txt"), "count": n}


async def phase_10_TLSCMS(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"10-TLSCMS"}:
        return {}
    _f2_out = outdir / "tls_wp.txt"
    if _f2_out.exists() and not force:
        return {"10-TLSCMS": str(_f2_out), "count": count_nonblank(_f2_out)}
    log("info", "Phase 10-TLSCMS: testssl + wpscan")
    hosts = outdir / "host_targets.txt"
    if not hosts.exists() or not read_lines(hosts):
        raw_hosts = outdir / "hosts.txt"
        if raw_hosts.exists() and read_lines(raw_hosts):
            _write_target_tokens(raw_hosts, hosts)
    if not hosts.exists() or not read_lines(hosts):
        hosts = outdir / "resolved.txt"
    if not hosts.exists() or not read_lines(hosts):
        log("warn", "10-TLSCMS: no hosts; skipping")
        return {"10-TLSCMS": str(outdir / "tls_wp.txt"), "count": 0}
    sample = read_lines(hosts)[:_PIPELINE_CFG.sample_hosts_ssl]
    testssl_bin = "testssl.sh" if t.has("testssl.sh") else ("testssl" if t.has("testssl") else None)
    # Pre-flight: verify testssl's bundled openssl actually works (old bundled
    # openssl 1.0.2 segfaults on modern glibc when OPENSSL_CONF is set by testssl).
    # `openssl version` works fine — must test s_client to trigger the real crash.
    if testssl_bin:
        _testssl_bin_path = shutil.which(testssl_bin)
        if _testssl_bin_path:
            # Resolve symlinks to find the REAL testssl installation directory
            _testssl_real = str(Path(_testssl_bin_path).resolve().parent)
            _openssl_bin = str(Path(_testssl_real) / "bin" / "openssl.Linux.x86_64")
            if not os.path.isfile(_openssl_bin):
                _openssl_bin = str(Path(_testssl_real) / "bin" / "openssl")
            if os.path.isfile(_openssl_bin):
                try:
                    _test = subprocess.run(
                        [_openssl_bin, "s_client", "-connect", "example.com:443", "-no_comp"],
                        stdin=subprocess.DEVNULL, capture_output=True,
                        timeout=10, env={**os.environ, "OPENSSL_CONF": "/dev/null"},
                    )
                    if _test.returncode < 0:
                        log("warn", f"10-TLSCMS: {_openssl_bin} segfaults (signal {-_test.returncode}); skipping testssl — using Python TLS fallback only")
                        testssl_bin = None
                except Exception:
                    pass
    # testssl: write PER-HOST files via a runner (no shared `>>` file ⇒ no race).
    # The Python TLS fallback below works correctly over proxychains (Python's
    # socket module is hooked by LD_PRELOAD) unlike testssl.sh's /dev/tcp.
    testssl_jobs: List[Tuple[str, List[str], int]] = []
    if testssl_bin:
        # Lightweight pre-check: skip hosts behind Cloudflare (testssl exits 254 on those)
        _cf_skip = set()
        for h in sample:
            try:
                _host = h.split("/")[2] if "://" in h else h.split(":")[0]
                _req = urllib.request.Request(f"https://{_host}", method="HEAD")
                _req.add_header("User-Agent", "Mozilla/5.0")
                _resp = urllib.request.urlopen(_req, timeout=5)
                _srv = _resp.headers.get("Server", "")
                if "cloudflare" in _srv.lower() or "cf-ray" in _resp.headers:
                    _cf_skip.add(h)
                    log("info", f"10-TLSCMS: {h} is behind Cloudflare; skipping testssl")
            except Exception:
                pass
        for h in sample:
            if h in _cf_skip:
                continue
            per_host = outdir / f"testssl_{safe_suffix(h)}.txt"
            runner = outdir / "logs" / f"testssl_{safe_suffix(h)}.sh"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"OUT={shlex.quote(str(per_host))}\n"
                f"H={shlex.quote(h)}\n"
                f"BIN={shlex.quote(testssl_bin)}\n"
                '# testssl expects a bare hostname, not a URL — strip scheme\n'
                'HOST=$(echo "$H" | sed "s|^https\\?://||" | sed "s| .*$||" | sed "s|/.*$||")\n'
                '"$BIN" --quiet --color 0 "$HOST" > "$OUT" 2>&1 || true\n'
            )
            runner.chmod(0o700)
            testssl_jobs.append((f"testssl-{_safe_name(h)}", ["bash", str(runner)], 3600))
    # Python TLS fallback (works with proxychains, unlike testssl.sh's /dev/tcp)
    tls_script = outdir / "tls_check.py"
    if tls_script.is_symlink():
        tls_script.unlink()
    tls_script.write_text(
        "#!/usr/bin/env python3\n"
        '"""Minimal TLS check that works through proxychains."""\n'
        "import json, ssl, socket, sys, urllib.parse\n"
        "from pathlib import Path\n"
        "HOSTS = " + json.dumps(sample) + "\n"
        "OUTDIR = " + json.dumps(str(outdir)) + "\n"
        'for h in HOSTS:\n'
        '    if h.startswith(("http://", "https://")):\n'
        '        try:\n'
        '            parsed = urllib.parse.urlparse(h)\n'
        '            host = parsed.hostname\n'
        '            port = parsed.port or 443\n'
        '        except Exception:\n'
        '            host = h.split("/")[2] if "://" in h else h.split(":")[0]\n'
        '            port = 443\n'
        '    else:\n'
        '        host = h.split(":")[0]\n'
        '        port = int(h.split(":")[1]) if ":" in h and h.split(":")[1].isdigit() else 443\n'
        '    safe = host.replace(".", "_").replace(":", "_")\n'
        '    out = Path(OUTDIR) / f"testssl_py_{safe}.txt"\n'
        '    try:\n'
        '        ctx = ssl.create_default_context()\n'
        '        ctx.check_hostname = True\n'
        '        ctx.verify_mode = ssl.CERT_REQUIRED\n'
        '        with socket.create_connection((host, port), timeout=15) as sock:\n'
        '            with ctx.wrap_socket(sock, server_hostname=host) as ssock:\n'
        '                ver = ssock.version()\n'
        '                cipher = ssock.cipher()\n'
        '                cert = ssock.getpeercert()\n'
        '                cn = next((v for part in cert.get("subject", []) for k, v in part if k == "commonName"), "")\n'
        '                san = [v for _, v in cert.get("subjectAltName", [])]\n'
        '                out.write_text(f"{h} | TLS {ver} | cipher={cipher[0]} | CN={cn} | SAN={san}\\n")\n'
        '    except Exception as e:\n'
        '        out.write_text(f"{h} | ERROR: {e}\\n")\n'
    )
    tls_script.chmod(0o700)
    testssl_jobs.append(("tls-check", ["python3", str(tls_script)], 300))
    # wpscan writes per-host files natively via --output.
    # Skip if the host doesn't appear to be WordPress (check multiple indicators).
    _f2_urlopen = _get_urlopener()
    wpscan_jobs: List[Tuple[str, List[str], int]] = []
    if t.has("wpscan"):
        for h in sample:
            if not h.startswith(("http://", "https://")):
                continue
            # Quick pre-check: is this WordPress? Check multiple paths + homepage body
            # to reduce false negatives from hardened / hidden wp-login.php.
            wp_found = False
            for wp_path in ("/wp-login.php", "/wp-content/", "/wp-includes/"):
                try:
                    req = urllib.request.Request(h.rstrip("/") + wp_path, method="HEAD")
                    wp_status, _, _ = await _async_urlopen(_f2_urlopen, req, timeout=10)
                    if wp_status in (200, 301, 302, 403, 401):
                        wp_found = True
                        break
                except Exception:
                    continue
            if not wp_found:
                # Check homepage body for WordPress markers
                try:
                    req = urllib.request.Request(h, method="GET", headers={"User-Agent": "Mozilla/5.0"})
                    _, _, wp_body_bytes = await _async_urlopen(_f2_urlopen, req, timeout=10)
                    body = wp_body_bytes.decode("utf-8", errors="ignore").lower()
                    if "wp-content" in body or "wordpress" in body:
                        wp_found = True
                except Exception:
                    pass
            if not wp_found:
                continue
            wps_out = outdir / f"wpscan_{safe_suffix(h)}.txt"
            wpscan_cmd = ["wpscan", "--url", h, "--no-banner",
                           "--enumerate", "vp,vt,tt,cb,dbe,u,ap,at",
                           "--output", str(wps_out)]
            if _PIPELINE_CFG.proxy:
                wpscan_cmd.extend(["--proxy", _PIPELINE_CFG.proxy])
            _wps_cookie = os.environ.get("COOKIE", "")
            if _wps_cookie:
                wpscan_cmd.extend(["--cookie", _wps_cookie])
            _wps_headers = os.environ.get("EXTRA_HEADERS", "")
            if _wps_headers:
                for hdr in _wps_headers.split("\n"):
                    hdr = hdr.strip()
                    if hdr:
                        wpscan_cmd.extend(["--header", hdr])
            # WPSCAN_API_TOKEN is read from the environment by wpscan natively,
            # so we do NOT pass it on the CLI to avoid credential exposure via ps.
            wpscan_jobs.append(
                (
                    f"wpscan-{_safe_name(h)}",
                    wpscan_cmd,
                    1800,
                )
            )
    # Clean up stale per-host files from prior runs BEFORE launching new jobs
    # to prevent old artifacts from being re-incorporated into the merge.
    for p in outdir.glob("testssl_*.txt"):
        p.unlink(missing_ok=True)
    for p in outdir.glob("testssl_py_*.txt"):
        p.unlink(missing_ok=True)
    for p in outdir.glob("wpscan_*.txt"):
        p.unlink(missing_ok=True)
    # STEP 1: TLS check (testssl or Python fallback) — sequential to keep RAM low
    if testssl_jobs:
        await run_parallel(testssl_jobs, outdir)
    # STEP 2: WordPress scan — after TLS check freed RAM
    if wpscan_jobs:
        await run_parallel(wpscan_jobs, outdir)
    n = merge_unique(
        list(outdir.glob("testssl_*.txt")) + list(outdir.glob("testssl_py_*.txt")) + list(outdir.glob("wpscan_*.txt")),
        outdir / "tls_wp.txt",
    )
    # Strip proxychains noise lines that pollute tool output
    tls_wp = outdir / "tls_wp.txt"
    if tls_wp.exists():
        clean = [ln for ln in read_lines(tls_wp) if not ln.startswith("[proxychains]")]
        if len(clean) != n:
            tls_wp.write_text("\n".join(clean) + "\n")
            n = len(clean)
    tls_script.unlink(missing_ok=True)
    return {"10-TLSCMS": str(tls_wp), "count": n}

async def phase_13_OOB(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, oast: Interactsh, force: bool = False) -> Dict[str, Any]:
    if skip & {"13-OOB"}:
        return {}
    _h_out = outdir / "oast" / "callbacks.txt"
    if _h_out.exists() and not force:
        return {"13-OOB": str(_h_out), "count": count_nonblank(_h_out)}
    log("info", "Phase 13-OOB: OAST callback collection")
    out = oast.stop()
    n = count_nonblank(out)
    if n:
        log("ok", f"13-OOB: {n} OOB callback(s) captured")
    else:
        log("info", "13-OOB: no OOB callbacks captured")
    return {"13-OOB": str(out), "count": n}

async def phase_68_DEPCVE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"68-DEPCVE"}:
        return {}
    _out = outdir / "dep_cve.txt"
    if _out.exists() and not force:
        return {"68-DEPCVE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 68-DEPCVE: dependency CVE scanning")
    findings: List[str] = []
    js_urls = outdir / "urls_js.txt"
    urls_all = outdir / "urls_all.txt"

    deps_found: Dict[str, str] = {}
    for src in [js_urls, urls_all]:
        if not src.exists():
            continue
        for u in read_lines(src):
            if not u.strip():
                continue
            path = u.split("?")[0].split("#")[0].lower()
            parts = path.rstrip("/").split("/")
            for i, p in enumerate(parts):
                if p in ("node_modules", "vendor", "lib", "components", "bower_components") and i + 1 < len(parts):
                    pkg = parts[i + 1]
                    if pkg.startswith("@") and i + 2 < len(parts):
                        pkg = f"{pkg}/{parts[i + 2]}"
                        ver_offset = i + 3
                    else:
                        ver_offset = i + 2
                    ver = ""
                    if ver_offset < len(parts) and parts[ver_offset].startswith(("@", "v")):
                        ver = parts[ver_offset]
                    elif ver_offset < len(parts):
                        ver = parts[ver_offset]
                    if pkg and pkg not in deps_found:
                        deps_found[pkg] = ver
            # Check for version strings in filename
            m = re.search(r'[./]([^./]+)[.-](\d+\.\d+\.\d+)[./]', path)
            if m:
                pkg = m.group(1)
                ver = m.group(2)
                if pkg and pkg not in deps_found:
                    deps_found[pkg] = ver

    known_vulns = {
        "jquery": (">=3.0.0", "CVE-2020-11023 (XSS) fixed in 3.5.0"),
        "lodash": (">=4.17.21", "CVE-2021-23337 (ReDoS) fixed in 4.17.21"),
        "moment": (">=2.29.4", "CVE-2022-24785 (ReDoS) fixed in 2.29.4"),
        "express": (">=4.18.2", "CVE-2022-24999 (qs) fixed in 4.18.0"),
        "underscore": (">=1.13.3", "CVE-2021-23358 (ReDoS) fixed in 1.13.1"),
        "axios": (">=1.6.0", "CVE-2023-45857 (SSRF) fixed in 1.6.0"),
    }

    def _parse_version(v: str):
        parts = []
        for p in v.replace("-", ".").replace("_", ".").split("."):
            try:
                parts.append(int(p))
            except ValueError:
                break
        return tuple(parts)

    for pkg, ver in deps_found.items():
        pkg_lower = pkg.lower()
        for vuln_pkg, (safe_ver, info) in known_vulns.items():
            if vuln_pkg in pkg_lower:
                if ver:
                    detected_tuple = _parse_version(ver)
                    safe_tuple = _parse_version(safe_ver.lstrip(">=v"))
                    if detected_tuple and safe_tuple and detected_tuple >= safe_tuple:
                        continue
                    findings.append(f"[dep-cve] {pkg}@{ver} — {info}")
                else:
                    findings.append(f"[dep-cve] {pkg} (version unknown) — {info}")

    if not deps_found:
        findings.append("[dep-cve] No dependencies detected for CVE scanning")

    if not findings:
        findings.append("[dep-cve] Dependencies scanned — no known CVEs found")

    # Try trivy if available
    if t.has("trivy") and (outdir / "urls_all.txt").exists():
        tmp_dir = outdir / ".trivy_scan"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        pkg_json = tmp_dir / "package.json"
        pkg_json.write_text(json.dumps({"name": "scan", "dependencies": deps_found}))
        trivy_out = outdir / "logs" / "trivy_output.txt"
        await _run("trivy-check", ["trivy", "fs", "--quiet", "--format", "json", "--output", str(trivy_out), str(tmp_dir)], 120, outdir)
        if trivy_out.exists() and read_lines(trivy_out):
            findings.append(f"[trivy-results] {trivy_out}")
        for p in tmp_dir.glob("*"):
            p.unlink(missing_ok=True)
        try:
            tmp_dir.rmdir()
        except OSError:
            pass

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"68-DEPCVE: {len(findings)} findings → {out}")
    return {"68-DEPCVE": str(_out), "count": len(findings)}
