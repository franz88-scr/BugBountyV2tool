"""Phases 04 and 04b: port scanning, HTTP probing, takeover detection and validation."""
from reconchain.phases.helpers import *


async def phase_04_SCAN(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"04-SCAN"}:
        return {}
    if only and "04-SCAN" not in only:
        return {}
    if all(
        (outdir / f).exists()
        for f in ("ports.txt", "hosts.txt", "host_targets.txt", "takeover.txt")
    ) and not force:
        ports_file = outdir / "ports.txt"
        return {
            "04-SCAN.ports": str(ports_file),
            "04-SCAN.hosts": str(outdir / "hosts.txt"),
            "04-SCAN.targets": str(outdir / "host_targets.txt"),
            "04-SCAN.takeover": str(outdir / "takeover.txt"),
            "count": count_nonblank(ports_file),
        }
    log("info", "Phase 04-SCAN: ports / hosts / takeover (sequential)")
    hosts = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
    subs = Path(prev.get("01-RECON") or outdir / "all_subs.txt")
    ports_file = outdir / "ports.txt"
    have_hosts = hosts.exists() and bool(read_lines(hosts))
    have_subs = subs.exists() and bool(read_lines(subs))
    if not have_hosts and not have_subs:
        for _ in range(240):
            await asyncio.sleep(5)
            have_hosts = hosts.exists() and bool(read_lines(hosts))
            have_subs = subs.exists() and bool(read_lines(subs))
            if have_hosts or have_subs:
                break
        if not have_hosts and not have_subs:
            log("warn", "04-SCAN: no host or subdomain input; skipping")
            return _existing_artifacts({
                "04-SCAN.ports": str(ports_file),
                "04-SCAN.hosts": str(outdir / "hosts.txt"),
                "04-SCAN.targets": str(outdir / "host_targets.txt"),
                "04-SCAN.takeover": str(outdir / "takeover.txt"),
            })
    # STEP 1: Port scan
    if have_hosts and t.has("naabu"):
        await run_parallel([(
            "naabu",
            ["naabu", "-silent", "-l", str(hosts), "-o", str(ports_file), "-top-ports", "1000"],
            _maybe_timeout(1800),
        )], outdir)
    elif have_hosts and t.has("nmap"):
        _nmap_timing = ["-T3", "--max-retries", "1"] if _PIPELINE_CFG.safe_mode else []
        _nmap_cmd = ["nmap", "-iL", str(hosts), "-Pn", "--top-ports", "1000", "--open",
                     "--script=http-enum", "-oG", str(outdir / "ports.gnmap")] + _nmap_timing
        await run_parallel([("nmap", _nmap_cmd, _maybe_timeout(1800))], outdir)
    # STEP 2: HTTP probe
    if have_hosts and t.has("httpx"):
        _httpx_proxy = []
        if _PIPELINE_CFG.proxy:
            _httpx_proxy = ["-proxy", _PIPELINE_CFG.proxy]
        await run_parallel([(
            "httpx",
             [
                "httpx",
                "-silent",
                "-l",
                str(hosts),
                "-o",
                str(outdir / "hosts.txt"),
                "-title",
                "-tech-detect",
                "-status-code",
                "-follow-redirects",
            ] + _extra_http_args() + _httpx_proxy + _rate_limit_args("httpx"),
            1800,
        )], outdir)
    elif have_hosts and t.has("httprobe"):
        httprobe_out = outdir / "hosts_httprobe.txt"
        httprobe_runner = outdir / "logs" / "httprobe_runner.sh"
        ensure(httprobe_runner)
        _httprobe_conc = "50"
        _httprobe_rl = _rate_limit_args("httprobe")
        if _httprobe_rl:
            for i, a in enumerate(_httprobe_rl):
                if a == "-c" and i + 1 < len(_httprobe_rl):
                    _httprobe_conc = _httprobe_rl[i + 1]
        httprobe_runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"INPUT={shlex.quote(str(hosts))}\n"
            f"OUTPUT={shlex.quote(str(httprobe_out))}\n"
            f'cat "$INPUT" | httprobe -c {_httprobe_conc} -t 3000 > "$OUTPUT"\n'
        )
        httprobe_runner.chmod(0o700)
        await run_parallel([(
            "httprobe",
            ["bash", str(httprobe_runner)],
            600,
        )], outdir)
    # STEP 3: Nuclei templates update
    if t.has("nuclei"):
        await _update_nuclei_templates(outdir)
    # STEP 4: Takeover detection
    if t.has("nuclei") and have_subs:
        _nuc_proxy = []
        if _PIPELINE_CFG.proxy:
            _nuc_proxy = ["-proxy", _PIPELINE_CFG.proxy]
        await run_parallel([(
            "nuclei-dns-takeover",
            [
                "nuclei", "-silent", "-l", str(subs),
                "-t", "dns/", "-tags", "takeover",
                "-timeout", "15", "-max-host-error", "10",
                "-o", str(outdir / "takeover_dns.txt"),
            ] + _nuc_proxy + _rate_limit_args("nuclei"),
            _maybe_timeout(1800),
        )], outdir)
    if have_hosts and t.has("nuclei"):
        _nuc_proxy = []
        if _PIPELINE_CFG.proxy:
            _nuc_proxy = ["-proxy", _PIPELINE_CFG.proxy]
        await run_parallel([(
            "nuclei-takeover",
            [
                "nuclei",
                "-silent",
                "-l",
                str(hosts),
                "-t",
                "http/takeovers",
                "-timeout", "30", "-max-host-error", "10",
                "-o",
                str(outdir / "takeover.txt"),
            ] + _extra_http_args() + _nuc_proxy + _rate_limit_args("nuclei"),
            _maybe_timeout(1800),
        )], outdir)
    # Deduplicate naabu port output
    if ports_file.exists():
        _deduped = sorted(set(read_lines(ports_file)))
        if _deduped:
            ensure(ports_file).write_text("\n".join(_deduped) + "\n")
    # Merge httprobe results
    httprobe_out = outdir / "hosts_httprobe.txt"
    hosts_file_path = outdir / "hosts.txt"
    if httprobe_out.exists() and read_lines(httprobe_out) and hosts_file_path.exists():
        merge_unique([httprobe_out], hosts_file_path)
    # Service version detection
    services_file = outdir / "services.txt"
    if ports_file.exists() and read_lines(ports_file) and t.has("nmap"):
        sv_jobs: List[Tuple[str, List[str], int]] = []
        host_ports: Dict[str, List[str]] = {}
        _live_hosts: Set[str] = set()
        _raw_hosts_file = outdir / "hosts.txt"
        if _raw_hosts_file.exists():
            for _ln in read_lines(_raw_hosts_file):
                if "[404]" not in _ln:
                    _h_match = _ln.split("]")[0].split("//")[-1].strip()
                    if _h_match:
                        _live_hosts.add(_h_match)
        _skipped = 0
        for ln in read_lines(ports_file):
            if ":" in ln:
                h, p = ln.rsplit(":", 1)
                if _live_hosts and h not in _live_hosts:
                    _skipped += 1
                    continue
                host_ports.setdefault(h, []).append(p)
        if _skipped:
            log("info", f"04-SCAN: nmap-sv allowlist: {len(host_ports)} live hosts, skipped {_skipped} wildcard hosts")
        for h, pp in host_ports.items():
            ports_csv = ",".join(pp)
            out_sv = outdir / f"services_{safe_suffix(h)}.gnmap"
            _sv_timing = ["-T3", "--max-retries", "1"] if _PIPELINE_CFG.safe_mode else []
            _sv_cmd = ["nmap", "-Pn", "-sV", "--open",
                       "-p", ports_csv, str(h), "--host-timeout", "10m", "-oG", str(out_sv)] + _sv_timing
            sv_jobs.append((f"nmap-sv-{_safe_name(h)}", _sv_cmd, 600))
        if sv_jobs:
            await run_parallel(sv_jobs, outdir)
            sv_findings: List[str] = []
            for svp in sorted(outdir.glob("services_*.gnmap")):
                for ln in svp.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if ln.startswith("Host:"):
                        sv_findings.append(ln.strip())
            if sv_findings:
                ensure(services_file).write_text("\n".join(sv_findings) + "\n")
                log("ok", f"04-SCAN: {len(sv_findings)} service detections → {services_file}")
            for svp in outdir.glob("services_*.gnmap"):
                svp.unlink(missing_ok=True)
    # Synthesize ports.txt from gnmap if nmap was used
    if not ports_file.exists():
        gnmap = outdir / "ports.gnmap"
        if gnmap.exists():
            ports: Set[str] = set()
            for ln in gnmap.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not ln.startswith("Host:"):
                    continue
                head, _, ports_part = ln.partition("Ports:")
                ip = head.split()[1] if len(head.split()) > 1 else ""
                for entry in ports_part.split(","):
                    bits = entry.strip().split("/")
                    if len(bits) >= 3 and bits[1] == "open":
                        ports.add(f"{ip}:{bits[0]}")
            if ports:
                ensure(ports_file).write_text("\n".join(sorted(ports)) + "\n")
    raw_hosts = outdir / "hosts.txt"
    targets = outdir / "host_targets.txt"
    if raw_hosts.exists() and read_lines(raw_hosts):
        _filtered = outdir / "hosts_active.txt"
        _active_lines = [ln for ln in read_lines(raw_hosts) if "[404]" not in ln]
        if _active_lines:
            ensure(_filtered).write_text("\n".join(_active_lines) + "\n")
            log("info", f"04-SCAN: {len(_active_lines)}/{len(read_lines(raw_hosts))} non-404 hosts for crawling")
            _write_target_tokens(_filtered, targets)
        else:
            _write_target_tokens(raw_hosts, targets)
        _parse_httpx_tech(raw_hosts, outdir / "tech.txt")
    elif have_hosts:
        _write_target_tokens(hosts, targets)
    ensure(outdir / ".phase_04.done")
    return {
        "hosts": str(raw_hosts),
        **_existing_artifacts({
            "04-SCAN.ports": str(ports_file),
            "04-SCAN.hosts": str(raw_hosts),
            "04-SCAN.targets": str(targets),
            "04-SCAN.takeover": str(outdir / "takeover.txt"),
        }),
    }


async def phase_04b_TAKEOVER_VALIDATE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"04b-TAKEOVER-VALIDATE"}:
        return {}
    if only and "04b-TAKEOVER-VALIDATE" not in only:
        return {}
    _out = outdir / "takeover_confirmed.txt"
    if _out.exists() and not force:
        return {"04b-TAKEOVER-VALIDATE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 04b-TAKEOVER-VALIDATE: confirm dangling CNAME takeover candidates")
    findings: List[str] = []
    _tv_urlopen = _get_urlopener()
    _tv_extra_headers = _extra_headers_dict()
    takeover_sources = [
        outdir / "takeover.txt",
        outdir / "takeover_dns.txt",
    ]
    candidates: List[str] = []
    for src in takeover_sources:
        if src.exists():
            for ln in read_lines(src):
                ln = ln.strip()
                if not ln:
                    continue
                url = ln.split()[0] if ln.split() else ln
                if url and (url.startswith("http://") or url.startswith("https://") or "." in url):
                    candidates.append(url)
    candidates = _dedupe_by_host_path(candidates)
    if not candidates:
        log("warn", "04b-TAKEOVER-VALIDATE: no takeover candidates found; skipping")
        return {"04b-TAKEOVER-VALIDATE": str(_out), "count": 0}
    findings.append(f"candidates_found={len(candidates)}")
    for cand in candidates[:_PIPELINE_CFG.sample_urls_fuzz]:
        await _throttle_rate()
        try:
            cand = cand.strip()
            if cand.startswith("http://") or cand.startswith("https://"):
                url = cand
            else:
                url = f"http://{cand}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_tv_extra_headers})
            status, headers, body_bytes = await _async_urlopen(_tv_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore").lower()
            takeover_indicators = [
                "no such bucket", "does not exist", "not found", "repository not found",
                "there is no site", "no such app", "404 blog not found", "please configure",
                "this page is not available", "the page you are looking for is not here",
                "this site is not configured", "account not found", "this user's page",
                "is not currently accepting", "there is nothing here for you",
            ]
            if status == 404 or any(ind in body for ind in takeover_indicators):
                findings.append(f"[confirmed] {cand} → HTTP {status} (likely vulnerable)")
                if "server" in headers:
                    findings.append(f"  server={headers['server']}")
            elif status in (200, 301, 302):
                findings.append(f"[potential] {cand} → HTTP {status} (check manually)")
            else:
                findings.append(f"[checked] {cand} → HTTP {status} (not vulnerable)")
        except Exception as e:
            findings.append(f"[error] {cand} → {e}")
    if not any(f.startswith("[confirmed]") for f in findings):
        findings.append("[result] No confirmed takeover vulnerabilities detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"04b-TAKEOVER-VALIDATE: {len(findings)} findings → {out}")
    return {"04b-TAKEOVER-VALIDATE": str(_out), "count": len(findings)}
