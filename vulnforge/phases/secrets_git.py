"""Secrets, git exposure, and secret rotation phases."""

from vulnforge.phases.helpers import (
    _PIPELINE_CFG,
    Any,
    Dict,
    List,
    Path,
    PhaseSet,
    Set,
    Tools,
    Tuple,
    _async_urlopen,
    _extra_headers_dict,
    _get_no_redirect_urlopener,
    _get_urlopener,
    _run,
    _safe_name,
    asyncio,
    count_nonblank,
    ensure,
    hashlib,
    json,
    log,
    math,
    merge_unique,
    os,
    re,
    read_lines,
    run_parallel,
    safe_suffix,
    shlex,
    urllib,
)
from vulnforge.phases.recon import _JS_SECRET_PATTERNS, _SOURCE_MAP_RE


async def phase_15_SECRETS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False
) -> Dict[str, Any]:
    if skip & {"15-SECRETS"}:
        return {}
    _k_out = outdir / "js_secrets_deep.txt"
    if _k_out.exists() and not force:
        return {"15-SECRETS": str(_k_out), "count": count_nonblank(_k_out)}
    log("info", "Phase 15-SECRETS: deep JS secret scanning (custom regex + entropy + source maps)")
    _k_extra_headers = _extra_headers_dict()
    _k_urlopen = _get_urlopener()
    js_urls = outdir / "urls_js.txt"
    if not js_urls.exists() or not read_lines(js_urls):
        await asyncio.sleep(3)
    if not js_urls.exists() or not read_lines(js_urls):
        log("info", "15-SECRETS: no JS URLs; skipping")
        return {"15-SECRETS": str(outdir / "js_secrets_deep.txt"), "count": 0}
    findings: List[str] = []
    seen_secrets: Set[str] = set()
    seen_sourcemaps: Set[str] = set()
    # unfurl URL component extraction from JS URLs (extracts paths, keys, values)
    if t.has("unfurl"):
        unfurl_out = outdir / "unfurled_urls.txt"
        runner = outdir / "logs" / "unfurl_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(js_urls))}\n"
            f"OUT={shlex.quote(str(unfurl_out))}\n"
            'cat "$IN" | unfurl paths >> "$OUT" 2>/dev/null\n'
            'cat "$IN" | unfurl keys >> "$OUT" 2>/dev/null\n'
            'cat "$IN" | unfurl values >> "$OUT"\n'
        )
        runner.chmod(0o700)
        unfurl_jobs: List[Tuple[str, List[str], int]] = []
        unfurl_jobs.append(("unfurl", ["bash", str(runner)], 300))
        await run_parallel(unfurl_jobs, outdir)
        if unfurl_out.exists() and read_lines(unfurl_out):
            deduped = set(read_lines(unfurl_out))
            unfurl_out.write_text("\n".join(sorted(deduped)) + "\n")
            merge_unique(
                [outdir / "urls_all.txt", unfurl_out],
                outdir / "urls_all.txt",
            )
    for js_url in read_lines(js_urls):
        try:
            _k_hdr = {"User-Agent": "Mozilla/5.0"}
            _k_hdr.update(_k_extra_headers)
            req = urllib.request.Request(js_url, headers=_k_hdr)
            _, _, body_bytes = await _async_urlopen(_k_urlopen, req, timeout=15)
            body = body_bytes.decode("utf-8", errors="ignore")
        except Exception:
            continue
        # Save raw JS file for gitleaks scanning
        js_raw = ensure(outdir / f"js_raw_{safe_suffix(js_url)}.js")
        js_raw.write_text(body)
        # Custom regex patterns
        for name, pattern in _JS_SECRET_PATTERNS:
            for m in re.finditer(pattern, body):
                val = m.group()
                if val not in seen_secrets:
                    seen_secrets.add(val)
                    findings.append(f"[{name}] {val}  ({js_url})")
        # Shannon-entropy scan for high-entropy strings (likely API keys /
        # secrets not caught by regex). Look for base64-ish strings of 32+ chars.
        for m in re.finditer(r"[\"']([A-Za-z0-9+/=_-]{32,})[\"']", body):
            val = m.group(1)
            if val in seen_secrets:
                continue
            # Shannon entropy > 4.5 suggests random-looking secret
            freq: Dict[str, int] = {}
            for c in val:
                freq[c] = freq.get(c, 0) + 1
            entropy = 0.0
            for count in freq.values():
                prob = count / len(val)
                entropy -= prob * math.log2(prob)
            if entropy > 4.5:
                seen_secrets.add(val)
                findings.append(f"[high-entropy] {val[:60]}… (entropy={entropy:.2f})  ({js_url})")
        # API key live validation - check if keys are functional
        for name, pattern in _JS_SECRET_PATTERNS:
            if name in ("github-tok", "aws-key", "stripe-live"):
                for m in re.finditer(pattern, body):
                    val = m.group()
                    if val in seen_secrets:
                        continue
                    if name == "github-tok" and val.startswith("gh"):
                        try:
                            import urllib.request as _ur
                            gh_req = urllib.request.Request(
                                "https://api.github.com/user",
                                headers={"Authorization": f"Bearer {val}", "User-Agent": "vulnforge"},
                            )
                            try:
                                gh_resp = _ur.urlopen(gh_req, timeout=5)
                                if gh_resp.status == 200:
                                    findings.append(f"[github-key-live] {val[:16]}... — active GitHub token ({js_url})")
                            except Exception:
                                pass
                        except Exception:
                            pass
        # Firebase database URL detection
        for fb_match in re.finditer(r"https?://[a-zA-Z0-9_-]+\.firebaseio\.com", body):
            fb_url = fb_match.group()
            if fb_url not in seen_secrets:
                seen_secrets.add(fb_url)
                findings.append(f"[firebase-db] {fb_url} ({js_url})")
                try:
                    fb_req = urllib.request.Request(
                        fb_url + "/.json",
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    try:
                        fb_resp = _ur.urlopen(fb_req, timeout=5)
                        fb_data = fb_resp.read().decode("utf-8", errors="ignore")
                        if fb_data and fb_data != "null":
                            findings.append(f"[firebase-open] {fb_url}/.json — database is publicly readable!")
                            findings.append(f"  data: {fb_data[:200]}")
                    except urllib.error.HTTPError as fb_err:
                        if fb_err.code == 401:
                            findings.append(f"[firebase-restricted] {fb_url}/.json — requires auth (401)")
                    except Exception:
                        pass
                except Exception:
                    pass
        # Source maps
        for m in _SOURCE_MAP_RE.finditer(body):
            sm_url = m.group(1)
            if not sm_url.startswith("http"):
                base = js_url.rsplit("/", 1)[0]
                sm_url = base.rstrip("/") + "/" + sm_url.lstrip("/")
            sm_entry = f"[sourcemap] {sm_url}  ({js_url})"
            if sm_url in seen_sourcemaps:
                continue
            seen_sourcemaps.add(sm_url)
            findings.append(sm_entry)
            try:
                _k_sm_hdr = {"User-Agent": "Mozilla/5.0"}
                _k_sm_hdr.update(_k_extra_headers)
                sm_req = urllib.request.Request(sm_url, headers=_k_sm_hdr)
                _, _, sm_body_bytes = await _async_urlopen(_k_urlopen, sm_req, timeout=15)
                sm_body = sm_body_bytes.decode("utf-8", errors="ignore")
                sm_data = json.loads(sm_body)
                sources = sm_data.get("sources") or []
                for src in sources:
                    if isinstance(src, str):
                        for name2, pattern2 in _JS_SECRET_PATTERNS:
                            for m2 in re.finditer(pattern2, src):
                                val2 = m2.group()
                                if val2 not in seen_secrets:
                                    seen_secrets.add(val2)
                                    findings.append(f"  [sourcemap-{name2}] {val2}")
            except Exception:
                continue
    # gitleaks scan on downloaded JS files for secret patterns
    # trufflehog scan on downloaded JS files
    if t.has("trufflehog"):
        if list(outdir.glob("js_raw_*.js")):
            truffle_jobs: List[Tuple[str, List[str], int]] = []
            for jf in sorted(outdir.glob("js_raw_*.js")):
                truffle_out = outdir / f"trufflehog_{safe_suffix(jf.name)}.txt"
                truffle_runner = outdir / "logs" / f"trufflehog_{safe_suffix(jf.name)}.sh"
                ensure(truffle_runner)
                truffle_runner.write_text(
                    "#!/usr/bin/env bash\n"
                    "set -eu\n"
                    f"IN={shlex.quote(str(jf))}\n"
                    f"OUT={shlex.quote(str(truffle_out))}\n"
                    'trufflehog filesystem "$IN" --no-verification --no-update > "$OUT"\n'
                )
                truffle_runner.chmod(0o700)
                truffle_jobs.append(
                    (
                        f"trufflehog-{safe_suffix(jf.name)[:16]}",
                        ["bash", str(truffle_runner)],
                        300,
                    )
                )
            if truffle_jobs:
                await run_parallel(truffle_jobs, outdir)
                for tfp in sorted(outdir.glob("trufflehog_*.txt")):
                    if tfp.exists() and read_lines(tfp):
                        for ln in read_lines(tfp):
                            findings.append(f"  [trufflehog] {ln}")
    if t.has("gitleaks"):
        if list(outdir.glob("js_raw_*.js")):
            gitleaks_jobs: List[Tuple[str, List[str], int]] = []
            for jf in sorted(outdir.glob("js_raw_*.js")):
                safe = safe_suffix(jf.name)
                gl_out = outdir / f"gitleaks_{safe}.json"
                gitleaks_jobs.append(
                    (
                        f"gitleaks-{safe[:16]}",
                        [
                            "gitleaks",
                            "detect",
                            "--source",
                            str(jf),
                            "--report-format",
                            "json",
                            "--report-path",
                            str(gl_out),
                            "--no-git",
                            "-v",
                        ],
                        300,
                    )
                )
            if gitleaks_jobs:
                await run_parallel(gitleaks_jobs, outdir)
                for glp in sorted(outdir.glob("gitleaks_*.json")):
                    try:
                        gl_data = json.loads(glp.read_text(encoding="utf-8", errors="ignore"))
                        if isinstance(gl_data, list):
                            for item in gl_data:
                                desc = item.get("description", "secret")
                                fname = item.get("file", "")
                                line = item.get("startLine", "")
                                match = item.get("match", "")[:80]
                                findings.append(f"  [gitleaks] {desc} in {fname}:{line} {match}")
                        elif isinstance(gl_data, dict) and gl_data.get("Findings"):
                            for item in gl_data["Findings"]:
                                findings.append(
                                    f"  [gitleaks] {item.get('Description', 'secret')} "
                                    f"in {item.get('File', '')}:{item.get('StartLine', '')} "
                                    f"{item.get('Match', '')[:80]}"
                                )
                    except (json.JSONDecodeError, ValueError):
                        continue
    out = ensure(outdir / "js_secrets_deep.txt")
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    # Clean up raw JS and intermediate gitleaks files
    for entry in outdir.glob("js_raw_*.js"):
        entry.unlink(missing_ok=True)
    for entry in outdir.glob("gitleaks_*.json"):
        entry.unlink(missing_ok=True)
    for entry in outdir.glob("trufflehog_*.txt"):
        entry.unlink(missing_ok=True)
    log("ok", f"15-SECRETS: {len(findings)} deep JS findings → {out}")
    # Push found credentials into the shared credential queue for downstream phases
    cred_patterns = re.compile(
        r"(?i)(api[_-]?key|secret|token|password|jwt|bearer|auth)", re.IGNORECASE
    )
    for finding in findings:
        if cred_patterns.search(finding):
            _PIPELINE_CFG.credentials_queue.append(finding)
    if _PIPELINE_CFG.credentials_queue:
        log(
            "info",
            f"15-SECRETS: {len(_PIPELINE_CFG.credentials_queue)} potential credentials added to testing queue",
        )
    return {"15-SECRETS": str(out), "count": len(findings)}


_GIT_PATHS = [
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.git/",
    "/git/config",
    "/.svn/entries",
]
_GIT_COMMON_REFS = [
    "refs/heads/master",
    "refs/heads/main",
    "refs/heads/dev",
    "refs/heads/develop",
]


async def phase_19_GIT(
    domain: str,
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"19-GIT"}:
        return {}
    _n_out = outdir / "git_exposure.txt"
    if _n_out.exists() and not force:
        return {"19-GIT": str(_n_out), "count": count_nonblank(_n_out)}
    log("info", "Phase 19-GIT: git exposure scanning")
    findings: List[str] = []
    _n_urlopen = _get_urlopener()
    # Collect targets: HTTP hosts from 04-SCAN or raw resolved hosts
    targets: List[str] = []
    hosts_file = Path(prev.get("04-SCAN.targets") or outdir / "host_targets.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("04-SCAN.hosts") or outdir / "hosts.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
    if hosts_file.exists():
        for h in read_lines(hosts_file)[: _PIPELINE_CFG.sample_hosts_git]:
            if not h.startswith("http"):
                h = f"https://{h}"
            targets.append(h.rstrip("/"))
    if not targets:
        log("warn", "Phase 19-GIT: no HTTP targets; skipping")
        return {"19-GIT": str(_n_out), "count": 0}
    # Check for exposed .git directories (use no-redirect to avoid false positives)
    _no_redirect_urlopen = _get_no_redirect_urlopener()

    async def _check_git(url: str) -> List[str]:
        results: List[str] = []
        for git_path in _GIT_PATHS:
            test_url = f"{url}{git_path}"
            try:
                req = urllib.request.Request(
                    test_url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"}
                )
                git_status, _, _ = await _async_urlopen(_no_redirect_urlopen, req, timeout=10)
                if git_status == 200:
                    results.append(f"[.git-exposed] {test_url} (HTTP {git_status})")
                    break
            except urllib.error.HTTPError as e:
                if e.code in (200, 301, 302):
                    results.append(f"[.git-exposed] {test_url} (HTTP {e.code})")
                    break
            except Exception:
                continue
        # Check .gitmodules for submodule URLs
        gm_url = f"{url}/.gitmodules"
        try:
            gm_req = urllib.request.Request(
                gm_url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"}
            )
            gm_status, _, _ = await _async_urlopen(_no_redirect_urlopen, gm_req, timeout=10)
            if gm_status == 200:
                get_req = urllib.request.Request(gm_url, headers={"User-Agent": "Mozilla/5.0"})
                _, _, gm_body = await _async_urlopen(_n_urlopen, get_req, timeout=10)
                results.append(f"[git-submodule-exposed] {gm_url}")
                for line in gm_body.decode("utf-8", errors="ignore").splitlines():
                    if "url = " in line:
                        sub_url = line.split("url = ")[-1].strip()
                        results.append(f"[git-submodule-url] {sub_url}")
        except Exception:
            pass
        # Check .gitignore content
        gi_url = f"{url}/.gitignore"
        try:
            gi_req = urllib.request.Request(gi_url, headers={"User-Agent": "Mozilla/5.0"})
            gi_status, _, gi_body = await _async_urlopen(_no_redirect_urlopen, gi_req, timeout=10)
            if gi_status == 200:
                results.append(f"[gitignore-exposed] {gi_url}")
                gi_text = gi_body.decode("utf-8", errors="ignore")
                for gi_line in gi_text.splitlines()[:20]:
                    gi_line = gi_line.strip()
                    if gi_line and not gi_line.startswith("#"):
                        results.append(f"[gitignore-entry] {gi_line}")
        except Exception:
            pass
        # If .git is exposed, try to download it
        if results and t.has("gitdumper"):
            git_base = url.rstrip("/") + "/.git/"
            dump_dir = outdir / f"git_dump_{safe_suffix(url)}"
            dump_dir.mkdir(parents=True, exist_ok=True)
            await _run(
                f"gitdumper-{_safe_name(url)}",
                ["gitdumper", git_base, str(dump_dir)],
                300,
                outdir,
            )
            if dump_dir.exists() and list(dump_dir.iterdir()):
                results.append(f"[git-dumped] {git_base} → {dump_dir}")
                # Run trufflehog on the dumped repo
                if t.has("trufflehog"):
                    truffle_out = outdir / f"trufflehog_{safe_suffix(url)}.txt"
                    runner = outdir / "logs" / f"trufflehog_{safe_suffix(url)}.sh"
                    ensure(runner)
                    runner.write_text(
                        "#!/usr/bin/env bash\n"
                        "set -eu\n"
                        f"DIR={shlex.quote(str(dump_dir))}\n"
                        f"OUT={shlex.quote(str(truffle_out))}\n"
                        'trufflehog filesystem "$DIR" --no-verification > "$OUT"\n'
                    )
                    runner.chmod(0o700)
                    await _run(
                        f"trufflehog-{_safe_name(url)}",
                        ["bash", str(runner)],
                        600,
                        outdir,
                    )
                    if truffle_out.exists() and read_lines(truffle_out):
                        results.append(f"[trufflehog] secrets found → {truffle_out}")
                # Git Object Recovery — download loose objects from known refs
                for ref in _GIT_COMMON_REFS:
                    ref_url = f"{url}/.git/{ref}"
                    try:
                        ref_req = urllib.request.Request(
                            ref_url, headers={"User-Agent": "Mozilla/5.0"}
                        )
                        ref_status, _, ref_body = await _async_urlopen(
                            _no_redirect_urlopen, ref_req, timeout=10
                        )
                        if ref_status == 200:
                            sha = ref_body.decode("utf-8", errors="ignore").strip()
                            if re.match(r"^[0-9a-f]{40}$", sha):
                                results.append(f"[git-object-recovered] {ref_url} — SHA: {sha}")
                                seen = set()
                                shas_to_try = [sha]
                                for depth in range(4):
                                    next_shas = []
                                    for s in shas_to_try:
                                        if s in seen:
                                            continue
                                        seen.add(s)
                                        obj_url = f"{url}/.git/objects/{s[:2]}/{s[2:]}"
                                        try:
                                            obj_req = urllib.request.Request(
                                                obj_url, headers={"User-Agent": "Mozilla/5.0"}
                                            )
                                            obj_status, _, obj_body = await _async_urlopen(
                                                _no_redirect_urlopen, obj_req, timeout=10
                                            )
                                            if obj_status == 200:
                                                results.append(
                                                    f"[git-object-recovered] {obj_url} — SHA: {s}"
                                                )
                                                obj_text = obj_body.decode("utf-8", errors="ignore")
                                                for pm in re.finditer(
                                                    r"parent ([0-9a-f]{40})", obj_text
                                                ):
                                                    parent_sha = pm.group(1)
                                                    if parent_sha not in seen:
                                                        next_shas.append(parent_sha)
                                        except Exception:
                                            continue
                                    shas_to_try = next_shas
                    except Exception:
                        continue
        return results

    git_results = await asyncio.gather(*[_check_git(t) for t in targets])
    for gr in git_results:
        findings.extend(gr)
    out = ensure(_n_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"Phase 19-GIT: {len(findings)} git exposure findings → {out}")
    return {"19-GIT": str(out), "count": len(findings)}


async def phase_79_SECRETDIFF(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"79-SECRETDIFF"}:
        return {}
    _out = outdir / "secret_rotation.txt"
    if _out.exists() and not force:
        return {"79-SECRETDIFF": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 79-SECRETDIFF: cross-scan secret rotation detection")
    findings: List[str] = []
    _state_dir = (
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "vulnforge" / "secrets"
    )
    _state_dir.mkdir(parents=True, exist_ok=True)
    _secret_state_file = _state_dir / f"{outdir.name}_secrets.json"
    secret_state: Dict[str, str] = {}
    if _secret_state_file.exists():
        try:
            secret_state = json.loads(
                _secret_state_file.read_text(encoding="utf-8", errors="ignore")
            )
        except (json.JSONDecodeError, ValueError):
            secret_state = {}
    current_secrets: Dict[str, str] = {}
    for src_file in [
        outdir / "js_secrets.txt",
        outdir / "js_secrets_deep.txt",
        outdir / "domain_creds.txt",
        outdir / "secrets.txt",
    ]:
        if src_file.exists():
            for ln in read_lines(src_file):
                if "=" in ln:
                    k, v = ln.split("=", 1)
                    k = k.strip()[:60]
                    v_fp = hashlib.md5(v.strip().encode()).hexdigest()[:16]
                    current_secrets[k] = v_fp
    for key, old_hash in secret_state.items():
        if key not in current_secrets:
            findings.append(f"[removed] {key} — secret no longer present (may have been rotated)")
        elif current_secrets[key] != old_hash:
            findings.append(
                f"[rotated] {key} — value changed (old_hash={old_hash} new_hash={current_secrets[key]})"
            )
    for key in current_secrets:
        if key not in secret_state:
            findings.append(f"[new] {key} — new secret detected (hash={current_secrets[key]})")
    if not findings:
        findings.append("[result] No secret rotation detected (baseline scan)")
    _secret_state_file.write_text(json.dumps(current_secrets, indent=2))
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"79-SECRETDIFF: {len(findings)} secret rotation findings → {out}")
    return {"79-SECRETDIFF": str(_out), "count": len(findings)}
