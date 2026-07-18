"""Phase 06 and shared JS secret patterns: JS intelligence analysis."""
from reconchain.phases.helpers import *

_JS_SECRET_PATTERNS: List[Tuple[str, str]] = [
    ("firebase", r"AIza[0-9A-Za-z\-_]{35}"),
    ("stripe-live", r"(?:sk|pk)_live_[0-9A-Za-z]{24,}"),
    ("stripe-test", r"(?:sk|pk)_test_[0-9A-Za-z]{24,}"),
    ("github-tok", r"gh[opsu]_[0-9A-Za-z]{36,}"),
    ("aws-key", r"AKIA[0-9A-Z]{16}"),
    ("aws-secret", r"(?i)aws(.{0,20})?(?:secret|key).{0,20}[\"'][0-9a-zA-Z\/+=]{40}[\"']"),
    ("google-oauth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("slack-tok", r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    ("jwt", r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    ("heroku", r"https://api\.heroku\.com"),
    ("graphql", r"(graphql|gql)\s*[=:]\s*[\"']https?://"),
    ("s3-bucket", r"(?:bucket|asset|media|uploads|backup|files|cdn|static)\.(?:s3\.amazonaws\.com|s3-[a-z0-9-]+\.amazonaws\.com)"),
    ("process-env", r"process\.env\.(?:SECRET|TOKEN|KEY|PASSWORD|API_KEY|ACCESS_KEY|SECRET_KEY)"),
    ("json-secret-key", r"""(?i)(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["'`][A-Za-z0-9_\-/=+]{16,}["'`]"""),
    (
        "internal-ip",
        r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
    ),
    (
        "internal-host",
        r"(?i)(?:internal|private|staging|dev|jenkins|gitlab|jira|confluence)\.(?:com|local|internal|corp)",
    ),
]
_SOURCE_MAP_RE = re.compile(r'(?://#\s*sourceMappingURL=|sourceMappingURL=)([^\s"\']+)', re.IGNORECASE)


async def phase_06_JSINTEL(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, domain: str = "", force: bool = False) -> Dict[str, Any]:
    if skip & {"06-JSINTEL"}:
        return {}
    if only and "06-JSINTEL" not in only:
        return {}
    _c2_out = outdir / "js_secrets.txt"
    if _c2_out.exists() and not force:
        return {"06-JSINTEL": str(_c2_out), "count": count_nonblank(_c2_out)}
    log("info", "Phase 06-JSINTEL: JS analysis (SecretFinder + nuclei)")
    urls = outdir / "urls_all.txt"
    js_urls = outdir / "urls_js.txt"
    map_urls = outdir / "urls_sourcemap.txt"
    xnlink_out = outdir / "urls_xnlink.txt"
    if urls.exists():
        keep_js: List[str] = []
        keep_map: List[str] = []
        seen_js: Set[str] = set()
        seen_map: Set[str] = set()
        for u in read_lines(urls):
            path = u.split("?", 1)[0].split("#", 1)[0].lower()
            if path.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
                if u not in seen_js:
                    seen_js.add(u)
                    keep_js.append(u)
            if path.endswith(".map") and u not in seen_map:
                seen_map.add(u)
                keep_map.append(u)
        if keep_js:
            ensure(js_urls).write_text("\n".join(keep_js) + "\n")
            log("ok", f"06-JSINTEL: collected {len(keep_js)} JS/TS URLs")
        if keep_map:
            ensure(map_urls).write_text("\n".join(keep_map) + "\n")
            log("ok", f"06-JSINTEL: collected {len(keep_map)} source-map URLs")
    if not js_urls.exists() or not read_lines(js_urls):
        log("info", "06-JSINTEL: no JS URLs found; skipping")
        ensure(outdir / "js_secrets.txt").write_text("")
        return {"06-JSINTEL": str(outdir / "js_secrets.txt"), "count": 0}
    _js_input = js_urls
    if _USE_PROXYCHAINS:
        js_lines = read_lines(js_urls)
        if len(js_lines) > 100:
            sampled = js_lines[:100]
            _js_input = outdir / "urls_js_sample.txt"
            ensure(_js_input).write_text("\n".join(sampled) + "\n")
            log("info", f"06-JSINTEL: downsampled {len(js_lines)} JS URLs to {len(sampled)} for slow network")

    jobs: List[Tuple[str, List[str], int]] = []
    if t.has("secretfinder"):
        runner = outdir / "logs" / "secretfinder_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'secrets.txt'))}\n"
            f"IN={shlex.quote(str(_js_input))}\n"
            ': > "$OUT"\n'
            'TMPDIR=$(mktemp -d) || exit 1\n'
            'trap "rm -rf \'$TMPDIR\'" EXIT\n'
            'export TMPDIR\n'
            'xargs -r -P 2 -I{} sh -c '
            '\'echo "[06-JSINTEL] secretfinder $1" >&2; '
              'timeout 120 secretfinder -i "$1" -o cli > '
             '"$TMPDIR/$(echo "$1" | md5sum | cut -d" " -f1).txt"\' _ {} < "$IN"\n'
             'cat "$TMPDIR"/*.txt >> "$OUT" || true\n'
        )
        runner.chmod(0o700)
        jobs.append(("secretfinder", ["bash", str(runner)], _maybe_timeout(3600)))

    if t.has("nuclei"):
        _nuc_proxy = []
        if _PIPELINE_CFG.proxy:
            _nuc_proxy = ["-proxy", _PIPELINE_CFG.proxy]
        _nuc_exposure_input = _js_input
        _nuc_js_lines = read_lines(_js_input) if _js_input.exists() else []
        _nuc_cap = 20 if _USE_PROXYCHAINS or (
            _PIPELINE_CFG.proxy and _PIPELINE_CFG.proxy.startswith(("socks4", "socks5"))
        ) else 50
        if len(_nuc_js_lines) > _nuc_cap:
            _nuc_exposure_input = outdir / "urls_js_nuclei_sample.txt"
            ensure(_nuc_exposure_input).write_text("\n".join(_nuc_js_lines[:_nuc_cap]) + "\n")
            log("info", f"06-JSINTEL: capped nuclei-exposures input to {_nuc_cap} URLs (from {len(_nuc_js_lines)})")
        jobs.append(
            (
                "nuclei-exposures",
                [
                    "nuclei",
                    "-silent",
                    "-l",
                    str(_nuc_exposure_input),
                    "-t",
                    "http/exposed-panels",
                    "-t",
                    "http/exposures",
                    "-timeout", "30", "-max-host-error", "10",
                    "-o",
                    str(outdir / "nuclei_exposures.txt"),
                ] + _extra_http_args() + _nuc_proxy + _rate_limit_args("nuclei"),
                min(_maybe_timeout(900), 1800),
            )
        )
    if t.has("xnLinkFinder"):
        jobs.append(
            (
                "xnlinkfinder",
                [
                    "xnLinkFinder",
                    "-i", str(_js_input),
                    "-o", str(xnlink_out),
                    "-sf", domain,
                    "-d", "1",
                    "-p", "10",
                    "-t", "30",
                    "-inc",
                    "-nb",
                    "-ow",
                ] + _extra_http_args(),
                _maybe_timeout(1800),
            )
        )
    if jobs:
        await run_parallel(jobs, outdir)
    secrets_file = outdir / "secrets.txt"
    if secrets_file.exists() and read_lines(secrets_file):
        filtered: List[str] = []
        fp_placeholder = re.compile(
            r'(?i)^0{8}-0{4}-0{4}-0{4}-0{12}$'
            r'|^f{8}-f{4}-f{4}-f{4}-f{12}$'
            r'|^D27CDB6E-AE6D-11cf-96B8-444553540000$'
            r'|^[0]+$|^[f]+$|^-?1+$'
        )
        fp_month_patterns = re.compile(
            r'(?i)(january|february|march|april|may|june|july|august|september|october|november|december'
            r'|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec'
            r'|apple-mobile-web-app|getGlobalThis|classCallCheck|defineProperty|setPrototypeOf'
            r'|toPropertyKey|possibleConstructorReturn|assertThisInitialized)'
        )
        for ln in read_lines(secrets_file):
            parts = ln.split("\t->\t", 1)
            if len(parts) == 2:
                secret_value = parts[1].strip().strip('"').strip("'")
                if fp_placeholder.search(secret_value):
                    continue
                if len(secret_value) < 16 and fp_month_patterns.search(secret_value):
                    continue
                if len(secret_value) < 16 and " " not in secret_value and "_" not in secret_value:
                    continue
            filtered.append(ln)
        if len(filtered) < len(read_lines(secrets_file)):
            log("info", f"06-JSINTEL: filtered {len(read_lines(secrets_file)) - len(filtered)} SecretFinder false positives")
            secrets_file.write_text("\n".join(filtered) + ("\n" if filtered else ""))
    if xnlink_out.exists() and read_lines(xnlink_out):
        merge_unique(
            [xnlink_out],
            outdir / "urls_all.txt",
        )
    json_urls = outdir / "urls_json.txt"
    json_keep: List[str] = []
    json_seen: Set[str] = set()
    for src in [xnlink_out, outdir / "secrets.txt"]:
        if src and src.exists():
            for u in read_lines(src):
                path = u.split("?", 1)[0].split("#", 1)[0].lower()
                if path.endswith(".json") and u not in json_seen:
                    json_seen.add(u)
                    json_keep.append(u)
    if urls.exists():
        for u in read_lines(urls):
            path = u.split("?", 1)[0].split("#", 1)[0].lower()
            if path.endswith(".json") and u not in json_seen:
                json_seen.add(u)
                json_keep.append(u)
    if json_keep:
        ensure(json_urls).write_text("\n".join(json_keep) + "\n")
        log("ok", f"06-JSINTEL: collected {len(json_keep)} JSON API endpoints")
    if json_urls.exists() and read_lines(json_urls):
        merge_unique(
            [json_urls],
            outdir / "urls_all.txt",
        )
    n = merge_unique(
        [outdir / "secrets.txt", outdir / "nuclei_exposures.txt"],
        outdir / "js_secrets.txt",
    )
    if n == 0:
        log("warn", "06-JSINTEL: no JS findings produced")
        ensure(outdir / "js_secrets.txt").write_text("")
    return {"06-JSINTEL": str(outdir / "js_secrets.txt"), "count": n}
