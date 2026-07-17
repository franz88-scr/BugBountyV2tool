"""Extended OSINT and discovery phases: email finder, metagoofil, porch pirate, dork hunter, crt.sh, GitHub subs, TLS, analytics, favicon, jsluice, shortscan, grpcurl."""
from reconchain.phases.helpers import *
from reconchain.process import _run_limited


async def phase_137_EMAILFINDER(domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if "137-EMAILFINDER" in skip: return {}
    await _throttle_rate()
    out = ensure(Path(outdir) / "137-EMAILFINDER.txt")
    _urlopen = _get_urlopener()
    emails = set()
    # crt.sh certificate transparency logs
    try:
        crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(crt_url, headers={"User-Agent": "reconchain/2.0"})
        resp = await asyncio.to_thread(_urlopen, req, timeout=30)
        data = json.loads(resp.read().decode("utf-8"))
        for entry in data:
            name = entry.get("name_value", "")
            for part in name.split("\n"):
                part = part.strip().lower()
                if "@" in part and part.endswith(f"@{domain}"):
                    emails.add(part)
    except Exception:
        pass
    # theHarvester-style email search
    email_file = Path(outdir) / "88-EMPLOYEE.txt"
    if email_file.exists():
        for line in email_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip().lower()
            if "@" in line and domain in line:
                emails.add(line)
    # Write results
    out.write_text("\n".join(sorted(emails)) + ("\n" if emails else ""))
    log("ok", f"137-EMAILFINDER: {len(emails)} emails → {out}")
    return {"137-EMAILFINDER": str(out), "count": len(emails)}


# ─── 138-METAGOOFIL ───────────────────────────────────────────────
async def phase_138_METAGOOFIL(domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if "138-METAGOOFIL" in skip: return {}
    await _throttle_rate()
    out = ensure(Path(outdir) / "138-METAGOOFIL.txt")
    meta = set()
    doc_extensions = ["doc", "docx", "pdf", "xls", "xlsx", "ppt", "pptx", "odt", "ods"]
    # Use gau to fetch URLs from the domain, then filter for document extensions
    try:
        cmd = ["gau", domain, "--o", "-", "--threads", "5", "--fc", "404", "--timeout", "15"]
        rc, stdout, _ = await _run_limited(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, timeout=120)
        if stdout:
            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and any(f".{ext}" in line.lower() for ext in doc_extensions):
                    meta.add(line)
    except Exception:
        pass
    out.write_text("\n".join(sorted(meta)) + ("\n" if meta else ""))
    log("ok", f"138-METAGOOFIL: {len(meta)} documents → {out}")
    return {"138-METAGOOFIL": str(out), "count": len(meta)}


# ─── 139-PORCHPIRATE ──────────────────────────────────────────────
async def phase_139_PORCHPIRATE(domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if "139-PORCHPIRATE" in skip: return {}
    await _throttle_rate()
    out = ensure(Path(outdir) / "139-PORCHPIRATE.txt")
    leaks = set()
    # Check for exposed packages/dependencies
    paths_to_check = [
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/Gemfile.lock", "/requirements.txt", "/Pipfile.lock",
        "/composer.lock", "/go.sum", "/Cargo.lock",
        "/pom.xml", "/build.gradle", "/build.gradle.kts",
    ]
    urls_file = Path(outdir) / "hosts.txt"
    urls = []
    if urls_file.exists():
        urls = urls_file.read_text(encoding="utf-8", errors="ignore").splitlines()[:500]
    _p_urlopen = _get_urlopener()
    for base_url in urls:
        base = base_url.rstrip("/")
        for path in paths_to_check:
            try:
                url = base + path
                req = urllib.request.Request(url, headers={"User-Agent": "reconchain/2.0"}, method="HEAD")
                status, _, _ = await _async_urlopen(_p_urlopen, req, timeout=8)
                if status == 200:
                    leaks.add(f"{url} (status={status})")
            except urllib.error.HTTPError as e:
                if e.code == 200:
                    leaks.add(f"{base + path} (status=200)")
            except Exception:
                pass
    out.write_text("\n".join(sorted(leaks)) + ("\n" if leaks else ""))
    log("ok", f"139-PORCHPIRATE: {len(leaks)} leaks → {out}")
    return {"139-PORCHPIRATE": str(out), "count": len(leaks)}


# ─── 140-DORKHUNTER ───────────────────────────────────────────────
async def phase_140_DORKHUNTER(domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if "140-DORKHUNTER" in skip: return {}
    await _throttle_rate()
    out = ensure(Path(outdir) / "140-DORKHUNTER.txt")
    dorks = [
        f'site:{domain} intitle:"index of"',
        f'site:{domain} inurl:admin',
        f'site:{domain} inurl:login',
        f'site:{domain} filetype:env',
        f'site:{domain} inurl:backup',
        f'site:{domain} inurl:config',
        f'site:{domain} filetype:sql',
        f'site:{domain} filetype:log',
        f'site:{domain} "password"',
        f'site:{domain} "confidential"',
    ]
    _d_urlopen = _get_urlopener()
    findings = set()
    for dork in dorks:
        try:
            encoded = urllib.parse.quote(dork)
            url = f"https://www.google.com/search?q={encoded}&num=10"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml",
            })
            resp = await asyncio.to_thread(_d_urlopen, req, timeout=15)
            body = resp.read().decode("utf-8", errors="ignore")
            urls = re.findall(r'href="/url\?q=([^&"]+)', body)
            for found_url in urls:
                if domain in found_url and "google.com" not in found_url:
                    findings.add(f"{dork} → {found_url}")
            await asyncio.sleep(2)  # Rate limit to avoid Google blocks
        except Exception:
            pass
    out.write_text("\n".join(sorted(findings)) + ("\n" if findings else ""))
    log("ok", f"140-DORKHUNTER: {len(findings)} findings → {out}")
    return {"140-DORKHUNTER": str(out), "count": len(findings)}


# ─── 141-CRTSH ────────────────────────────────────────────────────
async def phase_141_CRTSH(domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Any = None, force: bool = False) -> Dict[str, Any]:
    if "141-CRTSH" in skip: return {}
    await _throttle_rate()
    out = ensure(Path(outdir) / "141-CRTSH.txt")
    _c_urlopen = _get_urlopener()
    subs = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "reconchain/2.0"})
        resp = await asyncio.to_thread(_c_urlopen, req, timeout=30)
        data = json.loads(resp.read().decode("utf-8"))
        for entry in data:
            name = entry.get("name_value", "")
            for part in name.split("\n"):
                part = part.strip().lower()
                if part.endswith(f".{domain}") or part == domain:
                    subs.add(part)
    except Exception:
        pass
    out.write_text("\n".join(sorted(subs)) + ("\n" if subs else ""))
    log("ok", f"141-CRTSH: {len(subs)} subdomains → {out}")
    return {"141-CRTSH": str(out), "count": len(subs)}


# ─── 142-GITHUBSUB ────────────────────────────────────────────────
async def phase_142_GITHUBSUB(domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Any = None, force: bool = False) -> Dict[str, Any]:
    if "142-GITHUBSUB" in skip: return {}
    await _throttle_rate()
    out = ensure(Path(outdir) / "142-GITHUBSUB.txt")
    subs = set()
    github_token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "reconchain/2.0"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    _g_urlopen = _get_urlopener()
    queries = [f'"{domain}"', f'domain:{domain}']
    for query in queries:
        try:
            url = f"https://api.github.com/search/code?q={urllib.parse.quote(query)}&per_page=100"
            req = urllib.request.Request(url, headers=headers)
            resp = await asyncio.to_thread(_g_urlopen, req, timeout=30)
            data = json.loads(resp.read().decode("utf-8"))
            for item in data.get("items", []):
                text = item.get("text_matches", [])
                # Parse subdomains from code snippets
                for match in text:
                    fragment = match.get("fragment", "")
                    for word in fragment.split():
                        word = word.strip("\"'`<>,;:()[]{}").lower()
                        if "." in word and domain in word and len(word) < 253:
                            subs.add(word)
        except Exception:
            pass
    out.write_text("\n".join(sorted(subs)) + ("\n" if subs else ""))
    log("ok", f"142-GITHUBSUB: {len(subs)} subdomains → {out}")
    return {"142-GITHUBSUB": str(out), "count": len(subs)}


# ─── 143-TLSX ─────────────────────────────────────────────────────
async def phase_143_TLSX(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Any = None, force: bool = False) -> Dict[str, Any]:
    if "143-TLSX" in skip: return {}
    await _throttle_rate()
    out = ensure(Path(outdir) / "143-TLSX.txt")
    tls_results = set()
    # Read targets
    target_file = Path(outdir) / "hosts.txt"
    targets = []
    if target_file.exists():
        targets = [l.strip() for l in target_file.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()][:200]
    for target in targets:
        try:
            host = target.split("://")[-1].split(":")[0].split("/")[0]
            rc, stdout, _ = await _run_limited(
                ["tlsx", "-host", host, "-silent", "-json"],
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                timeout=30,
            )
            if stdout:
                for line in stdout.decode("utf-8", errors="ignore").splitlines():
                    try:
                        data = json.loads(line)
                        cn = data.get("cn", "")
                        sn = data.get("san", "")
                        if cn or sn:
                            tls_results.add(f"{host}: cn={cn} san={sn}")
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass
    out.write_text("\n".join(sorted(tls_results)) + ("\n" if tls_results else ""))
    log("ok", f"143-TLSX: {len(tls_results)} TLS certs → {out}")
    return {"143-TLSX": str(out), "count": len(tls_results)}


# ─── 144-ANALYTICSRELS ────────────────────────────────────────────
async def phase_144_ANALYTICSRELS(domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Any = None, force: bool = False) -> Dict[str, Any]:
    if "144-ANALYTICSRELS" in skip: return {}
    await _throttle_rate()
    out = ensure(Path(outdir) / "144-ANALYTICSRELS.txt")
    relations = set()
    urls_file = Path(outdir) / "hosts.txt"
    urls = []
    if urls_file.exists():
        urls = urls_file.read_text(encoding="utf-8", errors="ignore").splitlines()[:500]
    _a_urlopen = _get_urlopener()
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "reconchain/2.0"})
            resp = await asyncio.to_thread(_a_urlopen, req, timeout=10)
            body = resp.read().decode("utf-8", errors="ignore")
            ga_ids = re.findall(r'UA-\d{4,}-\d+', body)
            gtm_ids = re.findall(r'GTM-\w+', body)
            for ga in ga_ids:
                relations.add(f"GA: {ga} from {url}")
            for gtm in gtm_ids:
                relations.add(f"GTM: {gtm} from {url}")
        except Exception:
            pass
    out.write_text("\n".join(sorted(relations)) + ("\n" if relations else ""))
    log("ok", f"144-ANALYTICSRELS: {len(relations)} relations → {out}")
    return {"144-ANALYTICSRELS": str(out), "count": len(relations)}


# ─── 145-FAVIRECON ────────────────────────────────────────────────
async def phase_145_FAVIRECON(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Any = None, force: bool = False) -> Dict[str, Any]:
    if "145-FAVIRECON" in skip: return {}
    await _throttle_rate()
    out = ensure(Path(outdir) / "145-FAVIRECON.txt")
    favicons = set()
    urls_file = Path(outdir) / "hosts.txt"
    urls = []
    if urls_file.exists():
        urls = urls_file.read_text(encoding="utf-8", errors="ignore").splitlines()[:500]
    for url in urls:
        base = url.rstrip("/")
        _f_urlopen = _get_urlopener()
        for path in ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"]:
            try:
                fav_url = base + path
                req = urllib.request.Request(fav_url, headers={"User-Agent": "reconchain/2.0"}, method="HEAD")
                status, _, _ = await _async_urlopen(_f_urlopen, req, timeout=8)
                if status == 200:
                    favicons.add(f"{fav_url} (found)")
            except Exception:
                pass
    out.write_text("\n".join(sorted(favicons)) + ("\n" if favicons else ""))
    log("ok", f"145-FAVIRECON: {len(favicons)} favicons → {out}")
    return {"145-FAVIRECON": str(out), "count": len(favicons)}


# ─── 146-JSLUICE ──────────────────────────────────────────────────
async def phase_146_JSLUICE(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Any = None, force: bool = False) -> Dict[str, Any]:
    if "146-JSLUICE" in skip: return {}
    await _throttle_rate()
    out = ensure(Path(outdir) / "146-JSLUICE.txt")
    js_endpoints = set()
    js_file = Path(outdir) / "urls_js.txt"
    js_urls = []
    if js_file.exists():
        js_urls = [l.strip() for l in js_file.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and l.strip().endswith(".js")][:50]
    for js_url in js_urls:
        try:
            rc, stdout, _ = await _run_limited(
                ["jsluice", "urls", js_url],
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                timeout=30,
            )
            if stdout:
                for line in stdout.decode("utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line:
                        js_endpoints.add(line)
        except Exception:
            pass
    out.write_text("\n".join(sorted(js_endpoints)) + ("\n" if js_endpoints else ""))
    log("ok", f"146-JSLUICE: {len(js_endpoints)} endpoints → {out}")
    return {"146-JSLUICE": str(out), "count": len(js_endpoints)}


# ─── 147-SHORTSCAN ────────────────────────────────────────────────
async def phase_147_SHORTSCAN(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Any = None, force: bool = False) -> Dict[str, Any]:
    if "147-SHORTSCAN" in skip: return {}
    await _throttle_rate()
    out = ensure(Path(outdir) / "147-SHORTSCAN.txt")
    shortlinks = set()
    urls_file = Path(outdir) / "hosts.txt"
    urls = []
    if urls_file.exists():
        urls = urls_file.read_text(encoding="utf-8", errors="ignore").splitlines()[:200]
    for url in urls:
        try:
            rc, stdout, _ = await _run_limited(
                ["shortscan", "scan", url, "-o", "-"],
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                timeout=30,
            )
            if stdout:
                for line in stdout.decode("utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line:
                        shortlinks.add(line)
        except Exception:
            pass
    out.write_text("\n".join(sorted(shortlinks)) + ("\n" if shortlinks else ""))
    log("ok", f"147-SHORTSCAN: {len(shortlinks)} shortlinks → {out}")
    return {"147-SHORTSCAN": str(out), "count": len(shortlinks)}


# ─── 148-GRPCURL ──────────────────────────────────────────────────
async def phase_148_GRPCURL(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Any = None, force: bool = False) -> Dict[str, Any]:
    if "148-GRPCURL" in skip: return {}
    await _throttle_rate()
    out = ensure(Path(outdir) / "148-GRPCURL.txt")
    grpc_results = set()
    urls_file = Path(outdir) / "hosts.txt"
    urls = []
    if urls_file.exists():
        urls = urls_file.read_text(encoding="utf-8", errors="ignore").splitlines()[:200]
    for url in urls:
        try:
            host = url.split("://")[-1].split(":")[0].split("/")[0]
            # Try common gRPC ports
            for port in ["50051", "443"]:
                try:
                    target = f"{host}:{port}"
                    rc, stdout, _ = await _run_limited(
                        ["grpcurl", "-plaintext", target, "list"],
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                        timeout=15,
                    )
                    if stdout and rc == 0:
                        grpc_results.add(f"{target}: {stdout.decode().strip()}")
                except Exception:
                    pass
        except Exception:
            pass
    out.write_text("\n".join(sorted(grpc_results)) + ("\n" if grpc_results else ""))
    log("ok", f"148-GRPCURL: {len(grpc_results)} gRPC services → {out}")
    return {"148-GRPCURL": str(out), "count": len(grpc_results)}
