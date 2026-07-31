"""Supply chain security phases — dependency confusion, typo-squatting."""

from vulnforge.phases.helpers import (
    Any,
    Dict,
    List,
    Path,
    PhaseSet,
    Set,
    Tools,
    _async_urlopen,
    _get_urlopener,
    _load_live_hosts,
    _throttle_rate,
    count_nonblank,
    ensure,
    json,
    log,
    re,
    urllib,
)

_DEPENDENCY_FILES = [
    "package.json",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "Cargo.toml",
    "Cargo.lock",
    "yarn.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "nuget.config",
    "packages.config",
    "build.gradle",
    "pom.xml",
    "Podfile",
    "Podfile.lock",
    "pubspec.yaml",
    "mix.exs",
    "rebar.config",
    "Makefile.PL",
    "cpanfile",
    "DESCRIPTION",
]

_POPULAR_NPM_PACKAGES = [
    "lodash",
    "express",
    "axios",
    "react",
    "vue",
    "angular",
    "chalk",
    "commander",
    "moment",
    "debug",
    "uuid",
    "colors",
    "body-parser",
    "cors",
    "request",
    "mkdirp",
    "fs-extra",
    "glob",
    "dotenv",
    "yargs",
    "node-fetch",
    "typeorm",
    "mongoose",
    "socket.io",
    "passport",
]

_POPULAR_PYTHON_PACKAGES = [
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "fastapi",
    "sqlalchemy",
    "pydantic",
    "click",
    "httpx",
    "aiohttp",
    "scrapy",
    "scipy",
    "matplotlib",
    "jupyter",
    "boto3",
    "celery",
    "redis",
    "beautifulsoup4",
    "lxml",
    "pyyaml",
    "tqdm",
    "jinja2",
]


async def _check_public_package_exists(registry_url: str, package_name: str) -> bool:
    try:
        opener = _get_urlopener()
        req = urllib.request.Request(f"{registry_url}/{package_name}", method="HEAD")
        status, _, _ = await _async_urlopen(opener, req, timeout=10)
        return status == 200
    except Exception:
        return False


async def phase_165_DEPCONF(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"165-DEPCONF"}:
        return {}
    _out = outdir / "supplychain_depconf.txt"
    if _out.exists() and not force:
        return {"165-DEPCONF": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 165-DEPCONF: dependency confusion testing")
    findings: List[str] = []
    dependency_urls: List[str] = []
    live_hosts = _load_live_hosts(outdir)
    for h in live_hosts:
        base = h if h.startswith("http") else f"https://{h}"
        for dep_file in _DEPENDENCY_FILES:
            dependency_urls.append(f"{base}/{dep_file}")
            dependency_urls.append(f"{base}/../{dep_file}")
            dependency_urls.append(f"{base}/app/{dep_file}")
            dependency_urls.append(f"{base}/src/{dep_file}")
            dependency_urls.append(f"{base}/vendor/{dep_file}")
    private_packages: Set[str] = set()
    for dep_url in dependency_urls:
        await _throttle_rate()
        try:
            opener_sc = _get_urlopener()
            req_sc = urllib.request.Request(dep_url)
            _, _, data = await _async_urlopen(opener_sc, req_sc, timeout=10)
            if not data:
                continue
            content = data.decode("utf-8", errors="replace")
            findings.append(f"[dep-file-found] {dep_url}")
            if dep_url.endswith("package.json"):
                try:
                    pkg = json.loads(content)
                    for section in ["dependencies", "devDependencies"]:
                        for pkg_name in pkg.get(section, {}):
                            if (
                                not pkg_name.startswith("@")
                                and pkg_name not in _POPULAR_NPM_PACKAGES
                            ):
                                private_packages.add(pkg_name)
                except (json.JSONDecodeError, Exception):
                    pass
            elif dep_url.endswith("requirements.txt"):
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("-"):
                        pkg_name = re.split(r"[=<>!~]", line)[0].strip()
                        if pkg_name and pkg_name not in _POPULAR_PYTHON_PACKAGES:
                            private_packages.add(pkg_name)
            elif dep_url.endswith("go.mod"):
                for line in content.splitlines():
                    m = re.match(r"\s+([a-z0-9./-]+)\s+v", line)
                    if m:
                        pkg_path = m.group(1)
                        if "github.com/" in pkg_path or "gitlab.com/" in pkg_path:
                            org_repo = pkg_path.split("/", 3)
                            if len(org_repo) >= 3:
                                candidate = "/".join(org_repo[:3])
                                if candidate.endswith("/"):
                                    candidate = candidate[:-1]
                                private_packages.add(candidate)
        except Exception:
            continue
    findings.append("")
    findings.append("--- potential dependency confusion candidates ---")
    for pkg in sorted(private_packages)[:30]:
        await _throttle_rate()
        npm_exists = await _check_public_package_exists("https://registry.npmjs.org", pkg)
        if not npm_exists:
            findings.append(f"[npm-confusion] {pkg} → NOT on public npm (confusion risk)")
    findings.append("")
    findings.append(
        f"[summary] {len(private_packages)} private packages found, "
        f"{sum(1 for f in findings if 'npm-confusion' in f)} confusion candidates"
    )
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"165-DEPCONF: {len(findings)} findings → {out}")
    return {"165-DEPCONF": str(_out), "count": len(findings)}


async def phase_166_TYPOSQUAT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"166-TYPOSQUAT"}:
        return {}
    _out = outdir / "supplychain_typosquat.txt"
    if _out.exists() and not force:
        return {"166-TYPOSQUAT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 166-TYPOSQUAT: typo-squatting detection")
    findings: List[str] = []
    known_squats = [
        ("lodahs", "lodash"),
        ("expresss", "express"),
        ("axiox", "axios"),
        ("reqiest", "request"),
        ("colorss", "colors"),
        ("chak", "chalk"),
        ("momen", "moment"),
        ("uuidv4", "uuid"),
        ("debugg", "debug"),
        ("commnder", "commander"),
        ("flask", "flask"),
        ("dajngo", "django"),
        ("requets", "requests"),
        ("numpy", "numpy"),
        ("panadas", "pandas"),
        ("fastapi", "fastapi"),
        ("celerry", "celery"),
        ("solalchemy", "sqlalchemy"),
        ("beautifulsup4", "beautifulsoup4"),
        ("pyyaml", "pyyaml"),
    ]
    live_hosts = _load_live_hosts(outdir)
    dep_urls: List[str] = []
    for h in live_hosts:
        base = h if h.startswith("http") else f"https://{h}"
        for dep_file in _DEPENDENCY_FILES[:10]:
            dep_urls.append(f"{base}/{dep_file}")
            dep_urls.append(f"{base}/../{dep_file}")
    all_packages: Set[str] = set()
    for dep_url in dep_urls:
        await _throttle_rate()
        try:
            opener_sc = _get_urlopener()
            req_sc = urllib.request.Request(dep_url)
            _, _, data = await _async_urlopen(opener_sc, req_sc, timeout=10)
            if not data:
                continue
            content = data.decode("utf-8", errors="replace")
            if dep_url.endswith("package.json"):
                try:
                    pkg = json.loads(content)
                    for section in ["dependencies", "devDependencies"]:
                        all_packages.update(pkg.get(section, {}).keys())
                except (json.JSONDecodeError, Exception):
                    pass
            elif dep_url.endswith("requirements.txt"):
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("-"):
                        pkg_name = re.split(r"[=<>!~]", line)[0].strip()
                        if pkg_name:
                            all_packages.add(pkg_name)
        except Exception:
            continue
    findings.append(f"[packages] Found {len(all_packages)} dependency references")
    findings.append("")
    findings.append("--- known typo-squatting checks ---")
    for pkg in sorted(all_packages):
        for squat, legitimate in known_squats:
            if pkg.lower() == squat:
                findings.append(
                    f"[typo-squat-detected] {pkg} → looks like a typo-squat of '{legitimate}'"
                )
    findings.append("")
    findings.append("--- slightly misspelled packages ---")
    for pkg in sorted(all_packages):
        for squat, legitimate in known_squats:
            if pkg.lower() == legitimate:
                continue
            if len(pkg) >= 4 and len(set(pkg.lower()) & set(legitimate)) >= len(legitimate) - 1:
                findings.append(f"[possible-typo] {pkg} → may be a typo of '{legitimate}'")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"166-TYPOSQUAT: {len(findings)} findings → {out}")
    return {"166-TYPOSQUAT": str(_out), "count": len(findings)}
