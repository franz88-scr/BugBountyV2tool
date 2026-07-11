"""CLI entry points: build_parser, main, interactive_setup."""
from __future__ import annotations
import argparse
import asyncio
import contextlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, List, Optional, Set

from reconchain.config import __version__, VALID_PHASES
from reconchain.phases import _RECON_LEVELS
from reconchain.pipeline import run_pipeline
from reconchain.process import _parse_phase_csv, MAX_PARALLEL_JOBS
from reconchain.utils import (
    C, log, ScanStatus, _is_valid_hostname, _auto_detect_proxy,
    disable_color,
)


import unicodedata as _unicodedata

def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False

def _clean_input(raw: str) -> str:
    """Strip all Unicode whitespace, zero-width / invisible characters, and control chars."""
    ZERO_WIDTH = dict.fromkeys(range(0x200B, 0x200F + 1))  # zero-width spaces, LRM, RLM
    ZERO_WIDTH.update({0xFEFF: None, 0x00A0: None, 0x2060: None})  # BOM, NBSP, WJ
    cleaned = raw.translate(ZERO_WIDTH)
    # Strip control characters (0x00-0x1F, 0x7F-0x9F) except common whitespace
    CONTROL = dict.fromkeys(i for i in range(0x20) if i not in (0x09, 0x0A, 0x0D))
    CONTROL.update(dict.fromkeys(range(0x7F, 0xA0)))
    cleaned = cleaned.translate(CONTROL)
    cleaned = _unicodedata.normalize("NFKC", cleaned)
    return cleaned.strip()

def _prompt(prompt_text: str, default: str = "", validator: Optional[Callable[[str], bool]] = None, error_msg: str = "", max_retries: int = 20, sensitive: bool = False) -> str:
    import getpass
    import time as _time
    for attempt in range(max_retries):
        if attempt > 0:
            _time.sleep(0.1)  # Small delay to prevent rapid-fire retries
        suffix = f" [{default}]" if default else ""
        if sensitive:
            try:
                val = getpass.getpass(f"  {prompt_text}{suffix}: ")
            except (EOFError, KeyboardInterrupt):
                val = ""
        else:
            val = _clean_input(input(f"  {prompt_text}{suffix}: "))
        if not val:
            if sensitive and default:
                log("warn", "sensitive field returned default value — ensure this is intended")
            return default
        if validator is None or validator(val):
            return val
        log("err", error_msg or "invalid input")
    return default


def _prompt_yes_no(prompt_text: str, default: bool = True) -> bool:
    suffix = " [Y/n]" if default else " [y/N]"
    val = input(f"  {prompt_text}{suffix}: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


def _banner() -> None:
    banner = f"""
{C["c"]}    ██████╗ ██████╗ ████████╗
{C["c"]}    ██╔══██╗██╔══██╗╚══██╔══╝
{C["c"]}    ██████╔╝██████╔╝   ██║
{C["c"]}    ██╔══██╗██╔══██╗   ██║
{C["c"]}    ██████╔╝██████╔╝   ██║
{C["c"]}    ╚═════╝ ╚═════╝    ╚═╝
{C["r"]}
{C["g"]}   ╔══════════════════════════════════════════════════════╗
{C["g"]}   ║  {C["c"]}ReconChain v{__version__}{C["g"]}  —  {C["y"]}Bug Bounty Recon & Vuln Pipeline{C["g"]}   ║
{C["g"]}   ║  {C["d"]}41+ tools  |  152 phases  |  24 DAG stages  |  Resumable{C["g"]}   ║
{C["g"]}   ╚══════════════════════════════════════════════════════╝{C["r"]}
"""
    print(banner, flush=True)


def interactive_setup() -> argparse.Namespace:
    _banner()
    log("info", "Interactive setup — press Ctrl+C anytime to abort\n")
    log("info", "Multi-domain: comma-separated (e.g. example.com,test.org)\n")
    def _multi_domain_validator(v: str) -> bool:
        return all(_is_valid_hostname(d.strip()) for d in v.split(",") if d.strip())
    domain = _prompt("Target domain(s) (e.g. example.com or example.com,test.org)", validator=_multi_domain_validator, error_msg="Enter valid domain(s) with at least one dot each")
    print(f"\n{C['b']}Recon levels:{C['r']}")
    for key, lvl in sorted(_RECON_LEVELS.items()):
        print(f"  {C['y']}{key:4}{C['r']} {lvl['name']}")
        print(f"       {C['d']}{lvl['desc']}{C['r']}")
    level = _prompt("Choose recon level", default="full", validator=lambda v: v in _RECON_LEVELS, error_msg="Enter 1, 2, or full")
    base_phases = _RECON_LEVELS[level]["phases"]
    out = _prompt("Output directory", default=f"./out_{domain}")
    jobs_str = _prompt("Max parallel processes", default=str(MAX_PARALLEL_JOBS), validator=lambda v: v.isdigit() and int(v) > 0, error_msg="Enter a positive number")
    jobs = int(jobs_str)
    print(f"\n{C['b']}Scan depth configuration:{C['r']}")
    sqlmap_level = _prompt("SQLmap --level (1=fast/basic, 5=deep/slow)", default="1", validator=lambda v: v.isdigit() and 1 <= int(v) <= 5, error_msg="Enter a number between 1 and 5")
    sqlmap_risk = _prompt("SQLmap --risk (1=safe, 3=aggressive/destructive)", default="1", validator=lambda v: v.isdigit() and 1 <= int(v) <= 3, error_msg="Enter a number between 1 and 3")
    delay = _prompt("Delay between requests in seconds (0=fast, 2=polite, 5=stealth)", default="0", validator=lambda v: v.replace(".", "", 1).isdigit(), error_msg="Enter a number (e.g. 0, 0.5, 2)")
    _suggested_procs = min(jobs, max(2, (os.cpu_count() or 4) // 2))
    max_procs_str = _prompt(
        f"Max concurrent tool subprocesses (prevents VM crashes, 0=auto)",
        default=str(_suggested_procs),
        validator=lambda v: v.isdigit() and int(v) >= 0,
        error_msg="Enter 0 or a positive number"
    )
    max_procs = int(max_procs_str)
    rate_limit_str = _prompt(
        "Rate limit: max requests/sec per tool (0=unlimited, 5=gentle, 10=polite, 50=fast)",
        default="10",
        validator=lambda v: v.isdigit() and int(v) >= 0,
        error_msg="Enter 0 or a positive number"
    )
    rate_limit = int(rate_limit_str)
    proxy = _prompt("Proxy URL (e.g. socks5://127.0.0.1:9050), or leave empty for auto-detect", default="", validator=lambda v: not v or "://" in v, error_msg="Enter a valid proxy URL or leave empty")
    if not proxy:
        proxy = _auto_detect_proxy()

    def _validate_count(v: str) -> bool:
        return v.lower() == "all" or (v.isdigit() and int(v) > 0)

    sample_fuzz = _prompt("Number of URLs to fuzz (enter 'all' for every URL, more = thorough but slow)", default="5", validator=_validate_count, error_msg="Enter a positive number or 'all'")
    sample_params = _prompt("Number of URLs for parameter discovery (enter 'all' for every URL, more = thorough but slow)", default="50", validator=_validate_count, error_msg="Enter a positive number or 'all'")
    speed = _prompt_yes_no("Fast mode — reduce sample sizes for quicker scans (thorough but slow by default)", default=False)
    dos_mode = _prompt_yes_no("DoS mode — enable aggressive attacks (race bursts, HTTP smuggling, GraphQL depth DoS, H2 rapid reset, credential spray)", default=False)
    if not dos_mode:
        print(f"  {C['y']}DoS phases disabled:{C['r']} 20-GRAPHQL, 23-RACE, 34-RATELIMIT, 38-SMUGGLE, 38b-H2SMUGGLE, 54-WS-FUZZ, 83-RACEBURST, 93-PWDSPRAY, 132-GQLABUSE, 136-RATELIMITBYPASS")
    print(f"\n{C['b']}Reporting:{C['r']}")
    report_format = _prompt("Report format (html, md, json, sarif)", default="html", validator=lambda v: v in ("html", "md", "json", "sarif"), error_msg="Enter html, md, json, or sarif")
    print(f"\n{C['b']}Authentication:{C['r']}")
    cookie = _prompt("Cookie string (e.g. 'session=abc123'), or leave empty", default="", sensitive=True)
    extra_headers_raw = _prompt("Extra HTTP headers, comma-separated (e.g. 'Authorization: Bearer xyz,X-Custom: val'), or leave empty", default="")
    extra_headers_list: List[str] = [h.strip() for h in extra_headers_raw.split(",") if h.strip()] if extra_headers_raw else []
    extra_phases: Set[str] = set()
    if level in ("2", "full"):
        _all_extra = [
            ("04b-TAKEOVER-VALIDATE", "Confirm dangling CNAME exploitability"),
            ("05b-APISPEC", "API spec discovery (Swagger/OpenAPI/GraphQL SDL)"),
            ("11-INJECT", "XSS (dalfox/kxss), SSRF probes, parameter injection"),
            ("11a-DOMXSS", "DOM-based XSS via browser automation (Playwright)"),
            ("11b-SQLMAP", "SQL injection via sqlmap (pre-filtered)"),
            ("12-SSTI", "SSTI fuzzing"),
            ("13-OOB", "OOB interaction tracking (DNS/HTTP Callback)"),
            ("14-ORIGIN", "Origin IP bypass (Cloudflare)"),
            ("15-SECRETS", "Deep JS secret scanning"),
            ("16a-AUTHZ", "Auth bypass header injection"),
            ("16b-MASSASSIGN", "Mass assignment field discovery"),
            ("17-IDOR", "ID manipulation / predictable IDs"),
            ("17b-SSRFMETA", "Cloud metadata exfiltration (SSRF confirmed)"),
            ("18-CLOUD", "Cloud bucket discovery (AWS/GCP/Azure)"),
            ("19-GIT", "Git exposure scanning (.git + trufflehog)"),
            ("20-GRAPHQL", "GraphQL introspection + schema analysis + deep probes"),
            ("21-WAF", "WAF detection (50+ vendor signatures)"),
            ("21b-WAFBYPASS", "WAF bypass technique testing (Cloudflare, Akamai, AWS WAF, ModSecurity)"),
            ("22-NOSQLI", "NoSQL injection probes"),
            ("23-RACE", "Race condition detection"),
            ("24-JWT", "JWT token analysis"),
            ("25-XXE", "XML external entity injection"),
            ("26-CMDINJECT", "OS command injection detection"),
            ("27-SSPP", "Server-side prototype pollution"),
            ("28-CACHED", "Web cache poisoning/deception + v2 probes (WCD, key confusion)"),
            ("29-DEPCHECK", "JS dependency vulnerability scan"),
            ("30-LFI", "Local file inclusion / path traversal"),
            ("31-OPENREDIR", "Open redirect detection"),
            ("32-CLICKJACK", "Clickjacking protection check"),
            ("33-CRLF", "CRLF injection detection"),
            ("34-RATELIMIT", "Rate limiting detection"),
            ("35-CORSADV", "Advanced CORS misconfiguration"),
            ("36-JWTADV", "Advanced JWT attacks"),
            ("37-FILEUPLOAD", "File upload vulnerability testing"),
            ("38-SMUGGLE", "HTTP request smuggling detection"),
            ("38b-H2SMUGGLE", "HTTP/2 + HTTP/3 attack surface (H2 smugg, QUIC, HPACK)"),
            ("39-OAUTH", "OAuth misconfiguration testing"),
            ("40-PWRESET", "Password reset logic testing"),
            ("41-WEBSOCKET", "WebSocket security testing + deep probes"),
            ("42-LDAP", "LDAP injection detection"),
            ("43-DESERIAL", "Deserialization attack detection"),
            ("44-CHAIN", "Cross-phase finding correlation"),
            ("45-EVIDENCE", "Capture request/response + auto PoC generation for findings"),
            ("46-BUCKET", "Cloud storage bucket enumeration (S3/Azure/GCP)"),
            ("47-CDN", "CDN provider detection + origin IP discovery"),
            ("48-CONTENT", "Content discovery via common path probing"),
            ("49-FRAMEWORKS", "Framework detection + edge runtime vulnerability checks"),
            ("50-BUCKET-PERMS", "Cloud bucket permission auditing (public read/write)"),
            ("51-HPP", "HTTP parameter pollution detection"),
            ("52-SERVERLESS", "Serverless/cloud function endpoint discovery"),
            ("53-CSP", "CSP header analysis + bypass detection"),
            ("54-WS-FUZZ", "WebSocket message fuzzing"),
            ("55-CSV-INJECT", "CSV/Excel formula injection (DDE, HYPERLINK)"),
            ("56-EXPOSED-DB", "Exposed database / storage probing (ES, Redis, Mongo, K8s)"),
            ("57-DEFAULT-CREDS", "Default credentials testing on admin services"),
            ("58-HOST-INJECT", "Host header injection / cache poisoning variants"),
            ("59-EMAIL-SEC", "Email security posture (SPF/DMARC/DKIM)"),
            ("60-SMTP-ENUM", "SMTP enumeration / email bombing detection"),
            ("61-OAUTH-ADV", "OAuth redirect_uri bypass variants"),
            ("62-LOG-INJECT", "Log injection / log forging detection"),
            ("63-DOC-ATTACK", "Document-based attacks (DDE, macro, XXE, SVG-XSS)"),
            ("64-IDEMPOTENCY", "Idempotency key replay testing (POST endpoints)"),
            ("65-SESSION", "Session fixation & token lifecycle analysis"),
            ("66-SSRF-FULL", "Full SSRF with OOB callback + cloud metadata exfil"),
            ("67-PATHNORM", "Path normalization bypass (e.g. /admin → /Admin)"),
            ("68-DEPCVE", "Known CVE check for JS/Python/Go dependencies"),
            ("69-DNSZT", "DNS zone transfer attempt (AXFR)"),
            ("70-PORTFULL", "Full port scan (all 65535 ports)"),
            ("71-EMHARVEST", "Email address harvesting from web pages"),
            ("72-ACCOUNTENUM", "Account enumeration via login/register error messages"),
            ("73-CSPBYPASS", "CSP bypass technique testing"),
            ("74-GHTOOLS", "GitHub dorking for tokens, secrets, endpoints"),
            ("75-MOBILEAPI", "Mobile API endpoint discovery (.well-known, APK)"),
            ("76-WORKFLOW", "Workflow logic bypass testing"),
            ("77-CACHEKEY", "Cache key probe & poisoning via key differences"),
            ("78-FILEUPLOADADV", "Advanced file upload (polyglot, metadata stripping)"),
            ("79-SECRETDIFF", "Secret rotation diff analysis (old vs new)"),
            ("80-STOREXSS", "Stored XSS payload injection + verification"),
            ("81-IDORFUZZ", "IDOR via parameter fuzzing (cross-session)"),
            ("82-OAUTHDEEP", "Deep OAuth redirect_uri bypass (state, PKCE)"),
            ("83-RACEBURST", "Race condition burst (Turbo Intruder style)"),
            ("84-WHOIS", "WHOIS registration data lookup"),
            ("85-ASN", "ASN & BGP prefix enumeration"),
            ("86-DORK", "Google/Bing dorking for sensitive files & pages"),
            ("87-SHODAN", "Shodan host & service fingerprinting"),
            ("88-EMPLOYEE", "Employee name harvesting (LinkedIn, Hunter)"),
            ("89-PASSIVEDNS", "Passive DNS historical subdomain lookup"),
            ("90-CSRF", "CSRF token validation & SameSite audit"),
            ("91-SESSIONFIX", "Session fixation & session handling audit"),
            ("92-SAML", "SAML authentication bypass testing"),
            ("93-PWDSPRAY", "Credential spray & password policy testing"),
            ("94-COOKIEAUDIT", "Cookie security flags audit (HttpOnly/Secure/SameSite)"),
            ("95-POSTTEST", "POST-based authentication bypass testing"),
            ("96-METHODOVERRIDE", "HTTP method override (X-HTTP-Method-Override)"),
            ("97-FORCEDBROWSE", "Forced browsing to hidden endpoints"),
            ("98-CASEBYPASS", "Case-sensitive path access bypass"),
            ("99-APIPAGE", "Hidden API page discovery (/api, /graphql, /swagger)"),
            ("99a-TABNAB", "Reverse tabnabbing via target=_blank links"),
            ("99b-APIKEYLEAK", "API key exposure in JS, HTML comments, error pages"),
            ("99c-REDIRABUSE", "Open redirect chain abuse for SSRF/XSS"),
            ("99d-LOGTRIGGER", "Log injection trigger (CRLF in User-Agent, Referer)"),
            ("99e-XSSSTORED", "Stored XSS with payload persistence check"),
            ("99f-HOSTABUSE", "Host header abuse (password reset poisoning, cache)"),
            ("99g-AUTHBYPASSADV", "Advanced auth bypass (path traversal, header injection)"),
            ("100-SSI", "SSI injection testing"),
            ("101-JSONINJECT", "JSON-based injection (JWT, template, expression)"),
            ("102-NULLBYTE", "Null byte injection bypass"),
            ("103-DOUBLEENCOD", "Double URL encoding bypass"),
            ("104-UNICODE", "Unicode normalization bypass"),
            ("105-POSTMSGXSS", "postMessage XSS via window.postMessage"),
            ("106-JSONP", "JSONP hijacking & callback abuse"),
            ("107-SRI", "Subresource Integrity (SRI) missing/bypass"),
            ("108-MIXEDCONTENT", "Mixed HTTP/HTTPS content loading"),
            ("109-HSTSPRELOAD", "HSTS preload list compliance check"),
            ("110-THIRDPARTYJS", "Third-party JS library vulnerability scan"),
            ("111-BROWSERSTORAGE", "Browser storage (localStorage/sessionStorage) audit"),
            ("112-RFI", "Remote file inclusion probing"),
            ("113-WEBDAV", "WebDAV method & file exposure"),
            ("114-SNMP", "SNMP community string & info leak"),
            ("115-BANNER", "Server banner fingerprinting"),
            ("116-PHPINFO", "phpinfo() exposure detection"),
            ("117-SRVSTATUS", "Server status page exposure (/server-status)"),
            ("118-ERRORLEAK", "Error message info leakage (stack traces, debug)"),
            ("119-WILDCARDDNS", "Wildcard DNS detection & DDoS surface"),
            ("120-DNSREBIND", "DNS rebinding attack surface check"),
            ("121-IISASPNET", "IIS/ASP.NET exposure (web.config, debug, traversal)"),
            ("122-TOMCAT", "Tomcat manager default creds & JMX exposure"),
            ("123-NODEJS", "Node.js/Express exposed files & SSTI probes"),
            ("124-LARAVEL", "Laravel .env/log/dashboard exposure"),
            ("125-DJANGO", "Django debug mode, admin, DRF exposure"),
            ("126-SYMFONY", "Symfony profiler/debug toolbar exposure"),
            ("127-CICD", "CI/CD pipeline file exposure (.gitlab-ci.yml, Jenkinsfile)"),
            ("128-DOCKER", "Docker registry & compose file exposure"),
            ("129-K8S", "Kubernetes API/kubelet/etcd/dashboard exposure"),
            ("130-TERRAFORM", "Terraform state file secret leakage"),
            ("131-ENVDEEP", "Deep env/config file secret scanning"),
            ("132-GQLABUSE", "GraphQL batching, depth DoS & schema leak"),
            ("133-APIVERSION", "API versioning bypass (v0, internal, legacy, beta)"),
            ("134-LBDETECT", "Load balancer detection & origin bypass"),
            ("135-VHOST", "Virtual host enumeration via Host header"),
            ("136-RATELIMITBYPASS", "Rate limit bypass (IP rotation, case, unicode)"),
        ]
        extra_set = {p for p, _ in _all_extra}
        base_only = [p for p in sorted(VALID_PHASES) if p not in extra_set]
        if base_only:
            print(f"\n{C['b']}Core phases (always included for level '{level}'):{C['r']}")
            _phase_tag = {"00-SCOPE": "Scope validation", "01-RECON": "Passive recon (subfinder, amass, etc.)",
                "02-RESOLVE": "DNS resolution & live probing", "03-PERMUTE": "Subdomain permutation",
                "04-SCAN": "Port scanning (naabu/nmap)", "05-HARVEST": "URL gathering (gau, wayback, katana)",
                "06-JSINTEL": "JavaScript analysis (secretfinder)",
                "07-PARAMS": "Parameter discovery (arjun/x8)", "08-FUZZ": "Endpoint fuzzing (ffuf)",
                "09-VULNSCAN": "Vulnerability scanning (nuclei)", "10-TLSCMS": "TLS/CMS fingerprinting"}
            for p in base_only:
                desc = _phase_tag.get(p, "")
                print(f"  {C['g']}{p:20}{C['r']} {desc}")
        print(f"\n{C['b']}Additional phases (toggle on/off):{C['r']}")
        for p, desc in _all_extra:
            in_base = "  (included in base)" if p in base_phases else ""
            print(f"  {C['y']}{p:20}{C['r']} {desc}{in_base}")
        if level == "full":
            skip_raw = _prompt("Phases to SKIP (comma-separated, or empty to run all 152)", default="")
            skipped = {s.strip().upper() for s in skip_raw.split(",") if s.strip()}
            extra_phases = {p for p, _ in _all_extra} - skipped
            base_phases = base_phases - skipped
        else:
            incl_raw = _prompt("Phases to INCLUDE (comma-separated, or empty for none)", default="")
            included = {s.strip().upper() for s in incl_raw.split(",") if s.strip()}
            extra_phases = {p for p, _ in _all_extra} & included
    selected = base_phases | extra_phases
    state_path = Path(out) / "state.json"
    resume = False
    force = False
    if state_path.exists():
        resume = _prompt_yes_no("State file exists — resume previous scan", default=True)
        if resume:
            force = _prompt_yes_no("Force re-run all phases (ignore cached results)", default=False)
    print(f"\n{C['b']}{'─' * 60}{C['r']}")
    print(f" {C['g']}Scan summary:{C['r']}")
    print(f"   Domain:           {C['y']}{domain}{C['r']}")
    print(f"   Output:           {C['y']}{out}{C['r']}")
    print(f"   Level:            {C['y']}{level}{C['r']}")
    print(f"   Proxy:            {C['y']}{proxy if proxy else 'none (auto-detected)'}{C['r']}")
    print(f"   Phases:           {C['y']}{', '.join(sorted(selected))}{C['r']}")
    print(f"   Jobs:             {C['y']}{jobs}{C['r']}")
    print(f"   Max procs:        {C['y']}{max_procs if max_procs else 'auto'}{C['r']}")
    print(f"   Rate limit:       {C['y']}{rate_limit if rate_limit else 'unlimited'} req/s{C['r']}")
    print(f"   SQLmap level/risk:{C['y']} {sqlmap_level}/{sqlmap_risk}{C['r']}")
    print(f"   Delay:            {C['y']}{delay}s{C['r']}")
    print(f"   Cookie:           {C['y']}{'set' if cookie else 'none'}{C['r']}")
    print(f"   Extra headers:    {C['y']}{len(extra_headers_list)} set{C['r']}")
    print(f"   Resume:           {C['y']}{'yes' if resume else 'no'}{C['r']}")
    print(f"   Force:            {C['y']}{'yes' if force else 'no'}{C['r']}")
    print(f"   Report:           {C['y']}{report_format}{C['r']}")
    print(f"   Fast mode:        {C['y']}{'yes' if speed else 'no'}{C['r']}")
    print(f"   DoS mode:         {C['y']}{'yes (aggressive)' if dos_mode else 'no (safe)'}{C['r']}")
    print(f" {C['b']}{'─' * 60}{C['r']}")
    if not _prompt_yes_no("Start scan", default=True):
        log("info", "Aborted by user")
        sys.exit(0)

    ns = argparse.Namespace()
    ns.domain = domain
    ns.out = out
    if not dos_mode:
        from reconchain.config import DOS_PHASES
        selected = selected - DOS_PHASES
    ns.only = selected
    ns.skip = set()
    ns.jobs = jobs
    ns.max_procs = max_procs
    ns.fast = False
    ns.dos_mode = dos_mode
    ns.resume = resume
    ns.force = force
    ns.sample = False
    ns.quiet = False
    ns.no_color = False
    ns.interactive = True
    ns.sqlmap_level = int(sqlmap_level)
    ns.sqlmap_risk = int(sqlmap_risk)
    ns.delay = float(delay)
    ns.proxy = proxy
    ns.rate_limit = rate_limit
    ns.vuln_proxy = ""

    def _resolve_count(v: str) -> int:
        return sys.maxsize if v.lower() == "all" else int(v)

    ns.sample_urls_fuzz = _resolve_count(sample_fuzz)
    ns.sample_urls_params = _resolve_count(sample_params)
    ns.cookie = cookie
    ns.extra_headers = extra_headers_list if extra_headers_list else []
    ns.daemon = False
    ns.status = ""
    ns.format = report_format
    ns.sample_urls_nosqli = 30
    ns.sample_endpoints_race = 10
    ns.sample_hosts_jwt = 20
    ns.sample_urls_xxe = 10
    ns.sample_urls_cmdi = 30
    ns.sample_endpoints_sspp = 10
    ns.sample_hosts_cached = 10
    ns.sample_urls_depcheck = 30
    ns.sample_hosts_cloud = 5
    ns.sample_hosts_git = 5
    ns.sample_hosts_graphql = 5
    ns.sample_hosts_waf = 5
    ns.sample_urls_redirect = 30
    ns.sample_hosts_clickjack = 20
    ns.sample_urls_crlf = 20
    ns.sample_hosts_ratelimit = 10
    ns.sample_endpoints_corsadv = 10
    ns.sample_hosts_jwtadv = 20
    ns.sample_urls_upload = 10
    ns.sample_hosts_smuggle = 10
    ns.sample_endpoints_oauth = 10
    ns.sample_endpoints_pwreset = 10
    ns.sample_hosts_websocket = 10
    ns.sample_hosts_h2smuggle = 10
    ns.sample_hosts_frameworks = 20
    ns.sample_urls_domxss = 30
    ns.sample_urls_ldap = 20
    ns.sample_endpoints_deserial = 10
    ns.sample_hosts_ssl = 10
    ns.sample_hosts_origin = 10
    ns.sample_endpoints_cors = 10
    ns.sample_endpoints_l = 20
    ns.sample_endpoints_post = 5
    ns.sample_hosts_iisaspnet = 10
    ns.sample_hosts_tomcat = 10
    ns.sample_hosts_nodejs = 10
    ns.sample_hosts_laravel = 10
    ns.sample_hosts_django = 10
    ns.sample_hosts_symfony = 10
    ns.sample_hosts_cicd = 10
    ns.sample_hosts_docker = 10
    ns.sample_hosts_k8s = 10
    ns.sample_hosts_terraform = 10
    ns.sample_hosts_envdeep = 10
    ns.sample_hosts_gqlabuse = 10
    ns.sample_urls_apiversion = 20
    ns.sample_hosts_lbdetect = 15
    ns.sample_hosts_vhost = 10
    ns.sample_urls_ratelimitbypass = 20
    ns.sample_urls_csrf = 20
    ns.sample_hosts_sessionfix = 10
    ns.sample_endpoints_saml = 10
    ns.sample_users_spray = 20
    ns.sample_hosts_cookie = 20
    ns.sample_urls_posttest = 30
    ns.sample_urls_methodoverride = 20
    ns.sample_hosts_forcedbrowse = 20
    ns.sample_urls_casebypass = 20
    ns.sample_urls_apipage = 20
    ns.sample_urls_tabnab = 30
    ns.sample_urls_apikeyleak = 30
    ns.sample_urls_redirabuse = 20
    ns.sample_urls_logtrigger = 20
    ns.sample_urls_xssstored = 10
    ns.sample_hosts_hostabuse = 10
    ns.sample_urls_authbypassadv = 20
    ns.sample_urls_ssi = 20
    ns.sample_urls_jsoninject = 20
    ns.sample_urls_nullbyte = 20
    ns.sample_urls_doubleencod = 20
    ns.sample_urls_unicode = 20
    ns.sample_hosts_postmsg = 15
    ns.sample_hosts_jsonp = 20
    ns.sample_hosts_sri = 20
    ns.sample_hosts_mixedcontent = 20
    ns.sample_hosts_hstspreload = 20
    ns.sample_hosts_thirdpartyjs = 15
    ns.sample_hosts_browserstorage = 15
    ns.sample_urls_rfi = 20
    ns.sample_hosts_webdav = 10
    ns.sample_hosts_snmp = 10
    ns.sample_hosts_banner = 15
    ns.sample_hosts_phpinfo = 15
    ns.sample_hosts_srvstatus = 15
    ns.sample_urls_errorleak = 20
    ns.sample_hosts_wildcarddns = 10
    ns.sample_hosts_dnsrebind = 10
    if speed:
        ns.sample_urls_fuzz = min(ns.sample_urls_fuzz, 50)
        ns.sample_urls_params = min(ns.sample_urls_params, 10)
        ns.sample_urls_nosqli = min(ns.sample_urls_nosqli, 5)
        ns.sample_urls_cmdi = min(ns.sample_urls_cmdi, 5)
        ns.sample_urls_xxe = min(ns.sample_urls_xxe, 3)
        ns.sample_urls_crlf = min(ns.sample_urls_crlf, 5)
        ns.sample_urls_redirect = min(ns.sample_urls_redirect, 5)
        ns.sample_urls_ldap = min(ns.sample_urls_ldap, 5)
        ns.sample_urls_depcheck = min(ns.sample_urls_depcheck, 5)
        ns.sample_urls_upload = min(ns.sample_urls_upload, 3)
    ns.sample_urls_xss_blind = 20
    ns.sample_urls_ssti = 5
    if speed:
        ns.sample_urls_xss_blind = min(ns.sample_urls_xss_blind, 5)
        ns.sample_urls_ssti = min(ns.sample_urls_ssti, 2)
        ns.sample_hosts_ssl = min(ns.sample_hosts_ssl, 2)
        ns.sample_hosts_origin = min(ns.sample_hosts_origin, 3)
        ns.sample_hosts_cloud = min(ns.sample_hosts_cloud, 2)
        ns.sample_hosts_git = min(ns.sample_hosts_git, 2)
        ns.sample_hosts_graphql = min(ns.sample_hosts_graphql, 2)
        ns.sample_hosts_waf = min(ns.sample_hosts_waf, 2)
        ns.sample_hosts_jwt = min(ns.sample_hosts_jwt, 5)
        ns.sample_hosts_jwtadv = min(ns.sample_hosts_jwtadv, 5)
        ns.sample_hosts_cached = min(ns.sample_hosts_cached, 3)
        ns.sample_hosts_clickjack = min(ns.sample_hosts_clickjack, 5)
        ns.sample_hosts_ratelimit = min(ns.sample_hosts_ratelimit, 3)
        ns.sample_hosts_smuggle = min(ns.sample_hosts_smuggle, 3)
        ns.sample_hosts_websocket = min(ns.sample_hosts_websocket, 3)
        ns.sample_hosts_h2smuggle = min(ns.sample_hosts_h2smuggle, 3)
        ns.sample_hosts_frameworks = min(ns.sample_hosts_frameworks, 5)
        ns.sample_urls_domxss = min(ns.sample_urls_domxss, 5)
        ns.sample_endpoints_race = min(ns.sample_endpoints_race, 3)
        ns.sample_endpoints_cors = min(ns.sample_endpoints_cors, 3)
        ns.sample_endpoints_corsadv = min(ns.sample_endpoints_corsadv, 3)
        ns.sample_endpoints_sspp = min(ns.sample_endpoints_sspp, 3)
        ns.sample_endpoints_l = min(ns.sample_endpoints_l, 5)
        ns.sample_endpoints_post = min(ns.sample_endpoints_post, 2)
        ns.sample_endpoints_oauth = min(ns.sample_endpoints_oauth, 3)
        ns.sample_endpoints_pwreset = min(ns.sample_endpoints_pwreset, 3)
        ns.sample_endpoints_deserial = min(ns.sample_endpoints_deserial, 3)
        ns.sample_hosts_iisaspnet = min(ns.sample_hosts_iisaspnet, 3)
        ns.sample_hosts_tomcat = min(ns.sample_hosts_tomcat, 3)
        ns.sample_hosts_nodejs = min(ns.sample_hosts_nodejs, 3)
        ns.sample_hosts_laravel = min(ns.sample_hosts_laravel, 3)
        ns.sample_hosts_django = min(ns.sample_hosts_django, 3)
        ns.sample_hosts_symfony = min(ns.sample_hosts_symfony, 3)
        ns.sample_hosts_cicd = min(ns.sample_hosts_cicd, 3)
        ns.sample_hosts_docker = min(ns.sample_hosts_docker, 3)
        ns.sample_hosts_k8s = min(ns.sample_hosts_k8s, 3)
        ns.sample_hosts_terraform = min(ns.sample_hosts_terraform, 3)
        ns.sample_hosts_envdeep = min(ns.sample_hosts_envdeep, 3)
        ns.sample_hosts_gqlabuse = min(ns.sample_hosts_gqlabuse, 3)
        ns.sample_urls_apiversion = min(ns.sample_urls_apiversion, 5)
        ns.sample_hosts_lbdetect = min(ns.sample_hosts_lbdetect, 3)
        ns.sample_hosts_vhost = min(ns.sample_hosts_vhost, 3)
        ns.sample_urls_ratelimitbypass = min(ns.sample_urls_ratelimitbypass, 5)
    return ns


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reconchain", description="Chain recon tools into a single orchestrated pipeline.")
    p.add_argument("-d", "--domain", type=str, default="", help="target root domain (or comma-separated list for multi-domain), e.g. example.com or example.com,test.com")
    p.add_argument("-o", "--out", default="", help="output directory (default: ./out/<domain>)")
    p.add_argument("-i", "--interactive", action="store_true", help="interactive setup wizard (prompts for domain, level, etc.)")
    p.add_argument("--only", default=set(), type=_parse_phase_csv, help="comma-separated phases to run, e.g. 01-RECON,02-RESOLVE,04-SCAN")
    p.add_argument("--skip", default=set(), type=_parse_phase_csv, help="comma-separated phases to skip, e.g. 10-TLSCMS,23-RACE")
    p.add_argument("-j", "--jobs", type=int, default=MAX_PARALLEL_JOBS, help=f"max parallel phases (default: {MAX_PARALLEL_JOBS})")
    p.add_argument("--max-procs", type=int, default=0, help="max concurrent tool subprocesses across all phases (0 = unlimited, default: 0)")
    p.add_argument("--fast", action="store_true", help="fast mode: only run essential recon phases (01-RECON, 02-RESOLVE, 04-SCAN, 05-HARVEST), skipping vuln scanning")
    p.add_argument("--dos", action="store_true", default=False, dest="dos_mode", help="enable DoS-like attack phases (race bursts, HTTP smuggling, GraphQL depth DoS, H2 rapid reset, credential spray) — disabled by default")
    p.add_argument("--no-dos", action="store_false", dest="dos_mode", help="disable DoS-like attack phases to avoid service disruption")
    p.add_argument("--resume", action="store_true", help="resume from ./out/state.json if it exists (only for the same target domain)")
    p.add_argument("--force", action="store_true", help="re-run all phases even if output files already exist")
    p.add_argument("--sample", action="store_true", help="downsample artifacts to 1 entry for faster downstream testing (default: keep all results)")
    p.add_argument("--keep-all", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("-q", "--quiet", action="store_true", help="suppress info-level logs")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    p.add_argument("--proxy", type=str, default="", help="proxy URL for all phases, e.g. socks5://127.0.0.1:9050")
    p.add_argument("--vuln-proxy", type=str, default="", help="proxy URL only for vulnerability probing phases (overrides --proxy for phases 09+), e.g. socks5://127.0.0.1:9050")
    p.add_argument("--proxy-timeout-multiplier", type=float, default=1.5, help="multiplier applied to tool timeouts when proxy is active (default: 1.5)")
    p.add_argument("--cookie", type=str, default="", help="cookie string to include with HTTP requests (e.g. 'session=abc')")
    p.add_argument("--header", type=str, action="append", default=[], dest="extra_headers", help="extra HTTP header (can be repeated), e.g. --header 'Authorization: Bearer xyz'")
    p.add_argument("--sqlmap-level", type=int, default=1, choices=range(1, 6), help="sqlmap --level (1-5, default: 1; higher = deeper but slower)")
    p.add_argument("--sqlmap-risk", type=int, default=1, choices=range(1, 4), help="sqlmap --risk (1-3, default: 1; higher = more payloads but destructive)")
    p.add_argument("--delay", type=float, default=0.0, help="seconds to wait between requests (polite mode)")
    p.add_argument("--rate-limit", type=int, default=0, help="max requests per second (0 = unlimited)")
    p.add_argument("--sample-urls-fuzz", type=int, default=200, help="number of URLs to sample for fuzzing (default: 200)")
    p.add_argument("--sample-urls-params", type=int, default=50, help="number of URLs to sample for parameter discovery (default: 50)")
    p.add_argument("--sample-hosts-ssl", type=int, default=10, help="number of hosts to sample for SSL/TLS scanning via testssl (default: 10)")
    p.add_argument("--sample-hosts-origin", type=int, default=10, help="number of hosts to sample for origin bypass scans (favicon, crt.sh resolve, ipinfo) (default: 10)")
    p.add_argument("--sample-hosts-cloud", type=int, default=5, help="number of hosts to check for cloud bucket exposure (default: 5)")
    p.add_argument("--sample-hosts-git", type=int, default=5, help="number of hosts to scan for Git exposure (default: 5)")
    p.add_argument("--sample-hosts-graphql", type=int, default=5, help="number of hosts for GraphQL introspection (default: 5)")
    p.add_argument("--sample-hosts-waf", type=int, default=5, help="number of hosts for WAF detection (default: 5)")
    p.add_argument("--sample-endpoints-l", type=int, default=20, help="number of endpoints to sample for auth bypass / mass assignment probes (default: 20)")
    p.add_argument("--sample-urls-xss-blind", type=int, default=20, help="number of URLs to probe for blind XSS via OAST (default: 20)")
    p.add_argument("--sample-urls-domxss", type=int, default=30, help="number of URLs for DOM XSS browser automation (default: 30)")
    p.add_argument("--sample-hosts-h2smuggle", type=int, default=10, help="number of hosts for H2/H3 attack surface testing (default: 10)")
    p.add_argument("--sample-hosts-frameworks", type=int, default=20, help="number of hosts for framework detection and vuln checks (default: 20)")
    p.add_argument("--exclude-tags", type=str, default="", help="nuclei tags to exclude (comma-separated), e.g. 'info,tech'")
    p.add_argument("--sample-urls-ssti", type=int, default=5, help="number of SSTI probe URLs (default: 5)")
    p.add_argument("--sample-endpoints-post", type=int, default=5, help="number of endpoints for POST mass-assignment probes (default: 5)")
    p.add_argument("--sample-endpoints-cors", type=int, default=10, help="number of endpoints for CORS misconfiguration probes (default: 10)")
    p.add_argument("--sample-urls-nosqli", type=int, default=30, help="number of URLs for NoSQL injection probes (default: 30)")
    p.add_argument("--sample-endpoints-race", type=int, default=10, help="number of endpoints for race condition testing (default: 10)")
    p.add_argument("--sample-hosts-jwt", type=int, default=20, help="number of hosts for JWT analysis (default: 20)")
    p.add_argument("--sample-urls-xxe", type=int, default=10, help="number of URLs for XXE injection probes (default: 10)")
    p.add_argument("--sample-urls-cmdi", type=int, default=30, help="number of URLs for command injection detection (default: 30)")
    p.add_argument("--sample-endpoints-sspp", type=int, default=10, help="number of API endpoints for prototype pollution probes (default: 10)")
    p.add_argument("--sample-hosts-cached", type=int, default=10, help="number of hosts for cache poisoning probes (default: 10)")
    p.add_argument("--sample-urls-depcheck", type=int, default=30, help="number of JS URLs for dependency vulnerability scanning (default: 30)")
    p.add_argument("--sample-urls-redirect", type=int, default=30, help="number of URLs for open redirect detection (default: 30)")
    p.add_argument("--sample-hosts-clickjack", type=int, default=20, help="number of targets for clickjacking detection (default: 20)")
    p.add_argument("--sample-urls-crlf", type=int, default=20, help="number of URLs for CRLF injection testing (default: 20)")
    p.add_argument("--sample-hosts-ratelimit", type=int, default=10, help="number of targets for rate limiting detection (default: 10)")
    p.add_argument("--sample-endpoints-corsadv", type=int, default=10, help="number of endpoints for advanced CORS testing (default: 10)")
    p.add_argument("--sample-hosts-jwtadv", type=int, default=20, help="number of targets for advanced JWT analysis (default: 20)")
    p.add_argument("--sample-urls-upload", type=int, default=10, help="number of upload endpoints to test (default: 10)")
    p.add_argument("--sample-hosts-smuggle", type=int, default=10, help="number of hosts for request smuggling testing (default: 10)")
    p.add_argument("--sample-endpoints-oauth", type=int, default=10, help="number of OAuth endpoints to test (default: 10)")
    p.add_argument("--sample-endpoints-pwreset", type=int, default=10, help="number of password reset endpoints to test (default: 10)")
    p.add_argument("--sample-hosts-websocket", type=int, default=10, help="number of hosts for WebSocket testing (default: 10)")
    p.add_argument("--sample-urls-ldap", type=int, default=20, help="number of URLs for LDAP injection testing (default: 20)")
    p.add_argument("--sample-endpoints-deserial", type=int, default=10, help="number of API endpoints for deserialization testing (default: 10)")
    p.add_argument("--sample-urls-csrf", type=int, default=20, help="number of URLs for CSRF testing (default: 20)")
    p.add_argument("--sample-hosts-sessionfix", type=int, default=10, help="number of hosts for session fixation testing (default: 10)")
    p.add_argument("--sample-endpoints-saml", type=int, default=10, help="number of endpoints for SAML bypass testing (default: 10)")
    p.add_argument("--sample-users-spray", type=int, default=20, help="number of usernames for password spray (default: 20)")
    p.add_argument("--sample-hosts-cookie", type=int, default=20, help="number of hosts for cookie audit (default: 20)")
    p.add_argument("--sample-urls-posttest", type=int, default=30, help="number of URLs for POST auth bypass (default: 30)")
    p.add_argument("--sample-urls-methodoverride", type=int, default=20, help="number of URLs for method override testing (default: 20)")
    p.add_argument("--sample-hosts-forcedbrowse", type=int, default=20, help="number of hosts for forced browsing (default: 20)")
    p.add_argument("--sample-urls-casebypass", type=int, default=20, help="number of URLs for case-sensitivity bypass (default: 20)")
    p.add_argument("--sample-urls-apipage", type=int, default=20, help="number of URLs for hidden API page discovery (default: 20)")
    p.add_argument("--sample-urls-tabnab", type=int, default=30, help="number of URLs for reverse tabnabbing (default: 30)")
    p.add_argument("--sample-urls-apikeyleak", type=int, default=30, help="number of URLs for API key leak detection (default: 30)")
    p.add_argument("--sample-urls-redirabuse", type=int, default=20, help="number of redirect URLs for abuse testing (default: 20)")
    p.add_argument("--sample-urls-logtrigger", type=int, default=20, help="number of URLs for log injection triggers (default: 20)")
    p.add_argument("--sample-urls-xssstored", type=int, default=10, help="number of URLs for stored XSS testing (default: 10)")
    p.add_argument("--sample-hosts-hostabuse", type=int, default=10, help="number of hosts for host header abuse (default: 10)")
    p.add_argument("--sample-urls-authbypassadv", type=int, default=20, help="number of URLs for advanced auth bypass (default: 20)")
    p.add_argument("--sample-urls-ssi", type=int, default=20, help="number of URLs for SSI injection (default: 20)")
    p.add_argument("--sample-urls-jsoninject", type=int, default=20, help="number of URLs for JSON injection (default: 20)")
    p.add_argument("--sample-urls-nullbyte", type=int, default=20, help="number of URLs for null byte injection (default: 20)")
    p.add_argument("--sample-urls-doubleencod", type=int, default=20, help="number of URLs for double encoding bypass (default: 20)")
    p.add_argument("--sample-urls-unicode", type=int, default=20, help="number of URLs for unicode bypass (default: 20)")
    p.add_argument("--sample-hosts-postmsg", type=int, default=15, help="number of hosts for postMessage XSS (default: 15)")
    p.add_argument("--sample-hosts-jsonp", type=int, default=20, help="number of hosts for JSONP hijacking (default: 20)")
    p.add_argument("--sample-hosts-sri", type=int, default=20, help="number of hosts for SRI check (default: 20)")
    p.add_argument("--sample-hosts-mixedcontent", type=int, default=20, help="number of hosts for mixed content check (default: 20)")
    p.add_argument("--sample-hosts-hstspreload", type=int, default=20, help="number of hosts for HSTS preload check (default: 20)")
    p.add_argument("--sample-hosts-thirdpartyjs", type=int, default=15, help="number of hosts for third-party JS audit (default: 15)")
    p.add_argument("--sample-hosts-browserstorage", type=int, default=15, help="number of hosts for browser storage audit (default: 15)")
    p.add_argument("--sample-urls-rfi", type=int, default=20, help="number of URLs for RFI probing (default: 20)")
    p.add_argument("--sample-hosts-webdav", type=int, default=10, help="number of hosts for WebDAV testing (default: 10)")
    p.add_argument("--sample-hosts-snmp", type=int, default=10, help="number of hosts for SNMP testing (default: 10)")
    p.add_argument("--sample-hosts-banner", type=int, default=15, help="number of hosts for banner fingerprinting (default: 15)")
    p.add_argument("--sample-hosts-phpinfo", type=int, default=15, help="number of hosts for phpinfo detection (default: 15)")
    p.add_argument("--sample-hosts-srvstatus", type=int, default=15, help="number of hosts for server-status check (default: 15)")
    p.add_argument("--sample-urls-errorleak", type=int, default=20, help="number of URLs for error leakage check (default: 20)")
    p.add_argument("--sample-hosts-wildcarddns", type=int, default=10, help="number of hosts for wildcard DNS check (default: 10)")
    p.add_argument("--sample-hosts-dnsrebind", type=int, default=10, help="number of hosts for DNS rebinding check (default: 10)")
    p.add_argument("--sample-hosts-iisaspnet", type=int, default=10, help="number of hosts for IIS/ASP.NET probing (default: 10)")
    p.add_argument("--sample-hosts-tomcat", type=int, default=10, help="number of hosts for Tomcat probing (default: 10)")
    p.add_argument("--sample-hosts-nodejs", type=int, default=10, help="number of hosts for Node.js probing (default: 10)")
    p.add_argument("--sample-hosts-laravel", type=int, default=10, help="number of hosts for Laravel probing (default: 10)")
    p.add_argument("--sample-hosts-django", type=int, default=10, help="number of hosts for Django probing (default: 10)")
    p.add_argument("--sample-hosts-symfony", type=int, default=10, help="number of hosts for Symfony probing (default: 10)")
    p.add_argument("--sample-hosts-cicd", type=int, default=10, help="number of hosts for CI/CD file exposure (default: 10)")
    p.add_argument("--sample-hosts-docker", type=int, default=10, help="number of hosts for Docker registry exposure (default: 10)")
    p.add_argument("--sample-hosts-k8s", type=int, default=10, help="number of hosts for Kubernetes exposure (default: 10)")
    p.add_argument("--sample-hosts-terraform", type=int, default=10, help="number of hosts for Terraform state exposure (default: 10)")
    p.add_argument("--sample-hosts-envdeep", type=int, default=10, help="number of hosts for deep env file scanning (default: 10)")
    p.add_argument("--sample-hosts-gqlabuse", type=int, default=10, help="number of GraphQL endpoints for abuse testing (default: 10)")
    p.add_argument("--sample-urls-apiversion", type=int, default=20, help="number of API URLs for versioning bypass (default: 20)")
    p.add_argument("--sample-hosts-lbdetect", type=int, default=15, help="number of hosts for load balancer detection (default: 15)")
    p.add_argument("--sample-hosts-vhost", type=int, default=10, help="number of hosts for virtual host enumeration (default: 10)")
    p.add_argument("--sample-urls-ratelimitbypass", type=int, default=20, help="number of URLs for rate limit bypass (default: 20)")
    p.add_argument("--format", type=str, default="html", choices=["html", "md", "json", "sarif"], help="report format (default: html; sarif produces results.sarif for GitHub/GitLab CI)")
    p.add_argument("--daemon", action="store_true", help="run in background; check progress with --status <domain>")
    p.add_argument("--status", type=str, default="", help="show live progress of a running scan (provide domain name, or 'list' to show all active scans)")
    return p


def _run_single(domain: str, args: argparse.Namespace) -> int:
    import copy
    a = copy.copy(args)
    a.domain = domain.rstrip(".").lower()
    if not a.out or a.out == f"./out/{args.domain}":
        a.out = f"./out/{a.domain}"
    a.out = str(Path(a.out).resolve())
    try:
        return asyncio.run(run_pipeline(a))
    except (ValueError, KeyboardInterrupt) as e:
        if isinstance(e, ValueError):
            log("err", str(e))
            return 2
        log("warn", "interrupted")
        return 130


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.status:
        if args.status.lower() == "list":
            active = ScanStatus.list_active()
            if not active:
                print("No active scans found.")
                return 0
            for s in active:
                print(f"  {s.get('domain')} — phase={s.get('phase')} completed={len(s.get('completed_phases', []))}/{s.get('total_phases')} errors={len(s.get('errors', []))}")
            return 0
        data = ScanStatus.load(args.status)
        if not data:
            print(f"No status found for domain '{args.status}'.")
            print("Active scans:")
            for s in ScanStatus.list_active():
                print(f"  {s.get('domain')}")
            return 1
        print(f"Domain:   {data.get('domain')}")
        print(f"Output:   {data.get('outdir')}")
        print(f"Phase:    {data.get('phase')} — {data.get('phase_progress', '')}")
        print(f"Started:  {data.get('started_at')}")
        print(f"Updated:  {data.get('updated_at')}")
        print(f"Progress: {len(data.get('completed_phases', []))}/{data.get('total_phases', '?')} phases completed")
        if data.get("completed_phases"):
            print(f"Done:     {', '.join(data['completed_phases'])}")
        if data.get("running_phases"):
            print(f"Running:  {', '.join(data['running_phases'])}")
        if data.get("errors"):
            print(f"Errors:   {len(data['errors'])}")
            for e in data["errors"][-3:]:
                print(f"  - {e}")
        if data.get("missing_tools"):
            print(f"Missing:  {', '.join(data['missing_tools'])}")
        return 0
    if args.interactive:
        args = interactive_setup()
    else:
        if not args.domain:
            parser.error("the following arguments are required: -d/--domain (or use -i for interactive)")
        args.domain = args.domain.rstrip(".").lower()
    if args.no_color:
        disable_color()
    if hasattr(args, 'proxy') and args.proxy:
        if not args.proxy.startswith(("http://", "https://", "socks4://", "socks5://", "socks5h://", "socks4a://")):
            parser.error(f"invalid proxy URL scheme: {args.proxy!r} (must start with http://, https://, socks4://, socks5://, socks5h://, or socks4a://)")
    if hasattr(args, 'vuln_proxy') and args.vuln_proxy:
        if not args.vuln_proxy.startswith(("http://", "https://", "socks4://", "socks5://", "socks5h://", "socks4a://")):
            parser.error(f"invalid vuln-proxy URL scheme: {args.vuln_proxy!r}")
    if args.only and args.skip and (args.only & args.skip):
        parser.error("phase(s) cannot be both --only and --skip: " + ", ".join(sorted(args.only & args.skip)))
    if args.quiet:
        from reconchain.utils import log as _quiet_log
        def _quiet_log_impl(lvl, msg):
            if lvl in ("ok", "err", "warn"):
                _quiet_log(lvl, msg)
        import reconchain.utils as _utils
        _utils.log = _quiet_log_impl
        import reconchain.phases as _phases
        _phases.log = _quiet_log_impl
        import reconchain.reporting as _rep
        _rep.log = _quiet_log_impl
        import reconchain.pipeline as _pl
        _pl.log = _quiet_log_impl
    domains = [d.strip() for d in args.domain.split(",") if d.strip()]
    if not domains:
        parser.error("the following arguments are required: -d/--domain (or use -i for interactive)")
    for domain in domains:
        if not _is_valid_hostname(domain):
            parser.error(f"invalid domain: {domain}")
    try:
        if args.daemon:
            daemon_args = [a for a in sys.argv if a != "--daemon"]
            for domain in domains:
                fd, pidfile_path = tempfile.mkstemp(prefix=f"reconchain_{domain.replace('.', '_')}_", suffix=".pid")
                try:
                    os.write(fd, b"")
                    os.close(fd)
                    proc = subprocess.Popen([sys.executable] + daemon_args + ["-d", domain], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                    with open(pidfile_path, "w") as pf:
                        pf.write(str(proc.pid))
                    import atexit
                    def _cleanup_pidfile(path=pidfile_path):
                        try:
                            with open(path) as f:
                                pid = int(f.read().strip())
                            if not _pid_alive(pid):
                                os.unlink(path)
                        except Exception:
                            pass
                    atexit.register(_cleanup_pidfile)
                except Exception:
                    with contextlib.suppress(Exception):
                        os.unlink(pidfile_path)
                    raise
                log("info", f"daemon started for {domain} (PID {proc.pid}); check status with: --status {domain}")
            return 0
        results = []
        for domain in domains:
            log("info", f"{'='*60}")
            log("info", f"Starting scan for domain: {domain}")
            log("info", f"{'='*60}")
            rc = _run_single(domain, args)
            results.append((domain, rc))
            if rc != 0:
                log("warn", f"Scan for {domain} exited with code {rc}")
        failed = [(d, c) for d, c in results if c != 0]
        if failed:
            log("warn", f"{len(failed)} domain(s) had errors: {', '.join(d for d, _ in failed)}")
            return 1
        return 0
    except KeyboardInterrupt:
        log("warn", "interrupted")
        return 130
