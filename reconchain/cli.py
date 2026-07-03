"""CLI entry points: build_parser, main, interactive_setup."""
from __future__ import annotations
import argparse
import asyncio
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from reconchain.config import VALID_PHASES, FAST_PHASES, _HOSTNAME_RE, __version__
from reconchain.phases import _RECON_LEVELS
from reconchain.pipeline import run_pipeline
from reconchain.process import _parse_phase_csv, _domain_arg, _cleanup_child_procs, MAX_PARALLEL_JOBS
from reconchain.utils import (
    C, log, ScanStatus, _is_valid_hostname, _auto_detect_proxy,
    disable_color,
)
from reconchain.utils import log as _orig_log


def _prompt(prompt_text: str, default: str = "", validator: Optional[Callable[[str], bool]] = None, error_msg: str = "") -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        val = input(f"  {prompt_text}{suffix}: ").strip()
        if not val:
            return default
        if validator is None or validator(val):
            return val
        log("err", error_msg or "invalid input")


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
{C["g"]}   ║  {C["d"]}41+ tools  |  51 phases  |  DAG stages  |  Resumable{C["g"]}   ║
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
    proxy = _auto_detect_proxy()

    def _validate_count(v: str) -> bool:
        return v.lower() == "all" or (v.isdigit() and int(v) > 0)

    sample_fuzz = _prompt("Number of URLs to fuzz (enter 'all' for every URL, more = thorough but slow)", default="5", validator=_validate_count, error_msg="Enter a positive number or 'all'")
    sample_params = _prompt("Number of URLs for parameter discovery (enter 'all' for every URL, more = thorough but slow)", default="50", validator=_validate_count, error_msg="Enter a positive number or 'all'")
    speed = _prompt_yes_no("Fast mode — reduce sample sizes for quicker scans (thorough but slow by default)", default=False)
    print(f"\n{C['b']}Authentication:{C['r']}")
    cookie = _prompt("Cookie string (e.g. 'session=abc123'), or leave empty", default="")
    extra_headers_raw = _prompt("Extra HTTP headers, comma-separated (e.g. 'Authorization: Bearer xyz,X-Custom: val'), or leave empty", default="")
    extra_headers_list: List[str] = [h.strip() for h in extra_headers_raw.split(",") if h.strip()] if extra_headers_raw else []
    extra_phases: Set[str] = set()
    if level in ("2", "full"):
        _all_extra = [
            ("04b-TAKEOVER-VALIDATE", "Confirm dangling CNAME exploitability"),
            ("05b-APISPEC", "API spec discovery (Swagger/OpenAPI/GraphQL SDL)"),
            ("11b-SQLMAP", "SQL injection via sqlmap (pre-filtered)"),
            ("12-SSTI", "SSTI fuzzing"),
            ("14-ORIGIN", "Origin IP bypass (Cloudflare)"),
            ("15-SECRETS", "Deep JS secret scanning"),
            ("16A-AUTHZ", "Auth bypass header injection"),
            ("16B-MASSASSIGN", "Mass assignment field discovery"),
            ("17-IDOR", "ID manipulation / predictable IDs"),
            ("17B-SSRFMETA", "Cloud metadata exfiltration (SSRF confirmed)"),
            ("18-CLOUD", "Cloud bucket discovery (AWS/GCP/Azure)"),
            ("19-GIT", "Git exposure scanning (.git + trufflehog)"),
            ("20-GRAPHQL", "GraphQL introspection + schema analysis"),
            ("21-WAF", "WAF detection (50+ vendor signatures)"),
            ("22-NOSQLI", "NoSQL injection probes"),
            ("23-RACE", "Race condition detection"),
            ("24-JWT", "JWT token analysis"),
            ("25-XXE", "XML external entity injection"),
            ("26-CMDINJECT", "OS command injection detection"),
            ("27-SSPP", "Server-side prototype pollution"),
            ("28-CACHED", "Web cache poisoning/deception"),
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
            ("39-OAUTH", "OAuth misconfiguration testing"),
            ("40-PWRESET", "Password reset logic testing"),
            ("41-WEBSOCKET", "WebSocket security testing"),
            ("42-LDAP", "LDAP injection detection"),
            ("43-DESERIAL", "Deserialization attack detection"),
            ("44-CHAIN", "Cross-phase finding correlation"),
            ("45-EVIDENCE", "Capture request/response for confirmed findings"),
            ("46-BUCKET", "Cloud storage bucket enumeration (S3/Azure/GCP)"),
            ("47-CDN", "CDN provider detection + origin IP discovery"),
            ("48-CONTENT", "Content discovery via common path probing"),
        ]
        print(f"\n{C['b']}Additional phases:{C['r']}")
        for p, desc in _all_extra:
            print(f"  {C['y']}{p:20}{C['r']} {desc}")
        if level == "full":
            skip_raw = _prompt("Phases to SKIP (comma-separated, or empty to run all)", default="")
            skipped = {s.strip().upper() for s in skip_raw.split(",") if s.strip()}
            extra_phases = {p for p, _ in _all_extra} - skipped
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
    print(f"   SQLmap level/risk:{C['y']} {sqlmap_level}/{sqlmap_risk}{C['r']}")
    print(f"   Delay:            {C['y']}{delay}s{C['r']}")
    print(f"   Cookie:           {C['y']}{'set' if cookie else 'none'}{C['r']}")
    print(f"   Extra headers:    {C['y']}{len(extra_headers_list)} set{C['r']}")
    print(f"   Resume:           {C['y']}{'yes' if resume else 'no'}{C['r']}")
    print(f"   Force:            {C['y']}{'yes' if force else 'no'}{C['r']}")
    print(f"   Fast mode:        {C['y']}{'yes' if speed else 'no'}{C['r']}")
    print(f" {C['b']}{'─' * 60}{C['r']}")
    if not _prompt_yes_no("Start scan", default=True):
        log("info", "Aborted by user")
        sys.exit(0)

    ns = argparse.Namespace()
    ns.domain = domain
    ns.out = out
    ns.only = selected
    ns.skip = set()
    ns.jobs = jobs
    ns.fast = False
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
    ns.rate_limit = 0

    def _resolve_count(v: str) -> int:
        return sys.maxsize if v.lower() == "all" else int(v)

    ns.sample_urls_fuzz = _resolve_count(sample_fuzz)
    ns.sample_urls_params = _resolve_count(sample_params)
    ns.cookie = cookie
    ns.extra_headers = extra_headers_list if extra_headers_list else []
    ns.daemon = False
    ns.status = ""
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
    ns.sample_urls_ldap = 20
    ns.sample_endpoints_deserial = 10
    ns.sample_hosts_ssl = 10
    ns.sample_hosts_origin = 10
    ns.sample_endpoints_cors = 10
    ns.sample_endpoints_l = 20
    ns.sample_endpoints_post = 5
    if speed:
        ns.sample_urls_nosqli = min(ns.sample_urls_nosqli, 5)
        ns.sample_urls_cmdi = min(ns.sample_urls_cmdi, 5)
        ns.sample_urls_xxe = min(ns.sample_urls_xxe, 3)
        ns.sample_urls_crlf = min(ns.sample_urls_crlf, 5)
        ns.sample_urls_redirect = min(ns.sample_urls_redirect, 5)
        ns.sample_urls_ldap = min(ns.sample_urls_ldap, 5)
        ns.sample_urls_depcheck = min(ns.sample_urls_depcheck, 5)
        ns.sample_urls_upload = min(ns.sample_urls_upload, 3)
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
        ns.sample_endpoints_race = min(ns.sample_endpoints_race, 3)
        ns.sample_endpoints_cors = min(ns.sample_endpoints_cors, 3)
        ns.sample_endpoints_corsadv = min(ns.sample_endpoints_corsadv, 3)
        ns.sample_endpoints_sspp = min(ns.sample_endpoints_sspp, 3)
        ns.sample_endpoints_l = min(ns.sample_endpoints_l, 5)
        ns.sample_endpoints_post = min(ns.sample_endpoints_post, 2)
        ns.sample_endpoints_oauth = min(ns.sample_endpoints_oauth, 3)
        ns.sample_endpoints_pwreset = min(ns.sample_endpoints_pwreset, 3)
        ns.sample_endpoints_deserial = min(ns.sample_endpoints_deserial, 3)
    return ns


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reconchain", description="Chain recon tools into a single orchestrated pipeline.")
    p.add_argument("-d", "--domain", type=str, default="", help="target root domain (or comma-separated list for multi-domain), e.g. example.com or example.com,test.com")
    p.add_argument("-o", "--out", default="", help="output directory (default: ./out/<domain>)")
    p.add_argument("-i", "--interactive", action="store_true", help="interactive setup wizard (prompts for domain, level, etc.)")
    p.add_argument("--only", default=set(), type=_parse_phase_csv, help="comma-separated phases to run, e.g. 01-RECON,02-RESOLVE,04-SCAN")
    p.add_argument("--skip", default=set(), type=_parse_phase_csv, help="comma-separated phases to skip, e.g. 10-TLSCMS,23-RACE")
    p.add_argument("-j", "--jobs", type=int, default=MAX_PARALLEL_JOBS, help=f"max parallel external processes (default: {MAX_PARALLEL_JOBS})")
    p.add_argument("--fast", action="store_true", help="fast mode: only run essential recon phases (01-RECON, 02-RESOLVE, 04-SCAN, 05-HARVEST), skipping vuln scanning")
    p.add_argument("--resume", action="store_true", help="resume from ./out/state.json if it exists (only for the same target domain)")
    p.add_argument("--force", action="store_true", help="re-run all phases even if output files already exist")
    p.add_argument("--sample", action="store_true", help="downsample artifacts to 1 entry for faster downstream testing (default: keep all results)")
    p.add_argument("--keep-all", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("-q", "--quiet", action="store_true", help="suppress info-level logs")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    p.add_argument("--proxy", type=str, default="", help="proxy URL for tools that support it, e.g. socks5://127.0.0.1:9050")
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
                pidfile = Path(tempfile.gettempdir()) / f"reconchain_{domain.replace('.', '_')}.pid"
                proc = subprocess.Popen([sys.executable] + daemon_args + ["-d", domain], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                pidfile.write_text(str(proc.pid))
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
