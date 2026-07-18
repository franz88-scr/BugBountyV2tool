"""Argument parser for ReconChain CLI."""
from __future__ import annotations

import argparse
import os
from typing import Set

from reconchain.config import VALID_PHASES
from reconchain.process import MAX_PARALLEL_JOBS, _parse_phase_csv


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for reconchain CLI.

    Returns an ``ArgumentParser`` with 8 argument groups that organize
    170+ flags by purpose, making ``--help`` output scannable.
    """
    p = argparse.ArgumentParser(
        prog="reconchain",
        description="Chain recon tools into a single orchestrated pipeline.",
        epilog=(
            "examples:\n"
            "  reconchain -d example.com                    # full scan with defaults\n"
            "  reconchain -d example.com --fast             # quick recon only\n"
            "  reconchain -d example.com --safe              # conservative VM-safe mode\n"
            "  reconchain -d example.com --only 01-RECON     # run a single phase\n"
            "  reconchain -d example.com --daemon            # run in background\n"
            "  reconchain -i                                # interactive wizard\n"
            "  reconchain --batch targets.txt                # scan multiple domains\n"
            "  reconchain --status list                      # show active scans\n"
            "  reconchain -d example.com --format sarif     # CI/CD-friendly output\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Target ───────────────────────────────────────────────────────
    g_target = p.add_argument_group("target", "what to scan")
    g_target.add_argument("-d", "--domain", type=str, default="", help="target root domain (or comma-separated list for multi-domain), e.g. example.com or example.com,test.com")
    g_target.add_argument("-o", "--out", default="", help="output directory (default: ./out/<domain>)")
    g_target.add_argument("-i", "--interactive", action="store_true", help="interactive setup wizard with menu navigation, presets, and profile save/load")
    g_target.add_argument("--only", default=set(), type=_parse_phase_csv, help="comma-separated phases to run, e.g. 01-RECON,02-RESOLVE,04-SCAN")
    g_target.add_argument("--skip", default=set(), type=_parse_phase_csv, help="comma-separated phases to skip, e.g. 10-TLSCMS,23-RACE")
    g_target.add_argument("--resume", action="store_true", help="resume from ./out/state.json if it exists (only for the same target domain)")
    g_target.add_argument("--force", action="store_true", help="re-run all phases even if output files already exist")
    g_target.add_argument("--batch", type=str, default="", help="batch scan: file with one domain per line")
    g_target.add_argument("--compare", type=str, nargs=2, metavar=("OLD_DIR", "NEW_DIR"), help="compare two scan outputs")
    g_target.add_argument("--review", action="store_true", help="interactive finding review mode (confirm/FP/mark)")

    # ── Authentication ───────────────────────────────────────────────
    g_auth = p.add_argument_group("authentication", "credentials and session handling")
    g_auth.add_argument("--cookie", type=str, default="", help="cookie string to include with HTTP requests (e.g. 'session=abc')")
    g_auth.add_argument("--cookie-a", type=str, default="", help="first session cookie for IDOR cross-session diffing")
    g_auth.add_argument("--cookie-b", type=str, default="", help="second session cookie for IDOR cross-session diffing")
    g_auth.add_argument("--no-fix-permissions", action="store_true", default=False, help="do not auto-fix overly permissive cookies.txt file permissions")
    g_auth.add_argument("--header", type=str, action="append", default=[], dest="extra_headers", help="extra HTTP header (can be repeated), e.g. --header 'Authorization: Bearer xyz'")
    g_auth.add_argument("--auth-bearer", type=str, default="", help="Bearer token for Authorization header (e.g. --auth-bearer 'mytoken123')")
    g_auth.add_argument("--auth-api-key", type=str, default="", help="API key value for custom header (e.g. --auth-api-key 'key123')")
    g_auth.add_argument("--auth-api-key-header", type=str, default="X-API-Key", help="custom header name for API key (default: X-API-Key)")
    g_auth.add_argument("--auth-client-cert", type=str, default="", help="path to client certificate PEM for mTLS (e.g. --auth-client-cert /path/to/cert.pem)")
    g_auth.add_argument("--auth-basic", type=str, default="", help="basic auth credentials as user:pass (e.g. --auth-basic 'admin:password')")

    # ── Proxy ────────────────────────────────────────────────────────
    g_proxy = p.add_argument_group("proxy", "network proxy settings")
    g_proxy.add_argument("--proxy", type=str, default="", help="proxy URL for all phases, e.g. socks5://127.0.0.1:9050")
    g_proxy.add_argument("--vuln-proxy", type=str, default="", help="proxy URL only for vulnerability probing phases (overrides --proxy for phases 09+), e.g. socks5://127.0.0.1:9050")
    g_proxy.add_argument("--proxy-timeout-multiplier", type=float, default=1.5, help="multiplier applied to tool timeouts when proxy is active (default: 1.5)")

    # ── Performance ──────────────────────────────────────────────────
    g_perf = p.add_argument_group("performance", "concurrency and resource limits")
    g_perf.add_argument("-j", "--jobs", type=int, default=MAX_PARALLEL_JOBS, help=f"max parallel phases (default: {MAX_PARALLEL_JOBS})")
    g_perf.add_argument("--max-procs", type=int, default=0, help="max concurrent tool subprocesses across all phases (0 = unlimited, default: 0)")
    g_perf.add_argument("--adaptive", action="store_true", default=True, help="enable adaptive resource monitor (auto-scales job concurrency AND OS subprocesses based on CPU/RAM)")
    g_perf.add_argument("--no-adaptive", action="store_false", dest="adaptive", help="disable adaptive monitor, use static concurrency")
    g_perf.add_argument("--adaptive-start", type=int, default=min(os.cpu_count() or 4, 6), help="starting concurrency for adaptive monitor (default: auto, 2-6)")
    g_perf.add_argument("--adaptive-max", type=int, default=0, help="max concurrency cap for adaptive monitor (0 = auto based on CPU/RAM, default: 0)")
    g_perf.add_argument("--adaptive-max-procs", type=int, default=0, help="hard cap on concurrent subprocesses (0 = auto scales with job concurrency, default: 0)")
    g_perf.add_argument("--adaptive-interval", type=float, default=5.0, help="monitor check interval in seconds (default: 5.0)")
    g_perf.add_argument("--adaptive-cpu-high", type=int, default=80, help="CPU%% threshold to reduce concurrency (default: 80)")
    g_perf.add_argument("--adaptive-ram-crit", type=float, default=1.0, help="RAM free GB threshold to reduce concurrency (default: 1.0)")
    g_perf.add_argument("--safe", action="store_true", default=False, help="very conservative mode for VMs: reduced concurrency, sample sizes, memory limits, and serial tool execution")
    g_perf.add_argument("--fast", action="store_true", help="fast mode: only run essential recon phases (01-RECON, 02-RESOLVE, 04-SCAN, 05-HARVEST), skipping vuln scanning")
    g_perf.add_argument("--profile", type=str, default="", choices=["quick"], help="scan profile: quick skips ~37 redundant/low-signal phases (default: full)")
    g_perf.add_argument("--delay", type=float, default=0.0, help="seconds to wait between requests (polite mode)")
    g_perf.add_argument("--rate-limit", type=int, default=0, help="max requests per second (0 = unlimited)")
    g_perf.add_argument("--rate-limit-per-domain", type=int, default=0, help="max requests per second per domain (0 = unlimited, default: 0)")
    g_perf.add_argument("--parallel", action="store_true", default=True, help="run independent phases in parallel (default: on)")
    g_perf.add_argument("--no-parallel", action="store_false", dest="parallel", help="run phases sequentially (useful for debugging)")
    g_perf.add_argument("--sqlmap-level", type=int, default=1, choices=range(1, 6), help="sqlmap --level (1-5, default: 1; higher = deeper but slower)")
    g_perf.add_argument("--sqlmap-risk", type=int, default=1, choices=range(1, 4), help="sqlmap --risk (1-3, default: 1; higher = more payloads but destructive)")

    # ── Sampling ─────────────────────────────────────────────────────
    g_samp = p.add_argument_group("sampling", "artifact sample sizes per phase")
    g_samp.add_argument("--sample", action="store_true", help="downsample artifacts to 1 entry for faster downstream testing (default: keep all results)")
    g_samp.add_argument("--sample-mode", choices=["minimal", "normal", "all"], default="normal", help="global sample size: minimal=1 per tool, normal=default sizes, all=no limits (default: normal)")
    g_samp.add_argument("--keep-all", action="store_true", help=argparse.SUPPRESS)
    g_samp.add_argument("--exclude-tags", type=str, default="", help="nuclei tags to exclude (comma-separated), e.g. 'info,tech'")
    g_samp.add_argument("--sample-urls-fuzz", type=int, default=200, help="number of URLs to sample for fuzzing (default: 200)")
    g_samp.add_argument("--sample-urls-params", type=int, default=50, help="number of URLs to sample for parameter discovery (default: 50)")
    g_samp.add_argument("--sample-hosts-ssl", type=int, default=10, help="number of hosts to sample for SSL/TLS scanning via testssl (default: 10)")
    g_samp.add_argument("--sample-hosts-origin", type=int, default=10, help="number of hosts to sample for origin bypass scans (favicon, crt.sh resolve, ipinfo) (default: 10)")
    g_samp.add_argument("--sample-hosts-cloud", type=int, default=5, help="number of hosts to check for cloud bucket exposure (default: 5)")
    g_samp.add_argument("--sample-hosts-git", type=int, default=5, help="number of hosts to scan for Git exposure (default: 5)")
    g_samp.add_argument("--sample-hosts-graphql", type=int, default=5, help="number of hosts for GraphQL introspection (default: 5)")
    g_samp.add_argument("--sample-hosts-waf", type=int, default=5, help="number of hosts for WAF detection (default: 5)")
    g_samp.add_argument("--sample-endpoints-l", type=int, default=20, help="number of endpoints to sample for auth bypass / mass assignment probes (default: 20)")
    g_samp.add_argument("--sample-urls-xss-blind", type=int, default=20, help="number of URLs to probe for blind XSS via OAST (default: 20)")
    g_samp.add_argument("--sample-urls-domxss", type=int, default=30, help="number of URLs for DOM XSS browser automation (default: 30)")
    g_samp.add_argument("--sample-hosts-h2smuggle", type=int, default=10, help="number of hosts for H2/H3 attack surface testing (default: 10)")
    g_samp.add_argument("--sample-hosts-frameworks", type=int, default=20, help="number of hosts for framework detection and vuln checks (default: 20)")
    g_samp.add_argument("--sample-urls-ssti", type=int, default=5, help="number of SSTI probe URLs (default: 5)")
    g_samp.add_argument("--sample-endpoints-post", type=int, default=5, help="number of endpoints for POST mass-assignment probes (default: 5)")
    g_samp.add_argument("--sample-endpoints-cors", type=int, default=10, help="number of endpoints for CORS misconfiguration probes (default: 10)")
    g_samp.add_argument("--sample-urls-nosqli", type=int, default=30, help="number of URLs for NoSQL injection probes (default: 30)")
    g_samp.add_argument("--sample-endpoints-race", type=int, default=10, help="number of endpoints for race condition testing (default: 10)")
    g_samp.add_argument("--sample-hosts-jwt", type=int, default=20, help="number of hosts for JWT analysis (default: 20)")
    g_samp.add_argument("--sample-urls-xxe", type=int, default=10, help="number of URLs for XXE injection probes (default: 10)")
    g_samp.add_argument("--sample-urls-cmdi", type=int, default=30, help="number of URLs for command injection detection (default: 30)")
    g_samp.add_argument("--sample-endpoints-sspp", type=int, default=10, help="number of API endpoints for prototype pollution probes (default: 10)")
    g_samp.add_argument("--sample-hosts-cached", type=int, default=10, help="number of hosts for cache poisoning probes (default: 10)")
    g_samp.add_argument("--sample-urls-depcheck", type=int, default=30, help="number of JS URLs for dependency vulnerability scanning (default: 30)")
    g_samp.add_argument("--sample-urls-redirect", type=int, default=30, help="number of URLs for open redirect detection (default: 30)")
    g_samp.add_argument("--sample-hosts-clickjack", type=int, default=20, help="number of targets for clickjacking detection (default: 20)")
    g_samp.add_argument("--sample-urls-crlf", type=int, default=20, help="number of URLs for CRLF injection testing (default: 20)")
    g_samp.add_argument("--sample-hosts-ratelimit", type=int, default=10, help="number of targets for rate limiting detection (default: 10)")
    g_samp.add_argument("--sample-endpoints-corsadv", type=int, default=10, help="number of endpoints for advanced CORS testing (default: 10)")
    g_samp.add_argument("--sample-hosts-jwtadv", type=int, default=20, help="number of targets for advanced JWT analysis (default: 20)")
    g_samp.add_argument("--sample-urls-upload", type=int, default=10, help="number of upload endpoints to test (default: 10)")
    g_samp.add_argument("--sample-hosts-smuggle", type=int, default=10, help="number of hosts for request smuggling testing (default: 10)")
    g_samp.add_argument("--sample-endpoints-oauth", type=int, default=10, help="number of OAuth endpoints to test (default: 10)")
    g_samp.add_argument("--sample-endpoints-pwreset", type=int, default=10, help="number of password reset endpoints to test (default: 10)")
    g_samp.add_argument("--sample-hosts-websocket", type=int, default=10, help="number of hosts for WebSocket testing (default: 10)")
    g_samp.add_argument("--sample-urls-ldap", type=int, default=20, help="number of URLs for LDAP injection testing (default: 20)")
    g_samp.add_argument("--sample-endpoints-deserial", type=int, default=10, help="number of API endpoints for deserialization testing (default: 10)")
    g_samp.add_argument("--sample-urls-csrf", type=int, default=20, help="number of URLs for CSRF testing (default: 20)")
    g_samp.add_argument("--sample-hosts-sessionfix", type=int, default=10, help="number of hosts for session fixation testing (default: 10)")
    g_samp.add_argument("--sample-endpoints-saml", type=int, default=10, help="number of endpoints for SAML bypass testing (default: 10)")
    g_samp.add_argument("--sample-users-spray", type=int, default=20, help="number of usernames for password spray (default: 20)")
    g_samp.add_argument("--sample-hosts-cookie", type=int, default=20, help="number of hosts for cookie audit (default: 20)")
    g_samp.add_argument("--sample-urls-posttest", type=int, default=30, help="number of URLs for POST auth bypass (default: 30)")
    g_samp.add_argument("--sample-urls-methodoverride", type=int, default=20, help="number of URLs for method override testing (default: 20)")
    g_samp.add_argument("--sample-hosts-forcedbrowse", type=int, default=20, help="number of hosts for forced browsing (default: 20)")
    g_samp.add_argument("--sample-urls-casebypass", type=int, default=20, help="number of URLs for case-sensitivity bypass (default: 20)")
    g_samp.add_argument("--sample-urls-apipage", type=int, default=20, help="number of URLs for hidden API page discovery (default: 20)")
    g_samp.add_argument("--sample-urls-tabnab", type=int, default=30, help="number of URLs for reverse tabnabbing (default: 30)")
    g_samp.add_argument("--sample-urls-apikeyleak", type=int, default=30, help="number of URLs for API key leak detection (default: 30)")
    g_samp.add_argument("--sample-urls-redirabuse", type=int, default=20, help="number of redirect URLs for abuse testing (default: 20)")
    g_samp.add_argument("--sample-urls-logtrigger", type=int, default=20, help="number of URLs for log injection triggers (default: 20)")
    g_samp.add_argument("--sample-urls-xssstored", type=int, default=10, help="number of URLs for stored XSS testing (default: 10)")
    g_samp.add_argument("--sample-hosts-hostabuse", type=int, default=10, help="number of hosts for host header abuse (default: 10)")
    g_samp.add_argument("--sample-urls-authbypassadv", type=int, default=20, help="number of URLs for advanced auth bypass (default: 20)")
    g_samp.add_argument("--sample-urls-ssi", type=int, default=20, help="number of URLs for SSI injection (default: 20)")
    g_samp.add_argument("--sample-urls-jsoninject", type=int, default=20, help="number of URLs for JSON injection (default: 20)")
    g_samp.add_argument("--sample-urls-nullbyte", type=int, default=20, help="number of URLs for null byte injection (default: 20)")
    g_samp.add_argument("--sample-urls-doubleencod", type=int, default=20, help="number of URLs for double encoding bypass (default: 20)")
    g_samp.add_argument("--sample-urls-unicode", type=int, default=20, help="number of URLs for unicode bypass (default: 20)")
    g_samp.add_argument("--sample-hosts-postmsg", type=int, default=15, help="number of hosts for postMessage XSS (default: 15)")
    g_samp.add_argument("--sample-hosts-jsonp", type=int, default=20, help="number of hosts for JSONP hijacking (default: 20)")
    g_samp.add_argument("--sample-hosts-sri", type=int, default=20, help="number of hosts for SRI check (default: 20)")
    g_samp.add_argument("--sample-hosts-mixedcontent", type=int, default=20, help="number of hosts for mixed content check (default: 20)")
    g_samp.add_argument("--sample-hosts-hstspreload", type=int, default=20, help="number of hosts for HSTS preload check (default: 20)")
    g_samp.add_argument("--sample-hosts-thirdpartyjs", type=int, default=15, help="number of hosts for third-party JS audit (default: 15)")
    g_samp.add_argument("--sample-hosts-browserstorage", type=int, default=15, help="number of hosts for browser storage audit (default: 15)")
    g_samp.add_argument("--sample-urls-rfi", type=int, default=20, help="number of URLs for RFI probing (default: 20)")
    g_samp.add_argument("--sample-hosts-webdav", type=int, default=10, help="number of hosts for WebDAV testing (default: 10)")
    g_samp.add_argument("--sample-hosts-snmp", type=int, default=10, help="number of hosts for SNMP testing (default: 10)")
    g_samp.add_argument("--sample-hosts-banner", type=int, default=15, help="number of hosts for banner fingerprinting (default: 15)")
    g_samp.add_argument("--sample-hosts-phpinfo", type=int, default=15, help="number of hosts for phpinfo detection (default: 15)")
    g_samp.add_argument("--sample-hosts-srvstatus", type=int, default=15, help="number of hosts for server-status check (default: 15)")
    g_samp.add_argument("--sample-urls-errorleak", type=int, default=20, help="number of URLs for error leakage check (default: 20)")
    g_samp.add_argument("--sample-hosts-wildcarddns", type=int, default=10, help="number of hosts for wildcard DNS check (default: 10)")
    g_samp.add_argument("--sample-hosts-dnsrebind", type=int, default=10, help="number of hosts for DNS rebinding check (default: 10)")
    g_samp.add_argument("--sample-hosts-iisaspnet", type=int, default=10, help="number of hosts for IIS/ASP.NET probing (default: 10)")
    g_samp.add_argument("--sample-hosts-tomcat", type=int, default=10, help="number of hosts for Tomcat probing (default: 10)")
    g_samp.add_argument("--sample-hosts-nodejs", type=int, default=10, help="number of hosts for Node.js probing (default: 10)")
    g_samp.add_argument("--sample-hosts-laravel", type=int, default=10, help="number of hosts for Laravel probing (default: 10)")
    g_samp.add_argument("--sample-hosts-django", type=int, default=10, help="number of hosts for Django probing (default: 10)")
    g_samp.add_argument("--sample-hosts-symfony", type=int, default=10, help="number of hosts for Symfony probing (default: 10)")
    g_samp.add_argument("--sample-hosts-cicd", type=int, default=10, help="number of hosts for CI/CD file exposure (default: 10)")
    g_samp.add_argument("--sample-hosts-docker", type=int, default=10, help="number of hosts for Docker registry exposure (default: 10)")
    g_samp.add_argument("--sample-hosts-k8s", type=int, default=10, help="number of hosts for Kubernetes exposure (default: 10)")
    g_samp.add_argument("--sample-hosts-terraform", type=int, default=10, help="number of hosts for Terraform state exposure (default: 10)")
    g_samp.add_argument("--sample-hosts-envdeep", type=int, default=10, help="number of hosts for deep env file scanning (default: 10)")
    g_samp.add_argument("--sample-hosts-gqlabuse", type=int, default=10, help="number of GraphQL endpoints for abuse testing (default: 10)")
    g_samp.add_argument("--sample-urls-apiversion", type=int, default=20, help="number of API URLs for versioning bypass (default: 20)")
    g_samp.add_argument("--sample-hosts-lbdetect", type=int, default=15, help="number of hosts for load balancer detection (default: 15)")
    g_samp.add_argument("--sample-hosts-vhost", type=int, default=10, help="number of hosts for virtual host enumeration (default: 10)")
    g_samp.add_argument("--sample-urls-ratelimitbypass", type=int, default=20, help="number of URLs for rate limit bypass (default: 20)")

    # ── Reporting ────────────────────────────────────────────────────
    g_rep = p.add_argument_group("reporting", "output formats and notifications")
    g_rep.add_argument("--format", type=str, default="html", choices=["html", "md", "json", "sarif"], help="report format (default: html; sarif produces results.sarif for GitHub/GitLab CI)")
    g_rep.add_argument("--no-tui", action="store_true", help="disable terminal UI dashboard")
    g_rep.add_argument("--no-confidence", action="store_true", help="disable confidence scoring")
    g_rep.add_argument("--no-poc", action="store_true", help="disable auto-PoC generation")
    g_rep.add_argument("--no-risk", action="store_true", help="disable risk scoring")
    g_rep.add_argument("--no-profile", action="store_true", help="disable target profiling")
    g_rep.add_argument("--attack-graph", action="store_true", help="generate interactive attack surface graph")
    g_rep.add_argument("--incremental", action="store_true", help="only report findings new since last scan (diff mode)")

    # ── Integration ──────────────────────────────────────────────────
    g_int = p.add_argument_group("integration", "API server, dashboard, and notifications")
    g_int.add_argument("--api-port", type=int, default=0, help="start REST API server on this port (0 = disabled, default: 0)")
    g_int.add_argument("--daemon", action="store_true", help="run in background; check progress with --status <domain>")
    g_int.add_argument("--status", type=str, default="", help="show live progress of a running scan (provide domain name, or 'list' to show all active scans)")
    g_int.add_argument("--notify", type=str, default="", help="notification webhook URL (Slack/Discord/Telegram bot:chat)")
    g_int.add_argument("--dashboard", action="store_true", help="start live web dashboard (auto-opens browser)")
    g_int.add_argument("--dashboard-port", type=int, default=0, help="dashboard port (0=disabled, default: 0; set via --dashboard)")
    g_int.add_argument("--dashboard-host", type=str, default="127.0.0.1", help="dashboard bind address (default: 127.0.0.1)")
    g_int.add_argument("--dashboard-browser", action="store_true", default=True, help="auto-open browser when dashboard starts")
    g_int.add_argument("--no-dashboard-browser", action="store_false", dest="dashboard_browser")
    g_int.add_argument("--bot", type=str, default="", choices=["discord", "slack", ""], help="start companion bot (discord or slack)")
    g_int.add_argument("--bot-token", type=str, default="", help="bot token (or set DISCORD_BOT_TOKEN/SLACK_BOT_TOKEN)")
    g_int.add_argument("--bot-channel", type=str, default="", help="bot channel ID (or set DISCORD_CHANNEL_ID/SLACK_CHANNEL_ID)")
    g_int.add_argument("--bot-mention", action="store_true", default=True, help="@channel on critical findings")
    g_int.add_argument("--no-bot-mention", action="store_false", dest="bot_mention")

    # ── Advanced ─────────────────────────────────────────────────────
    g_adv = p.add_argument_group("advanced", "AI, plugins, distributed scanning")
    g_adv.add_argument("--dos", action="store_true", default=False, dest="dos_mode", help="enable DoS-like attack phases (race bursts, HTTP smuggling, GraphQL depth DoS, H2 rapid reset, credential spray) -- disabled by default")
    g_adv.add_argument("--no-dos", action="store_false", dest="dos_mode", help="disable DoS-like attack phases to avoid service disruption")
    g_adv.add_argument("--ai-provider", type=str, default="none", choices=["openai", "anthropic", "ollama", "dry-run", "none"], help="AI LLM provider (default: none)")
    g_adv.add_argument("--ai-model", type=str, default="", help="specific AI model name (e.g. gpt-4o, claude-3-5-sonnet, llama3)")
    g_adv.add_argument("--no-ai", action="store_true", help="disable all AI features")
    g_adv.add_argument("--exploit-chains", action="store_true", default=True, help="enable exploit chain analysis (default: on)")
    g_adv.add_argument("--no-exploit-chains", action="store_false", dest="exploit_chains")
    g_adv.add_argument("--distributed", action="store_true", help="enable distributed scanning via SSH")
    g_adv.add_argument("--distributed-hosts", type=str, nargs="+", default=[], help="list of remote hosts for distributed scanning")
    g_adv.add_argument("--distributed-workers", type=int, default=5, help="max concurrent SSH workers (default: 5)")
    g_adv.add_argument("--distributed-ssh-key", type=str, default="", help="path to SSH private key")
    g_adv.add_argument("--distributed-ssh-user", type=str, default="root", help="SSH username for remote hosts")
    g_adv.add_argument("--plugins-dir", type=str, default="", help="directory containing plugin .py files")
    g_adv.add_argument("--list-plugins", action="store_true", help="list discovered plugins and exit")
    g_adv.add_argument("--no-plugins", action="store_true", help="disable plugin loading")

    # ── Meta ─────────────────────────────────────────────────────────
    g_meta = p.add_argument_group("meta", "configuration and display")
    g_meta.add_argument("-q", "--quiet", action="store_true", help="suppress info-level logs")
    g_meta.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    g_meta.add_argument("--config", type=str, default="", help="path to TOML config file (default: searches ./reconchain.cfg, ~/.config/reconchain/reconchain.cfg)")
    g_meta.add_argument("--dry-run", action="store_true", help="preview commands without executing anything")
    g_meta.add_argument("--gen-config", action="store_true", help="generate an example reconchain.cfg and exit")

    return p
