"""Report generation: summary JSON, HTML, Markdown, text."""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from reconchain.config import __version__
from reconchain.utils import ensure, read_lines, count_nonblank, log

HTML_CSS = """
:root{--fg:#e6edf3;--bg:#0d1117;--mut:#8b949e;--acc:#58a6ff;--warn:#d29922;--ok:#3fb950;--err:#f85149;}
*{box-sizing:border-box}body{font-family:ui-monospace,Menlo,Consolas,monospace;
background:var(--bg);color:var(--fg);margin:0;padding:32px;line-height:1.5}
h1{font-size:1.6em;margin:0 0 4px;color:var(--acc)}
h2{font-size:1.2em;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:32px}
small{color:var(--mut)}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-top:12px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px}
.card b{color:var(--acc);font-size:1.4em;display:block}.card span{color:var(--mut);font-size:.85em}
pre{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px;overflow:auto;font-size:.85em;max-height:480px}
.miss{color:var(--warn)}footer{margin-top:48px;color:var(--mut);font-size:.8em}
"""


def _counts(outdir: Path) -> Dict[str, int]:
    keys = {
        "subdomains": outdir / "all_subs.txt",
        "resolved": outdir / "resolved.txt",
        "open_ports": outdir / "ports.txt",
        "services": outdir / "services.txt",
        "live_hosts": outdir / "hosts.txt",
        "tech": outdir / "tech.txt",
        "takeover": outdir / "takeover.txt",
        "urls": outdir / "urls_all.txt",
        "js_urls": outdir / "urls_js.txt",
        "js_secrets": outdir / "js_secrets.txt",
        "js_deep": outdir / "js_secrets_deep.txt",
        "params": outdir / "params.txt",
        "fuzz": outdir / "fuzz.txt",
        "nuclei": outdir / "nuclei_combined.txt",
        "tls_wp": outdir / "tls_wp.txt",
        "ssti": outdir / "ssti.txt",
        "origin": outdir / "origin.txt",
        "auth_bypass": outdir / "auth_bypass.txt",
        "vulns": outdir / "vulns.txt",
        "oast": outdir / "oast" / "callbacks.txt",
        "cloud_buckets": outdir / "cloud_buckets.txt",
        "git_exposure": outdir / "git_exposure.txt",
        "graphql": outdir / "graphql_introspection.txt",
        "waf": outdir / "waf_detection.txt",
        "nosqli": outdir / "nosqli.txt",
        "race": outdir / "race_conditions.txt",
        "jwt": outdir / "jwt_analysis.txt",
        "xxe": outdir / "xxe.txt",
        "cmdi": outdir / "cmd_injection.txt",
        "sspp": outdir / "sspp.txt",
        "cached": outdir / "cache_poison.txt",
        "depcheck": outdir / "depcheck.txt",
        "open_redirect": outdir / "open_redirect.txt",
        "clickjacking": outdir / "clickjacking.txt",
        "crlf": outdir / "crlf_injection.txt",
        "rate_limiting": outdir / "rate_limiting.txt",
        "cors_advanced": outdir / "cors_advanced.txt",
        "jwt_advanced": outdir / "jwt_advanced.txt",
        "file_upload": outdir / "file_upload.txt",
        "smuggling": outdir / "smuggling.txt",
        "oauth": outdir / "oauth_misconfig.txt",
        "password_reset": outdir / "password_reset.txt",
        "websocket": outdir / "websocket.txt",
        "ldap": outdir / "ldap_injection.txt",
        "deserialization": outdir / "deserialization.txt",
        "takeover_confirmed": outdir / "takeover_confirmed.txt",
        "api_specs": outdir / "api_specs.txt",
        "sqlmap": outdir / "sqlmap_findings.txt",
        "idor": outdir / "idor.txt",
        "ssrf_meta": outdir / "ssrf_meta.txt",
        "lfi": outdir / "lfi.txt",
        "mass_assign": outdir / "mass_assign.txt",
        "authz_bypass": outdir / "authz_bypass.txt",
        "domxss": outdir / "domxss_findings.txt",
        "h2_smuggling": outdir / "h2_smuggling.txt",
        "framework_vulns": outdir / "framework_vulns.txt",
        "chain_correlation": outdir / "chain_correlation.txt",
        "evidence": outdir / "evidence.txt",
        "bucket_permissions": outdir / "bucket_permissions.txt",
        "hpp": outdir / "hpp.txt",
        "serverless_endpoints": outdir / "serverless_endpoints.txt",
        "csp_analysis": outdir / "csp_analysis.txt",
        "websocket_fuzz": outdir / "websocket_fuzz.txt",
        "csv_injection": outdir / "csv_injection.txt",
        "exposed_databases": outdir / "exposed_databases.txt",
        "default_creds": outdir / "default_creds.txt",
        "host_header_injection": outdir / "host_header_injection.txt",
        "email_security": outdir / "email_security.txt",
        "smtp_enumeration": outdir / "smtp_enumeration.txt",
        "oauth_advanced": outdir / "oauth_advanced.txt",
        "log_injection": outdir / "log_injection.txt",
        "document_attacks": outdir / "document_attacks.txt",
        "waf_bypass": outdir / "waf_bypass.txt",
        "idempotency": outdir / "idempotency.txt",
        "session": outdir / "session_analysis.txt",
        "ssrf_full": outdir / "ssrf_full.txt",
        "pathnorm": outdir / "path_normalization.txt",
        "dep_cve": outdir / "dep_cve.txt",
        "dns_zt": outdir / "dns_zone_transfer.txt",
        "ports_full": outdir / "ports_full.txt",
        "emails": outdir / "emails_harvested.txt",
        "account_enum": outdir / "account_enum.txt",
        "github_dorking": outdir / "github_dorking.txt",
        "mobile_api": outdir / "mobile_api.txt",
        "workflow_bypass": outdir / "workflow_bypass.txt",
        "cache_key": outdir / "cache_key_probe.txt",
        "file_upload_adv": outdir / "file_upload_adv.txt",
        "secret_rotation": outdir / "secret_rotation.txt",
        "stored_xss": outdir / "stored_xss.txt",
        "idor_fuzz": outdir / "idor_fuzz.txt",
        "oauth_deep": outdir / "oauth_deep.txt",
        "race_burst": outdir / "race_burst.txt",
        "whois": outdir / "whois.txt",
        "asn_ranges": outdir / "asn_ranges.txt",
        "dork_findings": outdir / "dork_findings.txt",
        "shodan_hosts": outdir / "shodan_hosts.txt",
        "employees": outdir / "employees.txt",
        "passive_dns_subs": outdir / "passive_dns_subs.txt",
        "csrf": outdir / "csrf_findings.txt",
        "session_fixation": outdir / "session_fixation.txt",
        "saml": outdir / "saml_findings.txt",
        "password_spray": outdir / "password_spray_results.txt",
        "cookie_audit": outdir / "cookie_audit.txt",
        "post_test": outdir / "post_findings.txt",
        "method_override": outdir / "method_override_bypass.txt",
        "forced_browse": outdir / "forced_browse.txt",
        "case_bypass": outdir / "case_bypass.txt",
        "api_pagination": outdir / "api_pagination_abuse.txt",
        "tabnabbing": outdir / "reverse_tabnabbing.txt",
        "api_key_leaks": outdir / "api_key_leaks.txt",
        "redirect_abuse": outdir / "redirect_abuse.txt",
        "log_inject_trigger": outdir / "log_injection_trigger.txt",
        "stored_xss_verified": outdir / "stored_xss_verified.txt",
        "host_header_abuse": outdir / "host_header_abuse.txt",
        "auth_bypass_adv": outdir / "auth_bypass_advanced.txt",
        "ssi_injection": outdir / "ssi_injection.txt",
        "json_injection": outdir / "json_injection.txt",
        "null_byte_injection": outdir / "null_byte_injection.txt",
        "double_encoding_bypass": outdir / "double_encoding_bypass.txt",
        "unicode_bypass": outdir / "unicode_bypass.txt",
        "postmessage_xss": outdir / "postmessage_xss.txt",
        "jsonp_endpoints": outdir / "jsonp_endpoints.txt",
        "sri_findings": outdir / "sri_findings.txt",
        "mixed_content": outdir / "mixed_content.txt",
        "hsts_preload": outdir / "hsts_preload.txt",
        "third_party_js": outdir / "third_party_js.txt",
        "browser_storage_audit": outdir / "browser_storage_audit.txt",
        "rfi_findings": outdir / "rfi_findings.txt",
        "webdav_enumeration": outdir / "webdav_enumeration.txt",
        "snmp_findings": outdir / "snmp_findings.txt",
        "banners": outdir / "banners.txt",
        "phpinfo_disclosure": outdir / "phpinfo_disclosure.txt",
        "server_status_exposed": outdir / "server_status_exposed.txt",
        "error_leakage": outdir / "error_leakage.txt",
        "wildcard_dns": outdir / "wildcard_dns.txt",
        "dns_rebinding": outdir / "dns_rebinding.txt",
        "iis_aspnet": outdir / "iis_aspnet_findings.txt",
        "tomcat": outdir / "tomcat_findings.txt",
        "nodejs": outdir / "nodejs_findings.txt",
        "laravel": outdir / "laravel_exposure.txt",
        "django": outdir / "django_exposure.txt",
        "symfony": outdir / "symfony_profiler.txt",
        "cicd": outdir / "cicd_exposure.txt",
        "docker": outdir / "docker_registry.txt",
        "k8s": outdir / "k8s_exposure.txt",
        "terraform": outdir / "terraform_exposure.txt",
        "env_deep": outdir / "env_files_found.txt",
        "graphql_abuse": outdir / "graphql_abuse.txt",
        "api_version": outdir / "api_version_bypass.txt",
        "lb_bypass": outdir / "load_balancer_bypass.txt",
        "vhost": outdir / "vhost_discovery.txt",
        "ratelimit_bypass": outdir / "rate_limit_bypass.txt",
    }
    return {k: count_nonblank(v) for k, v in keys.items() if v.exists()}


def _coverage(outdir: Path, all_phases: List[str]) -> Dict[str, Any]:
    """Compute coverage metrics: discovered vs tested, skipped by reason."""
    coverage: Dict[str, Any] = {
        "discovered_urls": count_nonblank(outdir / "urls_all.txt") if (outdir / "urls_all.txt").exists() else 0,
        "tested_phases": 0,
        "total_phases": len(all_phases),
        "uncovered_paths": [],
        "skipped": {},
    }
    phase_files = {
        "00-SCOPE": "scope_validated.txt",
        "01-RECON": "all_subs.txt",
        "02-RESOLVE": "resolved.txt",
        "04-SCAN": "hosts.txt",
        "05-HARVEST": "urls_all.txt",
    }
    for phase_name in all_phases:
        fname = phase_files.get(phase_name)
        if fname and (outdir / fname).exists():
            coverage["tested_phases"] += 1
    return coverage


def write_summary(outdir: Path, domain: str, state: dict, counts: Dict[str, int]) -> Path:
    payload = {
        "domain": domain,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "toolchain": f"reconchain v{__version__}",
        "missing_tools": sorted(set(state.get("missing_tools", []))),
        "tool_failures": dict(state.get("tool_failures", {})),
        "artifacts": {k: v for k, v in state.get("artifacts", {}).items()},
        "counts": counts,
        "coverage": state.get("coverage", {}),
    }
    out = ensure(outdir / "summary.json")
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, default=str))
    os.replace(tmp, out)
    return out


def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def write_html(outdir: Path, domain: str, counts: Dict[str, int], missing: List[str]) -> Path:
    cards = "\n".join(
        f'<div class="card"><b>{n}</b><span>{html_escape(k)}</span></div>'
        for k, n in counts.items()
    )
    sections = []
    for key in (
        "all_subs.txt", "resolved.txt", "hosts.txt", "ports.txt",
        "takeover.txt", "takeover_confirmed.txt", "urls_all.txt",
        "api_specs.txt", "js_secrets.txt", "js_secrets_deep.txt",
        "params.txt", "fuzz.txt", "nuclei_combined.txt", "tls_wp.txt",
        "ssti.txt", "origin.txt", "authz_bypass.txt", "mass_assign.txt",
        "idor.txt", "ssrf_meta.txt", "services.txt",
        "vulns.txt", "sqlmap_findings.txt", "cloud_buckets.txt",
        "git_exposure.txt", "graphql_introspection.txt", "waf_detection.txt",
        "nosqli.txt", "race_conditions.txt", "jwt_analysis.txt", "xxe.txt",
        "cmd_injection.txt", "sspp.txt", "cache_poison.txt", "depcheck.txt",
        "lfi.txt", "open_redirect.txt", "clickjacking.txt",
        "crlf_injection.txt", "rate_limiting.txt", "cors_advanced.txt",
        "jwt_advanced.txt", "file_upload.txt", "smuggling.txt",
        "oauth_misconfig.txt", "password_reset.txt", "websocket.txt",
        "ldap_injection.txt",         "deserialization.txt", "chain_correlation.txt",
        "evidence.txt", "domxss_findings.txt", "h2_smuggling.txt",
        "framework_vulns.txt",
        "bucket_permissions.txt", "hpp.txt", "serverless_endpoints.txt",
        "csp_analysis.txt", "websocket_fuzz.txt", "csv_injection.txt",
        "exposed_databases.txt", "default_creds.txt", "host_header_injection.txt",
        "email_security.txt", "smtp_enumeration.txt", "oauth_advanced.txt",
        "log_injection.txt", "document_attacks.txt",
        "waf_bypass.txt", "idempotency.txt",
        "session_analysis.txt", "ssrf_full.txt", "path_normalization.txt",
        "dep_cve.txt", "dns_zone_transfer.txt", "ports_full.txt", "emails_harvested.txt",
        "account_enum.txt", "github_dorking.txt", "mobile_api.txt",
        "workflow_bypass.txt", "cache_key_probe.txt", "file_upload_adv.txt",
        "secret_rotation.txt", "stored_xss.txt", "idor_fuzz.txt",
        "oauth_deep.txt", "race_burst.txt",
        "whois.txt", "asn_ranges.txt", "dork_findings.txt",
        "shodan_hosts.txt", "employees.txt", "passive_dns_subs.txt",
        "csrf_findings.txt", "session_fixation.txt", "saml_findings.txt",
        "password_spray_results.txt", "cookie_audit.txt", "post_findings.txt",
        "method_override_bypass.txt", "forced_browse.txt", "case_bypass.txt",
        "api_pagination_abuse.txt", "reverse_tabnabbing.txt", "api_key_leaks.txt",
        "redirect_abuse.txt", "log_injection_trigger.txt", "stored_xss_verified.txt",
        "host_header_abuse.txt", "auth_bypass_advanced.txt",
        "ssi_injection.txt", "json_injection.txt", "null_byte_injection.txt",
        "double_encoding_bypass.txt", "unicode_bypass.txt", "postmessage_xss.txt",
        "jsonp_endpoints.txt", "sri_findings.txt", "mixed_content.txt",
        "hsts_preload.txt", "third_party_js.txt", "browser_storage_audit.txt",
        "rfi_findings.txt", "webdav_enumeration.txt", "snmp_findings.txt",
        "banners.txt", "phpinfo_disclosure.txt", "server_status_exposed.txt",
        "error_leakage.txt", "wildcard_dns.txt", "dns_rebinding.txt",
        "iis_aspnet_findings.txt", "tomcat_findings.txt", "nodejs_findings.txt",
        "laravel_exposure.txt", "django_exposure.txt", "symfony_profiler.txt",
        "cicd_exposure.txt", "docker_registry.txt", "k8s_exposure.txt",
        "terraform_exposure.txt", "env_files_found.txt",
        "graphql_abuse.txt", "api_version_bypass.txt", "load_balancer_bypass.txt",
        "vhost_discovery.txt", "rate_limit_bypass.txt",
    ):
        p = outdir / key
        if p.exists():
            txt = p.read_text(encoding="utf-8", errors="ignore")
            if len(txt) > 50_000:
                log("warn", f"report.html: {key} truncated from {len(txt)} to 50KB")
                txt = txt[:50_000] + f"\n\n{'='*60}\n[WARNING: File truncated at 50KB — original size: {len(txt):,} bytes]\nFull content available in: {key}\n{'='*60}\n"
            sections.append(f"<h2>{html_escape(key)}</h2><pre>{html_escape(txt)}</pre>")
    oast_file = outdir / "oast" / "callbacks.txt"
    if oast_file.exists() and count_nonblank(oast_file):
        txt = oast_file.read_text(encoding="utf-8", errors="ignore")
        sections.append(f"<h2>oast/callbacks.txt</h2><pre>{html_escape(txt)}</pre>")
    miss_html = (
        "<p class='miss'>missing: " + ", ".join(html_escape(m) for m in missing) + "</p>"
        if missing
        else ""
    )
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>recon report \u2014 {html_escape(domain)}</title>
<style>{HTML_CSS}</style></head><body>
<h1>Recon Report: {html_escape(domain)}</h1>
<small>generated {datetime.now().isoformat(timespec="seconds")} \u00b7 reconchain v{__version__}</small>
{miss_html}
<h2>Summary</h2><div class="grid">{cards}</div>
{"".join(sections)}
<footer>chained recon \u00b7 all artifacts in <code>{html_escape(str(outdir))}</code></footer>
</body></html>"""
    out = ensure(outdir / "report.html")
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(html)
    os.replace(tmp, out)
    return out


def write_full_summary(outdir: Path, domain: str, counts: Dict[str, int], missing: List[str]) -> Path:
    lines = [
        "=" * 60,
        f"  Recon Summary \u2014 {domain}",
        f"  generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        "",
    ]
    if missing:
        lines += ["\u26a0 MISSING TOOLS (install via ./install.sh)", ""]
        for m in missing:
            lines.append(f"  \u2022 {m}")
        lines.append("")
    lines += ["RESULTS", "-------", ""]
    if counts:
        lines.append(f"{'Artifact':<30} {'Count':>8}")
        lines.append("-" * 40)
        for k, n in sorted(counts.items()):
            if n > 0:
                lines.append(f"{k:<30} {n:>8}")
    lines.append("")
    lines += ["KEY FINDINGS", "------------", ""]
    for key in (
        "all_subs.txt", "resolved.txt", "hosts.txt", "ports.txt",
        "takeover.txt", "takeover_confirmed.txt", "urls_all.txt", "urls_js.txt",
        "js_secrets.txt", "js_secrets_deep.txt", "params.txt",
        "fuzz.txt", "nuclei_combined.txt", "tls_wp.txt",
        "origin.txt", "authz_bypass.txt", "mass_assign.txt", "idor.txt",
        "vulns.txt", "sqlmap_findings.txt", "ssrf_meta.txt", "ssti.txt",
        "cloud_buckets.txt", "git_exposure.txt", "graphql_introspection.txt", "waf_detection.txt",
        "nosqli.txt", "race_conditions.txt", "jwt_analysis.txt", "xxe.txt",
        "cmd_injection.txt", "sspp.txt", "cache_poison.txt", "depcheck.txt",
        "lfi.txt", "api_specs.txt",
        "open_redirect.txt", "clickjacking.txt", "crlf_injection.txt",
        "rate_limiting.txt", "cors_advanced.txt", "jwt_advanced.txt",
        "file_upload.txt", "smuggling.txt", "oauth_misconfig.txt",
        "password_reset.txt", "websocket.txt", "ldap_injection.txt",
        "deserialization.txt", "chain_correlation.txt", "evidence.txt",
        "domxss_findings.txt", "h2_smuggling.txt", "framework_vulns.txt",
        "bucket_permissions.txt", "hpp.txt", "serverless_endpoints.txt",
        "csp_analysis.txt", "websocket_fuzz.txt", "csv_injection.txt",
        "exposed_databases.txt", "default_creds.txt", "host_header_injection.txt",
        "email_security.txt", "smtp_enumeration.txt", "oauth_advanced.txt",
        "log_injection.txt", "document_attacks.txt",
        "waf_bypass.txt", "idempotency.txt",
        "session_analysis.txt", "ssrf_full.txt", "path_normalization.txt",
        "dep_cve.txt", "dns_zone_transfer.txt", "ports_full.txt", "emails_harvested.txt",
        "account_enum.txt", "github_dorking.txt", "mobile_api.txt",
        "workflow_bypass.txt", "cache_key_probe.txt", "file_upload_adv.txt",
        "secret_rotation.txt", "stored_xss.txt", "idor_fuzz.txt",
        "oauth_deep.txt", "race_burst.txt",
        "whois.txt", "asn_ranges.txt", "dork_findings.txt",
        "shodan_hosts.txt", "employees.txt", "passive_dns_subs.txt",
        "csrf_findings.txt", "session_fixation.txt", "saml_findings.txt",
        "password_spray_results.txt", "cookie_audit.txt", "post_findings.txt",
        "method_override_bypass.txt", "forced_browse.txt", "case_bypass.txt",
        "api_pagination_abuse.txt", "reverse_tabnabbing.txt", "api_key_leaks.txt",
        "redirect_abuse.txt", "log_injection_trigger.txt", "stored_xss_verified.txt",
        "host_header_abuse.txt", "auth_bypass_advanced.txt",
        "ssi_injection.txt", "json_injection.txt", "null_byte_injection.txt",
        "double_encoding_bypass.txt", "unicode_bypass.txt", "postmessage_xss.txt",
        "jsonp_endpoints.txt", "sri_findings.txt", "mixed_content.txt",
        "hsts_preload.txt", "third_party_js.txt", "browser_storage_audit.txt",
        "rfi_findings.txt", "webdav_enumeration.txt", "snmp_findings.txt",
        "banners.txt", "phpinfo_disclosure.txt", "server_status_exposed.txt",
        "error_leakage.txt", "wildcard_dns.txt", "dns_rebinding.txt",
        "iis_aspnet_findings.txt", "tomcat_findings.txt", "nodejs_findings.txt",
        "laravel_exposure.txt", "django_exposure.txt", "symfony_profiler.txt",
        "cicd_exposure.txt", "docker_registry.txt", "k8s_exposure.txt",
        "terraform_exposure.txt", "env_files_found.txt",
        "graphql_abuse.txt", "api_version_bypass.txt", "load_balancer_bypass.txt",
        "vhost_discovery.txt", "rate_limit_bypass.txt",
    ):
        p = outdir / key
        if not p.exists():
            continue
        entries = read_lines(p)
        if not entries:
            continue
        first = entries[0] if entries else ""
        if "No " in first and (" found" in first or " detected" in first or " discovered" in first or "completed" in first):
            continue
        lines.append(f"\u2500\u2500 {key} ({len(entries)} entries)")
        for i, entry in enumerate(entries[:5]):
            lines.append(f"  {entry[:120]}")
        if len(entries) > 5:
            lines.append(f"  \u2026 and {len(entries) - 5} more")
        lines.append("")
    oast = outdir / "oast" / "callbacks.txt"
    if oast.exists() and count_nonblank(oast):
        lines.append(f"\u2500\u2500 OOB callbacks ({count_nonblank(oast)} entries)")
        for ln in read_lines(oast)[:5]:
            lines.append(f"  {ln[:120]}")
        lines.append("")
    lines.append("=" * 60)
    out = ensure(outdir / "summary.txt")
    out.write_text("\n".join(lines) + "\n")
    return out


def md_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def write_markdown(outdir: Path, domain: str, counts: Dict[str, int], missing: List[str]) -> Path:
    lines = [
        f"# Recon Report \u2014 {domain}",
        f"_generated {datetime.now().isoformat(timespec='seconds')}_",
        "",
    ]
    if missing:
        lines += ["## \u26a0 Missing tools", ", ".join(f"`{md_escape(m)}`" for m in missing), ""]
    lines += ["## Summary", "", "| Artifact | Count |", "|---|---:|"]
    for k, n in counts.items():
        lines.append(f"| `{md_escape(k)}` | {n} |")
    lines += ["", "## Artifacts", ""]
    for f in sorted(outdir.glob("*.txt")):
        lines.append(f"- `{md_escape(f.name)}`")
    oast = outdir / "oast" / "callbacks.txt"
    if oast.exists():
        lines += ["", "## OOB callbacks", ""]
        for ln in read_lines(oast)[:50]:
            lines.append(f"- `{md_escape(ln)}`")
    out = ensure(outdir / "report.md")
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.replace(tmp, out)
    return out


def write_sarif(outdir: Path, domain: str, counts: Dict[str, int], state: dict) -> Path:
    """Generate SARIF v2.1 output for GitHub Advanced Security / GitLab SAST."""
    sarif: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/openc2-json-schema/master/sarif/sarif-2-1.schema.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ReconChain",
                    "version": __version__,
                    "informationUri": "https://github.com/franz88-scr/BugBountyV2tool",
                }
            },
            "results": [],
            "properties": {
                "domain": domain,
                "generated_at": datetime.now().isoformat(timespec="seconds"),
            }
        }]
    }
    rule_ids: Dict[str, str] = {}
    for artifact_name, artifact_path_str in state.get("artifacts", {}).items():
        if not isinstance(artifact_path_str, str):
            continue
        p = Path(artifact_path_str)
        if not p.exists():
            continue
        lines = read_lines(p)
        for line_idx, line in enumerate(lines, 1):
            if not line.strip():
                continue
            parts = line.split(None, 1)
            tag = parts[0].strip("[]") if parts else "finding"
            tag_clean = tag.replace("-", "_").upper()[:30]
            if tag_clean not in rule_ids:
                rule_ids[tag_clean] = f"RC{len(rule_ids) + 1:04d}"
                sarif["runs"][0]["tool"]["driver"].setdefault("rules", []).append({
                    "id": rule_ids[tag_clean],
                    "name": tag_clean,
                    "shortDescription": {"text": tag_clean.replace("_", " ")},
                    "properties": {"tags": [tag]},
                })
            result = {
                "ruleId": rule_ids[tag_clean],
                "message": {"text": line[:200]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_name},
                        "region": {"startLine": line_idx},
                    }
                }],
            }
            sarif["runs"][0]["results"].append(result)
    out = ensure(outdir / "results.sarif")
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(sarif, indent=2, default=str))
    os.replace(tmp, out)
    log("ok", f"sarif report → {out}")
    return out
