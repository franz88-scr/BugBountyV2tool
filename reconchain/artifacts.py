"""Centralized artifact registry — single source of truth for all scan output files.

Every artifact produced by the pipeline is defined here. All modules that
reference artifact filenames (reporting, exploit_chain, ai_triage, etc.)
import from this module instead of hardcoding filenames.

Usage:
    from reconchain.artifacts import ARTIFACTS, ARTIFACT_REGISTRY, get_counts, get_findings_by_severity
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from reconchain.utils import count_nonblank, ensure, log, read_lines


@dataclass(frozen=True)
class ArtifactDef:
    """Definition of a single scan output artifact."""
    key: str
    filename: str
    display_name: str
    phase: str
    vuln_type: str = ""
    severity_hint: str = "info"
    category: str = "general"
    in_report: bool = True
    in_exploit_chain: bool = False
    in_triage: bool = False


# ── Severity classification ──────────────────────────────────────────────────
SEVERITY_KEYWORDS: Dict[str, List[str]] = {
    "critical": [
        "rce", "remote code execution", "command injection", "sql injection",
        "ssrf to cloud", "ssrf to metadata", "credential theft", "secret extraction",
        "container escape", "cluster compromise", "takeover confirmed",
        "default creds", "exposed database", "exposed git", "terraform state",
        "ci/cd exposure", "docker registry", "kubernetes api",
    ],
    "high": [
        "xss", "cross-site scripting", "ssrf", "lfi", "local file inclusion",
        "idor", "authentication bypass", "privilege escalation", "jwt",
        "oauth", "session hijacking", "stored xss", "ssti",
        "deserialization", "ldap injection", "smuggling",
        "race condition", "file upload", "graphql",
    ],
    "medium": [
        "cors", "clickjacking", "crlf", "open redirect", "method override",
        "csrf", "session fixation", "hpp", "csp", "rate limit",
        "mass assignment", "host header", "path normalization",
    ],
    "low": [
        "info leak", "banner", "server status", "phpinfo", "mixed content",
        "hsts", "sri", "jsonp", "browser storage", "third-party",
    ],
}


def guess_severity(text: str) -> str:
    """Classify finding severity from text using keyword matching."""
    lower = text.lower()
    for sev in ("critical", "high", "medium", "low"):
        for kw in SEVERITY_KEYWORDS[sev]:
            if kw in lower:
                return sev
    return "info"


# ── Artifact definitions ─────────────────────────────────────────────────────

ARTIFACTS: List[ArtifactDef] = [
    # Recon & Discovery
    ArtifactDef("subdomains", "all_subs.txt", "Subdomains", "01-RECON", category="recon"),
    ArtifactDef("resolved", "resolved.txt", "Resolved Hosts", "02-RESOLVE", category="recon"),
    ArtifactDef("open_ports", "ports.txt", "Open Ports", "04-SCAN", category="recon"),
    ArtifactDef("services", "services.txt", "Services", "04-SCAN", category="recon"),
    ArtifactDef("live_hosts", "hosts.txt", "Live Hosts", "04-SCAN", category="recon"),
    ArtifactDef("tech", "tech.txt", "Technologies", "04-SCAN", category="recon"),
    ArtifactDef("takeover", "takeover.txt", "Subdomain Takeover", "04b-TAKEOVER-VALIDATE", vuln_type="takeover", in_exploit_chain=True),
    ArtifactDef("takeover_confirmed", "takeover_confirmed.txt", "Confirmed Takeover", "04b-TAKEOVER-VALIDATE", vuln_type="takeover", severity_hint="critical"),
    ArtifactDef("urls", "urls_all.txt", "URLs", "05-HARVEST", category="recon"),
    ArtifactDef("js_urls", "urls_js.txt", "JS URLs", "06-JSINTEL", category="recon"),
    ArtifactDef("params", "params.txt", "Parameters", "07-PARAMS", category="recon"),
    ArtifactDef("fuzz", "fuzz.txt", "Fuzz Results", "08-FUZZ", category="recon"),
    ArtifactDef("api_specs", "api_specs.txt", "API Specs", "05b-APISPEC", category="recon"),

    # Vulnerability Scanning
    ArtifactDef("nuclei", "nuclei_combined.txt", "Nuclei Findings", "09-VULNSCAN", vuln_type="nuclei", severity_hint="high", in_exploit_chain=True, in_triage=True),
    ArtifactDef("vulns", "vulns.txt", "Injection Findings", "11-INJECT", vuln_type="injection", in_exploit_chain=True, in_triage=True),

    # Injection & XSS
    ArtifactDef("xss_findings", "xss_findings.txt", "XSS Findings", "11-INJECT", vuln_type="xss", severity_hint="high", in_exploit_chain=True, in_triage=True),
    ArtifactDef("domxss", "domxss_findings.txt", "DOM XSS", "11a-DOMXSS", vuln_type="xss", severity_hint="high", in_triage=True),
    ArtifactDef("sqlmap", "sqlmap_findings.txt", "SQLMap Findings", "11b-SQLMAP", vuln_type="sqli", severity_hint="high", in_triage=True),
    ArtifactDef("ssti", "ssti.txt", "SSTI Findings", "12-SSTI", vuln_type="ssti", in_exploit_chain=True, in_triage=True),
    ArtifactDef("ssrf_meta", "ssrf_meta.txt", "SSRF Metadata", "17b-SSRFMETA", vuln_type="ssrf", in_exploit_chain=True, in_triage=True),
    ArtifactDef("ssrf_full", "ssrf_full.txt", "SSRF Full", "66-SSRF-FULL", vuln_type="ssrf", in_exploit_chain=True, in_triage=True),
    ArtifactDef("lfi", "lfi.txt", "LFI Findings", "30-LFI", vuln_type="lfi", in_exploit_chain=True, in_triage=True),
    ArtifactDef("nosqli", "nosqli.txt", "NoSQL Injection", "22-NOSQLI", vuln_type="nosqli", severity_hint="high"),
    ArtifactDef("xxe", "xxe.txt", "XXE Findings", "25-XXE", vuln_type="xxe", in_triage=True),
    ArtifactDef("cmdi", "cmd_injection.txt", "Command Injection", "26-CMDINJECT", vuln_type="rce", severity_hint="critical"),
    ArtifactDef("sspp", "sspp.txt", "Prototype Pollution", "27-SSPP", vuln_type="sspp"),
    ArtifactDef("ldap", "ldap_injection.txt", "LDAP Injection", "42-LDAP", vuln_type="ldap"),
    ArtifactDef("deserialization", "deserialization.txt", "Deserialization", "43-DESERIAL", vuln_type="deserialization"),
    ArtifactDef("ssi_injection", "ssi_injection.txt", "SSI Injection", "100-SSI", vuln_type="ssi"),
    ArtifactDef("json_injection", "json_injection.txt", "JSON Injection", "101-JSONINJECT", vuln_type="json_inject"),
    ArtifactDef("null_byte_injection", "null_byte_injection.txt", "Null Byte Injection", "102-NULLBYTE"),
    ArtifactDef("double_encoding_bypass", "double_encoding_bypass.txt", "Double Encoding Bypass", "103-DOUBLEENCOD"),
    ArtifactDef("unicode_bypass", "unicode_bypass.txt", "Unicode Bypass", "104-UNICODE"),
    ArtifactDef("postmessage_xss", "postmessage_xss.txt", "postMessage XSS", "105-POSTMSGXSS", vuln_type="xss"),
    ArtifactDef("jsonp_endpoints", "jsonp_endpoints.txt", "JSONP Endpoints", "106-JSONP", vuln_type="jsonp"),
    ArtifactDef("csv_injection", "csv_injection.txt", "CSV Injection", "55-CSV-INJECT", vuln_type="csv_inject"),
    ArtifactDef("log_injection", "log_injection.txt", "Log Injection", "62-LOG-INJECT", vuln_type="log_inject"),
    ArtifactDef("stored_xss", "stored_xss.txt", "Stored XSS", "80-STOREXSS", vuln_type="stored_xss", severity_hint="high", in_exploit_chain=True, in_triage=True),
    ArtifactDef("stored_xss_verified", "stored_xss_verified.txt", "Verified Stored XSS", "99e-XSSSTORED", vuln_type="stored_xss", severity_hint="critical", in_triage=True),
    ArtifactDef("rfi_findings", "rfi_findings.txt", "RFI Findings", "112-RFI", vuln_type="rfi"),

    # Auth & Session
    ArtifactDef("jwt", "jwt_analysis.txt", "JWT Analysis", "24-JWT", vuln_type="jwt", in_exploit_chain=True, in_triage=True),
    ArtifactDef("jwt_advanced", "jwt_advanced.txt", "Advanced JWT Attacks", "36-JWTADV", vuln_type="jwt"),
    ArtifactDef("oauth", "oauth_misconfig.txt", "OAuth Misconfig", "39-OAUTH", vuln_type="oauth"),
    ArtifactDef("oauth_advanced", "oauth_advanced.txt", "OAuth Advanced", "61-OAUTH-ADV", vuln_type="oauth"),
    ArtifactDef("oauth_deep", "oauth_deep.txt", "OAuth Deep", "82-OAUTHDEEP", vuln_type="oauth"),
    ArtifactDef("password_reset", "password_reset.txt", "Password Reset", "40-PWRESET", vuln_type="password_reset"),
    ArtifactDef("auth_bypass", "auth_bypass.txt", "Auth Bypass", "16a-AUTHZ", vuln_type="auth_bypass", in_exploit_chain=True, in_triage=True),
    ArtifactDef("authz_bypass", "authz_bypass.txt", "Authorization Bypass", "16a-AUTHZ", vuln_type="auth_bypass"),
    ArtifactDef("auth_bypass_adv", "auth_bypass_advanced.txt", "Advanced Auth Bypass", "99g-AUTHBYPASSADV", vuln_type="auth_bypass"),
    ArtifactDef("mass_assign", "mass_assign.txt", "Mass Assignment", "16b-MASSASSIGN", vuln_type="mass_assign"),
    ArtifactDef("idor", "idor.txt", "IDOR Findings", "17-IDOR", vuln_type="idor", in_exploit_chain=True, in_triage=True),
    ArtifactDef("idor_fuzz", "idor_fuzz.txt", "IDOR Fuzz", "81-IDORFUZZ", vuln_type="idor"),
    ArtifactDef("csrf", "csrf_findings.txt", "CSRF Findings", "90-CSRF", vuln_type="csrf"),
    ArtifactDef("session_fixation", "session_fixation.txt", "Session Fixation", "91-SESSIONFIX", vuln_type="session_fixation"),
    ArtifactDef("session", "session_analysis.txt", "Session Analysis", "65-SESSION", vuln_type="session"),
    ArtifactDef("saml", "saml_findings.txt", "SAML Findings", "92-SAML", vuln_type="saml"),
    ArtifactDef("password_spray", "password_spray_results.txt", "Password Spray", "93-PWDSPRAY", vuln_type="password_spray"),
    ArtifactDef("cookie_audit", "cookie_audit.txt", "Cookie Audit", "94-COOKIEAUDIT", vuln_type="cookie"),
    ArtifactDef("account_enum", "account_enum.txt", "Account Enumeration", "72-ACCOUNTENUM", vuln_type="account_enum"),
    ArtifactDef("post_test", "post_findings.txt", "POST Auth Bypass", "95-POSTTEST", vuln_type="auth_bypass"),

    # Client-Side
    ArtifactDef("cached", "cache_poison.txt", "Cache Poisoning", "28-CACHED", vuln_type="cache_poison"),
    ArtifactDef("depcheck", "depcheck.txt", "Dependency Check", "29-DEPCHECK", vuln_type="cve"),
    ArtifactDef("open_redirect", "open_redirect.txt", "Open Redirects", "31-OPENREDIR", vuln_type="open_redirect", in_exploit_chain=True, in_triage=True),
    ArtifactDef("clickjacking", "clickjacking.txt", "Clickjacking", "32-CLICKJACK", vuln_type="clickjacking"),
    ArtifactDef("crlf", "crlf_injection.txt", "CRLF Injection", "33-CRLF", vuln_type="crlf", in_exploit_chain=True),
    ArtifactDef("rate_limiting", "rate_limiting.txt", "Rate Limiting", "34-RATELIMIT", vuln_type="rate_limit"),
    ArtifactDef("cors_advanced", "cors_advanced.txt", "CORS Advanced", "35-CORSADV", vuln_type="cors", in_exploit_chain=True, in_triage=True),
    ArtifactDef("file_upload", "file_upload.txt", "File Upload", "37-FILEUPLOAD", vuln_type="file_upload"),
    ArtifactDef("file_upload_adv", "file_upload_adv.txt", "Advanced File Upload", "78-FILEUPLOADADV", vuln_type="file_upload"),
    ArtifactDef("hpp", "hpp.txt", "HPP Findings", "51-HPP", vuln_type="hpp"),
    ArtifactDef("csp_analysis", "csp_analysis.txt", "CSP Analysis", "53-CSP", vuln_type="csp"),
    ArtifactDef("websocket", "websocket.txt", "WebSocket Findings", "41-WEBSOCKET", vuln_type="websocket"),
    ArtifactDef("websocket_fuzz", "websocket_fuzz.txt", "WebSocket Fuzz", "54-WS-FUZZ", vuln_type="websocket"),
    ArtifactDef("method_override", "method_override_bypass.txt", "Method Override", "96-METHODOVERRIDE", vuln_type="method_override"),
    ArtifactDef("forced_browse", "forced_browse.txt", "Forced Browse", "97-FORCEDBROWSE", vuln_type="forced_browse"),
    ArtifactDef("case_bypass", "case_bypass.txt", "Case Bypass", "98-CASEBYPASS"),
    ArtifactDef("api_pagination", "api_pagination_abuse.txt", "API Pagination Abuse", "99-APIPAGE", vuln_type="api_abuse"),
    ArtifactDef("tabnabbing", "reverse_tabnabbing.txt", "Reverse Tabnabbing", "99a-TABNAB", vuln_type="tabnabbing"),
    ArtifactDef("api_key_leaks", "api_key_leaks.txt", "API Key Leaks", "99b-APIKEYLEAK", vuln_type="secrets"),
    ArtifactDef("redirect_abuse", "redirect_abuse.txt", "Redirect Abuse", "99c-REDIRABUSE", vuln_type="open_redirect"),
    ArtifactDef("log_inject_trigger", "log_injection_trigger.txt", "Log Injection Trigger", "99d-LOGTRIGGER", vuln_type="log_inject"),
    ArtifactDef("host_header_abuse", "host_header_abuse.txt", "Host Header Abuse", "99f-HOSTABUSE", vuln_type="host_header"),
    ArtifactDef("host_header_injection", "host_header_injection.txt", "Host Header Injection", "58-HOST-INJECT", vuln_type="host_header"),
    ArtifactDef("pathnorm", "path_normalization.txt", "Path Normalization", "67-PATHNORM"),
    ArtifactDef("idempotency", "idempotency.txt", "Idempotency Bypass", "64-IDEMPOTENCY"),
    ArtifactDef("sri_findings", "sri_findings.txt", "SRI Findings", "107-SRI", vuln_type="sri"),
    ArtifactDef("mixed_content", "mixed_content.txt", "Mixed Content", "108-MIXEDCONTENT", vuln_type="mixed_content"),
    ArtifactDef("hsts_preload", "hsts_preload.txt", "HSTS Preload", "109-HSTSPRELOAD", vuln_type="hsts"),
    ArtifactDef("third_party_js", "third_party_js.txt", "Third-Party JS", "110-THIRDPARTYJS"),
    ArtifactDef("browser_storage_audit", "browser_storage_audit.txt", "Browser Storage", "111-BROWSERSTORAGE"),
    ArtifactDef("document_attacks", "document_attacks.txt", "Document Attacks", "63-DOC-ATTACK", vuln_type="doc_attack"),
    ArtifactDef("workflow_bypass", "workflow_bypass.txt", "Workflow Bypass", "76-WORKFLOW", vuln_type="workflow"),
    ArtifactDef("cache_key", "cache_key_probe.txt", "Cache Key Probe", "77-CACHEKEY", vuln_type="cache_poison"),

    # Infrastructure
    ArtifactDef("tls_wp", "tls_wp.txt", "TLS/CMS Fingerprint", "10-TLSCMS", category="infra"),
    ArtifactDef("origin", "origin.txt", "Origin IP", "14-ORIGIN", category="infra"),
    ArtifactDef("cloud_buckets", "cloud_buckets.txt", "Cloud Buckets", "18-CLOUD", vuln_type="cloud", in_exploit_chain=True, in_triage=True),
    ArtifactDef("bucket_permissions", "bucket_permissions.txt", "Bucket Permissions", "50-BUCKET-PERMS", vuln_type="cloud"),
    ArtifactDef("git_exposure", "git_exposure.txt", "Git Exposure", "19-GIT", vuln_type="git", in_exploit_chain=True, in_triage=True),
    ArtifactDef("graphql", "graphql_introspection.txt", "GraphQL", "20-GRAPHQL", vuln_type="graphql", in_exploit_chain=True, in_triage=True),
    ArtifactDef("graphql_abuse", "graphql_abuse.txt", "GraphQL Abuse", "132-GQLABUSE", vuln_type="graphql"),
    ArtifactDef("waf", "waf_detection.txt", "WAF Detection", "21-WAF", category="infra"),
    ArtifactDef("waf_bypass", "waf_bypass.txt", "WAF Bypass", "21b-WAFBYPASS", category="infra"),
    ArtifactDef("race", "race_conditions.txt", "Race Conditions", "23-RACE", vuln_type="race_condition"),
    ArtifactDef("race_burst", "race_burst.txt", "Race Burst", "83-RACEBURST", vuln_type="race_condition"),
    ArtifactDef("smuggling", "smuggling.txt", "HTTP Smuggling", "38-SMUGGLE", vuln_type="smuggle", in_exploit_chain=True, in_triage=True),
    ArtifactDef("h2_smuggling", "h2_smuggling.txt", "H2 Smuggling", "38b-H2SMUGGLE", vuln_type="smuggle"),
    ArtifactDef("dep_cve", "dep_cve.txt", "Dependency CVE", "68-DEPCVE", vuln_type="cve", in_exploit_chain=True, in_triage=True),
    ArtifactDef("dns_zt", "dns_zone_transfer.txt", "DNS Zone Transfer", "69-DNSZT"),
    ArtifactDef("ports_full", "ports_full.txt", "Full Port Scan", "70-PORTFULL", category="infra"),
    ArtifactDef("exposed_databases", "exposed_databases.txt", "Exposed Databases", "56-EXPOSED-DB", vuln_type="exposed_db", severity_hint="critical", in_triage=True),
    ArtifactDef("default_creds", "default_creds.txt", "Default Credentials", "57-DEFAULT-CREDS", vuln_type="default_creds", severity_hint="critical", in_triage=True),
    ArtifactDef("serverless_endpoints", "serverless_endpoints.txt", "Serverless Endpoints", "52-SERVERLESS", vuln_type="serverless"),
    ArtifactDef("framework_vulns", "framework_vulns.txt", "Framework Vulns", "49-FRAMEWORKS", vuln_type="framework"),
    ArtifactDef("chain_correlation", "chain_correlation.txt", "Chain Correlation", "44-CHAIN", category="correlation"),
    ArtifactDef("evidence", "evidence.txt", "Evidence", "45-EVIDENCE", category="correlation"),
    ArtifactDef("secret_rotation", "secret_rotation.txt", "Secret Rotation", "79-SECRETDIFF", vuln_type="secrets"),
    ArtifactDef("oast_callbacks", "oast/callbacks.txt", "OOB Callbacks", "13-OOB", category="oast"),

    # OSINT
    ArtifactDef("whois", "whois.txt", "WHOIS", "84-WHOIS", category="osint"),
    ArtifactDef("asn_ranges", "asn_ranges.txt", "ASN Ranges", "85-ASN", category="osint"),
    ArtifactDef("dork_findings", "dork_findings.txt", "Dork Findings", "86-DORK", category="osint"),
    ArtifactDef("shodan_hosts", "shodan_hosts.txt", "Shodan Hosts", "87-SHODAN", category="osint"),
    ArtifactDef("employees", "employees.txt", "Employees", "88-EMPLOYEE", category="osint"),
    ArtifactDef("passive_dns_subs", "passive_dns_subs.txt", "Passive DNS", "89-PASSIVEDNS", category="osint"),
    ArtifactDef("emails", "emails_harvested.txt", "Emails", "71-EMHARVEST", category="osint"),
    ArtifactDef("github_dorking", "github_dorking.txt", "GitHub Dorking", "74-GHTOOLS", category="osint"),
    ArtifactDef("js_secrets", "js_secrets.txt", "JS Secrets", "15-SECRETS", vuln_type="secrets", in_exploit_chain=True, in_triage=True),
    ArtifactDef("js_deep", "js_secrets_deep.txt", "JS Secrets Deep", "15-SECRETS", vuln_type="secrets"),
    ArtifactDef("mobile_api", "mobile_api.txt", "Mobile API", "75-MOBILEAPI", category="osint"),

    # CMS & Framework
    ArtifactDef("iis_aspnet", "iis_aspnet_findings.txt", "IIS/ASP.NET", "121-IISASPNET", vuln_type="framework"),
    ArtifactDef("tomcat", "tomcat_findings.txt", "Tomcat", "122-TOMCAT", vuln_type="framework"),
    ArtifactDef("nodejs", "nodejs_findings.txt", "Node.js", "123-NODEJS", vuln_type="framework"),
    ArtifactDef("laravel", "laravel_exposure.txt", "Laravel", "124-LARAVEL", vuln_type="framework"),
    ArtifactDef("django", "django_exposure.txt", "Django", "125-DJANGO", vuln_type="framework"),
    ArtifactDef("symfony", "symfony_profiler.txt", "Symfony", "126-SYMFONY", vuln_type="framework"),
    ArtifactDef("cicd", "cicd_exposure.txt", "CI/CD Exposure", "127-CICD", vuln_type="cicd", severity_hint="critical", in_exploit_chain=True, in_triage=True),
    ArtifactDef("docker", "docker_registry.txt", "Docker Registry", "128-DOCKER", vuln_type="docker", severity_hint="critical", in_exploit_chain=True, in_triage=True),
    ArtifactDef("k8s", "k8s_exposure.txt", "Kubernetes", "129-K8S", vuln_type="k8s", severity_hint="critical", in_exploit_chain=True, in_triage=True),
    ArtifactDef("terraform", "terraform_exposure.txt", "Terraform", "130-TERRAFORM", vuln_type="terraform", severity_hint="critical"),
    ArtifactDef("env_deep", "env_files_found.txt", "Env/Config Files", "131-ENVDEEP", vuln_type="secrets"),
    ArtifactDef("api_version", "api_version_bypass.txt", "API Version Bypass", "133-APIVERSION"),
    ArtifactDef("lb_bypass", "load_balancer_bypass.txt", "LB Bypass", "134-LBDETECT"),
    ArtifactDef("vhost", "vhost_discovery.txt", "Virtual Hosts", "135-VHOST"),
    ArtifactDef("ratelimit_bypass", "rate_limit_bypass.txt", "Rate Limit Bypass", "136-RATELIMITBYPASS", vuln_type="ratelimit_bypass"),
    ArtifactDef("email_security", "email_security.txt", "Email Security", "59-EMAIL-SEC", category="osint"),
    ArtifactDef("smtp_enumeration", "smtp_enumeration.txt", "SMTP Enumeration", "60-SMTP-ENUM", category="osint"),
    ArtifactDef("banners", "banners.txt", "Banners", "115-BANNER", category="infra"),
    ArtifactDef("phpinfo_disclosure", "phpinfo_disclosure.txt", "phpinfo()", "116-PHPINFO", vuln_type="info_leak"),
    ArtifactDef("server_status_exposed", "server_status_exposed.txt", "Server Status", "117-SRVSTATUS", vuln_type="info_leak"),
    ArtifactDef("error_leakage", "error_leakage.txt", "Error Leakage", "118-ERRORLEAK", vuln_type="info_leak"),
    ArtifactDef("wildcard_dns", "wildcard_dns.txt", "Wildcard DNS", "119-WILDCARDDNS"),
    ArtifactDef("dns_rebinding", "dns_rebinding.txt", "DNS Rebinding", "120-DNSREBIND"),
    ArtifactDef("webdav_enumeration", "webdav_enumeration.txt", "WebDAV", "113-WEBDAV"),
    ArtifactDef("snmp_findings", "snmp_findings.txt", "SNMP", "114-SNMP"),

    # Extended OSINT
    ArtifactDef("emails_finder", "137-EMAILFINDER.txt", "Email Finder", "137-EMAILFINDER", category="osint"),
    ArtifactDef("metagoofil", "138-METAGOOFIL.txt", "Metagoofil", "138-METAGOOFIL", category="osint"),
    ArtifactDef("porchpirate", "139-PORCHPIRATE.txt", "Porch Pirate", "139-PORCHPIRATE", category="osint"),
    ArtifactDef("dork_hunter", "140-DORKHUNTER.txt", "Dork Hunter", "140-DORKHUNTER", category="osint"),
    ArtifactDef("crtsh", "141-CRTSH.txt", "crt.sh", "141-CRTSH", category="osint"),
    ArtifactDef("github_sub", "142-GITHUBSUB.txt", "GitHub Subdomains", "142-GITHUBSUB", category="osint"),
    ArtifactDef("tlsx", "143-TLSX.txt", "TLS Intel", "143-TLSX", category="osint"),
    ArtifactDef("analytics_rels", "144-ANALYTICSRELS.txt", "Analytics", "144-ANALYTICSRELS", category="osint"),
    ArtifactDef("favirecon", "145-FAVIRECON.txt", "Favicon Recon", "145-FAVIRECON", category="osint"),
    ArtifactDef("jsluice", "146-JSLUICE.txt", "JSLuice", "146-JSLUICE", category="osint"),
    ArtifactDef("shortscan", "147-SHORTSCAN.txt", "Short Scan", "147-SHORTSCAN", category="osint"),
    ArtifactDef("grpcurl", "148-GRPCURL.txt", "gRPC", "148-GRPCURL", category="infra"),
]

# ── Indexes for fast lookup ──────────────────────────────────────────────────
ARTIFACT_REGISTRY: Dict[str, ArtifactDef] = {a.key: a for a in ARTIFACTS}
FILENAME_TO_ARTIFACT: Dict[str, ArtifactDef] = {a.filename: a for a in ARTIFACTS}
CATEGORY_ORDER: List[str] = [
    "recon", "injection", "auth", "client_side", "infra", "osint", "cms", "correlation", "oast", "general"
]


def get_counts(outdir: Path) -> Dict[str, int]:
    """Count non-blank lines in each artifact file. Returns {key: count}."""
    result: Dict[str, int] = {}
    for art in ARTIFACTS:
        p = outdir / art.filename
        if p.exists():
            count = count_nonblank(p)
            if count > 0:
                result[art.key] = count
    return result


def get_findings_by_severity(outdir: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Load all findings grouped by severity level."""
    by_severity: Dict[str, List[Dict[str, Any]]] = {
        "critical": [], "high": [], "medium": [], "low": [], "info": [],
    }
    for art in ARTIFACTS:
        if not art.vuln_type:
            continue
        p = outdir / art.filename
        if not p.exists():
            continue
        for line in read_lines(p):
            text = line.strip()
            if not text:
                continue
            sev = guess_severity(text)
            by_severity[sev].append({
                "finding": text,
                "source": art.display_name,
                "file": art.filename,
                "phase": art.phase,
                "vuln_type": art.vuln_type,
                "severity": sev,
            })
    return by_severity


def get_findings_for_triage(outdir: Path, max_per_file: int = 30) -> List[Dict[str, str]]:
    """Load findings formatted for AI triage."""
    findings: List[Dict[str, str]] = []
    for art in ARTIFACTS:
        if not art.vuln_type and not art.in_triage:
            continue
        p = outdir / art.filename
        if not p.exists():
            continue
        count = 0
        for line in read_lines(p):
            text = line.strip()
            if not text or count >= max_per_file:
                break
            findings.append({"finding": text, "source": art.display_name, "file": art.filename})
            count += 1
    return findings


def get_findings_for_exploit_chain(outdir: Path) -> List[Dict[str, str]]:
    """Load findings formatted for exploit chain analysis."""
    findings: List[Dict[str, str]] = []
    for art in ARTIFACTS:
        if not art.in_exploit_chain and not art.vuln_type:
            continue
        p = outdir / art.filename
        if not p.exists():
            continue
        for line in read_lines(p):
            text = line.strip()
            if text:
                findings.append({"finding": text, "source": art.filename, "phase": art.phase, "vuln_type": art.vuln_type})
    return findings


def get_report_files() -> List[str]:
    """Get ordered list of artifact filenames for reports."""
    return [a.filename for a in ARTIFACTS if a.in_report]


def get_artifact_keys() -> List[str]:
    """Get ordered list of artifact keys."""
    return [a.key for a in ARTIFACTS]


def get_coverage(outdir: Path, all_phases: List[str]) -> Dict[str, Any]:
    """Compute coverage metrics: how many phases produced output."""
    phases_with_output = set()
    for art in ARTIFACTS:
        p = outdir / art.filename
        if p.exists() and p.stat().st_size > 0:
            phases_with_output.add(art.phase)
    tested = len(phases_with_output & set(all_phases))
    return {
        "tested_phases": tested,
        "total_phases": len(all_phases),
        "coverage_pct": round(100.0 * tested / max(len(all_phases), 1), 1),
        "phases_with_output": sorted(phases_with_output),
    }
