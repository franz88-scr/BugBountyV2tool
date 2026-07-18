"""Configuration constants, dataclasses, and pipeline definitions."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from reconchain.exceptions import ConfigError as ConfigError

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
__version__ = "3.1.0"

VALID_PHASES = {
    "00-SCOPE", "01-RECON", "02-RESOLVE", "03-PERMUTE", "04-SCAN",
    "04b-TAKEOVER-VALIDATE", "05-HARVEST", "05b-APISPEC", "06-JSINTEL",
    "07-PARAMS", "08-FUZZ", "09-VULNSCAN", "10-TLSCMS", "11-INJECT",
    "11a-DOMXSS", "11b-SQLMAP", "12-SSTI", "13-OOB", "14-ORIGIN", "15-SECRETS",
    "16a-AUTHZ", "16b-MASSASSIGN", "17-IDOR", "17b-SSRFMETA", "18-CLOUD",
    "19-GIT", "20-GRAPHQL",     "21-WAF", "21b-WAFBYPASS", "22-NOSQLI", "23-RACE", "24-JWT",
    "25-XXE", "26-CMDINJECT", "27-SSPP", "28-CACHED", "29-DEPCHECK",
    "30-LFI", "31-OPENREDIR", "32-CLICKJACK", "33-CRLF", "34-RATELIMIT",
    "35-CORSADV", "36-JWTADV", "37-FILEUPLOAD", "38-SMUGGLE", "38b-H2SMUGGLE",
    "39-OAUTH", "40-PWRESET", "41-WEBSOCKET", "42-LDAP", "43-DESERIAL", "44-CHAIN",
    "45-EVIDENCE", "46-BUCKET", "47-CDN", "48-CONTENT", "49-FRAMEWORKS",
    "50-BUCKET-PERMS", "51-HPP", "52-SERVERLESS", "53-CSP", "54-WS-FUZZ",
    "55-CSV-INJECT", "56-EXPOSED-DB", "57-DEFAULT-CREDS", "58-HOST-INJECT",
    "59-EMAIL-SEC", "60-SMTP-ENUM", "61-OAUTH-ADV", "62-LOG-INJECT",     "63-DOC-ATTACK", "64-IDEMPOTENCY",
     "65-SESSION", "66-SSRF-FULL", "67-PATHNORM", "68-DEPCVE",
     "69-DNSZT", "70-PORTFULL", "71-EMHARVEST",
    "72-ACCOUNTENUM", "73-CSPBYPASS", "74-GHTOOLS", "75-MOBILEAPI",
    "76-WORKFLOW", "77-CACHEKEY", "78-FILEUPLOADADV", "79-SECRETDIFF",
     "80-STOREXSS", "81-IDORFUZZ", "82-OAUTHDEEP", "83-RACEBURST",
    "84-WHOIS", "85-ASN", "86-DORK", "87-SHODAN", "88-EMPLOYEE", "89-PASSIVEDNS",
    "90-CSRF", "91-SESSIONFIX", "92-SAML", "93-PWDSPRAY", "94-COOKIEAUDIT",
    "95-POSTTEST", "96-METHODOVERRIDE", "97-FORCEDBROWSE", "98-CASEBYPASS",
    "99-APIPAGE", "99a-TABNAB", "99b-APIKEYLEAK", "99c-REDIRABUSE",
    "99d-LOGTRIGGER", "99e-XSSSTORED", "99f-HOSTABUSE", "99g-AUTHBYPASSADV",
    "100-SSI", "101-JSONINJECT", "102-NULLBYTE", "103-DOUBLEENCOD", "104-UNICODE",
    "105-POSTMSGXSS", "106-JSONP", "107-SRI", "108-MIXEDCONTENT", "109-HSTSPRELOAD",
    "110-THIRDPARTYJS", "111-BROWSERSTORAGE", "112-RFI", "113-WEBDAV", "114-SNMP",
    "115-BANNER", "116-PHPINFO", "117-SRVSTATUS", "118-ERRORLEAK",
    "119-WILDCARDDNS", "120-DNSREBIND",
     "121-IISASPNET", "122-TOMCAT", "123-NODEJS", "124-LARAVEL", "125-DJANGO", "126-SYMFONY",
    "127-CICD", "128-DOCKER", "129-K8S", "130-TERRAFORM", "131-ENVDEEP",
    "132-GQLABUSE", "133-APIVERSION", "134-LBDETECT", "135-VHOST", "136-RATELIMITBYPASS",
    "137-EMAILFINDER", "138-METAGOOFIL", "139-PORCHPIRATE", "140-DORKHUNTER",
    "141-CRTSH", "142-GITHUBSUB", "143-TLSX", "144-ANALYTICSRELS",
    "145-FAVIRECON", "146-JSLUICE", "147-SHORTSCAN", "148-GRPCURL",
}
FAST_PHASES = {"00-SCOPE", "01-RECON", "02-RESOLVE", "04-SCAN", "05-HARVEST"}
# Phases that are redundant, low-signal, or produce false positives against wildcard-DNS targets.
# Used by --profile quick to skip them automatically.
QUICK_SKIP_PHASES = {
    # Info-leak probes that produce no real findings against modern targets
    "115-BANNER",        # SSH/FTP banners — rarely useful for web targets
    "116-PHPINFO",       # phpinfo() disclosure — already covered by nuclei
    "117-SRVSTATUS",     # Apache/Nginx server-status — already covered by nuclei
    # Framework-specific probes that only fire on matching tech (low hit rate)
    "121-IISASPNET",     # IIS/ASP.NET — only if IIS detected
    "122-TOMCAT",        # Tomcat manager/JMX — only if Tomcat detected
    "123-NODEJS",        # Node.js debug/SSTI — only if Node detected
    "124-LARAVEL",       # Laravel env/logs — only if Laravel detected
    "125-DJANGO",        # Django debug/admin — only if Django detected
    "126-SYMFONY",       # Symfony profiler — only if Symfony detected
    # Infrastructure probes (low signal for web apps)
    "119-WILDCARDDNS",   # Wildcard DNS detection — already handled by 404 filter
    "120-DNSREBIND",     # DNS rebinding — very niche attack
    "127-CICD",          # CI/CD file exposure — rarely found
    "128-DOCKER",        # Docker registry exposure — rarely found
    "129-K8S",           # Kubernetes exposure — rarely found
    "130-TERRAFORM",     # Terraform state exposure — rarely found
    # Duplicate/overlapping phases
    "84-WHOIS",          # WHOIS info — available via other tools
    "85-ASN",            # ASN lookup — low web security value
    "89-PASSIVEDNS",     # Passive DNS — already in recon data
    "91-SESSIONFIX",     # Session fixation — low signal
    "92-SAML",           # SAML bypass — only if SAML detected
    "95-POSTTEST",       # POST auth bypass — overlaps with 99g-AUTHBYPASSADV
    "96-METHODOVERRIDE", # Method override — overlaps with other auth phases
    "98-CASEBYPASS",     # Case-sensitivity bypass — overlaps with 97-FORCEDBROWSE
    "99a-TABNAB",        # Reverse tabnabbing — low priority
    "102-NULLBYTE",      # Null byte injection — modern servers block this
    "103-DOUBLEENCOD",   # Double encoding — covered by nuclei
    "104-UNICODE",       # Unicode bypass — covered by nuclei
    "106-JSONP",         # JSONP hijacking — very niche
    "108-MIXEDCONTENT",  # Mixed content — informational, not a vulnerability
    "109-HSTSPRELOAD",   # HSTS preload — informational only
    "110-THIRDPARTYJS",  # Third-party JS audit — informational only
    "112-RFI",           # Remote file inclusion — very niche
    "113-WEBDAV",        # WebDAV testing — very niche
    "114-SNMP",          # SNMP — not web security
    "52-SERVERLESS",     # Serverless detection — niche
    "59-EMAIL-SEC",      # Email security — not web security
    "60-SMTP-ENUM",      # SMTP enumeration — not web security
}
DOS_PHASES = {
    "20-GRAPHQL",      # 100-alias batching, depth-10 nested queries
    "23-RACE",         # 5 concurrent requests + TOCTOU write+read
    "34-RATELIMIT",    # Burst of 10-50 requests per URL
    "38-SMUGGLE",      # CL.TE/TE.CL raw socket smuggling (can crash proxies)
    "38b-H2SMUGGLE",   # 500x RST_STREAM (CVE-2023-44487), 100KB HPACK bomb
    "54-WS-FUZZ",      # 10KB+ WebSocket payload injection
    "83-RACEBURST",    # 10 concurrent "turbo" burst requests per endpoint
    "93-PWDSPRAY",     # Up to 300 login attempts across 3 URLs
    "132-GQLABUSE",    # 50-query batching, depth-10 nested GraphQL
    "136-RATELIMITBYPASS",  # Multi-vector rate limit bypass
}
DISCOVERY_PHASES = {
    "00-SCOPE", "01-RECON", "02-RESOLVE", "03-PERMUTE", "04-SCAN",
    "04b-TAKEOVER-VALIDATE", "05-HARVEST", "05b-APISPEC", "06-JSINTEL",
    "07-PARAMS", "08-FUZZ", "21-WAF",
}

# ── Phase categories for the interactive wizard ──────────────────────────────
# Each category groups related phases for the grouped phase selector UI.
# Order here defines display order in the wizard.
PHASE_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "Recon & Discovery": {
        "desc": "Scope validation, subdomain enumeration, DNS resolution, port scanning, URL harvesting, JS analysis, parameter discovery, fuzzing, vuln scanning, TLS/CMS fingerprinting",
        "phases": [
            ("00-SCOPE", "Scope validation"),
            ("01-RECON", "Subdomain enumeration (subfinder, findomain, etc.)"),
            ("02-RESOLVE", "DNS resolution & live probing"),
            ("03-PERMUTE", "Subdomain permutation"),
            ("04-SCAN", "Port scanning (naabu/nmap)"),
            ("04b-TAKEOVER-VALIDATE", "Confirm dangling CNAME exploitability"),
            ("05-HARVEST", "URL gathering (gau, wayback, katana)"),
            ("05b-APISPEC", "API spec discovery (Swagger/OpenAPI/GraphQL SDL)"),
            ("06-JSINTEL", "JavaScript analysis (secretfinder, corsy)"),
            ("07-PARAMS", "Parameter discovery (arjun/x8)"),
            ("08-FUZZ", "Endpoint fuzzing (ffuf)"),
            ("09-VULNSCAN", "Vulnerability scanning (nuclei)"),
            ("10-TLSCMS", "TLS/CMS fingerprinting"),
        ],
    },
    "OSINT & Passive Recon": {
        "desc": "WHOIS, ASN, Google dorking, Shodan, email harvesting, passive DNS, crt.sh, GitHub subdomains, metagoofil, porch-pirate",
        "phases": [
            ("84-WHOIS", "WHOIS registration data lookup"),
            ("85-ASN", "ASN & BGP prefix enumeration"),
            ("86-DORK", "Google/Bing dorking for sensitive files & pages"),
            ("87-SHODAN", "Shodan host & service fingerprinting"),
            ("88-EMPLOYEE", "Employee name harvesting"),
            ("89-PASSIVEDNS", "Passive DNS historical subdomain lookup"),
            ("71-EMHARVEST", "Email address harvesting from web pages"),
            ("137-EMAILFINDER", "Email address discovery"),
            ("138-METAGOOFIL", "Document metadata extraction"),
            ("139-PORCHPIRATE", "Exposed package / public repos discovery"),
            ("140-DORKHUNTER", "Advanced dorking for exposed panels"),
            ("141-CRTSH", "crt.sh certificate transparency lookup"),
            ("142-GITHUBSUB", "GitHub subdomain discovery"),
        ],
    },
    "Injection & XSS": {
        "desc": "XSS (dalfox/kxss/DOM), SQL injection (sqlmap), SSTI, NoSQLi, XXE, command injection, prototype pollution, LDAP, deserialization, stored XSS, SSI, JSON injection, null byte, encoding bypasses",
        "phases": [
            ("11-INJECT", "XSS (dalfox/kxss), SSRF probes, parameter injection"),
            ("11a-DOMXSS", "DOM-based XSS via browser automation (Playwright)"),
            ("11b-SQLMAP", "SQL injection via sqlmap (pre-filtered)"),
            ("12-SSTI", "SSTI fuzzing"),
            ("22-NOSQLI", "NoSQL injection probes"),
            ("25-XXE", "XML external entity injection"),
            ("26-CMDINJECT", "OS command injection detection"),
            ("27-SSPP", "Server-side prototype pollution"),
            ("42-LDAP", "LDAP injection detection"),
            ("43-DESERIAL", "Deserialization attack detection"),
            ("55-CSV-INJECT", "CSV/Excel formula injection (DDE, HYPERLINK)"),
            ("62-LOG-INJECT", "Log injection / log forging detection"),
            ("80-STOREXSS", "Stored XSS payload injection + verification"),
            ("99e-XSSSTORED", "Stored XSS with payload persistence check"),
            ("100-SSI", "SSI injection testing"),
            ("101-JSONINJECT", "JSON-based injection (JWT, template, expression)"),
            ("102-NULLBYTE", "Null byte injection bypass"),
            ("103-DOUBLEENCOD", "Double URL encoding bypass"),
            ("104-UNICODE", "Unicode normalization bypass"),
            ("105-POSTMSGXSS", "postMessage XSS via window.postMessage"),
            ("106-JSONP", "JSONP hijacking & callback abuse"),
        ],
    },
    "Auth & Session": {
        "desc": "JWT analysis, OAuth misconfig, session fixation, CSRF, IDOR, password reset poisoning, SAML bypass, cookie audit, mass assignment, credential spraying",
        "phases": [
            ("24-JWT", "JWT token analysis"),
            ("36-JWTADV", "Advanced JWT attacks"),
            ("39-OAUTH", "OAuth misconfiguration testing"),
            ("40-PWRESET", "Password reset logic testing"),
            ("61-OAUTH-ADV", "OAuth redirect_uri bypass variants"),
            ("65-SESSION", "Session fixation & token lifecycle analysis"),
            ("82-OAUTHDEEP", "Deep OAuth redirect_uri bypass (state, PKCE)"),
            ("16a-AUTHZ", "Auth bypass header injection"),
            ("16b-MASSASSIGN", "Mass assignment field discovery"),
            ("17-IDOR", "ID manipulation / predictable IDs"),
            ("17b-SSRFMETA", "Cloud metadata exfiltration (SSRF confirmed)"),
            ("81-IDORFUZZ", "IDOR via parameter fuzzing (cross-session)"),
            ("90-CSRF", "CSRF token validation & SameSite audit"),
            ("91-SESSIONFIX", "Session fixation & session handling audit"),
            ("92-SAML", "SAML authentication bypass testing"),
            ("93-PWDSPRAY", "Credential spray & password policy testing"),
            ("94-COOKIEAUDIT", "Cookie security flags audit (HttpOnly/Secure/SameSite)"),
            ("95-POSTTEST", "POST-based authentication bypass testing"),
            ("96-METHODOVERRIDE", "HTTP method override (X-HTTP-Method-Override)"),
            ("99f-HOSTABUSE", "Host header abuse (password reset poisoning, cache)"),
            ("99g-AUTHBYPASSADV", "Advanced auth bypass (path traversal, header injection)"),
        ],
    },
    "Client-Side & Web": {
        "desc": "Cache poisoning, CORS, clickjacking, open redirect, CRLF, file upload, CSP, HPP, rate limiting, WebSocket, evidence capture, cross-phase correlation",
        "phases": [
            ("28-CACHED", "Web cache poisoning/deception + v2 probes"),
            ("29-DEPCHECK", "JS dependency vulnerability scan"),
            ("30-LFI", "Local file inclusion / path traversal"),
            ("31-OPENREDIR", "Open redirect detection"),
            ("32-CLICKJACK", "Clickjacking protection check"),
            ("33-CRLF", "CRLF injection detection"),
            ("34-RATELIMIT", "Rate limiting detection"),
            ("35-CORSADV", "Advanced CORS misconfiguration (corsy)"),
            ("37-FILEUPLOAD", "File upload vulnerability testing"),
            ("41-WEBSOCKET", "WebSocket security testing + deep probes"),
            ("44-CHAIN", "Cross-phase finding correlation"),
            ("45-EVIDENCE", "Capture request/response + auto PoC generation"),
            ("48-CONTENT", "Content discovery via common path probing"),
            ("51-HPP", "HTTP parameter pollution detection"),
            ("54-WS-FUZZ", "WebSocket message fuzzing"),
            ("58-HOST-INJECT", "Host header injection / cache poisoning variants"),
            ("63-DOC-ATTACK", "Document-based attacks (DDE, macro, XXE, SVG-XSS)"),
            ("64-IDEMPOTENCY", "Idempotency key replay testing (POST endpoints)"),
            ("67-PATHNORM", "Path normalization bypass (e.g. /admin -> /Admin)"),
            ("73-CSPBYPASS", "CSP bypass technique testing"),
            ("76-WORKFLOW", "Workflow logic bypass testing"),
            ("77-CACHEKEY", "Cache key probe & poisoning via key differences"),
            ("78-FILEUPLOADADV", "Advanced file upload (polyglot, metadata stripping)"),
            ("97-FORCEDBROWSE", "Forced browsing to hidden endpoints"),
            ("98-CASEBYPASS", "Case-sensitive path access bypass"),
            ("99-APIPAGE", "Hidden API page discovery (/api, /graphql, /swagger)"),
            ("99a-TABNAB", "Reverse tabnabbing via target=_blank links"),
            ("99b-APIKEYLEAK", "API key exposure in JS, HTML comments, error pages"),
            ("99c-REDIRABUSE", "Open redirect chain abuse for SSRF/XSS"),
            ("99d-LOGTRIGGER", "Log injection trigger (CRLF in User-Agent, Referer)"),
            ("107-SRI", "Subresource Integrity (SRI) missing/bypass"),
            ("108-MIXEDCONTENT", "Mixed HTTP/HTTPS content loading"),
            ("109-HSTSPRELOAD", "HSTS preload list compliance check"),
            ("110-THIRDPARTYJS", "Third-party JS library vulnerability scan"),
            ("111-BROWSERSTORAGE", "Browser storage (localStorage/sessionStorage) audit"),
        ],
    },
    "Infrastructure & Cloud": {
        "desc": "SSRF, cloud buckets, WAF detection & bypass, race conditions, smuggling (HTTP/HTTP2), GraphQL abuse, CDN, serverless, exposed DBs, default creds, secret scanning",
        "phases": [
            ("13-OOB", "OOB interaction tracking (DNS/HTTP Callback)"),
            ("14-ORIGIN", "Origin IP bypass (Cloudflare)"),
            ("15-SECRETS", "Deep JS secret scanning (secretfinder + corsy)"),
            ("18-CLOUD", "Cloud bucket discovery (AWS/GCP/Azure)"),
            ("19-GIT", "Git exposure scanning (.git + trufflehog)"),
            ("20-GRAPHQL", "GraphQL introspection + schema analysis + deep probes"),
            ("21-WAF", "WAF detection (50+ vendor signatures)"),
            ("21b-WAFBYPASS", "WAF bypass technique testing"),
            ("23-RACE", "Race condition detection"),
            ("38-SMUGGLE", "HTTP request smuggling detection"),
            ("38b-H2SMUGGLE", "HTTP/2 + HTTP/3 attack surface (H2 smugg, QUIC, HPACK)"),
            ("46-BUCKET", "Cloud storage bucket enumeration (S3/Azure/GCP)"),
            ("47-CDN", "CDN provider detection + origin IP discovery"),
            ("49-FRAMEWORKS", "Framework detection + edge runtime vulnerability checks"),
            ("50-BUCKET-PERMS", "Cloud bucket permission auditing (public read/write)"),
            ("52-SERVERLESS", "Serverless/cloud function endpoint discovery"),
            ("53-CSP", "CSP header analysis + bypass detection"),
            ("56-EXPOSED-DB", "Exposed database / storage probing (ES, Redis, Mongo, K8s)"),
            ("57-DEFAULT-CREDS", "Default credentials testing on admin services"),
            ("59-EMAIL-SEC", "Email security posture (SPF/DMARC/DKIM)"),
            ("60-SMTP-ENUM", "SMTP enumeration / email bombing detection"),
            ("66-SSRF-FULL", "Full SSRF with OOB callback + cloud metadata exfil"),
            ("68-DEPCVE", "Known CVE check for JS/Python/Go dependencies"),
            ("69-DNSZT", "DNS zone transfer attempt (AXFR)"),
            ("70-PORTFULL", "Full port scan (all 65535 ports)"),
            ("72-ACCOUNTENUM", "Account enumeration via login/register error messages"),
            ("74-GHTOOLS", "GitHub dorking for tokens, secrets, endpoints"),
            ("75-MOBILEAPI", "Mobile API endpoint discovery (.well-known, APK)"),
            ("79-SECRETDIFF", "Secret rotation diff analysis (old vs new)"),
            ("83-RACEBURST", "Race condition burst (Turbo Intruder style)"),
            ("132-GQLABUSE", "GraphQL batching, depth DoS & schema leak"),
            ("133-APIVERSION", "API versioning bypass (v0, internal, legacy, beta)"),
            ("134-LBDETECT", "Load balancer detection & origin bypass"),
            ("135-VHOST", "Virtual host enumeration via Host header"),
            ("136-RATELIMITBYPASS", "Rate limit bypass (IP rotation, case, unicode)"),
        ],
    },
    "CMS & Framework Exposure": {
        "desc": "IIS/ASP.NET, Tomcat, Node.js, Laravel, Django, Symfony, CI/CD, Docker, Kubernetes, Terraform, env/config secrets, gRPC, TLS cert intel, analytics, favicon recon, JS endpoints, shortlinks",
        "phases": [
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
            ("115-BANNER", "Server banner fingerprinting"),
            ("116-PHPINFO", "phpinfo() exposure detection"),
            ("117-SRVSTATUS", "Server status page exposure (/server-status)"),
            ("118-ERRORLEAK", "Error message info leakage (stack traces, debug)"),
            ("119-WILDCARDDNS", "Wildcard DNS detection & DDoS surface"),
            ("120-DNSREBIND", "DNS rebinding attack surface check"),
            ("112-RFI", "Remote file inclusion probing"),
            ("113-WEBDAV", "WebDAV method & file exposure"),
            ("114-SNMP", "SNMP community string & info leak"),
            ("143-TLSX", "TLS certificate intel (expiry, SAN, CT logs)"),
            ("144-ANALYTICSRELS", "Analytics / tracking endpoint discovery"),
            ("145-FAVIRECON", "Favicon-based technology fingerprinting"),
            ("146-JSLUICE", "JS endpoint & secret extraction (jsluice)"),
            ("147-SHORTSCAN", "Short URL / link shortener endpoint scanning"),
            ("148-GRPCURL", "gRPC service enumeration & reflection"),
        ],
    },
}

# Phase IDs ordered by category (flat list preserving category order)
PHASE_CATEGORY_ORDER: List[str] = [
    pid for cat in PHASE_CATEGORIES.values() for pid, _ in cat["phases"]
]

# ── Wizard presets ───────────────────────────────────────────────────────────
# Each preset maps to a set of phase IDs + default config overrides.
WIZARD_PRESETS: Dict[str, Dict[str, Any]] = {
    "quick": {
        "name": "Quick Recon",
        "desc": "Scope -> Subs -> DNS -> Ports/HTTP -> URLs (~5 min)",
        "phases": {"00-SCOPE", "01-RECON", "02-RESOLVE", "04-SCAN", "05-HARVEST"},
        "defaults": {
            "delay": 0.0,
            "rate_limit": 0,
            "dos_mode": False,
            "sqlmap_level": 1,
            "sqlmap_risk": 1,
            "fast": True,
        },
    },
    "standard": {
        "name": "Standard Assessment",
        "desc": "Recon + perms + JS secrets + params + fuzzing + nuclei + TLS + origin + JWT + cache (~15 min)",
        "phases": {
            "00-SCOPE", "01-RECON", "02-RESOLVE", "03-PERMUTE", "04-SCAN",
            "05-HARVEST", "06-JSINTEL", "07-PARAMS", "08-FUZZ",
            "09-VULNSCAN", "10-TLSCMS", "14-ORIGIN", "24-JWT",
            "28-CACHED", "34-RATELIMIT", "41-WEBSOCKET",
        },
        "defaults": {
            "delay": 0.0,
            "rate_limit": 10,
            "dos_mode": False,
            "sqlmap_level": 1,
            "sqlmap_risk": 1,
            "fast": False,
        },
    },
    "full": {
        "name": "Full Audit",
        "desc": "All 164 phases — complete recon + vuln scan + auth + client-side + infra + CMS (~2 hrs)",
        "phases": VALID_PHASES,
        "defaults": {
            "delay": 0.0,
            "rate_limit": 10,
            "dos_mode": False,
            "sqlmap_level": 1,
            "sqlmap_risk": 1,
            "fast": False,
        },
    },
    "stealth": {
        "name": "Stealth / Polite",
        "desc": "Recon only with rate limiting — for monitored targets (~30 min)",
        "phases": {"00-SCOPE", "01-RECON", "02-RESOLVE", "04-SCAN", "05-HARVEST"},
        "defaults": {
            "delay": 2.0,
            "rate_limit": 5,
            "dos_mode": False,
            "sqlmap_level": 1,
            "sqlmap_risk": 1,
            "fast": True,
        },
    },
    "pentest": {
        "name": "Web App Pentest",
        "desc": "Standard + all injection + auth bypass + client-side (~45 min)",
        "phases": {
            "00-SCOPE", "01-RECON", "02-RESOLVE", "03-PERMUTE", "04-SCAN",
            "05-HARVEST", "06-JSINTEL", "07-PARAMS", "08-FUZZ",
            "09-VULNSCAN", "10-TLSCMS", "14-ORIGIN",
            "11-INJECT", "11a-DOMXSS", "11b-SQLMAP", "12-SSTI",
            "22-NOSQLI", "25-XXE", "26-CMDINJECT", "27-SSPP",
            "24-JWT", "36-JWTADV", "39-OAUTH", "40-PWRESET",
            "16a-AUTHZ", "16b-MASSASSIGN", "17-IDOR",
            "28-CACHED", "30-LFI", "31-OPENREDIR", "32-CLICKJACK",
            "33-CRLF", "35-CORSADV", "37-FILEUPLOAD", "51-HPP",
            "41-WEBSOCKET", "45-EVIDENCE", "44-CHAIN",
        },
        "defaults": {
            "delay": 0.0,
            "rate_limit": 10,
            "dos_mode": False,
            "sqlmap_level": 2,
            "sqlmap_risk": 1,
            "fast": False,
        },
    },
    "osint": {
        "name": "OSINT Focus",
        "desc": "Recon + all OSINT/passive phases — employee names, dorks, certs, GitHub (~20 min)",
        "phases": {
            "00-SCOPE", "01-RECON", "02-RESOLVE", "04-SCAN", "05-HARVEST",
            "84-WHOIS", "85-ASN", "86-DORK", "87-SHODAN", "88-EMPLOYEE",
            "89-PASSIVEDNS", "71-EMHARVEST", "137-EMAILFINDER", "138-METAGOOFIL",
            "139-PORCHPIRATE", "140-DORKHUNTER", "141-CRTSH", "142-GITHUBSUB",
        },
        "defaults": {
            "delay": 0.5,
            "rate_limit": 5,
            "dos_mode": False,
            "sqlmap_level": 1,
            "sqlmap_risk": 1,
            "fast": False,
        },
    },
}

PhaseSet = Set[str]

_SAFE_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")


@dataclass
class PipelineConfig:
    """Shared configuration carried through the pipeline.

    This dataclass holds every tunable parameter for the scan. Fields are
    grouped logically (scan params, sampling, auth, proxy, etc.) and
    validated at construction via ``__post_init__``.

    Sensitive fields (``auth_bearer``, ``auth_api_key``, ``auth_basic``,
    ``auth_client_cert``) are automatically redacted in ``__repr__``.

    Example::

        cfg = PipelineConfig(
            delay=0.5,
            rate_limit=10,
            auth_bearer="mytoken",
        )
    """
    # ── Scan behavior ────────────────────────────────────────────────
    dos_mode: bool = False
    sqlmap_level: int = 1
    sqlmap_risk: int = 1
    delay: float = 0.0
    rate_limit: int = 10
    # ── Sampling (max artifacts per phase) ───────────────────────────
    sample_mode: str = "normal"
    sample_urls_fuzz: int = 200
    sample_urls_params: int = 15
    sample_urls_arjun_waf: int = 5
    sample_hosts_ssl: int = 3
    sample_hosts_origin: int = 10
    sample_endpoints_l: int = 20
    sample_urls_xss_blind: int = 20
    sample_urls_ssti: int = 5
    sample_endpoints_post: int = 5
    sample_endpoints_cors: int = 10
    nuclei_exclude_tags: str = ""
    # ── Proxy ────────────────────────────────────────────────────────
    proxy: str = ""
    vuln_proxy: str = ""
    proxy_timeout_multiplier: float = 1.5
    sample_hosts_cloud: int = 5
    sample_hosts_git: int = 5
    sample_hosts_graphql: int = 5
    sample_hosts_waf: int = 5
    sample_urls_nosqli: int = 30
    sample_endpoints_race: int = 10
    sample_hosts_jwt: int = 20
    sample_urls_xxe: int = 10
    sample_urls_cmdi: int = 30
    sample_endpoints_sspp: int = 10
    sample_hosts_cached: int = 10
    sample_urls_depcheck: int = 30
    sample_urls_redirect: int = 30
    sample_hosts_clickjack: int = 20
    sample_urls_crlf: int = 20
    sample_hosts_ratelimit: int = 10
    sample_endpoints_ratelimit: int = 5
    sample_endpoints_corsadv: int = 10
    sample_hosts_jwtadv: int = 20
    sample_urls_upload: int = 10
    sample_hosts_smuggle: int = 10
    sample_endpoints_oauth: int = 10
    sample_endpoints_pwreset: int = 10
    sample_hosts_websocket: int = 10
    sample_urls_ldap: int = 20
    sample_endpoints_deserial: int = 10
    sample_urls_lfi: int = 30
    sample_urls_idor: int = 50
    sample_urls_apisec: int = 50
    sample_urls_domxss: int = 30
    sample_hosts_h2smuggle: int = 10
    sample_hosts_frameworks: int = 20
    takeover_validate: bool = True
    # ── WAF / evasion ────────────────────────────────────────────────
    waf_detected: bool = False
    waf_evasion_throttle: float = 0.0
    # ── Session / IDOR ───────────────────────────────────────────────
    credentials_queue: List[str] = field(default_factory=list)
    cookie_b: str = ""
    idor_session_a: str = ""
    idor_session_b: str = ""
    sample_urls_csrf: int = 20
    sample_hosts_sessionfix: int = 10
    sample_endpoints_saml: int = 10
    sample_users_spray: int = 20
    sample_hosts_cookie: int = 20
    sample_urls_posttest: int = 30
    sample_urls_methodoverride: int = 20
    sample_hosts_forcedbrowse: int = 20
    sample_urls_casebypass: int = 20
    sample_urls_apipage: int = 20
    sample_urls_tabnab: int = 30
    sample_urls_apikeyleak: int = 30
    sample_urls_redirabuse: int = 20
    sample_urls_logtrigger: int = 20
    sample_urls_xssstored: int = 10
    sample_hosts_hostabuse: int = 10
    sample_urls_authbypassadv: int = 20
    sample_urls_ssi: int = 20
    sample_urls_jsoninject: int = 20
    sample_urls_nullbyte: int = 20
    sample_urls_doubleencod: int = 20
    sample_urls_unicode: int = 20
    sample_hosts_postmsg: int = 15
    sample_hosts_jsonp: int = 20
    sample_hosts_sri: int = 20
    sample_hosts_mixedcontent: int = 20
    sample_hosts_hstspreload: int = 20
    sample_hosts_thirdpartyjs: int = 15
    sample_hosts_browserstorage: int = 15
    sample_urls_rfi: int = 20
    sample_hosts_webdav: int = 10
    sample_hosts_snmp: int = 10
    sample_hosts_banner: int = 15
    sample_hosts_phpinfo: int = 15
    sample_hosts_srvstatus: int = 15
    sample_urls_errorleak: int = 20
    sample_hosts_wildcarddns: int = 10
    sample_hosts_dnsrebind: int = 10
    sample_hosts_iisaspnet: int = 10
    sample_hosts_tomcat: int = 10
    sample_hosts_nodejs: int = 10
    sample_hosts_laravel: int = 10
    sample_hosts_django: int = 10
    sample_hosts_symfony: int = 10
    sample_hosts_cicd: int = 10
    sample_hosts_docker: int = 10
    sample_hosts_k8s: int = 10
    sample_hosts_terraform: int = 10
    sample_hosts_envdeep: int = 10
    sample_hosts_gqlabuse: int = 10
    sample_urls_apiversion: int = 20
    sample_hosts_lbdetect: int = 15
    sample_hosts_vhost: int = 10
    sample_urls_ratelimitbypass: int = 20
    sample_hosts_emailfinder: int = 10
    sample_urls_metagoofil: int = 50
    sample_hosts_porchpirate: int = 10
    sample_urls_dorkhunter: int = 20
    sample_hosts_crtsh: int = 10
    sample_hosts_githubsub: int = 10
    sample_hosts_tlsx: int = 10
    sample_hosts_analyticsrels: int = 10
    sample_hosts_favirecon: int = 10
    sample_urls_jsluice: int = 20
    sample_urls_shortscan: int = 20
    sample_hosts_grpcurl: int = 10
    safe_mode: bool = False
    # ── Authentication ──────────────────────────────────────────────
    auth_bearer: str = ""
    auth_api_key: str = ""
    auth_api_key_header: str = "X-API-Key"
    auth_client_cert: str = ""
    auth_basic: str = ""
    # ── Rate limiter ────────────────────────────────────────────────
    rate_limit_per_domain: int = 0

    _SENSITIVE_FIELDS = frozenset({
        "auth_bearer", "auth_api_key", "auth_basic", "auth_client_cert",
        "proxy", "vuln_proxy", "cookie", "cookie_b",
        "idor_session_a", "idor_session_b",
        "extra_headers", "credentials_queue",
    })

    def __repr__(self) -> str:
        """Redact sensitive fields in repr to prevent credential leakage in logs/tracebacks."""
        from dataclasses import fields as dc_fields
        parts = []
        for f in dc_fields(self):
            val = getattr(self, f.name)
            if f.name in self._SENSITIVE_FIELDS:
                if val:
                    parts.append(f"{f.name}=***")
                else:
                    parts.append(f"{f.name}={val!r}")
            else:
                parts.append(f"{f.name}={val!r}")
        return f"PipelineConfig({', '.join(parts)})"

    def __post_init__(self) -> None:
        """Validate configuration values at construction time."""
        _positive_int = [
            "sqlmap_level", "sqlmap_risk", "rate_limit", "sample_urls_fuzz",
            "sample_urls_params", "sample_urls_arjun_waf", "sample_hosts_ssl",
            "sample_hosts_origin", "sample_endpoints_l", "sample_urls_xss_blind",
            "sample_urls_ssti", "sample_endpoints_post", "sample_endpoints_cors",
            "sample_hosts_cloud", "sample_hosts_git", "sample_hosts_graphql",
            "sample_hosts_waf", "sample_urls_nosqli", "sample_endpoints_race",
            "sample_hosts_jwt", "sample_urls_xxe", "sample_urls_cmdi",
            "sample_endpoints_sspp", "sample_hosts_cached", "sample_urls_depcheck",
            "sample_urls_redirect", "sample_hosts_clickjack", "sample_urls_crlf",
            "sample_hosts_ratelimit", "sample_endpoints_ratelimit",
            "sample_endpoints_corsadv", "sample_hosts_jwtadv", "sample_urls_upload",
            "sample_hosts_smuggle", "sample_endpoints_oauth", "sample_endpoints_pwreset",
            "sample_hosts_websocket", "sample_urls_ldap", "sample_endpoints_deserial",
            "sample_urls_lfi", "sample_urls_idor", "sample_urls_apisec",
            "sample_urls_domxss", "sample_hosts_h2smuggle", "sample_hosts_frameworks",
            "sample_urls_csrf", "sample_hosts_sessionfix", "sample_endpoints_saml",
            "sample_users_spray", "sample_hosts_cookie", "sample_urls_posttest",
            "sample_urls_methodoverride", "sample_hosts_forcedbrowse",
            "sample_urls_casebypass", "sample_urls_apipage", "sample_urls_tabnab",
            "sample_urls_apikeyleak", "sample_urls_redirabuse", "sample_urls_logtrigger",
            "sample_urls_xssstored", "sample_hosts_hostabuse", "sample_urls_authbypassadv",
            "sample_urls_ssi", "sample_urls_jsoninject", "sample_urls_nullbyte",
            "sample_urls_doubleencod", "sample_urls_unicode", "sample_hosts_postmsg",
            "sample_hosts_jsonp", "sample_hosts_sri", "sample_hosts_mixedcontent",
            "sample_hosts_hstspreload", "sample_hosts_thirdpartyjs",
            "sample_hosts_browserstorage", "sample_urls_rfi", "sample_hosts_webdav",
            "sample_hosts_snmp", "sample_hosts_banner", "sample_hosts_phpinfo",
            "sample_hosts_srvstatus", "sample_urls_errorleak", "sample_hosts_wildcarddns",
            "sample_hosts_dnsrebind", "sample_hosts_iisaspnet", "sample_hosts_tomcat",
            "sample_hosts_nodejs", "sample_hosts_laravel", "sample_hosts_django",
            "sample_hosts_symfony", "sample_hosts_cicd", "sample_hosts_docker",
            "sample_hosts_k8s", "sample_hosts_terraform", "sample_hosts_envdeep",
            "sample_hosts_gqlabuse", "sample_urls_apiversion", "sample_hosts_lbdetect",
            "sample_hosts_vhost", "sample_urls_ratelimitbypass", "sample_hosts_emailfinder",
            "sample_urls_metagoofil", "sample_hosts_porchpirate", "sample_urls_dorkhunter",
            "sample_hosts_crtsh", "sample_hosts_githubsub", "sample_hosts_tlsx",
            "sample_hosts_analyticsrels", "sample_hosts_favirecon", "sample_urls_jsluice",
            "sample_urls_shortscan", "sample_hosts_grpcurl", "rate_limit_per_domain",
        ]
        for field_name in _positive_int:
            val = getattr(self, field_name, 0)
            if not isinstance(val, int) or val < 0:
                raise ConfigError(f"{field_name} must be a non-negative integer, got {val!r}")

        if not (1 <= self.sqlmap_level <= 5):
            raise ConfigError(f"sqlmap_level must be 1-5, got {self.sqlmap_level}")
        if not (1 <= self.sqlmap_risk <= 3):
            raise ConfigError(f"sqlmap_risk must be 1-3, got {self.sqlmap_risk}")
        if self.delay < 0:
            raise ConfigError(f"delay must be >= 0, got {self.delay}")
        if self.proxy_timeout_multiplier <= 0:
            raise ConfigError(f"proxy_timeout_multiplier must be > 0, got {self.proxy_timeout_multiplier}")
        if self.waf_evasion_throttle < 0:
            raise ConfigError(f"waf_evasion_throttle must be >= 0, got {self.waf_evasion_throttle}")
        if self.proxy and not self.proxy.startswith(("http://", "https://", "socks4://", "socks5://")):
            raise ConfigError(
                f"proxy must start with http://, https://, socks4://, or socks5://, got {self.proxy!r}"
            )
        if self.vuln_proxy and not self.vuln_proxy.startswith(("http://", "https://", "socks4://", "socks5://")):
            raise ConfigError(
                f"vuln_proxy must start with http://, https://, socks4://, or socks5://, got {self.vuln_proxy!r}"
            )



