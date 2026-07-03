# ReconChain v1.5.1

A Python orchestrator that chains 54+ recon and vulnerability phases into a single,
resumable DAG pipeline — no config files, no YAML, no DSL.

```bash
# Quick start — interactive wizard
reconchain -i

# One-liner (full audit)
reconchain -d example.com -o ./out

# Multi-domain scan
reconchain -d example.com,test.org -o ./out

# Just recon, no scanning
reconchain -d example.com --fast
```

## Quick Start

```bash
# Install Python deps
pip install tqdm
python3 -m pip install -e '.[dev]'

# Install external tools (Go-based + system)
chmod +x install.sh
./install.sh

# Check what's available
./install.sh --check
```

## Usage

### Interactive wizard (recommended for new users)

```bash
reconchain -i
```

Prompts for:
- **Domain(s)** — single or comma-separated multi-domain
- **Recon level** — Basic / Standard / Full (see levels below)
- **Output directory** — defaults to `./out_{domain}`
- **Parallel jobs** — how many tools to run simultaneously
- **Scan depth** — SQLmap level/risk, request delay, sample sizes
- **Manual testing add-ons** — SSTI, origin bypass, deep JS secrets, auth bypass, IDOR, mass assignment, SSRF metadata, LFI, cloud, git, GraphQL, WAF, NoSQLi, race, JWT, XXE, CMDi, proto pollution, cache, dependency check, open redirect, clickjack, CRLF, CORS, file upload, smuggling, OAuth, password reset, WebSocket, LDAP, deserialization, bucket enum, CDN detection, content discovery
- **Resume / Force** — picks up where you left off, or force re-run all phases

Shows a summary before starting. Zero flags to remember.

### Command-line

```bash
# Full audit (everything)
reconchain -d example.com -o ./out

# Multi-domain (runs pipeline per domain)
reconchain -d example.com,test.org,sub.example.com

# Basic recon only (fast)
reconchain -d example.com --fast

# Pick specific phases
reconchain -d example.com -o ./out --only 00-SCOPE,01-RECON,02-RESOLVE,04-SCAN,05-HARVEST,44-REPORT

# Skip slow phases
reconchain -d example.com -o ./out --skip 10-TLSCMS,11-INJECT

# Resume a cancelled scan
reconchain -d example.com -o ./out --resume

# Force re-run all phases
reconchain -d example.com -o ./out --force

# Tune parallelism
reconchain -d example.com -o ./out -j 32

# Custom scan depth
reconchain -d example.com --sqlmap-level 3 --sqlmap-risk 2 --delay 1

# Custom sample sizes (more URLs = thorough but slower)
reconchain -d example.com --sample-urls-fuzz 50 --sample-urls-params 200

# Exclude noisy nuclei tags
reconchain -d example.com --exclude-tags info,tech

# Proxy through tor/socks
reconchain -d example.com --proxy socks5://127.0.0.1:9050
```

## Recon Levels

| Level | What Runs | Use Case |
|-------|-----------|----------|
| **1 — Basic** | 00-SCOPE → 01-RECON → 02-RESOLVE → 04-SCAN → 05-HARVEST → 44-REPORT | Quick domain recon: scope validation, subdomains, DNS, ports, URLs |
| **2 — Standard** | Level 1 + 03-PERMUTE → 06-JSINTEL → 07-PARAMS → 08-FUZZ → 09-VULNSCAN → 10-TLSCMS → 24-JWT → 28-CACHED → 34-RATELIMIT → 41-WEBSOCKET | Full automated vuln scanning + basic web checks |
| **Full** | All 54 phases | Maximum coverage (scope validation, takeover confirm, API specs, XSS, SQLi, SSTI, OOB, NoSQLi, race, XXE, cmd inject, proto pollution, open redirect, clickjack, CRLF, CORS, JWT, file upload, smuggling, OAuth, password reset, LDAP, deserialization, IDOR, SSRF metadata, LFI, chain correlation, evidence capture, bucket enum, CDN detection, content discovery) |

## Pipeline — Execution Stages (DAG)

### Stage 0 — Scope + Discovery
```
00-SCOPE   scope validation          ──→ scope_validated.txt
01-RECON   subdomains                ──→ all_subs.txt
02-RESOLVE DNS resolve (fallback)    ──→ resolved.txt + resolved_full.txt
03-PERMUTE permute subs              ──→ all_subs.txt (append)
04-SCAN    ports/hosts               ──→ ports.txt + hosts.txt + takeover.txt
04b-TAKEOVER-VALIDATE confirm CNAME  ──→ takeover_confirmed.txt
34-RATELIMIT rate-limit burst test   ──→ rate_limiting.txt
```

### Stage 1 — WAF Detection (informs throttle for later stages)
```
21-WAF     WAF detection             ──→ waf_detection.txt
```

### Stage 2 — Parallel Harvest + Analysis
```
05-HARVEST URL harvest               ──→ urls_all.txt
05b-APISPEC API spec hunt            ──→ api_specs.txt
06-JSINTEL JS analysis               ──→ js_secrets.txt
15-SECRETS deep JS secrets           ──→ secrets.txt
```

### Stage 3 — Parameter Discovery
```
07-PARAMS  parameters                ──→ params.txt
```

### Stage 4 — Fuzzing (throttled by WAF profile)
```
08-FUZZ    fuzzing                   ──→ fuzz.txt
```

### Stage 5 — Independent Parallel Scans
```
09-VULNSCAN nuclei + tech            ──→ nuclei_combined.txt
10-TLSCMS  ssl + wp                  ──→ tls_wp.txt
14-ORIGIN  origin bypass             ──→ origin.txt
18-CLOUD   cloud buckets             ──→ cloud_buckets.txt
19-GIT     git exposure              ──→ git_exposure.txt
20-GRAPHQL GraphQL introsp.          ──→ graphql_introspection.txt
```

### Stage 6 — Main Injection Cluster (consume parameter corpus)
```
11-INJECT  XSS + SSRF                ──→ vulns.txt
11b-SQLMAP sqlmap (pre-filtered)     ──→ sqlmap_findings.txt
12-SSTI    SSTI fuzzing              ──→ ssti.txt
22-NOSQLI  NoSQL injection           ──→ nosqli.txt
25-XXE     XXE injection             ──→ xxe.txt
26-CMDINJECT cmd injection           ──→ cmd_injection.txt
27-SSPP    proto pollution           ──→ sspp.txt
42-LDAP    LDAP injection            ──→ ldap_injection.txt
43-DESERIAL deserialization          ──→ deserialization.txt
```

### Stage 7 — SSRF Follow-up
```
17B-SSRFMETA cloud metadata exfil    ──→ ssrf_meta.txt
```

### Stage 8 — JWT Analysis (feeds into auth probes)
```
24-JWT     JWT analysis              ──→ jwt_analysis.txt
36-JWTADV  advanced JWT              ──→ jwt_advanced.txt
```

### Stage 9 — Auth-focused Cluster
```
39-OAUTH   OAuth testing             ──→ oauth_misconfig.txt
40-PWRESET password reset            ──→ password_reset.txt
16A-AUTHZ  auth bypass headers       ──→ authz_bypass.txt
16B-MASSASSIGN mass assignment       ──→ mass_assign.txt
17-IDOR    ID manipulation            ──→ idor.txt
```

### Stage 10 — Long Tail Independent Checks
```
28-CACHED  cache poison              ──→ cache_poison.txt
29-DEPCHECK dependency check         ──→ depcheck.txt
30-LFI     path traversal            ──→ lfi.txt
31-OPENREDIR open redirect           ──→ open_redirect.txt
32-CLICKJACK clickjacking            ──→ clickjacking.txt
33-CRLF    CRLF injection            ──→ crlf_injection.txt
35-CORSADV advanced CORS             ──→ cors_advanced.txt
37-FILEUPLOAD file upload            ──→ file_upload.txt
38-SMUGGLE request smugg.            ──→ smuggling.txt
41-WEBSOCKET WebSocket               ──→ websocket.txt
```

### Stage 11 — OOB + Race
```
13-OOB     OAST polling              ──→ callbacks.txt
23-RACE    race condition            ──→ race_conditions.txt
```

### Stage 12 — Correlation + Evidence
```
44-CHAIN   cross-reference findings  ──→ chain_correlation.txt
45-EVIDENCE capture req/resp pairs   ──→ evidence/
```

### Stage 13 — Enhancement Phases
```
46-BUCKET  cloud bucket enum         ──→ bucket_enum.txt
47-CDN     CDN detection             ──→ cdn_detection.txt
48-CONTENT content discovery         ──→ content_discovery.txt
```

### Always runs last
```
44-REPORT  reports                   ──→ summary.json + report.html + report.md + summary.txt
```

### Phase Details

| Phase | Tools | Description |
|-------|-------|-------------|
| **00-SCOPE** | Python builtins | Validates target assets against scope/allowlist file |
| **01-RECON** | subfinder, amass | Passive subdomain enumeration from CT logs, search engines, DNS |
| **02-RESOLVE** | massdns, dnsx, puredns, socket | DNS resolution with parallel fallback chain (massdns → dnsx → Python socket) |
| **03-PERMUTE** | dnsgen, dnsx | Subdomain permutation generation; resolves candidates |
| **04-SCAN** | naabu (nmap fallback), httprobe, httpx, nuclei | Port scanning, HTTP probing, service detection, subdomain takeover |
| **04b-TAKEOVER-VALIDATE** | curl, Python socket | Connects to dangling CNAME targets to confirm exploitability |
| **05-HARVEST** | gau, gospider, katana, subjs, waymore | Historical URL harvesting + active crawling + JS URL extraction |
| **05b-APISPEC** | curl, Python requests | Probes /swagger.json, /openapi.yaml, GraphQL SDL |
| **06-JSINTEL** | LinkFinder, SecretFinder, nuclei (exposures) | JavaScript file analysis for endpoints and secrets |
| **07-PARAMS** | Arjun | Parameter discovery on harvested URLs |
| **08-FUZZ** | ffuf, feroxbuster | Directory/file fuzzing with SecLists wordlists |
| **09-VULNSCAN** | nuclei (full + technologies) | Vulnerability scanning with auto-updated templates |
| **10-TLSCMS** | testssl.sh, wpscan | TLS security assessment + WordPress scanning |
| **11-INJECT** | kxss, Gxss, dalfox, SSRF probes | XSS pre-filter, scanning, SSRF parameter injection |
| **11b-SQLMAP** | sqlmap (via response-diff heuristic pre-filter) | SQL injection with pre-screening to reduce false positives |
| **12-SSTI** | SSTI probes | Server-Side Template Injection detection |
| **13-OOB** | interactsh-client | OOB interaction capture for SSRF/blind findings |
| **14-ORIGIN** | favicon hash, crt.sh, dig MX/SPF/DMARC/DKIM, ipinfo.io, cdncheck | Origin IP bypass enumeration (Cloudflare, CDN discovery) |
| **15-SECRETS** | gitleaks, unfurl, deep JS regex + source map analysis | GitLeaks secret scanning, URL extraction, entropy-based secret detection; pushes credentials to shared queue |
| **16A-AUTHZ** | qsreplace, auth bypass headers, role bypass | Authentication bypass testing (X-Original-URL, X-Forwarded-For, header injection) |
| **16B-MASSASSIGN** | POST field injection | Mass assignment vulnerability detection (admin, role, balance fields) |
| **17-IDOR** | Python probes | ID sequencing, UUID swap, numeric increment/decrement |
| **17B-SSRFMETA** | curl to cloud metadata IPs | Cloud metadata credential theft (AWS/GCP/Azure) triggered by confirmed SSRF |
| **18-CLOUD** | cloud_enum, custom Python probes | Cloud bucket discovery across AWS, GCP, Azure, DigitalOcean, etc. |
| **19-GIT** | gitdumper, trufflehog | Git repository download + secret scanning from exposed .git |
| **20-GRAPHQL** | inql, custom GraphQL probes | GraphQL introspection + deep schema analysis |
| **21-WAF** | wafw00f, custom WAF signatures | WAF detection with 50+ vendor signatures; sets global throttle/evasion flag |
| **22-NOSQLI** | Custom Python probes | NoSQL injection detection via MongoDB operators ($ne, $regex, $where) |
| **23-RACE** | Concurrent request bursts | Race condition detection on state-changing endpoints (redeem, transfer, purchase, vote) |
| **24-JWT** | jwt_tool | JWT decoding, algorithm confusion, weak signature testing |
| **25-XXE** | Custom Python probes | XML External Entity injection via payload reflection |
| **26-CMDINJECT** | Custom Python probes | OS command injection via timing-based and error-based detection |
| **27-SSPP** | Custom Python probes | Server-side prototype pollution via JSON key collision |
| **28-CACHED** | Cache key manipulation probes | Web cache poisoning via unkeyed headers and parameter cloaking |
| **29-DEPCHECK** | Custom Python probes | Dependency confusion detection via npm/PyPI/RubyGems package enumeration |
| **30-LFI** | Custom Python probes | Path traversal probes for /etc/passwd, /windows/win.ini, log poisoning |
| **31-OPENREDIR** | Custom Python probes | Open redirect detection via URL scheme and host validation |
| **32-CLICKJACK** | Custom Python probes | Clickjacking vulnerability via missing X-Frame-Options/CSP frame-ancestors |
| **33-CRLF** | Custom Python probes | CRLF injection via response splitting and header injection |
| **34-RATELIMIT** | URL burst requests | Rate limiting assessment via sequential request bursts (runs early after Stage 0) |
| **35-CORSADV** | Custom origin reflection test | Advanced CORS misconfiguration testing (origin reflection, null, trusted domains) |
| **36-JWTADV** | JWK header injection | JWT key injection, algorithm confusion, KID traversal |
| **37-FILEUPLOAD** | Custom Python probes | File upload vulnerability detection (extension bypass, magic bytes, size limits) |
| **38-SMUGGLE** | Raw socket CL.TE/TE.CL | HTTP request smuggling via Content-Length / Transfer-Encoding desync |
| **39-OAUTH** | Custom Python probes | OAuth misconfiguration testing (redirect_uri, state, scope, CSRF); consumes JWT findings |
| **40-PWRESET** | Custom Python probes | Password reset token analysis (predictability, enumeration, host header poisoning); consumes JWT findings |
| **41-WEBSOCKET** | Raw socket upgrade handshake | WebSocket endpoint discovery and insecure handshake detection |
| **42-LDAP** | Custom Python probes | LDAP injection via filter manipulation and boolean-based detection |
| **43-DESERIAL** | Custom Python payload POSTs | Deserialization attack surface detection via Java/Python/PHP/Ruby serialized payloads |
| **44-CHAIN** | Python cross-referencing | Correlates findings across phases (secrets→auth, IDOR→mass-assign, SSRF→LFI) |
| **45-EVIDENCE** | Python request/response capture | Captures request/response pairs for confirmed findings |
| **46-BUCKET** | Python HTTP probes | Cloud storage bucket enumeration (S3, GCP, Azure, DigitalOcean) based on domain patterns |
| **47-CDN** | Python HTTP probes | CDN provider detection via response header signatures (Cloudflare, Akamai, Fastly, etc.) |
| **48-CONTENT** | Python HTTP probes | Content discovery via probing common sensitive paths (.env, .git, admin, etc.) |
| **44-REPORT** | gowitness, reporting | Screenshots + HTML, Markdown, JSON, and text summary |

## Output

```
out/
├── all_subs.txt              # Subdomains
├── resolved.txt              # Resolved hosts (bare hostnames)
├── resolved_full.txt         # Resolved hosts with DNS record types
├── ports.txt                 # Open ports (TCP)
├── ports_udp.txt             # Open ports (UDP)
├── hosts.txt                 # Live HTTP hosts with titles + tech
├── host_targets.txt          # Normalized HTTP targets
├── takeover.txt              # Subdomain takeover candidates
├── takeover_confirmed.txt    # Confirmed dangling CNAME exploits
├── scope_validated.txt       # In-scope assets validated
├── api_specs.txt             # API specification files found
├── urls_all.txt              # All discovered URLs
├── urls_js.txt               # JavaScript URLs
├── urls_xss.txt              # URLs with parameters (XSS candidates)
├── urls_ssrf.txt             # URLs with SSRF-prone parameters
├── js_secrets.txt            # Secrets from SecretFinder/nuclei
├── secrets.txt               # Deep JS secrets (custom regex + source maps)
├── params.txt                # Discovered parameters
├── fuzz.txt                  # Fuzzing results
├── nuclei_combined.txt       # Nuclei findings (full + tech)
├── nuclei.txt                # Nuclei findings (full scan)
├── tech.txt                  # Technology detection results
├── tls_wp.txt                # TLS + WordPress results
├── ssti.txt                  # SSTI probe results
├── vulns.txt                 # XSS/SSRF findings (merged)
├── xss.txt                   # Dalfox XSS findings
├── sqlmap_findings.txt       # Extracted SQLi findings from sqlmap
├── nosqli.txt                # NoSQL injection findings
├── race_conditions.txt       # Race condition probes
├── jwt_analysis.txt          # JWT analysis results
├── xxe.txt                   # XXE injection probes
├── cmd_injection.txt         # Command injection probes
├── sspp.txt                  # Server-side prototype pollution probes
├── cache_poison.txt          # Cache poisoning probes
├── depcheck.txt              # Dependency confusion probes
├── origin.txt                # Origin IP candidates
├── authz_bypass.txt          # Auth bypass probes
├── mass_assign.txt           # Mass assignment fields discovered
├── idor.txt                  # IDOR findings
├── ssrf_meta.txt             # SSRF metadata exfiltration results
├── lfi.txt                   # Local file inclusion findings
├── open_redirect.txt         # Open redirect findings
├── clickjacking.txt          # Clickjacking findings
├── crlf_injection.txt        # CRLF injection findings
├── rate_limiting.txt         # Rate limit test results
├── cors_advanced.txt         # Advanced CORS findings
├── jwt_advanced.txt          # Advanced JWT attack findings
├── file_upload.txt           # File upload vulnerability findings
├── smuggling.txt             # Request smuggling findings
├── oauth_misconfig.txt       # OAuth misconfiguration findings
├── password_reset.txt        # Password reset token analysis
├── websocket.txt             # WebSocket endpoint findings
├── ldap_injection.txt        # LDAP injection findings
├── deserialization.txt       # Deserialization findings
├── cloud_buckets.txt         # Cloud bucket discovery results
├── git_exposure.txt          # Git exposure findings
├── graphql_introspection.txt # GraphQL introspection results
├── waf_detection.txt         # WAF detection results
├── bucket_enum.txt           # Cloud storage bucket enumeration
├── cdn_detection.txt         # CDN provider detection results
├── content_discovery.txt     # Content discovery findings
├── chain_correlation.txt     # Cross-phase correlation findings
├── evidence/                 # Request/response pairs for confirmed vulns
├── screenshots/              # Browser screenshots (gowitness)
│   └── *.png
├── oast/
│   └── callbacks.txt         # OOB interactions
├── logs/                     # Per-tool raw output
│   ├── phase_*.log           # Phase execution logs
│   ├── amass.sh              # Generated runner scripts
│   ├── *_runner.sh
│   └── interactsh.log        # Raw interactsh output
├── state.json                # Resume state
├── dedup_state.json          # Deduplication state
├── summary.json              # Machine-readable results
├── report.html               # HTML report (with severity badge + screenshots)
├── report.md                 # Markdown report
└── summary.txt               # Text summary
```

## Supported Tools

| Category | Tools |
|----------|-------|
| Enumeration | subfinder, amass, alterx, dnsx, puredns, massdns |
| Network | naabu, nmap, httpx, httprobe, nuclei, cdncheck |
| URLs | gau, gospider, katana, subjs, waymore, unfurl |
| Analysis | SecretFinder, Arjun, dnsgen, alterx, inql |
| Fuzzing | ffuf, feroxbuster, qsreplace, Gxss |
| Vulns | nuclei, dalfox, sqlmap, testssl.sh, wpscan, kxss, wafw00f |
| Secrets | gitleaks, trufflehog, SecretFinder, LinkFinder |
| Cloud | cloud_enum |
| Git | gitdumper |
| Screenshots | gowitness |
| OAST | interactsh-client (with optional HTTP webhook) |
| DNS | dig, massdns |

Missing tools are automatically skipped — the pipeline never crashes over a missing
binary.

## Flags

```
  -d, --domain                  Target domain(s) — single or comma-separated for multi-domain (e.g. example.com or example.com,test.org)
  -o, --out                     Output directory (default: ./out/<domain>)
  -i, --interactive             Interactive wizard
  --only                        Comma-separated phases to run (e.g. 01-RECON,14-ORIGIN,15-SECRETS)
  --skip                        Comma-separated phases to skip
  -j, --jobs                    Max parallel processes (default: cpu_count × 2)
  --fast                        Basic recon only (00-SCOPE, 01-RECON, 02-RESOLVE, 04-SCAN, 05-HARVEST, 44-REPORT)
  --resume                      Resume from state.json
  --force                       Re-run all phases even if output files exist
  --keep-all                    Disable downsampling (keep all results)
  -q, --quiet                   Suppress info logs
  --no-color                    Disable ANSI colors
  --proxy                       Proxy URL (e.g. socks5://127.0.0.1:9050); auto-detected from ALL_PROXY / HTTPS_PROXY / HTTP_PROXY / PROXY env vars
  --cookie                      Cookie string for authenticated scans
  --header                      Extra HTTP header (repeatable)
  --sqlmap-level                SQLmap --level (1-5, default: 1)
  --sqlmap-risk                 SQLmap --risk (1-3, default: 1)
  --delay                       Seconds between requests (default: 0)
  --rate-limit                  Max requests per second (default: 0)
  --sample-urls-fuzz            URLs to fuzz (default: 200)
  --sample-urls-params          URLs for parameter discovery (default: 50)
  --sample-hosts-ssl            Hosts for SSL/TLS scanning (default: 10)
  --sample-hosts-origin         Hosts for origin bypass (default: 10)
  --sample-hosts-cloud          Hosts for cloud bucket discovery (default: 5)
  --sample-hosts-git            Hosts for Git exposure (default: 5)
  --sample-hosts-graphql        Hosts for GraphQL introspection (default: 5)
  --sample-hosts-waf            Hosts for WAF detection (default: 5)
  --sample-urls-xss-blind       URLs for blind XSS probe (default: 20)
  --sample-urls-ssti            SSTI sample URLs (default: 5)
  --sample-endpoints-l          Endpoints for auth bypass (default: 20)
  --sample-endpoints-post       Endpoints to mass-assign POST (default: 5)
  --sample-endpoints-cors       Endpoints to CORS-fuzz (default: 10)
  --exclude-tags                Nuclei tags to exclude (e.g. 'info,tech')
```

## Features

### Multi-domain Support
Scan multiple domains in a single run by separating them with commas:
```bash
reconchain -d example.com,test.org,sub.example.com
```
Each domain is scanned independently (own state, own output directory under
`./out/<domain>/`). Results from each domain are reported separately.

### Parallel Resolver Fallback
`02-RESOLVE` now uses a fallback chain: **massdns → dnsx → Python socket**.
If the fastest resolver (`massdns`) is unavailable or its resolvers file is
missing, it falls back to `dnsx` batch resolution. If `dnsx` is also
unavailable, it falls back to Python's built-in `getaddrinfo()` via asyncio.
This ensures resolution never blocks on a missing binary.

### Smarter Rate Limiting
The `RateLimiter` offers per-domain tracking with adaptive exponential backoff
on failures and jitter to avoid thundering-herd patterns. Wired into the
pipeline via the `--rate-limit` flag.

### Cross-scan Deduplication
The `DedupEngine` persists seen findings to `dedup_state.json` with normalized
key matching and optional content fingerprinting (MD5 of normalized content)
for fuzzy dedup across multiple scans.

### OAST Callback Collector v2
In addition to the `interactsh-client` subprocess, `Interactsh` now supports an
optional local HTTP webhook server (`start_webhook()`) that captures callbacks
directly. Webhook callbacks are merged with interactsh-client callbacks in the
final `callbacks.txt` output.

### Scan Monitoring
The `MonitorEngine` persists watched domains to
`~/.config/reconchain/monitor/watches.json`. When the pipeline finishes, it
checks for due scans and automatically re-launches them via subprocess.

### User-Agent Rotation
`UARotator` provides a pool of 15+ modern browser user-agent strings and is
available for pipeline phases to rotate through instead of hardcoding a single UA.

### New Phases
- **46-BUCKET** — Cloud storage bucket enumeration (S3, GCP, Azure, DigitalOcean)
- **47-CDN** — CDN provider detection via response header signatures
- **48-CONTENT** — Content/path discovery probing common sensitive paths

## Configuration

| Variable | Purpose |
|----------|---------|
| `WEBHOOK_URL` | Webhook URL for JSON notifications (with severity) |
| `INTERACTSH_TOKEN` | Interactsh auth token |
| `WPSCAN_API_TOKEN` | WPScan API token (enables vulnerability data) |
| `FFUF_WORDLIST` | Custom ffuf wordlist path |
| `KITE_FILE` | Kiterunner wordlist path |
| `PROXY` | Default proxy for HTTP tools (deprecated — set `ALL_PROXY` instead) |
| `COOKIE` | Default cookie for authenticated scans |
| `NO_COLOR` | Disable colour output |

### Proxy Support

All outbound HTTP/S tool calls respect the standard `ALL_PROXY`, `HTTPS_PROXY`, and
`HTTP_PROXY` environment variables (lowercase variants also supported). On startup
the orchestrator detects these variables and propagates them to every subprocess,
so **Go, Python, Ruby, and Rust tools** all route through the proxy without
per-tool configuration. Additionally, explicit `--proxy`/`-x` flags are passed to
`ffuf`, `nuclei`, `dalfox`, `katana`, `feroxbuster`, and `wpscan` for tools that
honour CLI flags better than environment variables.

For **SOCKS proxies**, `proxychains4` is automatically prepended to bash-runner
commands when `ALL_PROXY` contains a `socks4://` or `socks5://` scheme. Direct
tool invocations (Go/Python/Ruby binaries) use the native SOCKS support built into
those runtimes, avoiding double-proxying.

On startup, the orchestrator performs a **pre-flight connectivity check** against
the proxy address. If the proxy is unreachable (e.g. Tor not running), the proxy
is disabled with a warning, preventing all downstream tools from hanging until
timeout.

**No explicit `--proxy` flag is required** — just export your proxy variable before
launching the scan:

```bash
export ALL_PROXY=socks5://127.0.0.1:9050
reconchain -d example.com
```

## Severity Scoring

Each artifact contributes a severity weight. The overall scan is labelled in the
HTML report:

| Level | Score | Example |
|-------|-------|---------|
| CRITICAL | 10+ | Subdomain takeover, OOB callback, SSRF metadata |
| HIGH | 5–9 | SQLi, XSS, exposed git repo, cloud bucket, IDOR, LFI |
| MEDIUM | 1–4 | Open port, JS secret, origin IP found, mass assignment |
| LOW | 0 | No findings |

## Key Improvements (v1.5.1)

- **54 phases** — 18 new phases: 00-SCOPE, 04b-TAKEOVER-VALIDATE, 05b-APISPEC, 11b-SQLMAP, 16A-AUTHZ, 16B-MASSASSIGN, 17-IDOR, 17B-SSRFMETA, 30-LFI, 44-CHAIN, 45-EVIDENCE, 46-BUCKET, 47-CDN, 48-CONTENT
- **DAG execution stages** — 13 ordered stages with feedback loops: WAF detection informs throttle/evasion, SSRF triggers metadata exfil, JWT analysis feeds auth probes, secrets flow into credential queue
- **Cross-phase correlation** — 44-CHAIN cross-references findings (secrets→auth, IDOR→mass-assign, SSRF→LFI); 45-EVIDENCE captures request/response pairs
- **Scope gating** — 00-SCOPE validates assets against allowlist/scope file before any recon runs
- **WAF-aware throttling** — 21-WAF sets global `waf_detected` / `waf_evasion_throttle` flags consumed by all downstream phases
- **Multi-domain** — comma-separated `-d` runs pipeline per domain
- **Parallel resolver fallback** — massdns → dnsx → Python socket fallback chain
- **Cross-scan dedup** — persisted `DedupEngine` with content fingerprinting
- **OAST webhook** — local HTTP server captures OOB callbacks directly
- **Smarter rate limiting** — per-domain tracking + adaptive exponential backoff
- **Scan monitoring** — `MonitorEngine` schedules and auto-launches re-scans
- **41+ tools** — added alterx, massdns
- **Screenshots** — gowitness captures browser screenshots of live hosts
- **Webhook notifications** — send JSON payloads with severity to any webhook URL
- **Streaming pipeline** — 01-RECON, 02-RESOLVE, 04-SCAN, 05-HARVEST run concurrently; overall wall-clock reduction of 40–60%
- **Downsampling** — artifacts truncated to 1 entry per phase (--keep-all to disable)
- **Per-phase output guards** — skip completed phases unless --force is set
- **Nuclei template cache** — auto-updates at most once per 24h
- **Graceful degradation** — every external tool is optional; pipeline handles missing binaries without crashing
- **Modular package** — code split into 14 submodules with backward-compatible re-exports

## Security

Only scan systems you own or have explicit permission to test. Recon tools may
trigger security alerts or rate-limiting on the target.

## License

MIT
