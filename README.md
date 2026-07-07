# ReconChain v1.6.0

Chains 73 recon and vulnerability phases into a single resumable pipeline — no config files required.

```bash
# Interactive wizard (recommended)
reconchain -i

# One-liner
reconchain -d example.com -o ./out

# Multi-domain
reconchain -d example.com,test.org -o ./out

# Quick recon only
reconchain -d example.com --fast

# SARIF output for CI/CD (GitHub Advanced Security / GitLab SAST)
reconchain -d example.com --format sarif
```

## Install

```bash
pip install tqdm && python3 -m pip install -e '.[dev]'
chmod +x install.sh && ./install.sh
```

## Usage

| Command | Description |
|---------|-------------|
| `reconchain -i` | Interactive wizard — zero flags |
| `-d example.com -o ./out` | Full audit |
| `--fast` | Basic recon only (subdomains, DNS, ports, URLs) |
| `--only 01-RECON,14-ORIGIN` | Run specific phases |
| `--skip 10-TLSCMS,11-INJECT` | Skip slow phases |
| `--format sarif` | Generate SARIF v2.1 report (`results.sarif`) |
| `--resume` | Resume cancelled scan |
| `--force` | Re-run all phases |
| `-j 32` | Parallelism (default: cpu×2) |
| `--proxy socks5://127.0.0.1:9050` | Route through SOCKS/Tor |

Recon levels: **Basic** (recon only), **Standard** (recon + vuln scan), **Full** (all 73 phases).

## Generate AI Report

After a scan, feed the output to an LLM for a natural-language summary:

```bash
# Ask an AI to analyze the results (works with any CLI LLM tool)
cat out/example.com/summary.txt | llm "Summarize these security findings for a non-technical audience, highlight critical risks, and suggest remediation steps"

# Or point an AI code editor at the out/ directory
# e.g. in Claude Code, Cursor, or Continue.dev:
# "Review the scan results in ./out/example.com/ and write a pentest report"
```

The `summary.txt` and `summary.json` files contain all findings in a machine-readable format that AI tools can analyze directly. The `summary.json` now includes coverage metrics (`discovered_urls`, `tested_phases`, `total_phases`) under a `"coverage"` key.

## Pipeline Stages (73 phases in DAG)

**Discovery & Reconnaissance:**
```
00-SCOPE   → scope validation
01-RECON   → subdomains (subfinder, amass)
02-RESOLVE → DNS resolution (massdns → dnsx → socket)
03-PERMUTE → subdomain permutation (alterx, dnsgen)
04-SCAN    → ports, HTTP probing, service detection
05-HARVEST → URL harvesting (gau, gospider, katana, waymore)
```

**Vulnerability Scanning:**
```
09-VULNSCAN   → nuclei + tech detection
10-TLSCMS     → TLS + WordPress
11-INJECT     → XSS, SSRF, SQLi, SSTI, NoSQLi, XXE, CMDi, LDAP
11a-DOMXSS    → DOM XSS via browser automation (Playwright)
11b-SQLMAP    → SQL injection via sqlmap
20-GRAPHQL    → GraphQL introspection + schema analysis
21-WAF        → WAF detection (50+ vendor signatures)
21b-WAFBYPASS → WAF bypass technique testing (Cloudflare, Akamai, AWS WAF, ModSecurity)
28-CACHED     → Web cache poisoning/deception + v2 probes
35-CORSADV    → Advanced CORS + JSONP endpoint detection
38b-H2SMUGGLE → HTTP/2 + HTTP/3 attack surface
41-WEBSOCKET  → WebSocket security testing + deep probes
```

**Enhancement Phases:**
```
50-BUCKET-PERMS  → Bucket permission auditing (public read/write on S3/Azure/GCP)
51-HPP           → HTTP parameter pollution detection
52-SERVERLESS    → Serverless/cloud function endpoint discovery
53-CSP           → CSP header analysis + bypass detection
54-WS-FUZZ       → WebSocket message fuzzing (injection, auth bypass)
55-CSV-INJECT    → CSV/Excel formula injection (DDE, HYPERLINK, WEBSERVICE)
56-EXPOSED-DB    → Exposed database probing (Elasticsearch, Redis, Mongo, K8s)
57-DEFAULT-CREDS → Default credentials on admin panels and services
58-HOST-INJECT   → Host header injection / cache poisoning variants (+ CRLF/unicode)
59-EMAIL-SEC     → Email security posture (SPF/DMARC/DKIM)
60-SMTP-ENUM     → SMTP enumeration / email bombing detection
61-OAUTH-ADV     → OAuth redirect_uri bypass variants
62-LOG-INJECT    → Log injection / log forging detection
63-DOC-ATTACK    → Document-based attacks (DDE, macro, XXE, SVG-XSS)
64-IDEMPOTENCY   → Idempotency key replay testing on POST endpoints
```

All 73 phases run in a DAG with 21 ordered stages — see `reconchain -h` or the code for the full list.

## Output

```
out/example.com/
├── summary.json           # Machine-readable (feed to AI) + coverage metrics
├── summary.txt            # Human-readable
├── report.html            # HTML report with severity badges
├── report.md              # Markdown report
├── results.sarif          # SARIF v2.1 (GitHub Advanced Security / GitLab SAST)
├── hosts.txt              # Live hosts with tech
├── urls_all.txt           # All discovered URLs
├── nuclei_combined.txt    # Vulnerability findings
├── cors_advanced.txt      # CORS misconfig + JSONP endpoint findings
├── waf_bypass.txt         # WAF bypass test results
├── idempotency.txt        # Idempotency key replay findings
├── bucket_permissions.txt # S3/Azure/GCP bucket public access
├── csp_analysis.txt       # CSP header analysis + bypasses
├── csv_injection.txt      # CSV formula injection findings
├── default_creds.txt      # Default credentials found
├── document_attacks.txt   # Document-based attack vectors
├── email_security.txt     # SPF/DMARC/DKIM posture
├── exposed_databases.txt  # Open DB services
├── host_header_injection.txt # Host header poisoning
├── hpp.txt                # HTTP parameter pollution
├── log_injection.txt      # Log forging findings
├── oauth_advanced.txt     # OAuth redirect_uri bypasses
├── serverless_endpoints.txt # Lambda/GAE/Netlify endpoints
├── smtp_enumeration.txt   # SMTP user enumeration
├── websocket_fuzz.txt     # WebSocket message fuzzing results
├── evidence/              # Auto-generated PoCs
│   └── poc/               # Per-finding PoC files + index
├── screenshots/           # Gowitness browser screenshots
├── logs/                  # Raw tool output
└── state.json             # Resume state
```

## Proxy Support

Auto-detects `ALL_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY` env vars. SOCKS proxies use `proxychains4` automatically. Pre-flight connectivity check prevents hangs.

```bash
export ALL_PROXY=socks5://127.0.0.1:9050
reconchain -d example.com
```

## Security

Only scan systems you own or have explicit permission to test.

## License

MIT
