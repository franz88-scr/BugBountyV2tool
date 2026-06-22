# ReconChain v2.1

A Python orchestrator that chains 40+ recon and vulnerability tools into a single,
resumable pipeline — no config files, no YAML, no DSL.

```bash
# Quick start — interactive wizard
./reconchain.py -i

# One-liner (full audit)
./reconchain.py -d example.com -o ./out

# Just recon, no scanning
./reconchain.py -d example.com --fast
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
./reconchain.py -i
```

Prompts for:
- **Domain** — validated hostname
- **Recon level** — Basic / Standard / Full (see levels below)
- **Output directory** — defaults to `./out_{domain}`
- **Parallel jobs** — how many tools to run simultaneously
- **Scan depth** — SQLmap level/risk, request delay, sample sizes
- **Manual testing add-ons** — SSTI, origin bypass, deep JS secrets, auth bypass, cloud buckets, git exposure, GraphQL, WAF
- **Resume / Force** — picks up where you left off, or force re-run all phases

Shows a summary before starting. Zero flags to remember.

### Command-line

```bash
# Full audit (everything)
./reconchain.py -d example.com -o ./out

# Basic recon only (fast)
./reconchain.py -d example.com --fast

# Pick specific phases
./reconchain.py -d example.com -o ./out --only 01-RECON,02-RESOLVE,04-SCAN,05-HARVEST,17-REPORT

# Skip slow phases
./reconchain.py -d example.com -o ./out --skip 10-TLSCMS,11-INJECT

# Resume a cancelled scan
./reconchain.py -d example.com -o ./out --resume

# Force re-run all phases
./reconchain.py -d example.com -o ./out --force

# Tune parallelism
./reconchain.py -d example.com -o ./out -j 32

# Custom scan depth
./reconchain.py -d example.com --sqlmap-level 3 --sqlmap-risk 2 --delay 1

# Custom sample sizes (more URLs = thorough but slower)
./reconchain.py -d example.com --sample-urls-fuzz 50 --sample-urls-params 200

# Exclude noisy nuclei tags
./reconchain.py -d example.com --exclude-tags info,tech

# Proxy through tor/socks
./reconchain.py -d example.com --proxy socks5://127.0.0.1:9050
```

## Recon Levels

| Level | What Runs | Use Case |
|-------|-----------|----------|
| **1 — Basic** | 01-RECON → 02-RESOLVE → 03-PERMUTE → 04-SCAN → 05-HARVEST → 17-REPORT | Quick domain recon: subdomains, DNS, ports, URLs |
| **2 — Standard** | Level 1 + 06-JSINTEL → 07-PARAMS → 08-FUZZ → 09-VULNSCAN → 10-TLSCMS | Full automated vuln scanning |
| **Full** | Level 2 + 12-SSTI → 14-ORIGIN → 15-SECRETS → 16-AUTHZ → M → N → O → P | Maximum coverage (SSTI, origin bypass, deep JS, auth bypass, cloud, git, GraphQL, WAF) |

## Pipeline (streaming: 01-RECON→02-RESOLVE→04-SCAN→05-HARVEST overlap via incremental processing)

```
Enum Pt1 — Subdomains, DNS, Ports, URLs
  01-RECON  subdomains        ──→ all_subs.txt
  02-RESOLVE DNS resolve       ──→ resolved.txt + resolved_full.txt
  03-PERMUTE permute subs      ──→ all_subs.txt (append)
  04-SCAN   ports/hosts       ──→ ports.txt + hosts.txt + takeover.txt
  05-HARVEST URL harvest       ──→ urls_all.txt

Enum Pt2 — JS, Parameters, Fuzzing, Vuln Scanning
  06-JSINTEL JS analysis       ──→ js_secrets.txt
  07-PARAMS  parameters        ──→ params.txt
  08-FUZZ    fuzzing           ──→ fuzz.txt
  09-VULNSCAN nuclei + tech     ──→ nuclei_combined.txt
  10-TLSCMS  ssl + wp          ──→ tls_wp.txt

Vuln Pt1 — XSS, SQLi, SSTI, OAST
  11-INJECT XSS + SQLi + SSRF ──→ vulns.txt
  12-SSTI   SSTI fuzzing      ──→ ssti.txt
  13-OOB    OAST polling      ──→ callbacks.txt

Deep Pt1 — Origin Bypass, Deep JS, Auth Bypass
  14-ORIGIN  origin bypass     ──→ origin.txt
  15-SECRETS deep JS secrets   ──→ js_secrets_deep.txt
  16-AUTHZ   auth bypass       ──→ auth_bypass.txt

Deep Pt2 — Cloud, Git, GraphQL, WAF
  M   cloud buckets     ──→ cloud_buckets.txt
  N   git exposure      ──→ git_exposure.txt
  O   GraphQL introsp.  ──→ graphql_introspection.txt
  P   WAF detection     ──→ waf_detection.txt

Report
  17-REPORT reports           ──→ summary.json + report.html + report.md + summary.txt
```

Streaming stages: 01-RECON/02-RESOLVE/03-PERMUTE/04-SCAN/05-HARVEST all run concurrently in the first stage — 01-RECON writes
subdomains incrementally, 02-RESOLVE polls and resolves them as they arrive, 04-SCAN and 05-HARVEST start
on partial hosts. This cuts wall-clock time by overlapping the linear chain.
The remaining phases fan out in the second stage with independent concurrent execution.

### Phase Details

| Phase | Tools | Description |
|-------|-------|-------------|
| **01-RECON** | subfinder, amass, assetfinder | Passive subdomain enumeration from CT logs, search engines, DNS |
| **02-RESOLVE** | dnsx, puredns | DNS resolution + wildcard-resistant validation |
| **03-PERMUTE** | dnsgen, dnsx | Subdomain permutation generation; resolves candidates |
| **04-SCAN** | naabu (nmap fallback), httprobe, httpx, subjack (nuclei fallback) | Port scanning, HTTP probing, service detection, subdomain takeover |
| **05-HARVEST** | gau, waybackurls, gospider, katana, subjs, waymore | Historical URL harvesting + active crawling + JS URL extraction |
| **06-JSINTEL** | LinkFinder, SecretFinder, nuclei (exposures) | JavaScript file analysis for endpoints and secrets |
| **07-PARAMS** | ParamSpider, Arjun, x8 | Parameter discovery on harvested URLs |
| **08-FUZZ** | ffuf, kiterunner (kr), feroxbuster | Directory/file fuzzing with SecLists wordlists |
| **09-VULNSCAN** | nuclei (full + technologies) | Vulnerability scanning with auto-updated templates |
| **10-TLSCMS** | testssl.sh, wpscan | TLS security assessment + WordPress scanning |
| **11-INJECT** | kxss, Gxss, dalfox, sqlmap, SSRF probes | XSS pre-filter, scanning, SQL injection, SSRF parameter injection |
| **12-SSTI** | SSTI probes | Server-Side Template Injection detection |
| **13-OOB** | interactsh-client | OOB interaction capture for SSRF/blind findings |
| **17-REPORT** | gowitness, reporting | Screenshots + HTML, Markdown, JSON, and text summary |
| **14-ORIGIN** | favicon hash, crt.sh, dig MX/SPF/DMARC/DKIM, ipinfo.io, cdncheck | Origin IP bypass enumeration (Cloudflare, CDN discovery) |
| **15-SECRETS** | gitleaks, unfurl, deep JS regex + source map analysis | GitLeaks secret scanning, URL extraction, entropy-based secret detection |
| **16-AUTHZ** | qsreplace, auth bypass headers, mass assignment probes | Authentication bypass testing + mass assignment field discovery |
| **M** | cloud_enum, custom Python probes | Cloud bucket discovery across AWS, GCP, Azure, DigitalOcean, etc. |
| **N** | gitdumper, trufflehog | Git repository download + secret scanning from exposed .git |
| **O** | inql, custom GraphQL probes | GraphQL introspection + deep schema analysis |
| **P** | wafw00f, custom WAF signatures | WAF detection with 50+ vendor signatures + malicious probes |

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
├── urls_all.txt              # All discovered URLs
├── urls_js.txt               # JavaScript URLs
├── urls_xss.txt              # URLs with parameters (XSS candidates)
├── urls_ssrf.txt             # URLs with SSRF-prone parameters
├── js_secrets.txt            # Secrets from SecretFinder/linkfinder
├── js_secrets_deep.txt       # Deep JS secrets (custom regex + source maps)
├── params.txt                # Discovered parameters
├── fuzz.txt                  # Fuzzing results
├── nuclei_combined.txt       # Nuclei findings (full + tech)
├── nuclei.txt                # Nuclei findings (full scan)
├── tech.txt                  # Technology detection results
├── tls_wp.txt                # TLS + WordPress results
├── ssti.txt                  # SSTI probe results
├── vulns.txt                 # XSS/SQLi/SSRF findings (merged)
├── xss.txt                   # Dalfox XSS findings
├── sqlmap_findings.txt       # Extracted SQLi findings from sqlmap
├── origin.txt                # Origin IP candidates
├── auth_bypass.txt           # Auth bypass probes + mass assignment fields
├── cloud_buckets.txt         # Cloud bucket discovery results
├── git_exposure.txt          # Git exposure findings
├── graphql_introspection.txt # GraphQL introspection results
├── waf_detection.txt         # WAF detection results
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
├── summary.json              # Machine-readable results
├── report.html               # HTML report (with severity badge + screenshots)
├── report.md                 # Markdown report
└── summary.txt               # Text summary
```

## Supported Tools

| Category | Tools |
|----------|-------|
| Enumeration | subfinder, amass, assetfinder, dnsx, puredns |
| Network | naabu, nmap, httpx, httprobe, subjack, cdncheck |
| URLs | gau, waybackurls, gospider, katana, subjs, waymore, unfurl |
| Analysis | LinkFinder, SecretFinder, ParamSpider, Arjun, x8, dnsgen, inql |
| Fuzzing | ffuf, kiterunner (kr), feroxbuster, qsreplace, Gxss |
| Vulns | nuclei, dalfox, sqlmap, testssl.sh, wpscan, kxss, wafw00f |
| Secrets | gitleaks, trufflehog, SecretFinder, LinkFinder |
| Cloud | cloud_enum |
| Git | gitdumper |
| Screenshots | gowitness |
| OAST | interactsh-client |
| DNS | dig |

Missing tools are automatically skipped — the pipeline never crashes over a missing
binary.

## Flags

```
  -d, --domain                  Target domain (e.g. example.com)
  -o, --out                     Output directory (default: ./out/<domain>)
  -i, --interactive             Interactive wizard
  --config                      Path to JSON config file
  --only                        Comma-separated phases to run (e.g. 01-RECON,14-ORIGIN,15-SECRETS)
  --skip                        Comma-separated phases to skip
  -j, --jobs                    Max parallel processes (default: cpu_count × 2)
  --fast                        Basic recon only (01-RECON, 02-RESOLVE, 04-SCAN, 05-HARVEST, 17-REPORT)
  --resume                      Resume from state.json
  --force                       Re-run all phases even if output files exist
  --keep-all                    Disable downsampling (keep all results)
  -q, --quiet                   Suppress info logs
  --no-color                    Disable ANSI colors
  --proxy                       Proxy URL (e.g. socks5://127.0.0.1:9050)
  --cookie                      Cookie string for authenticated scans
  --header                      Extra HTTP header (repeatable)
  --sqlmap-level                SQLmap --level (1-5, default: 1)
  --sqlmap-risk                 SQLmap --risk (1-3, default: 1)
  --delay                       Seconds between requests (default: 0)
  --rate-limit                  Max requests per second (default: 0)
  --sample-urls-fuzz            URLs to fuzz (default: 5)
  --sample-urls-params          URLs for parameter discovery (default: 50)
  --sample-urls-pspider         URLs for ParamSpider (default: 3)
  --sample-urls-xss-blind       URLs for blind XSS probe (default: 20)
  --sample-urls-ssti            SSTI sample URLs (default: 5)
  --sample-endpoints-l          Endpoints for auth bypass (default: 20)
  --sample-endpoints-post       Endpoints to mass-assign POST (default: 5)
  --sample-endpoints-cors       Endpoints to CORS-fuzz (default: 10)
  --sample-buckets              Bucket names to test (default: 50)
  --sample-hosts-git            Hosts for git exposure (default: 20)
  --sample-hosts-graphql        Hosts for GraphQL probe (default: 20)
  --sample-hosts-waf            Hosts for WAF detection (default: 20)
  --exclude-tags                Nuclei tags to exclude (e.g. 'info,tech')
```

## Configuration

| Variable | Purpose |
|----------|---------|
| `WEBHOOK_URL` | Webhook URL for JSON notifications (with severity) |
| `INTERACTSH_TOKEN` | Interactsh auth token |
| `WPSCAN_API_TOKEN` | WPScan API token (enables vulnerability data) |
| `FFUF_WORDLIST` | Custom ffuf wordlist path |
| `KITE_FILE` | Kiterunner wordlist path |
| `PROXY` | Default proxy for HTTP tools |
| `COOKIE` | Default cookie for authenticated scans |
| `NO_COLOR` | Disable colour output |

## Severity Scoring

Each artifact contributes a severity weight. The overall scan is labelled in the
HTML report:

| Level | Score | Example |
|-------|-------|---------|
| CRITICAL | 10+ | Subdomain takeover, OOB callback |
| HIGH | 5–9 | SQLi, XSS, exposed git repo, cloud bucket |
| MEDIUM | 1–4 | Open port, JS secret, origin IP found |
| LOW | 0 | No findings |

## Key Improvements

- **40+ tools** — 12 new tools added: httprobe, puredns, Gxss, unfurl, qsreplace,
  cdncheck, gowitness, cloud_enum, gitdumper, trufflehog, wafw00f, inql
- **Phases M–P** — Cloud bucket discovery, git exposure scanning, GraphQL
  introspection, WAF detection
- **Screenshots** — gowitness captures browser screenshots of live hosts
- **Webhook notifications** — send JSON payloads with severity to any webhook URL
- **Config file support** — `--config` JSON file pre-populates options
- **Dockerfile** — containerised deployment with multi-stage build
- **Streaming pipeline** — 01-RECON/02-RESOLVE/03-PERMUTE/04-SCAN/05-HARVEST all run concurrently; wall-clock reduction
  of 40–60% on typical targets
- **Downsampling** — artifacts truncated to 1 entry per phase (--keep-all to disable)
- **Per-phase output guards** — skip completed phases unless --force is set
- **Nuclei template cache** — auto-updates at most once per 24h
- **Graceful degradation** — every external tool is optional; pipeline handles
  missing binaries without crashing

## Security

Only scan systems you own or have explicit permission to test. Recon tools may
trigger security alerts or rate-limiting on the target.

## License

MIT
