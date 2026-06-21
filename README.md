# ReconChain v2.2

A Python orchestrator that chains 30+ recon and vulnerability tools into a single,
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
- **Manual testing add-ons** — SSTI, origin bypass, deep JS secrets, auth bypass
- **Resume / Force** — picks up where you left off, or force re-run all phases

Shows a summary before starting. Zero flags to remember.

### Command-line

```bash
# Full audit (everything)
./reconchain.py -d example.com -o ./out

# Basic recon only (fast)
./reconchain.py -d example.com --fast

# Pick specific phases
./reconchain.py -d example.com -o ./out --only A1,A2,B1,C1,I

# Skip slow phases
./reconchain.py -d example.com -o ./out --skip F2,G

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
```

## Recon Levels

| Level | What Runs | Use Case |
|-------|-----------|----------|
| **1 — Basic** | A1 → A2 → A3 → B1 → C1 → I | Quick domain recon: subdomains, DNS, ports, URLs |
| **2 — Standard** | Level 1 + C2 → D → E → F1 → F2 | Full automated vuln scanning |
| **Full** | Level 2 + G2 → J → K → L | Maximum coverage (SSTI, origin bypass, deep JS, auth bypass) |

## Pipeline (streaming: A1→A2→B1→C1 overlap via incremental processing)

```
A1  subdomains     ──→ all_subs.txt
A2  DNS resolve    ──→ resolved.txt + resolved_full.txt
A3  permute subs   ──→ all_subs.txt (append)
B1  ports/hosts    ──→ ports.txt + ports_udp.txt + hosts.txt + takeover.txt
C1  URL harvest    ──→ urls_all.txt
C2  JS analysis    ──→ js_secrets.txt
D   parameters     ──→ params.txt
E   fuzzing        ──→ fuzz.txt
F1  nuclei + tech  ──→ nuclei_combined.txt
F2  ssl + wp       ──→ tls_wp.txt
G   XSS + SQLi + SSRF ──→ vulns.txt
G2  SSTI fuzzing   ──→ ssti.txt
H   OAST polling   ──→ callbacks.txt
I   reports        ──→ summary.json + report.html + report.md + summary.txt
J   origin bypass  ──→ origin.txt
K   deep JS sec.   ──→ js_secrets_deep.txt
L   auth bypass    ──→ auth_bypass.txt
```

Phases A1–I are the standard automated pipeline. Phases G2, J, K, L target gaps that
automated scanners often miss (SSTI, Cloudflare origin discovery, deep secret scanning,
mass assignment probes).

Streaming stages: A1/A2/A3/B1/C1 all run concurrently in the first stage — A1 writes
subdomains incrementally, A2 polls and resolves them as they arrive, B1 and C1 start
on partial hosts. This cuts wall-clock time by overlapping the linear chain.
The remaining phases C2/D/E/F1/F2/G/G2/J/K/L fan out in the second stage.

### Phase Details

| Phase | Tools | Description |
|-------|-------|-------------|
| **A1** | subfinder, amass, assetfinder | Passive subdomain enumeration from CT logs, search engines, DNS |
| **A2** | dnsx | DNS resolution with A/AAAA/CNAME records; validates and deduplicates |
| **A3** | dnsgen, dnsx | Subdomain permutation generation; resolves candidates, appends new findings |
| **B1** | naabu (nmap fallback), httpx, subjack (nuclei fallback) | TCP + UDP port scanning, HTTP service detection, subdomain takeover checks |
| **C1** | gau, waybackurls, gospider, katana, subjs, waymore | Historical URL harvesting + active crawling + JS URL extraction |
| **C2** | LinkFinder, SecretFinder, nuclei (exposures) | JavaScript file analysis for endpoints and secrets |
| **D** | ParamSpider, Arjun, x8 | Parameter discovery on harvested URLs |
| **E** | ffuf, kiterunner (kr), feroxbuster | Directory/file fuzzing with SecLists wordlists |
| **F1** | nuclei (full + technologies) | Vulnerability scanning with auto-updated templates |
| **F2** | testssl.sh, wpscan | TLS security assessment + WordPress scanning |
| **G** | kxss, dalfox, sqlmap, SSRF probes | Pre-filter reflected params, XSS scanning, SQL injection fuzzing, SSRF parameter injection |
| **G2** | SSTI probes | Server-Side Template Injection detection with parameter-aware payloads |
| **H** | interactsh-client | OOB (out-of-band) interaction capture for SSRF/blind findings |
| **I** | Reporting | HTML, Markdown, JSON, and text summary generation |
| **J** | favicon hash, crt.sh, dig MX/SPF/DMARC/DKIM, ipinfo.io | Origin IP bypass enumeration (Cloudflare, CDN discovery, DNS record auditing) |
| **K** | gitleaks, deep JS regex + source map analysis | GitLeaks secret scanning on raw JS + entropy/regex-based secret detection |
| **L** | Auth bypass headers, mass assignment probes | Authentication bypass testing + mass assignment field discovery |

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
├── oast/
│   └── callbacks.txt         # OOB interactions
├── logs/                     # Per-tool raw output
│   ├── phase_*.log           # Phase execution logs
│   ├── amass.sh              # Generated runner scripts
│   ├── *_runner.sh
│   └── interactsh.log        # Raw interactsh output
├── state.json                # Resume state
├── summary.json              # Machine-readable results
├── report.html               # HTML report
├── report.md                 # Markdown report
└── summary.txt               # Text summary
```

## Supported Tools

| Category | Tools |
|----------|-------|
| Enumeration | subfinder, amass, assetfinder, dnsx |
| Network | naabu, nmap, httpx, subjack |
| URLs | gau, waybackurls, gospider, katana, subjs, waymore |
| Analysis | LinkFinder, SecretFinder, ParamSpider, Arjun, x8, dnsgen |
| Fuzzing | ffuf, kiterunner (kr), feroxbuster |
| Vulns | nuclei (with auto-updated templates), dalfox, sqlmap, testssl.sh, wpscan, kxss |
| Secrets | gitleaks, SecretFinder, LinkFinder |
| OAST | interactsh-client |
| DNS | dig |

Missing tools are automatically skipped — the pipeline never crashes over a missing
binary.

## Flags

```
-d, --domain      Target domain (e.g. example.com)
-o, --out         Output directory (default: ./out/<domain>)
-i, --interactive Interactive wizard
--only            Comma-separated phases to run (e.g. A1,J,K)
--skip            Comma-separated phases to skip
-j, --jobs        Max parallel processes (default: cpu_count × 2)
--fast            Basic recon only (A1, A2, B1, C1, I)
--resume          Resume from state.json
--force           Re-run all phases even if output files already exist
-q, --quiet       Suppress info logs
--no-color        Disable ANSI colors
--proxy           Proxy URL (e.g. socks5://127.0.0.1:9050)
--cookie          Cookie string for authenticated scans
--header          Extra HTTP header (repeatable)
--sqlmap-level    SQLmap --level (1-5, default: 1)
--sqlmap-risk     SQLmap --risk (1-3, default: 1)
--delay           Seconds between requests (default: 0)
--rate-limit      Max requests per second (default: 0 = unlimited)
--sample-urls-fuzz        URLs to fuzz (default: 5)
--sample-urls-params      URLs for parameter discovery (default: 50)
--sample-urls-pspider     URLs for ParamSpider (default: 20)
--sample-urls-xss-blind   URLs for blind XSS probe (default: 20)
--sample-urls-ssti        SSTI sample URLs (default: 5)
--sample-endpoints-post   Endpoints to mass-assign POST (default: 5)
--sample-endpoints-cors   Endpoints to CORS-fuzz (default: 10)
--exclude-tags            Nuclei tags to exclude (e.g. 'info,tech')
```

## Configuration

| Variable | Purpose |
|----------|---------|
| `INTERACTSH_TOKEN` | Interactsh auth token |
| `WPSCAN_API_TOKEN` | WPScan API token (enables vulnerability data) |
| `FFUF_WORDLIST` | Custom ffuf wordlist path |
| `KITE_FILE` | Kiterunner wordlist path |
| `PROXY` | Default proxy for HTTP tools |
| `COOKIE` | Default cookie for authenticated scans |
| `NO_COLOR` | Disable colour output |

## Key Improvements

- **Streaming pipeline** — A1/A2/A3/B1/C1 all run concurrently in a single stage; A1 writes
  subdomains incrementally every 30s, A2 polls and resolves them as they arrive, B1 and C1
  start on partial hosts. Wall-clock reduction of 40–60% on typical targets.
- **Output-existence guards (all phases)** — every phase now skips if its output exists and
  `--force` is not set; saves 5–10 min on incremental re-runs.
- **`--exclude-tags`** — exclude nuclei tags at runtime (e.g. `--exclude-tags info,tech`)
- **Nuclei template cache** — templates auto-update at most once per 24 hours (stamp file)
- **Nuclei `-bs 25`** — bulk-size=25 for faster multi-template scanning
- **Waymore support** — optional waymore URL harvester (combines gau+wayback+crtsh)
- **URL dedup in D, G, G2, L** — reduce redundant work by deduplicating (host, path) and
  (param keys) before scanning
- **Deduplicated silent re-runs** — `only.isdisjoint` removed from A1/A2 guards; phases
  respect their output files regardless of `--only`
- **httpx `-fr`** — follow-redirects on same host (faster)
- **Katana `-duc`** — disable unique check for faster incremental re-runs

## Security

Only scan systems you own or have explicit permission to test. Recon tools may
trigger security alerts or rate-limiting on the target.

## License

MIT
