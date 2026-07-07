# ReconChain v1.5.1

Chains 57 recon and vulnerability phases into a single resumable pipeline — no config files required.

```bash
# Interactive wizard (recommended)
reconchain -i

# One-liner
reconchain -d example.com -o ./out

# Multi-domain
reconchain -d example.com,test.org -o ./out

# Quick recon only
reconchain -d example.com --fast
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
| `--resume` | Resume cancelled scan |
| `--force` | Re-run all phases |
| `-j 32` | Parallelism (default: cpu×2) |
| `--proxy socks5://127.0.0.1:9050` | Route through SOCKS/Tor |

Recon levels: **Basic** (recon only), **Standard** (recon + vuln scan), **Full** (all 57 phases).

## Generate AI Report

After a scan, feed the output to an LLM for a natural-language summary:

```bash
# Ask an AI to analyze the results (works with any CLI LLM tool)
cat out/example.com/summary.txt | llm "Summarize these security findings for a non-technical audience, highlight critical risks, and suggest remediation steps"

# Or point an AI code editor at the out/ directory
# e.g. in Claude Code, Cursor, or Continue.dev:
# "Review the scan results in ./out/example.com/ and write a pentest report"
```

The `summary.txt` and `summary.json` files contain all findings in a machine-readable format that AI tools can analyze directly.

## Key Pipeline Stages

```
00-SCOPE   → scope validation
01-RECON   → subdomains (subfinder, amass)
02-RESOLVE → DNS resolution (massdns → dnsx → socket)
04-SCAN    → ports, HTTP probing, service detection
05-HARVEST → URL harvesting (gau, gospider, katana, waymore)
09-VULNSCAN → nuclei + tech detection
10-TLSCMS  → TLS + WordPress
11-INJECT  → XSS, SSRF, SQLi, SSTI, NoSQLi, XXE, CMDi, LDAP
11a-DOMXSS → DOM XSS via browser automation (Playwright)
20-GRAPHQL → GraphQL introspection + schema analysis + deep probes
28-CACHED  → Web cache poisoning/deception + v2 probes
38b-H2SMUGGLE → HTTP/2 + HTTP/3 attack surface (Rapid Reset, HPACK, QUIC)
41-WEBSOCKET → WebSocket security testing + deep probes
45-EVIDENCE → Evidence capture + auto PoC generation
49-FRAMEWORKS → Framework detection + edge runtime vuln checks
```

All 57 phases run in a DAG with 18 ordered stages — see `reconchain -h` or the code for the full list.

## Output

```
out/example.com/
├── summary.json       # Machine-readable (feed to AI)
├── summary.txt        # Human-readable
├── report.html        # HTML report with severity badges
├── report.md          # Markdown report
├── hosts.txt          # Live hosts with tech
├── urls_all.txt       # All discovered URLs
├── nuclei_combined.txt # Vulnerability findings
├── ssti.txt           # SSTI findings
├── vulns.txt          # XSS/SSRF findings
├── sqlmap_findings.txt # SQL injection candidates
├── ...                # 50+ artifact files
├── domxss_findings.txt  # DOM XSS candidates
├── h2_smuggling.txt     # H2/H3 attack surface results
├── framework_vulns.txt  # Framework detection + vuln checks
├── websocket.txt        # WebSocket endpoint findings
├── cache_poison.txt     # Cache poisoning/deception results
├── graphql_introspection.txt # GraphQL introspection + deep probe results
├── evidence/            # Auto-generated PoCs
│   └── poc/             # Per-finding PoC files + index
├── screenshots/         # Gowitness browser screenshots
├── logs/                # Raw tool output
└── state.json           # Resume state
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
