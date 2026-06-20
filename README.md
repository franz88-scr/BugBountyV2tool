# ReconChain v2.2

A Python orchestrator that chains 25+ recon and vulnerability tools into a single,
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
- **Manual testing add-ons** — SSTI, origin bypass, deep JS secrets, auth bypass
- **Resume** — picks up where you left off

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

# Tune parallelism
./reconchain.py -d example.com -o ./out -j 32
```

## Recon Levels

| Level | What Runs | Use Case |
|-------|-----------|----------|
| **1 — Basic** | A1 → A2 → B1 → C1 → I | Quick domain recon: subdomains, DNS, ports, URLs |
| **2 — Standard** | Level 1 + C2 → D → E → F1 → F2 | Full automated vuln scanning |
| **Full** | Level 2 + G2 → J → K → L | Maximum coverage (SSTI, origin bypass, deep JS, auth bypass) |

## Pipeline

```
A1  subdomains ──→ all_subs.txt
A2  DNS resolve ──→ resolved.txt
B1  ports/hosts  ──→ ports.txt + hosts.txt + takeover.txt
C1  URL harvest  ──→ urls_all.txt
C2  JS analysis  ──→ js_secrets.txt
D   parameters   ──→ params.txt
E   fuzzing      ──→ fuzz.txt
F1  nuclei + tech──→ nuclei.txt
F2  ssl + wp     ──→ tls_wp.txt
G   XSS + SQLi   ──→ vulns.txt (dalfox/sqlmap/SSRF)
G2  SSTI fuzzing ──→ ssti.txt                        ← new
H   OAST polling ──→ callbacks.txt
I   reports     ──→ summary.json + report.html + report.md
J   origin bypass──→ origin.txt                       ← new
K   deep JS sec. ──→ js_secrets_deep.txt              ← new
L   auth bypass  ──→ auth_bypass.txt                  ← new
```

Phases A1–I are the standard automated pipeline. Phases G2, J, K, L target gaps that
automated scanners often miss (SSTI, Cloudflare origin discovery, deep secret scanning,
mass assignment probes).

Parallel stages: C2/D/E/F1/F2/G/G2/J/K/L all run concurrently once URLs and hosts are
available.

## Output

```
out/
├── all_subs.txt          # Subdomains
├── resolved.txt          # Resolved hosts
├── ports.txt             # Open ports
├── hosts.txt             # Live HTTP hosts
├── takeover.txt          # Subdomain takeover candidates
├── urls_all.txt          # All discovered URLs
├── urls_js.txt           # JavaScript URLs
├── js_secrets.txt        # Secrets from SecretFinder/linkfinder
├── js_secrets_deep.txt   # Deep JS secrets (custom regex + source maps)  ← new
├── params.txt            # Discovered parameters
├── fuzz.txt              # Fuzzing results
├── nuclei.txt            # Nuclei findings
├── tls_wp.txt            # TLS + WordPress results
├── vulns.txt             # XSS/SQLi/SSRF findings
├── ssti.txt              # SSTI probe results                              ← new
├── origin.txt            # Origin IP candidates                            ← new
├── auth_bypass.txt       # Auth bypass probes + mass assignment fields     ← new
├── oast/
│   └── callbacks.txt     # OOB interactions
├── logs/                 # Per-tool raw output
├── state.json            # Resume state
├── summary.json          # Machine-readable results
├── report.html           # HTML report
└── report.md             # Markdown report
```

## Supported Tools

| Category | Tools |
|----------|-------|
| Enumeration | subfinder, amass, assetfinder, dnsx |
| Network | naabu, nmap, httpx, subjack |
| URLs | gau, waybackurls, gospider, katana, subjs |
| Analysis | LinkFinder, SecretFinder, ParamSpider, Arjun, x8 |
| Fuzzing | ffuf, kiterunner (kr), feroxbuster |
| Vulns | nuclei, dalfox, sqlmap, testssl.sh, wpscan |
| OAST | interactsh-client |

Missing tools are automatically skipped — the pipeline never crashes over a missing
binary.

## Flags

```
-d, --domain      Target domain (e.g. example.com)
-o, --out         Output directory (default: ./out)
-i, --interactive Interactive wizard
--only            Comma-separated phases to run (e.g. A1,J,K)
--skip            Comma-separated phases to skip
-j, --jobs        Max parallel processes (default: 16)
--fast            Basic recon only (A1, A2, B1, C1, I)
--resume          Resume from state.json
-q, --quiet       Suppress info logs
--no-color        Disable ANSI colors
```

## Configuration

| Variable | Purpose |
|----------|---------|
| `INTERACTSH_TOKEN` | Interactsh auth token |
| `FFUF_WORDLIST` | Custom ffuf wordlist path |
| `KITELIST` | Kiterunner wordlist path |
| `NO_COLOR` | Disable colour output |

## Security

Only scan systems you own or have explicit permission to test. Recon tools may
trigger security alerts or rate-limiting on the target.

## License

MIT
