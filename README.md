# ReconChain

A single Python orchestrator that chains 25+ reconnaissance and vulnerability assessment tools into one structured, resumable pipeline.

## Overview

ReconChain automates the entire reconnaissance workflow from subdomain enumeration to vulnerability discovery and reporting.

Instead of manually chaining dozens of tools together, ReconChain executes them in a structured phase based pipeline with:

- Parallel execution where possible  
- Automatic dependency detection  
- Resume support after interruptions  
- Background OAST collection via Interactsh  
- Multiple report formats  
- Graceful handling of missing tools  

The result is a single command that performs a complete reconnaissance workflow and produces actionable reports.

## Pipeline

subfinder + amass + assetfinder  
→ dnsx  
→ naabu / nmap + httpx + subjack  
→ gau + waybackurls + gospider + katana + subjs  
→ LinkFinder + SecretFinder + nuclei exposures  
→ ParamSpider + Arjun + x8  
→ ffuf + kiterunner + feroxbuster  
→ nuclei + testssl.sh + wpscan  
→ interactsh polling  
→ dalfox + sqlmap + SSRF probes  
→ report generation  

## Features

### Full Recon Pipeline

Single command execution covering:

- Subdomain enumeration  
- DNS resolution  
- Port scanning  
- Live host discovery  
- Takeover detection  
- URL collection  
- JavaScript analysis  
- Secret discovery  
- Parameter enumeration  
- Content fuzzing  
- Vulnerability scanning  
- SSL and TLS assessment  
- WordPress enumeration  
- OAST callback tracking  
- Automated reporting  

### Phase Aware Parallelism

Independent branches execute concurrently using asyncio.gather.

### Background OAST Collection

interactsh client is launched automatically before active testing begins and remains active throughout the scan.

Detected callbacks are exported to:

oast/callbacks.txt

### Graceful Degradation

Dependencies are checked using shutil.which.

Missing tools are skipped without crashing the pipeline.

### Resume Support

./reconchain.py --resume

State file:

state.json

### Reports

- summary.json  
- report.html  
- report.md  

## Supported Tools

Enumeration:
subfinder, amass, assetfinder, dnsx

Network:
naabu, nmap, httpx, subjack

URLs:
gau, waybackurls, gospider, katana, subjs

Analysis:
LinkFinder, SecretFinder, ParamSpider, Arjun, x8

Fuzzing:
ffuf, kiterunner (`kr`), feroxbuster

Vulns:
nuclei, dalfox, sqlmap, testssl.sh, wpscan

OAST:
interactsh-client

## Installation

Python package and development tooling:

pip install tqdm

python3 -m pip install -e '.[dev]'

External recon tools:

chmod +x install.sh
./install.sh

Modes:

./install.sh --check
./install.sh --go-only
./install.sh --py-only

## Platforms

Ubuntu, Debian, Fedora, Arch, macOS (Homebrew)

## Usage

Full scan:
./reconchain.py -d example.com -o ./out

Only phases:
./reconchain.py -d example.com -o ./out --only A1,A2,B1

Skip phases:
./reconchain.py -d example.com -o ./out --skip F2,G

Resume:
./reconchain.py -d example.com -o ./out --resume

Quiet:
./reconchain.py -d example.com -o ./out -q

## Flags

-d target domain  
-o output folder  
--only selected phases  
--skip skip phases  
--resume resume scan  
-q quiet mode  
-h show help

## Scan Phases

A1 subdomains → all_subs.txt  
A2 DNS resolve → resolved.txt  
B1 ports + takeover → ports.txt  
C1 URL collection → urls.txt  
C2 JS + secrets → js_secrets.txt  
D parameters → params.txt  
E fuzzing → fuzz.txt  
F1 nuclei + tech → nuclei.txt  
F2 ssl + wordpress → testssl.txt  
G vulns → vulns.txt  
H oast callbacks → callbacks.txt  
I reporting → report.html  

## Output

out/
all_subs.txt
resolved.txt
ports.txt
hosts.txt
takeover.txt
urls_*.txt
js_secrets.txt
params.txt
fuzz.txt
nuclei.txt
testssl.txt
vulns.txt
oast/callbacks.txt
logs/
state.json
summary.json
report.html
report.md

## Configuration

INTERACTSH_TOKEN
FFUF_WORDLIST
KITELIST
NO_COLOR

`KITELIST` points to the kiterunner wordlist used by the `kr` binary.

## Security Notice

Only scan systems you own or have permission to test.

Recon tools may trigger security alerts or logs.

## Roadmap

Docker support  
GitHub Actions  
Kubernetes mode  
Cloud asset inventory  
More nuclei profiles  
Alpine support  
Nix package  

## License

MIT
