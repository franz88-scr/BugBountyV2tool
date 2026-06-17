ReconChain

A single Python orchestrator that chains 25+ reconnaissance and vulnerability assessment tools into one structured, resumable pipeline.

⸻

Overview

ReconChain automates the entire reconnaissance workflow, from subdomain enumeration to vulnerability discovery and reporting.

Instead of manually chaining dozens of tools together, ReconChain executes them in a structured, phase-based pipeline with:

* Parallel execution where possible
* Automatic dependency detection
* Resume support after interruptions
* Background OAST collection via Interactsh
* Multiple report formats
* Graceful handling of missing tools

The result is a single command that performs a complete reconnaissance workflow and produces actionable reports.

⸻

Pipeline

┌── subfinder ──┐
       PHASE A1 ────┼── amass ──────┼── all_subs.txt
                    └── assetfinder ┘
                            │
                            ▼
                    dnsx → resolved.txt
                            │
       ┌────────────────────┼─────────────────────┐
       ▼                    ▼                     ▼
   naabu/nmap            httpx              subjack
   ports                 live hosts         takeover checks
                            │
                            ├────────── parallel ──────────┐
                            ▼                             ▼
                     gau/waybackurls                   katana
                     + gospider                        + subjs
                            │                             │
                            └─────────────┬───────────────┘
                                          ▼
                         LinkFinder + SecretFinder
                             nuclei exposures
                                          │
                                          ▼
                         ParamSpider + Arjun + x8
                                          │
                                          ▼
                     ffuf + kiterunner + feroxbuster
                                          │
                            ┌─────────────┴──────────────┐
                            ▼                            ▼
                     nuclei (full)                 testssl.sh
                     tech detection                wpscan
                            │                            │
                            └─────────────┬──────────────┘
                                          ▼
                              interactsh polling
                                          ▼
                     dalfox → sqlmap → SSRF probes
                                          │
                                          ▼
                               report generation

⸻

Features

Full Recon Pipeline

Single command execution covering:

* Subdomain Enumeration
* DNS Resolution
* Port Scanning
* Live Host Discovery
* Takeover Detection
* URL Collection
* JavaScript Analysis
* Secret Discovery
* Parameter Enumeration
* Content Fuzzing
* Vulnerability Scanning
* SSL/TLS Assessment
* WordPress Enumeration
* OAST Callback Tracking
* Automated Reporting

Phase-Aware Parallelism

Independent branches execute concurrently using asyncio.gather().

Examples:

* Enumeration tools run simultaneously
* URL collection branches execute in parallel
* SSL and vulnerability scans run independently

Background OAST Collection

interactsh-client is launched automatically before active testing begins and remains active throughout the scan.

Detected callbacks are exported to:

oast/callbacks.txt

Graceful Degradation

Every dependency is verified using:

shutil.which()

Missing tools are reported and skipped without crashing the pipeline.

Resume Support

If execution stops unexpectedly:

./reconchain.py --resume

ReconChain restores progress from:

state.json

Multi-Format Reporting

Generated reports:

* summary.json
* report.html
* report.md

⸻

Supported Tools

Enumeration

* subfinder
* amass
* assetfinder
* dnsx

Network Discovery

* naabu
* nmap
* httpx
* subjack

URL Collection

* gau
* waybackurls
* gospider
* katana
* subjs

Analysis

* LinkFinder
* SecretFinder
* ParamSpider
* Arjun
* x8

Fuzzing

* ffuf
* kiterunner
* feroxbuster

Vulnerability Assessment

* nuclei
* dalfox
* sqlmap
* testssl.sh
* wpscan

OAST

* interactsh-client

⸻

Installation

1. Install Dependencies

chmod +x install.sh
./install.sh

Installation typically takes:

* 10–15 minutes
* Downloads ~25 external tools

Installation Modes

./install.sh

Full installation.

./install.sh --check

Check installed tools.

./install.sh --go-only

Install only Go-based tools.

./install.sh --py-only

Install only Python-based tools.

⸻

Supported Platforms

* Ubuntu
* Debian
* Fedora
* Arch Linux
* macOS (Homebrew)

The installer automatically:

* Installs Go ≥ 1.22
* Installs system packages
* Installs Python dependencies
* Installs Ruby dependencies
* Updates Nuclei templates
* Configures PATH

⸻

Clone Repository

git clone https://github.com/<username>/reconchain.git
cd reconchain
chmod +x reconchain.py

No Python dependencies are required beyond the standard library.

⸻

Usage

Full Scan

./reconchain.py -d example.com -o ./out

Run Specific Phases

./reconchain.py \
    -d example.com \
    -o ./out \
    --only A1,A2,B1

Skip Heavy Scans

./reconchain.py \
    -d example.com \
    -o ./out \
    --skip F2,G

Resume Execution

./reconchain.py \
    -d example.com \
    -o ./out \
    --resume

Quiet Mode

./reconchain.py \
    -d example.com \
    -o ./out \
    -q

⸻

Command Line Options

Flag	Description
-d	Target root domain
-o	Output directory
--only	Run selected phases
--skip	Skip selected phases
--resume	Resume from state.json
-q	Quiet mode

⸻

Scan Phases

Phase	Description	Output
A1	Subdomain Enumeration	all_subs.txt
A2	DNS Resolution	resolved.txt
B1	Ports, Hosts, Takeover Checks	ports.txt
C1	URL Harvesting	urls_*.txt
C2	JS & Secret Analysis	js_secrets.txt
D	Parameter Discovery	params.txt
E	Content Fuzzing	fuzz.txt
F1	Nuclei & Tech Detection	nuclei.txt
F2	SSL & WordPress Analysis	testssl.txt
G	XSS, SQLi, SSRF Testing	vulns.txt
H	OAST Callback Collection	callbacks.txt
I	Reporting	report.html

⸻

Output Structure

out/
├── all_subs.txt
├── resolved.txt
├── ports.txt
├── hosts.txt
├── takeover.txt
├── urls_gau.txt
├── urls_katana.txt
├── urls_all.txt
├── js_secrets.txt
├── params.txt
├── fuzz.txt
├── nuclei.txt
├── tech.txt
├── nuclei_combined.txt
├── testssl.txt
├── vulns.txt
├── oast/
│   └── callbacks.txt
├── logs/
├── state.json
├── summary.json
├── report.html
└── report.md

⸻

Configuration

Environment variables:

Variable	Description
INTERACTSH_TOKEN	Registered Interactsh token
FFUF_WORDLIST	Custom FFUF wordlist
KITELIST	Custom Kiterunner route list
NO_COLOR	Disable ANSI colors

⸻

Security Notice

ReconChain includes tools that perform active reconnaissance and vulnerability testing.

These tools may:

* Trigger IDS/IPS alerts
* Generate extensive logs
* Impact production systems
* Violate laws or policies if used without authorization

Only scan systems you own or have explicit written permission to test.

⸻

Roadmap

* Docker image
* GitHub Actions support
* Kubernetes deployment mode
* Cloud asset inventory integration
* Additional nuclei template profiles
* Alpine Linux support
* Nix package support

⸻

Contributing

Contributions are welcome.

Ideas:

* New tool integrations
* Additional report formats
* Better wordlists
* New scan phases
* Performance improvements

⸻

License

MIT License

See the LICENSE file for details.