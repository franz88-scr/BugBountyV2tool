# BugBountyV2tool

Read me

A single Python orchestrator that chains 25+ recon tools into one structured pipeline — subfinder → dnsx → httpx/naabu → gau/katana → nuclei → interactsh → report.
text
Copy

┌── subfinder ──┐
       PHASE A1 ────┼── amass ──────┼── all_subs.txt
                    └── assetfinder ┘
                            │
                            ▼
                    dnsx → resolved.txt
                            │
       ┌────────────────────┼─────────────────────┐
       ▼                    ▼                     ▼
   naabu/nmap            httpx              subjack/takeover
   ports/                hosts/             takeover candidates
                            │
                            ├────────── parallel ──────────┐
                            ▼                             ▼
                     gau/waybackurls                   katana
                     + gospider                        + subjs
                            │                             │
                            └─────────────┬───────────────┘
                                          ▼
                                LinkFinder + SecretFinder
                                nuclei/exposures
                                          │
                                          ▼
                          ParamSpider + Arjun + x8
                                          │
                                          ▼
                          ffuf + kiterunner + feroxbuster
                                          │
                            ┌─────────────┴──────────────┐
                            ▼                            ▼
                       nuclei (full)               testssl.sh
                       + tech-scanner              + wpscan
                            │                            │
                            └─────────────┬──────────────┘
                                          ▼
                  [interactsh running im Hintergrund seit E1]
                                          ▼
                      dalfox → sqlmap → SSRF-Probes
                                          │
                                          ▼
                  interactsh polling → oast/callbacks.txt
                                          │
                                          ▼
                              dedup → summary.json
                                   → report.html
                                   → report.md
✨ Features
* One script, full pipeline — reconchain.py is a single ~700-line file, stdlib-only.
* Phase-aware parallelism — branches in the diagram (B1, C1, F1‖F2) run concurrently via asyncio.gather.
* Background OOB collection — interactsh-client starts before phase E, runs in the background, and its JSON event log is parsed to oast/callbacks.txt at the end.
* Graceful degradation — every tool is detected via shutil.which; missing binaries are reported, never crash the run.
* Resumable — every phase persists its outputs to state.json; pick up with --resume if anything dies.
* Three report formats — summary.json (machine), report.html (dark-themed, embedded CSS), report.md (table).
* Subset execution — --only A1,A2,B1or --skip F2,G to slice the pipeline.
📦 Install
1. Install all the external tools
bash
Copy

chmod +x install.sh
./install.sh          # full install (~10-15 min, downloads ~25 Go/Python tools)
./install.sh --check  # show what you're missing
./install.sh --go-only   # only Go tools
./install.sh --py-only   # only Python tools
Supported: Debian/Ubuntu, Fedora, Arch, macOS (Homebrew). The script:
* Installs nmap, python3, ruby, jq via your package manager.
* Installs Go 1.22+ if missing.
* go installs 18 Go tools (subfinder, amass, dnsx, naabu, httpx, subjack, nuclei, gau, waybackurls, gospider, katana, subjs, x8, ffuf, kiterunner, feroxbuster, dalfox, interactsh-client, assetfinder).
* pip installs arjun, secretfinder; git-clones sqlmap, paramspider, linkfinder.
* gem installs wpscan.
* Clones testssl.sh.
* Runs nuclei -update-templates.
After install, add the Go bin dir to your PATH (the script does this for you in ~/.bashrc / ~/.zshrc if writable):
bash
Copy

export PATH=$PATH:$HOME/go/bin
2. Drop the script in
bash
Copy

git clone https://github.com/<you>/reconchain.git
cd reconchain
chmod +x reconchain.py
No Python dependencies — stdlib only.
🚀 Usage
bash
Copy

# full chain
./reconchain.py -d example.com -o ./out

# only enumerate subdomains
./reconchain.py -d example.com -o ./out --only A1

# skip slow/heavy steps
./reconchain.py -d example.com -o ./out --skip F2,G

# resume after a crash
./reconchain.py -d example.com -o ./out --resume

# quiet mode
./reconchain.py -d example.com -o ./out -q
CLI
flag	description
-d DOMAIN	target root domain (required)
-o OUT	output directory (default ./out)
--only	comma-separated phases to run, e.g. A1,A2,B1
--skip	comma-separated phases to skip, e.g. F2,G
--resume	resume from ./out/state.json
-q	suppress info-level logs
Phases
id	what it does	outputs
A1	subdomain enumeration: subfinder · amass · assetfinder (parallel)	all_subs.txt
A2	dnsx resolution	resolved.txt
B1	ports (naabu/nmap) ‖ live hosts (httpx) ‖ takeover (subjack)	ports.txt hosts.txt takeover.txt
C1	URL harvest: gau/waybackurls+gospider ‖ katana+subjs	urls_gau.txt urls_katana.txt
C2	JS analysis: LinkFinder · SecretFinder · nuclei/exposures	js_secrets.txt
D	parameter discovery: ParamSpider · Arjun · x8	params.txt
E	fuzzing: ffuf · kiterunner · feroxbuster	fuzz.txt
F1	nuclei (full) · tech-scanner	nuclei.txt tech.txt
F2	testssl.sh · wpscan	testssl.txt wpscan_*.txt
G	XSS (dalfox) → SQLi (sqlmap) → SSRF probes (auto-injected with OAST domain)	vulns.txt
H	interactsh polling (started before E)	oast/callbacks.txt
I	dedup + 3 report formats	summary.json report.html report.md
📁 Output layout
text
Copy

out/
├── all_subs.txt              # every subdomain found
├── resolved.txt              # DNS-resolved hosts (dnsx)
├── ports.txt                 # naabu open ports
├── hosts.txt                 # httpx live hosts
├── takeover.txt              # subjack candidates
├── urls_gau.txt              # gau URLs
├── urls_katana.txt           # katana URLs
├── urls_all.txt              # deduped union
├── js_secrets.txt            # LinkFinder + SecretFinder + nuclei/exposures
├── params.txt                # ParamSpider + Arjun + x8
├── fuzz.txt                  # ffuf + kiterunner + feroxbuster
├── nuclei.txt                # nuclei (full)
├── tech.txt                  # nuclei tech-detect
├── nuclei_combined.txt       # dedup of above
├── testssl.txt               # TLS scan
├── vulns.txt                 # XSS / SQLi / SSRF
├── oast/
│   └── callbacks.txt         # interactsh events
├── logs/                     # raw stdout/stderr per tool
├── state.json                # resumable state
├── summary.json              # machine-readable summary
├── report.html               # dark-themed HTML report
└── report.md                 # markdown summary
🔧 Configuration
Environment variables (all optional):
var	purpose
INTERACTSH_TOKEN	forward to interactsh-client -t (for registered OAST)
FFUF_WORDLIST	override fuzz wordlist (default: raft-medium-directories.txt)
KITELIST	override kiterunner routes (default: api/api-endpoints.txt)
NO_COLOR	set to anything to disable ANSI colors
The script falls back to seclists paths from the seclists apt package when available, otherwise skips fuzzing gracefully.
🛡 Legal
Only run this against systems you own or have explicit written permission to test.Most of the bundled tools (nuclei, sqlmap, dalfox, feroxbuster, nmap, wpscan) will trigger IDS/IPS, generate loud logs, and may be illegal to use against third-party infrastructure. The author(s) of this script accept no liability for misuse.
🤝 Contributing
PRs welcome — especially:
* New tool integrations (drop them into the relevant phase function).
* Better wordlists / nuclei template categories.
* Support for non-Debian PMs (Alpine, Nix, etc.).
* Cloud-friendly mode (Docker / GitHub Actions).
📜 License
MIT.
