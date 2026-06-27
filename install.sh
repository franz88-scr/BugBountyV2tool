#!/usr/bin/env bash

# install.sh — install every external tool reconchain.py depends on.

#

# DAG: Stage 0 (00-SCOPE→01-RECON→02-RESOLVE→03-PERMUTE→04-SCAN→04b-TAKEOVER-VALIDATE→34-RATELIMIT),
#      Stage 1 (21-WAF), Stage 2 (05-HARVEST→05b-APISPEC→06-JSINTEL→15-SECRETS), Stage 3 (07-PARAMS),
#      Stage 4 (08-FUZZ), Stage 5 (09-VULNSCAN→10-TLSCMS→14-ORIGIN→18-CLOUD→19-GIT→20-GRAPHQL),
#      Stage 6 (11-INJECT→11b-SQLMAP→12-SSTI→22-NOSQLI→25-XXE→26-CMDINJECT→27-SSPP→42-LDAP→43-DESERIAL),
#      Stage 7 (17b-SSRFMETA), Stage 8 (24-JWT→36-JWTADV),
#      Stage 9 (39-OAUTH→40-PWRESET→16A-AUTHZ→16B-MASSASSIGN→17-IDOR),
#      Stage 10 (28-CACHED→29-DEPCHECK→30-LFI→31-OPENREDIR→32-CLICKJACK→33-CRLF→35-CORSADV→37-FILEUPLOAD→38-SMUGGLE→41-WEBSOCKET),
#      Stage 11 (13-OOB→23-RACE), Stage 12 (44-CHAIN→45-EVIDENCE), + 44-REPORT.

# Optional: proxychains4 for SOCKS proxy support (auto-detected).

#

# Usage:

#   ./install.sh              # install everything

#   ./install.sh --check      # only check what's missing

#   ./install.sh --go-only    # install only the Go-based tools

#   ./install.sh --py-only    # install only the Python-based tools

#

# Supported: Debian/Ubuntu, Fedora, Arch, macOS (Homebrew).

# All Go tools are installed to $GOPATH/bin (defaults to ~/go/bin).

#

set -euo pipefail


# ───────────────────────────── styling ─────────────────────────────

if [[ -t 1 ]]; then

  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'

  C_INFO=$'\033[36m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'

else

  C_OK=""; C_WARN=""; C_ERR=""; C_INFO=""; C_DIM=""; C_RST=""

fi

log()   { printf "%b[install]%b %s\n" "$C_INFO" "$C_RST" "$*"; }

ok()    { printf "%b[ ok  ]%b %s\n" "$C_OK"   "$C_RST" "$*"; }

warn()  { printf "%b[warn ]%b %s\n" "$C_WARN" "$C_RST" "$*"; }

err()   { printf "%b[err  ]%b %s\n" "$C_ERR"  "$C_RST" "$*"; }

dim()   { printf "%b[info ]%b %s\n" "$C_DIM"  "$C_RST" "$*"; }


# ───────────────────────────── flags ─────────────────────────────

MODE="all"

for arg in "$@"; do

  case "$arg" in

    --check)   MODE="check" ;;

    --go-only) MODE="go" ;;

    --py-only) MODE="py" ;;

    -h|--help)

      sed -n '2,12p' "$0"; exit 0 ;;

    *) err "unknown flag: $arg"; exit 1 ;;

  esac

done


# ───────────────────────────── OS detection ─────────────────────────

log "Detecting OS…"

. /etc/os-release 2>/dev/null && DIST=$ID || DIST=""

[[ -z "${DIST:-}" && "$(uname -s)" == "Darwin" ]] && DIST="macos"

case "$DIST" in

  ubuntu|debian|pop|linuxmint|kali|parrot) PM="apt" ;;

  fedora|centos|rhel|rocky|alma)          PM="dnf" ;;

  arch|manjaro)                            PM="pacman" ;;

  macos)                                   PM="brew" ;;

  *) warn "unknown distro '$DIST'; assuming apt"; PM="apt" ;;

esac

ok "package manager: $PM"


# ───────────────────────────── Go check/install ────────────────────

need_go() { ! command -v go >/dev/null 2>&1; }

install_go() {

  if need_go; then

    log "Installing Go (1.22+)…"

    case "$PM" in

      apt)    sudo apt-get update -y && sudo apt-get install -y golang-go ;;

      dnf)    sudo dnf install -y golang ;;

      pacman) sudo pacman -Sy --noconfirm go ;;

      brew)   brew install go ;;

      *) err "please install Go 1.22+ manually: https://go.dev/dl/"; exit 1 ;;

    esac

  fi

  if need_go; then err "Go install failed"; exit 1; fi

  ok "go: $(go version | awk '{print $3}')"

}


# ───────────────────────────── check helper ────────────────────────

check() {

  local missing=()

  for t in "$@"; do

    if ! command -v "$t" >/dev/null 2>&1; then

      missing+=("$t")

      printf "  %b✗%b %s\n" "$C_ERR" "$C_RST" "$t"

    else

      printf "  %b✓%b %s\n" "$C_OK" "$C_RST" "$t"

    fi

  done

  if [[ ${#missing[@]} -eq 0 ]]; then

    ok "all tools present"

  else

    warn "missing: ${missing[*]}"

    return 1

  fi

}


ALL_TOOLS=(subfinder amass dnsx naabu nmap httpx nuclei

           gau gospider katana subjs secretfinder

           arjun ffuf feroxbuster testssl.sh

           wpscan dalfox sqlmap interactsh-client

           kxss dnsgen gitleaks httprobe trufflehog unfurl qsreplace

           Gxss cdncheck puredns gowitness wafw00f inql cloud_enum gitdumper)




if [[ "$MODE" == "check" ]]; then

  log "Tool check:"

  check "${ALL_TOOLS[@]}"; exit $?

fi


# ───────────────────────────── system packages ─────────────────────

install_system() {

  log "Installing system packages via $PM…"

  case "$PM" in

    apt)

      sudo apt-get update -y

      sudo apt-get install -y nmap python3 python3-pip git curl wget \

        ruby ruby-dev build-essential libcurl4-openssl-dev libssl-dev \

        jq seclists cargo proxychains4 \
        libatk-1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxdamage1 \
        libxkbcommon0 libpango-1.0-0 libcairo2 libasound2 \
        2>/dev/null || warn "some apt packages failed (non-fatal)"

      ;;

    dnf)

      sudo dnf install -y nmap python3 python3-pip git curl wget \

        ruby ruby-devel gcc make openssl-devel jq cargo proxychains4

      ;;

    pacman)

      sudo pacman -Sy --noconfirm nmap python python-pip git curl wget \

        ruby jq base-devel rust proxychains-ng

      ;;

    brew)

      brew install nmap python git curl wget ruby jq go rust proxychains-ng

      ;;

  esac

  ok "system packages installed"

}


# ───────────────────────────── Go tool installer ───────────────────

GO_TOOLS=(

  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"

  "github.com/owasp-amass/amass/v4/...@master"

  "github.com/projectdiscovery/dnsx/cmd/dnsx"

  "github.com/projectdiscovery/naabu/v2/cmd/naabu"

  "github.com/projectdiscovery/httpx/cmd/httpx"

  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"

  "github.com/lc/gau/v2/cmd/gau"

  "github.com/jaeles-project/gospider"

  "github.com/projectdiscovery/katana/v2/cmd/katana"

  "github.com/lc/subjs"

  "github.com/ffuf/ffuf/v2"

  "github.com/hahwul/dalfox/v2"

  "github.com/projectdiscovery/interactsh/cmd/interactsh-client"

  "github.com/tomnomnom/hacks/kxss"

  "github.com/zricethezav/gitleaks/v8"

  "github.com/tomnomnom/httprobe"

  "github.com/trufflesecurity/trufflehog/v3"

  "github.com/tomnomnom/unfurl"

  "github.com/tomnomnom/qsreplace"

  "github.com/KathanP19/Gxss"

  "github.com/projectdiscovery/cdncheck/cmd/cdncheck"

  "github.com/d3mondev/puredns/v2"

  "github.com/sensepost/gowitness"

)


install_go_tools() {

  install_go

  export GOPATH="${GOPATH:-$HOME/go}"

  export PATH="$GOPATH/bin:$PATH"

  mkdir -p "$GOPATH/bin"

  log "Installing ${#GO_TOOLS[@]} Go tools (this can take a while)…"

  local i=0

  for repo in "${GO_TOOLS[@]}"; do

    i=$((i+1))

    printf "  [%d/%d] %s …\n" "$i" "${#GO_TOOLS[@]}" "$repo"

    # amass ships a cmd/amass binary under v4 — install that specific path

    # so we don't drag in unrelated sub-packages.

    if [[ "$repo" == "github.com/owasp-amass/amass/v4/...@master" ]]; then

      GO111MODULE=on go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest 2>/dev/null || \

        warn "amass install had warnings (may already be present)"

    else

      GO111MODULE=on go install -v "$repo@latest" 2>/dev/null || \

        warn "$repo install had warnings (may already be present)"

    fi

  done

  ok "go tools installed to $GOPATH/bin"

  dim "add to PATH if not already: export PATH=\$PATH:\$HOME/go/bin"

}


# ───────────────────────────── Python tools ────────────────────────

install_python_tools() {

  log "Installing Python-based tools…"


  # sqlmap

  if ! command -v sqlmap >/dev/null 2>&1; then

    if [[ -d /opt/sqlmap ]]; then

      sudo ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

    else

      sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

      sudo ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

    fi

    ok "sqlmap"

  fi


  # pipx-style installs

  pip3 install --user --upgrade pip 2>/dev/null || true

  # NOTE: secretfinder (m4ll0k/SecretFinder) is installed via git below,
  # not from pip. The pip package `secretfinder` is a different tool.
  for pkg in arjun; do
    if ! python3 -c "import ${pkg}" 2>/dev/null && \
       ! command -v "${pkg}" >/dev/null 2>&1; then
      pip3 install --user "$pkg" 2>/dev/null || \
        pip3 install --user --break-system-packages "$pkg" 2>/dev/null || \
        warn "$pkg pip install failed"
    fi
    command -v "$pkg" >/dev/null 2>&1 && ok "$pkg" || dim "$pkg not installed"
  done


  # dnsgen — subdomain permutation (Python)
  if ! command -v dnsgen >/dev/null 2>&1; then
    pip3 install --user dnsgen 2>/dev/null || warn "dnsgen pip install failed"
  fi
  ok "dnsgen"

  # secretfinder (git) — originally installed by m4ll0k/SecretFinder
  if ! command -v secretfinder >/dev/null 2>&1; then
    if [[ ! -d /opt/SecretFinder ]]; then
      sudo git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder 2>/dev/null || true
    fi
    if [[ -f /opt/SecretFinder/SecretFinder.py ]]; then
      sudo ln -sf /opt/SecretFinder/SecretFinder.py /usr/local/bin/secretfinder 2>/dev/null || true
      # also install its requirements
      pip3 install -r /opt/SecretFinder/requirements.txt 2>/dev/null || \
        pip3 install --break-system-packages -r /opt/SecretFinder/requirements.txt 2>/dev/null || true
      ok "secretfinder"
    else
      warn "secretfinder install failed"
    fi
  fi

  # wafw00f — WAF detection
  if ! python3 -c "import wafw00f" 2>/dev/null && ! command -v wafw00f >/dev/null 2>&1; then
    pip3 install --user wafw00f 2>/dev/null || pip3 install --user --break-system-packages wafw00f 2>/dev/null || warn "wafw00f install failed"
  fi
  command -v wafw00f >/dev/null 2>&1 && ok "wafw00f" || dim "wafw00f not installed (will use Python fallback)"

  # inql — GraphQL introspection
  if ! command -v inql >/dev/null 2>&1; then
    pip3 install --user inql 2>/dev/null || pip3 install --user --break-system-packages inql 2>/dev/null || warn "inql install failed"
  fi
  command -v inql >/dev/null 2>&1 && ok "inql" || dim "inql not installed (will use Python fallback)"

  # cloud_enum — multi-cloud bucket enumeration
  if ! command -v cloud_enum >/dev/null 2>&1; then
    pip3 install --user cloud_enum 2>/dev/null || pip3 install --user --break-system-packages cloud_enum 2>/dev/null || warn "cloud_enum install failed"
  fi
  command -v cloud_enum >/dev/null 2>&1 && ok "cloud_enum" || dim "cloud_enum not installed (will use Python fallback)"

  # gitdumper — .git repo downloader
  if ! command -v gitdumper >/dev/null 2>&1; then
    if [[ ! -d /opt/gitdumper ]]; then
      sudo git clone --depth 1 https://github.com/arthaud/git-dumper.git /opt/gitdumper 2>/dev/null || true
    fi
    cat <<'GITEOF' | sudo tee /usr/local/bin/gitdumper >/dev/null
#!/usr/bin/env bash
exec python3 /opt/gitdumper/git_dumper.py "$@"
GITEOF
    sudo chmod +x /usr/local/bin/gitdumper
  fi
  command -v gitdumper >/dev/null 2>&1 && ok "gitdumper" || dim "gitdumper not installed"

}


# ───────────────────────────── wpscan (Ruby) ───────────────────────

install_wpscan() {

  if ! command -v wpscan >/dev/null 2>&1; then

    log "Installing wpscan (Ruby gem)…"

    case "$PM" in

      apt)    sudo apt-get install -y ruby-dev libcurl4-openssl-dev ;;

      dnf)    sudo dnf install -y ruby-devel libcurl-devel ;;

      pacman) sudo pacman -Sy --noconfirm ruby base-devel ;;

      brew)   brew install ruby ;;

    esac

    gem install wpscan --no-document || warn "wpscan install failed"

    ok "wpscan"

  fi

}


# ───────────────────────────── feroxbuster (Rust) ─────────────────

install_feroxbuster() {

  if ! command -v feroxbuster >/dev/null 2>&1; then

    log "Installing feroxbuster (Rust crate)…"

    if ! command -v cargo >/dev/null 2>&1; then

      warn "cargo not found; install Rust/cargo, then run: cargo install feroxbuster"

      return

    fi

    cargo install feroxbuster || warn "feroxbuster install failed"

  fi

  if command -v feroxbuster >/dev/null 2>&1; then

    ok "feroxbuster"

  fi

}


# ───────────────────────────── testssl.sh ──────────────────────────

install_testssl() {

  if ! command -v testssl.sh >/dev/null 2>&1 && ! command -v testssl >/dev/null 2>&1; then

    log "Installing testssl.sh…"

    sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh

    sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

    ok "testssl.sh"

  fi

}


# ───────────────────────────── nuclei templates ────────────────────

update_nuclei_templates() {

  if command -v nuclei >/dev/null 2>&1; then
    if [[ -n "${NO_NUCLEI_UPDATE:-}" ]]; then
      log "NO_NUCLEI_UPDATE set, skipping nuclei template update"
    else
      log "Updating nuclei templates…"
      timeout 120 nuclei -update-templates -silent || warn "nuclei template update failed or timed out"
      ok "nuclei templates updated"
    fi
  fi

}


# ───────────────────────────── run ─────────────────────────────────

case "$MODE" in

  all)

    install_system

    install_go_tools

    install_python_tools

    install_feroxbuster

    install_wpscan

    install_testssl

    update_nuclei_templates

    ;;

  go)  install_go_tools ;;

  py)  install_python_tools; install_wpscan; install_testssl ;;

esac


# ───────────────────────────── post-check ─────────────────────────

log "Final tool check:"

# Add ~/.local/bin to PATH so pip --user installs are found (P2-5)
export PATH="$HOME/.local/bin:$PATH"

check "${ALL_TOOLS[@]}"


# ───────────────────────────── PATH hint ───────────────────────────

GOPATH_BIN="${GOPATH:-$HOME/go/bin}"

if [[ ":$PATH:" != *":$GOPATH_BIN:"* ]]; then

  warn "add Go bin to your PATH (current shell):"

  echo "    export PATH=\$PATH:$GOPATH_BIN"

  SHELL_RC="$HOME/.$(basename "${SHELL:-/bin/bash}")rc"

  [[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"

  [[ -f "$HOME/.bashrc" ]] && SHELL_RC="$HOME/.bashrc"

  if [[ -w "$SHELL_RC" ]] && ! grep -q "GOPATH/bin" "$SHELL_RC" 2>/dev/null; then

    echo "" >> "$SHELL_RC"

    echo "# reconchain Go tools" >> "$SHELL_RC"

    echo "export PATH=\$PATH:$GOPATH_BIN" >> "$SHELL_RC"

    dim "PATH appended to $SHELL_RC — restart shell or: source $SHELL_RC"

  fi

fi


# Ensure `python` points to `python3` (some tools use #!/usr/bin/env python)
if ! command -v python >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN_DIR="$(dirname "$(command -v python3)")"
  if [[ -w "$PYTHON_BIN_DIR" ]]; then
    ln -sf python3 "$PYTHON_BIN_DIR/python"
    ok "created $PYTHON_BIN_DIR/python -> python3"
  elif [[ -w "$HOME/.local/bin" ]]; then
    ln -sf "$(command -v python3)" "$HOME/.local/bin/python"
    ok "created ~/.local/bin/python -> python3"
  else
    warn "python not found — create symlink: sudo ln -sf \$(which python3) /usr/local/bin/python"
  fi
fi

ok "install complete. run: python3 reconchain.py -d example.com -o ./out"
