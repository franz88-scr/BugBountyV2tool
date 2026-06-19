#!/usr/bin/env bash

# install.sh — install every external tool reconchain.py depends on.

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

  fi

}


ALL_TOOLS=(subfinder amass assetfinder dnsx naabu nmap httpx subjack nuclei

           gau waybackurls gospider katana subjs linkfinder secretfinder

           paramspider arjun ffuf feroxbuster testssl.sh

           wpscan dalfox sqlmap interactsh-client kr x8)


if [[ "$MODE" == "check" ]]; then

  log "Tool check:"

  check "${ALL_TOOLS[@]}"

  exit 0

fi


# ───────────────────────────── system packages ─────────────────────

install_system() {

  log "Installing system packages via $PM…"

  case "$PM" in

    apt)

      sudo apt-get update -y

      sudo apt-get install -y nmap python3 python3-pip git curl wget \

        ruby ruby-dev build-essential libcurl4-openssl-dev libssl-dev \

        jq seclists cargo 2>/dev/null || warn "some apt packages failed (non-fatal)"

      ;;

    dnf)

      sudo dnf install -y nmap python3 python3-pip git curl wget \

        ruby ruby-devel gcc make openssl-devel jq cargo

      ;;

    pacman)

      sudo pacman -Sy --noconfirm nmap python python-pip git curl wget \

        ruby jq base-devel rust

      ;;

    brew)

      brew install nmap python git curl wget ruby jq go rust

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

  "github.com/haccer/subjack"

  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"

  "github.com/lc/gau/v2/cmd/gau"

  "github.com/tomnomnom/waybackurls"

  "github.com/jaeles-project/gospider"

  "github.com/projectdiscovery/katana/v2/cmd/katana"

  "github.com/lc/subjs"

  "github.com/ffuf/ffuf/v2"

  "github.com/assetnote/kiterunner/cmd/kiterunner"

  "github.com/hahwul/dalfox/v2"

  "github.com/projectdiscovery/interactsh/cmd/interactsh-client"

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

  for pkg in secretfinder arjun; do

    # previous code used ${pkg%finder} which looked for the `secret` stdlib

    # module and ALWAYS reported secretfinder as installed. Check the actual

    # package import name (and CLI binary as a fallback).

    if ! python3 -c "import ${pkg}" 2>/dev/null && \

       ! command -v "${pkg}" >/dev/null 2>&1; then

      pip3 install --user "$pkg" || warn "$pkg pip install failed"

    fi

    ok "$pkg"

  done


  # paramspider (git)

  if ! command -v paramspider >/dev/null 2>&1; then

    sudo git clone --depth 1 https://github.com/devanshbatham/paramspider /opt/paramspider || true

    sudo ln -sf /opt/paramspider/paramspider.py /usr/local/bin/paramspider 2>/dev/null || true

    cat <<'EOF' | sudo tee /usr/local/bin/paramspider >/dev/null

#!/usr/bin/env bash

exec python3 /opt/paramspider/paramspider.py "$@"

EOF

    sudo chmod +x /usr/local/bin/paramspider

    ok "paramspider"

  fi


  # linkfinder (git)

  if [[ ! -d /opt/LinkFinder ]]; then

    sudo git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder

  fi

  if [[ -f /opt/LinkFinder/linkfinder.py ]]; then

    sudo ln -sf /opt/LinkFinder/linkfinder.py /usr/local/bin/linkfinder

    ok "linkfinder"

  else

    warn "linkfinder install failed"

  fi


  # assetfinder (go binary but listed here for visibility)

  if ! command -v assetfinder >/dev/null 2>&1; then

    GO111MODULE=on go install -v github.com/tomnomnom/assetfinder@latest

    ok "assetfinder"

  fi

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


# ───────────────────────────── x8 (Rust) ──────────────────────────
install_x8() {
  if ! command -v x8 >/dev/null 2>&1; then
    log "Installing x8 (Rust crate)…"
    if ! command -v cargo >/dev/null 2>&1; then
      warn "cargo not found; install Rust/cargo, then run: cargo install x8"
      return
    fi
    cargo install x8 || warn "x8 install failed (try: cargo install x8 --locked)"
  fi
  if command -v x8 >/dev/null 2>&1; then
    ok "x8"
  fi
}

# ───────────────────────────── kiterunner kite wordlist ────────────
install_kr_wordlist() {
  if command -v kr >/dev/null 2>&1; then
    local kite="/tmp/common.kite"
    if [[ ! -f "$kite" ]] && [[ -f /usr/share/seclists/Discovery/Web-Content/common.txt ]]; then
      log "Generating kiterunner kite wordlist…"
      kr kb convert /usr/share/seclists/Discovery/Web-Content/common.txt "$kite" 2>/dev/null && \
        ok "kiterunner wordlist: $kite" || warn "failed to generate kite wordlist"
    fi
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

    log "Updating nuclei templates…"

    nuclei -update-templates -silent || warn "nuclei template update failed"

    ok "nuclei templates updated"

  fi

}


# ───────────────────────────── run ─────────────────────────────────

case "$MODE" in

  all)

    install_system

    install_go_tools

    install_python_tools

    install_feroxbuster

    install_x8

    install_wpscan

    install_testssl

    install_kr_wordlist

    update_nuclei_templates

    ;;

  go)  install_go_tools ;;

  py)  install_python_tools; install_wpscan; install_testssl ;;

esac


# ───────────────────────────── post-check ─────────────────────────

log "Final tool check:"

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


ok "install complete. run: python3 reconchain.py -d example.com -o ./out"
