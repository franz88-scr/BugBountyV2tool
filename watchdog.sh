#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain> <workdir> [extra args...]}"
WORKDIR="${2:?Usage: $0 <domain> <workdir> [extra args...]}"
EXTRA=("${@:3}")
EXTRA+=("--sample-urls-fuzz" "10" "--sample-urls-params" "10")

if [[ -z "$DOMAIN" || "$DOMAIN" == *".."* || "$DOMAIN" == *"/"* || "$DOMAIN" == *"\\"* ]]; then
    echo "ERROR: invalid domain '$DOMAIN'" >&2
    exit 1
fi
if [[ -z "$WORKDIR" || ! -d "$WORKDIR" ]]; then
    WORKDIR="$(cd "$(dirname "$0")" && pwd)"
fi
if [[ "$WORKDIR" == *".."* ]]; then
    echo "ERROR: invalid workdir '$WORKDIR'" >&2
    exit 1
fi

OUTDIR="$WORKDIR/out_${DOMAIN}"
LOGFILE="$OUTDIR/watchdog.log"
TIMEOUT=14400

mkdir -p "$OUTDIR"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOGFILE"; }

# ── pre-flight checks ─────────────────────────────────────────────
# Unset stray proxy env vars that would force all traffic through Tor
# when no Tor service is running (common footgun).
if [[ -z "${PROXY:-}" && -z "${ALL_PROXY:-}" ]]; then
  for _var in ALL_PROXY all_proxy HTTPS_PROXY https_proxy HTTP_PROXY http_proxy PROXY; do
    unset "$_var" 2>/dev/null || true
  done
fi

# Warn if proxychains is configured but Tor is not responding
if command -v proxychains4 &>/dev/null && ! timeout 2 bash -c '</dev/tcp/127.0.0.1/9050' 2>/dev/null; then
  log "WARN: proxychains4 is installed but Tor (127.0.0.1:9050) is not reachable."
  log "WARN: Tools that use bash runners may hang. Unset PROXY/ALL_PROXY or start Tor."
fi

# Ensure nuclei templates are up to date
if command -v nuclei &>/dev/null; then
  nuclei -update-templates -silent 2>/dev/null && log "nuclei templates updated" || log "WARN: nuclei template update failed"
fi

max_restarts=20
restart_count=0

log "Starting scan loop for $DOMAIN (max ${max_restarts} restarts, ${TIMEOUT}s timeout)"
log "Extra args: ${EXTRA[*]}"

CHILD_PID=""
cleanup_child() {
    if [[ -n "$CHILD_PID" ]] && kill -0 "$CHILD_PID" 2>/dev/null; then
        log "Killing child process tree (PID $CHILD_PID)"
        kill -- -"$CHILD_PID" 2>/dev/null || kill "$CHILD_PID" 2>/dev/null || true
        wait "$CHILD_PID" 2>/dev/null || true
    fi
}
trap cleanup_child EXIT

while [[ "$restart_count" -lt "$max_restarts" ]]; do
    restart_count=$((restart_count + 1))

    cd "$WORKDIR"
    cleanup_child
    if [[ -f "$OUTDIR/state.json" ]]; then
        log "Attempt $restart_count — resuming from state.json"
        rc=0
        setsid timeout "$TIMEOUT" python3 reconchain.py -d "$DOMAIN" -o "$OUTDIR" --resume "${EXTRA[@]}" 2>&1 &
        CHILD_PID=$!
        wait "$CHILD_PID" 2>/dev/null || rc=$?
        CHILD_PID=""
    else
        log "Attempt $restart_count — fresh start"
        rc=0
        setsid timeout "$TIMEOUT" python3 reconchain.py -d "$DOMAIN" -o "$OUTDIR" --force "${EXTRA[@]}" 2>&1 &
        CHILD_PID=$!
        wait "$CHILD_PID" 2>/dev/null || rc=$?
        CHILD_PID=""
    fi

    log "Attempt $restart_count exited with rc=$rc"

    if [[ -f "$OUTDIR/state.json" ]]; then
        log "State.json exists — scan incomplete, restarting in 5s"
        sleep 5
    else
        if [[ $rc -eq 124 ]]; then
            log "TIMED OUT after ${TIMEOUT}s — will restart"
            sleep 5
        else
            log "No state.json — scan appears complete (or fully crashed), stopping"
            break
        fi
    fi
done

if [[ "$restart_count" -ge "$max_restarts" ]]; then
    log "Reached max restarts ($max_restarts) — giving up"
fi

log "Scan loop ended"
