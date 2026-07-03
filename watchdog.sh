#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${1:-brandenburg.cloud}"
WORKDIR="${2:-/home/ferdi/BugBountyV2tool}"
EXTRA="${3:---sample-urls-fuzz 10 --sample-urls-params 10}"
OUTDIR="$WORKDIR/out_${DOMAIN}"
LOGFILE="$OUTDIR/watchdog.log"
TIMEOUT=14400

mkdir -p "$OUTDIR"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOGFILE"; }

max_restarts=20
restart_count=0

log "Starting scan loop for $DOMAIN (max ${max_restarts} restarts, ${TIMEOUT}s timeout)"
log "Extra args: $EXTRA"

while [[ "$restart_count" -lt "$max_restarts" ]]; do
    restart_count=$((restart_count + 1))

    cd "$WORKDIR"
    if [[ -f "$OUTDIR/state.json" ]]; then
        log "Attempt $restart_count — resuming from state.json"
        timeout "$TIMEOUT" python3 reconchain.py -d "$DOMAIN" -o "$OUTDIR" --resume $EXTRA 2>&1 || true
    else
        log "Attempt $restart_count — fresh start"
        timeout "$TIMEOUT" python3 reconchain.py -d "$DOMAIN" -o "$OUTDIR" --force $EXTRA 2>&1 || true
    fi

    rc=$?
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
