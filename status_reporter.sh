#!/bin/bash
set -euo pipefail

OUTDIR="${OUTDIR:-/home/ferdi/BugBountyV2tool/out_brandenburg.cloud}"
LOGFILE="$OUTDIR/monitor_stdout.log"
STATUSFILE="$OUTDIR/status_report.txt"

while true; do
    {
    echo "=== $(date '+%Y-%m-%d %H:%M:%S') ==="
    if pgrep -f "python3.*reconchain\.py" > /dev/null 2>&1 || pgrep -f "reconchain\.py" > /dev/null 2>&1; then
        echo "Status: RUNNING"
        echo "Recon PID: $(pgrep -f "reconchain\.py" | head -1 || echo 'unknown')"
        tail -3 "$LOGFILE" 2>/dev/null || true
        echo "---"
        [ -f "$OUTDIR/summary.txt" ] && tail -3 "$OUTDIR/summary.txt" || true
    else
        echo "Status: NOT RUNNING"
        [ -f "$LOGFILE" ] && tail -10 "$LOGFILE" || true
    fi
    echo ""
    } > "$STATUSFILE"
    sleep 120
done
