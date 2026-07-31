#!/usr/bin/env bash
set -euo pipefail

# beacon.sh — scan status reporter for VulnForge
#
# Writes a status snapshot to a report file.  By default loops every 2 min;
# pass --once for a single check (replaces the old pulse.sh).
#
# Usage:
#   beacon.sh -d example.com            # loop every 120s
#   beacon.sh -d example.com --once     # one-shot check
#   beacon.sh -d example.com -i 60      # custom interval (seconds)

ONCE=false
INTERVAL=120
DOMAIN=""
OUTDIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --once)    ONCE=true; shift ;;
        -i|--interval) INTERVAL="$2"; shift 2 ;;
        -d|--domain)
            DOMAIN="$2"; shift 2
            [[ -z "$OUTDIR" ]] && OUTDIR="out_${DOMAIN}"
            ;;
        -o|--outdir) OUTDIR="$2"; shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

OUTDIR="${OUTDIR:-out}"
STATUSFILE="$OUTDIR/status_report.txt"
LOGFILE="$OUTDIR/monitor_stdout.log"

mkdir -p "$OUTDIR"

write_report() {
    {
        echo "=== $(date '+%Y-%m-%d %H:%M:%S') ==="
        VF_PID=$(pgrep -f "vulnforge\.py" | head -1) || VF_PID=""
        if [[ -n "$VF_PID" ]] && kill -0 "$VF_PID" 2>/dev/null; then
            echo "Status: RUNNING"
            echo "PID: $VF_PID"
            echo ""
            echo "--- Recent output ---"
            tail -5 "$LOGFILE" 2>/dev/null || true
            if [[ -f "$OUTDIR/summary.txt" ]]; then
                echo ""
                echo "--- Summary ---"
                tail -5 "$OUTDIR/summary.txt"
            fi
            if [[ -f "$OUTDIR/state.json" ]]; then
                echo ""
                echo "--- State ---"
                VF_STATE="$OUTDIR/state.json" python3 -c "
import json, os, sys
s = json.load(open(os.environ['VF_STATE']))
arts = {k: v for k, v in s.get('artifacts', {}).items() if k not in ('count', 'failures') and not isinstance(v, dict)}
fails = s.get('tool_failures', {})
print(f'Artifacts: {len(arts)}  Tool failures: {len(fails)}')
" 2>/dev/null || true
            fi
        else
            echo "Status: NOT RUNNING"
            if [[ -f "$LOGFILE" ]]; then
                echo ""
                echo "--- Last 10 lines ---"
                tail -10 "$LOGFILE"
            fi
        fi
        echo ""
    } > "$STATUSFILE"
}

if [[ "$ONCE" == "true" ]]; then
    write_report
    cat "$STATUSFILE"
else
    echo "Beacon: writing status to $STATUSFILE every ${INTERVAL}s (Ctrl+C to stop)"
    while true; do
        write_report
        sleep "$INTERVAL"
    done
fi
