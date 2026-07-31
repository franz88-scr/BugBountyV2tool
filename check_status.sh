#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="${OUTDIR:-$SCRIPT_DIR/out}"
STATUSFILE="$OUTDIR/status_report.txt"

mkdir -p "$OUTDIR"

{
echo "=== $(date '+%Y-%m-%d %H:%M:%S') ==="
if pgrep -f "python3.*vulnforge\.py" > /dev/null 2>&1 || pgrep -f "vulnforge\.py" > /dev/null 2>&1; then
    echo "Status: RUNNING"
    echo "Monitor PID: $(pgrep -f "vulnforge\.py" | head -1 || echo 'unknown')"
else
    echo "Status: NOT RUNNING"
fi
echo ""
} > "$STATUSFILE"
