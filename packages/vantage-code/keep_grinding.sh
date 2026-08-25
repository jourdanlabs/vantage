#!/bin/bash
# Keep the VANTAGE CODE grind alive overnight. Restarts on halt/crash.
# Does not stamp Pan CLEAR. HOLD only.
set -u
cd /Users/sokpyeon/projects/vantage-recert-2026-08-02/vantage/packages/vantage-code
LOG=/Users/sokpyeon/projects/vantage-recert-2026-08-02/vantage/receipts/dev/vantage-code-overnight-2026-08-23/overnight.log
mkdir -p "$(dirname "$LOG")"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) keep_grinding start pid=$$" >> "$LOG"
STOP=/Users/sokpyeon/projects/vantage-recert-2026-08-02/vantage/receipts/dev/vantage-code-overnight-2026-08-23/STOP
while true; do
  if [ -f "$STOP" ]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) STOP file present — keep_grinding halt" >> "$LOG"
    exit 0
  fi
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) spawn overnight_loop.py" >> "$LOG"
  /usr/bin/python3 overnight_loop.py >> "$LOG" 2>&1
  rc=$?
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) overnight_loop exit=$rc — restart in 20s" >> "$LOG"
  sleep 20
done
