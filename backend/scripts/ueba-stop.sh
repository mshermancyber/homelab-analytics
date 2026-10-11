#!/usr/bin/env bash
# Stop the UEBA backend started by ueba-start.sh.
set -uo pipefail

API_PORT="${API_PORT:-28819}"
PID="$(pgrep -f "ueba.app:app.*${API_PORT}" || true)"

if [ -z "$PID" ]; then
    echo "UEBA not running"
    exit 0
fi

kill "$PID"
echo "Sent SIGTERM to PID $PID"
for _ in $(seq 1 10); do
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "UEBA stopped"
        exit 0
    fi
    sleep 1
done

echo "Force killing PID $PID"
kill -9 "$PID"
