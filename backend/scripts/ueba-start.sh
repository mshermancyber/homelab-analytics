#!/usr/bin/env bash
# Start the UEBA backend in the foreground.
#
# Resolves its own location, so it works from any directory and under systemd.
# Set VENV to use an interpreter other than ../.venv (or none, to use python3).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$BACKEND_DIR")"

VENV="${VENV:-$REPO_DIR/.venv}"
if [ -x "$VENV/bin/python3" ]; then
    PYTHON="$VENV/bin/python3"
else
    PYTHON="$(command -v python3)"
fi

API_HOST="${API_HOST:-0.0.0.0}"
API_PORT="${API_PORT:-28819}"
LOG_LEVEL="${UVICORN_LOG_LEVEL:-warning}"

cd "$BACKEND_DIR"
exec "$PYTHON" -m uvicorn ueba.app:app \
    --host "$API_HOST" --port "$API_PORT" --log-level "$LOG_LEVEL"
