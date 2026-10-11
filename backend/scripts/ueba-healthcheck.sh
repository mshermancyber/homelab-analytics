#!/usr/bin/env bash
# Health check — detects stalled ingestion and restarts the service.
#
# Both Pi-hole and firewall ingestion must be stale to trigger a restart;
# single-source stalls are handled by the in-process syslog watchdog.
#
# Usage:
#   ./ueba-healthcheck.sh          # check, restart if needed
#   ./ueba-healthcheck.sh --dry    # check only
#
# As a cron entry (every 5 minutes):
#   */5 * * * * /path/to/backend/scripts/ueba-healthcheck.sh >> /tmp/ueba-healthcheck.log 2>&1
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$BACKEND_DIR")"

DB="${UEBA_DB_PATH:-$BACKEND_DIR/data/ueba.db}"
SERVICE="${UEBA_SERVICE:-ueba}"
STALE_MINUTES="${STALE_MINUTES:-10}"
DRY_RUN="${1:-}"

VENV="${VENV:-$REPO_DIR/.venv}"
if [ -x "$VENV/bin/python3" ]; then
    PYTHON="$VENV/bin/python3"
else
    PYTHON="$(command -v python3)"
fi

if ! systemctl --user is-active "$SERVICE" >/dev/null 2>&1; then
    echo "$(date -Iseconds) WARN: $SERVICE not running, starting it"
    if [ "$DRY_RUN" != "--dry" ]; then
        systemctl --user start "$SERVICE"
    fi
    exit 0
fi

if [ ! -f "$DB" ]; then
    echo "$(date -Iseconds) ERROR: database not found at $DB"
    exit 1
fi

read -r pihole_age opnsense_age < <(UEBA_HC_DB="$DB" "$PYTHON" -c "
import os, sqlite3
conn = sqlite3.connect(os.environ['UEBA_HC_DB'])
cur = conn.cursor()
ages = []
for table in ('pihole_queries', 'opnsense_logs'):
    cur.execute(
        \"SELECT CAST((julianday('now') - julianday(MAX(timestamp))) * 1440 AS INTEGER) \"
        f'FROM {table}'
    )
    row = cur.fetchone()
    ages.append(row[0] if row and row[0] is not None else 9999)
conn.close()
print(ages[0], ages[1])
")

echo "$(date -Iseconds) pihole_age=${pihole_age}m firewall_age=${opnsense_age}m threshold=${STALE_MINUTES}m"

if [ "$pihole_age" -gt "$STALE_MINUTES" ] && [ "$opnsense_age" -gt "$STALE_MINUTES" ]; then
    echo "$(date -Iseconds) ALERT: both sources stale, restarting $SERVICE"
    if [ "$DRY_RUN" = "--dry" ]; then
        echo "$(date -Iseconds) DRY RUN: would restart $SERVICE"
    else
        systemctl --user restart "$SERVICE"
        sleep 5
        if systemctl --user is-active "$SERVICE" >/dev/null 2>&1; then
            echo "$(date -Iseconds) OK: $SERVICE restarted successfully"
        else
            echo "$(date -Iseconds) ERROR: $SERVICE failed to restart"
            exit 1
        fi
    fi
elif [ "$pihole_age" -gt "$STALE_MINUTES" ]; then
    echo "$(date -Iseconds) WARN: Pi-hole stale but firewall flowing — not restarting"
elif [ "$opnsense_age" -gt "$STALE_MINUTES" ]; then
    echo "$(date -Iseconds) WARN: firewall stale but Pi-hole flowing — syslog watchdog should handle it"
else
    echo "$(date -Iseconds) OK: both sources flowing"
fi
