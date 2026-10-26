#!/usr/bin/env bash

set -u

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="$PROJECT_DIR/.venv/bin/python"
CONFIG="${THREATLENS_CONFIG_PATH:-$PROJECT_DIR/config/agent.example.yaml}"

BACKEND_URL="${THREATLENS_BACKEND_URL:-http://127.0.0.1:5000}"
API_KEY="${THREATLENS_API_KEY:-}"

if [ -z "$API_KEY" ]; then
    echo "ERROR: Set THREATLENS_API_KEY before starting the agent." >&2
    exit 1
fi

cd "$PROJECT_DIR"

SSH_SOCKET=""
cleanup() {
    if [ -n "$SSH_SOCKET" ] && [ -e "$SSH_SOCKET" ]; then
        ssh -o BatchMode=yes -S "$SSH_SOCKET" -O exit localhost 2>/dev/null || true
        rm -f "$SSH_SOCKET"
    fi
}
trap cleanup EXIT INT TERM

# If user belongs to systemd-journal in /etc/group but current process session lacks it,
# establish a single persistent ControlMaster multiplexed session so NO new SSH logins
# are generated on each loop iteration.
RUN_CMD=()
if ! id -Gn | grep -qw "systemd-journal"; then
    if grep -qw "systemd-journal" /etc/group 2>/dev/null && ssh -o BatchMode=yes -o StrictHostKeyChecking=no localhost "true" 2>/dev/null; then
        SSH_SOCKET="/tmp/threatlens-ssh-control-$$.sock"
        rm -f "$SSH_SOCKET"
        ssh -o BatchMode=yes -o StrictHostKeyChecking=no -M -S "$SSH_SOCKET" -f -N localhost
        RUN_CMD=(ssh -o BatchMode=yes -S "$SSH_SOCKET" localhost)
    fi
fi

run_agent() {
    local subcmd="$1"
    shift
    if [ ${#RUN_CMD[@]} -gt 0 ]; then
        "${RUN_CMD[@]}" "cd '$PROJECT_DIR' && env THREATLENS_BACKEND_URL='$BACKEND_URL' THREATLENS_API_KEY='$API_KEY' '$PYTHON' -m threatlens_agent -c '$CONFIG' $subcmd $*"
    else
        (cd "$PROJECT_DIR" && env THREATLENS_BACKEND_URL="$BACKEND_URL" THREATLENS_API_KEY="$API_KEY" "$PYTHON" -m threatlens_agent -c "$CONFIG" "$subcmd" "$@")
    fi
}

while true; do
    echo "===== $(date '+%F %T') | Collecting events ====="

    if run_agent collect; then
        echo "===== $(date '+%F %T') | Forwarding events ====="
        run_agent flush --limit 50
    else
        echo "Collection failed; retrying after delay."
    fi

    sleep 10
done
