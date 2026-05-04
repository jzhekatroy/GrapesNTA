#!/usr/bin/env bash
# Backward-compatible sel wrapper for the universal permanent xdpflowd enable.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export STATE_FILE="${STATE_FILE:-/root/xdpflowd_sel_permanent_state.env}"
export ENV_INSTALL="${ENV_INSTALL:-/etc/xdpflowd/sel.env}"
export ENV_TEMPLATE="${ENV_TEMPLATE:-$REPO_ROOT/deploy/sel/xdpflowd.env.example}"
export SERVICE_TEMPLATE="${SERVICE_TEMPLATE:-$REPO_ROOT/deploy/sel/xdpflowd.service}"
export EXEC_WRAPPER="${EXEC_WRAPPER:-$REPO_ROOT/deploy/sel/xdpflowd-exec.sh}"
export BACKUP_TAG="${BACKUP_TAG:-sel-permanent}"

exec "$SCRIPT_DIR/prod_enable_xdpflowd.sh"
