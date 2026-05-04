#!/usr/bin/env bash
# Backward-compatible sel wrapper for the universal permanent xdpflowd rollback.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export STATE_FILE="${STATE_FILE:-/root/xdpflowd_sel_permanent_state.env}"
export BACKUP_TAG="${BACKUP_TAG:-sel-permanent}"

exec "$SCRIPT_DIR/prod_rollback_legacy.sh"
