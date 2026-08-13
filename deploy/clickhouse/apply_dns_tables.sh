#!/usr/bin/env bash
# Apply DNS tables from the canonical schema (layer 20_dns).
#
# Usage:
#   ./deploy/clickhouse/apply_dns_tables.sh
#   CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASS='...' ./deploy/clickhouse/apply_dns_tables.sh
#
# Accepts CH_PASSWORD as an alias for CH_PASS.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export CH_PASS="${CH_PASS:-${CH_PASSWORD:-}}"
exec "$ROOT/deploy/schema/apply.sh" 20_dns
