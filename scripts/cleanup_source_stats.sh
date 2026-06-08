#!/usr/bin/env bash
# Cleanup flow/DNS rows and rollup statistics for selected source_id(s).
#
# Examples:
#   # Show available sources
#   CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' \
#     ./scripts/cleanup_source_stats.sh --list-sources
#
#   # Dry run: cleanup one source for the last 30 minutes
#   CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' \
#     ./scripts/cleanup_source_stats.sh --source-id sflow-default --last 30m
#
#   # Execute: cleanup one source for explicit period
#   CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' \
#     ./scripts/cleanup_source_stats.sh --source-id sflow-default \
#       --from '2026-06-05 15:42:00' --to '2026-06-05 15:57:00' \
#       --execute
#
#   # Execute: cleanup all sources linked to collector_id
#   CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' \
#     ./scripts/cleanup_source_stats.sh --collector-id sflowd-moyka --last 1h --execute

set -euo pipefail

CH_HOST="${CH_HOST:-127.0.0.1}"
CH_PORT="${CH_PORT:-9000}"
CH_USER="${CH_USER:-default}"
CH_PASSWORD="${CH_PASSWORD:-}"
CH_DATABASE="${CH_DATABASE:-default}"
TARGET_DB="${TARGET_DB:-default}"

SOURCE_ID=""
COLLECTOR_ID=""
FROM_TS=""
TO_TS=""
LAST=""
EXECUTE=0
YES=0
LIST_SOURCES=0

usage() {
  cat <<'USAGE'
Cleanup flow/DNS rows and rollup statistics for selected source_id(s).

Examples:
  # Show available sources
  CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' \
    ./scripts/cleanup_source_stats.sh --list-sources

  # Dry run: cleanup one source for the last 30 minutes
  CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' \
    ./scripts/cleanup_source_stats.sh --source-id sflow-default --last 30m

  # Execute: cleanup one source for explicit period
  CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' \
    ./scripts/cleanup_source_stats.sh --source-id sflow-default \
      --from '2026-06-05 15:42:00' --to '2026-06-05 15:57:00' \
      --execute

  # Execute: cleanup all sources linked to collector_id
  CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' \
    ./scripts/cleanup_source_stats.sh --collector-id sflowd-moyka --last 1h --execute

Options:
  --list-sources              Show enabled source catalog and exit.
  --source-id ID              Cleanup a single source_id (example: sflow-default).
  --collector-id ID           Cleanup all source_id values linked to collector_id.
  --last 30m|1h|6h|1d         Cleanup only recent period.
  --from 'YYYY-MM-DD HH:MM:SS'
  --to   'YYYY-MM-DD HH:MM:SS'
  --execute                   Actually run ALTER TABLE ... DELETE. Without this it is dry-run.
  --yes                       Do not ask confirmation when --execute is used.
  -h, --help                  Show help.

Environment:
  CH_HOST, CH_PORT, CH_USER, CH_PASSWORD, CH_DATABASE, TARGET_DB

Important:
  Stop the collector and clear its local spool before deleting:
    sudo systemctl stop flowcollectord
    sudo rm -rf /var/lib/flowcollectord/ch-spool/*
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list-sources)
      LIST_SOURCES=1
      shift
      ;;
    --source-id)
      SOURCE_ID="${2:-}"
      shift 2
      ;;
    --collector-id)
      COLLECTOR_ID="${2:-}"
      shift 2
      ;;
    --from)
      FROM_TS="${2:-}"
      shift 2
      ;;
    --to)
      TO_TS="${2:-}"
      shift 2
      ;;
    --last)
      LAST="${2:-}"
      shift 2
      ;;
    --execute)
      EXECUTE=1
      shift
      ;;
    --yes)
      YES=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

ch_args=(
  --host "$CH_HOST"
  --port "$CH_PORT"
  --user "$CH_USER"
  --database "$CH_DATABASE"
)
if [[ -n "$CH_PASSWORD" ]]; then
  ch_args+=(--password "$CH_PASSWORD")
fi

ch_query() {
  clickhouse-client "${ch_args[@]}" --query "$1"
}

sql_quote() {
  local s="$1"
  s="${s//\'/\'\'}"
  printf "'%s'" "$s"
}

source_list_sql() {
  cat <<SQL
SELECT
    source_id,
    display_name,
    source_type,
    collector_id,
    location,
    include_in_total
FROM ${TARGET_DB}.net_flow_sources_enabled
ORDER BY collector_id, source_id
FORMAT PrettyCompact
SQL
}

if [[ "$LIST_SOURCES" -eq 1 ]]; then
  ch_query "$(source_list_sql)"
  exit 0
fi

if [[ -n "$SOURCE_ID" && -n "$COLLECTOR_ID" ]]; then
  echo "Use either --source-id or --collector-id, not both." >&2
  exit 2
fi

if [[ -z "$SOURCE_ID" && -z "$COLLECTOR_ID" ]]; then
  echo "No source selected." >&2
  echo
  echo "Enabled sources:"
  ch_query "$(source_list_sql)"
  echo
  read -r -p "Enter source_id or collector_id to cleanup: " selected
  if [[ -z "$selected" ]]; then
    echo "Nothing selected." >&2
    exit 2
  fi
  # Prefer exact source_id. If it is absent, treat input as collector_id.
  exists="$(ch_query "SELECT count() FROM ${TARGET_DB}.net_flow_sources_enabled WHERE source_id = $(sql_quote "$selected") FORMAT TabSeparated")"
  if [[ "$exists" == "1" ]]; then
    SOURCE_ID="$selected"
  else
    COLLECTOR_ID="$selected"
  fi
fi

if [[ -n "$LAST" && ( -n "$FROM_TS" || -n "$TO_TS" ) ]]; then
  echo "Use either --last or --from/--to, not both." >&2
  exit 2
fi

if [[ -z "$LAST" ]]; then
  if [[ -z "$FROM_TS" || -z "$TO_TS" ]]; then
    echo "Period is required: use --last 30m or --from ... --to ..." >&2
    exit 2
  fi
fi

last_to_interval() {
  local v="$1"
  if [[ "$v" =~ ^([0-9]+)[mM]$ ]]; then
    echo "${BASH_REMATCH[1]} MINUTE"
  elif [[ "$v" =~ ^([0-9]+)[hH]$ ]]; then
    echo "${BASH_REMATCH[1]} HOUR"
  elif [[ "$v" =~ ^([0-9]+)[dD]$ ]]; then
    echo "${BASH_REMATCH[1]} DAY"
  else
    echo "Invalid --last value: $v (expected 30m, 1h, 6h, 1d)" >&2
    exit 2
  fi
}

sources=()
if [[ -n "$SOURCE_ID" ]]; then
  sources+=("$SOURCE_ID")
else
  while IFS= read -r sid; do
    [[ -n "$sid" ]] && sources+=("$sid")
  done < <(ch_query "SELECT source_id FROM ${TARGET_DB}.net_flow_sources_enabled WHERE collector_id = $(sql_quote "$COLLECTOR_ID") FORMAT TabSeparated")
fi

if [[ "${#sources[@]}" -eq 0 ]]; then
  echo "No sources found for selector." >&2
  exit 2
fi

source_in_sql=""
for sid in "${sources[@]}"; do
  q="$(sql_quote "$sid")"
  if [[ -z "$source_in_sql" ]]; then
    source_in_sql="$q"
  else
    source_in_sql="${source_in_sql}, ${q}"
  fi
done

time_filter() {
  local col="$1"
  if [[ -n "$LAST" ]]; then
    echo "${col} >= now() - INTERVAL $(last_to_interval "$LAST")"
  else
    echo "${col} >= toDateTime($(sql_quote "$FROM_TS")) AND ${col} < toDateTime($(sql_quote "$TO_TS"))"
  fi
}

table_exists() {
  local table="$1"
  local count
  count="$(ch_query "SELECT count() FROM system.tables WHERE database = $(sql_quote "$TARGET_DB") AND name = $(sql_quote "$table") FORMAT TabSeparated")"
  [[ "$count" == "1" ]]
}

column_exists() {
  local table="$1"
  local col="$2"
  local count
  count="$(ch_query "SELECT count() FROM system.columns WHERE database = $(sql_quote "$TARGET_DB") AND table = $(sql_quote "$table") AND name = $(sql_quote "$col") FORMAT TabSeparated")"
  [[ "$count" == "1" ]]
}

# table|time_column|metric_expression
# metric_expression is only for preview. DELETE always uses source_id + time filter.
tables=(
  "flows_raw|time_received_ns|round(sum(bytes)/1e9, 3) AS gb"
  "traffic_dashboard_1m|minute|round(sum(total_bytes)/1e9, 3) AS gb"
  "traffic_dashboard_1h|hour|round(sum(total_bytes)/1e9, 3) AS gb"
  "traffic_dashboard_1d|day|round(sum(total_bytes)/1e9, 3) AS gb"
  "traffic_direction_1m|minute|round(sum(bytes)/1e9, 3) AS gb"
  "traffic_talker_1m|minute|round(sum(bytes)/1e9, 3) AS gb"
  "traffic_pair_1m|minute|round(sum(bytes)/1e9, 3) AS gb"
  "traffic_talker_1h|hour|round(sum(bytes)/1e9, 3) AS gb"
  "traffic_pair_1h|hour|round(sum(bytes)/1e9, 3) AS gb"
  "traffic_protocol_1m|minute|round(sum(bytes)/1e9, 3) AS gb"
  "traffic_service_1m|minute|round(sum(bytes)/1e9, 3) AS gb"
  "traffic_country_1m|minute|round(sum(bytes)/1e9, 3) AS gb"
  "traffic_role_1m|minute|round(sum(bytes)/1e9, 3) AS gb"
  "traffic_entity_1m|minute|round(sum(bytes)/1e9, 3) AS gb"
  "traffic_vlan_1m|minute|round(sum(bytes)/1e9, 3) AS gb"
  "traffic_unknown_port_1m|minute|round(sum(bytes)/1e9, 3) AS gb"
  "dns_log|ts|round(sum(raw_size)/1e9, 3) AS raw_gb"
  "dns_answers|ts|toUInt64(0) AS raw_gb"
)

echo "Target ClickHouse: ${CH_HOST}:${CH_PORT}/${TARGET_DB}"
echo "Sources: ${sources[*]}"
if [[ -n "$LAST" ]]; then
  echo "Period: last $LAST"
else
  echo "Period: [$FROM_TS, $TO_TS)"
fi
echo
echo "Preview rows that match cleanup filter:"

for spec in "${tables[@]}"; do
  IFS='|' read -r table time_col metric_expr <<<"$spec"
  if ! table_exists "$table"; then
    echo "  - ${table}: skipped (table does not exist)"
    continue
  fi
  if ! column_exists "$table" "source_id"; then
    echo "  - ${table}: skipped (source_id column missing)"
    continue
  fi
  if ! column_exists "$table" "$time_col"; then
    echo "  - ${table}: skipped (${time_col} column missing)"
    continue
  fi
  where_sql="source_id IN (${source_in_sql}) AND $(time_filter "$time_col")"
  ch_query "
SELECT
    $(sql_quote "$table") AS table,
    count() AS rows,
    ${metric_expr}
FROM ${TARGET_DB}.${table}
WHERE ${where_sql}
FORMAT PrettyCompact
"
done

if [[ "$EXECUTE" -ne 1 ]]; then
  echo
  echo "Dry-run only. Add --execute to run ALTER TABLE ... DELETE."
  exit 0
fi

echo
echo "WARNING: this will create ClickHouse mutations and delete matching rows."
echo "Make sure related collector services are stopped and local spool is cleared."
if [[ "$YES" -ne 1 ]]; then
  read -r -p "Type DELETE to continue: " confirm
  if [[ "$confirm" != "DELETE" ]]; then
    echo "Aborted."
    exit 1
  fi
fi

echo
echo "Creating mutations..."
for spec in "${tables[@]}"; do
  IFS='|' read -r table time_col _metric_expr <<<"$spec"
  if ! table_exists "$table"; then
    continue
  fi
  if ! column_exists "$table" "source_id" || ! column_exists "$table" "$time_col"; then
    continue
  fi
  where_sql="source_id IN (${source_in_sql}) AND $(time_filter "$time_col")"
  echo "==> ${TARGET_DB}.${table}"
  ch_query "ALTER TABLE ${TARGET_DB}.${table} DELETE WHERE ${where_sql}"
done

echo
echo "Mutations:"
tables_in_sql=""
for spec in "${tables[@]}"; do
  IFS='|' read -r table _time_col _metric_expr <<<"$spec"
  q="$(sql_quote "$table")"
  if [[ -z "$tables_in_sql" ]]; then
    tables_in_sql="$q"
  else
    tables_in_sql="${tables_in_sql}, ${q}"
  fi
done

ch_query "
SELECT
    table,
    mutation_id,
    is_done,
    latest_fail_reason
FROM system.mutations
WHERE database = $(sql_quote "$TARGET_DB")
  AND table IN (${tables_in_sql})
ORDER BY create_time DESC
FORMAT PrettyCompact
"

echo
echo "Run the script again without --execute to verify rows become zero after mutations finish."
