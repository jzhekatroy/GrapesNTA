#!/bin/sh
# Run an enrichment job, capture log, publish status to ClickHouse.
set -eu

JOB="${1:-}"
shift || true
if [ -z "$JOB" ] || [ "$#" -lt 1 ]; then
  echo "usage: run_job.sh <job-name> <command> [args...]" >&2
  exit 2
fi

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

REPORT=/app/bin/report_job_status.py
STARTED_AT="$(date -u +'%Y-%m-%d %H:%M:%S.000')"
START_S="$(date +%s)"

python3 "$REPORT" --job "$JOB" --status running --started-at "$STARTED_AT" || true

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

set +e
"$@" >"$LOG" 2>&1
RC=$?
set -e

END_S="$(date +%s)"
DUR_MS=$(( (END_S - START_S) * 1000 ))
FINISHED_AT="$(date -u +'%Y-%m-%d %H:%M:%S.000')"

# Echo log to container stdout so docker logs still work.
cat "$LOG"

if [ "$RC" -eq 0 ]; then
  STATUS=ok
else
  STATUS=error
fi

python3 "$REPORT" \
  --job "$JOB" \
  --status "$STATUS" \
  --exit-code "$RC" \
  --started-at "$STARTED_AT" \
  --finished-at "$FINISHED_AT" \
  --duration-ms "$DUR_MS" \
  --log-file "$LOG" || true

exit "$RC"
