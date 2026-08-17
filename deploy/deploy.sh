#!/usr/bin/env bash
# Deploy GrapesNTA services from the server checkout.
#
# Expected layout on nta:
#   /opt/GrapesNTA                   ← this repo (git pull)
#   /opt/GrapesNTA/deploy/worker     ← grapes-worker compose + .env
#   /opt/GrapesNTA/deploy/enrichment ← grapes-enrichment compose + .env
#   /opt/GrapesNTA/deploy/ui         ← grapes-nta compose + vendored NTAdmin app/
#   /opt/grapes/ui/.env              ← legacy secrets (copied once into deploy/ui/.env)
#   /opt/grapes/ui/data              ← UI data volume (default UI_DATA_DIR)
#
# Usage (as root on the server):
#   cd /opt/GrapesNTA
#   ./deploy/deploy.sh              # pull + rebuild worker + enrichment
#   ./deploy/deploy.sh worker       # only grapes-worker
#   ./deploy/deploy.sh enrichment   # only grapes-enrichment
#   ./deploy/deploy.sh ui           # pull + schema ensure + rebuild grapes-nta
#   ./deploy/deploy.sh full         # schema ensure + worker + enrichment + ui
#   ./deploy/deploy.sh schema       # only apply idempotent ClickHouse ensures
#   ./deploy/deploy.sh pull         # only git pull
#   ./deploy/deploy.sh status       # containers + repo head
#   ./deploy/deploy.sh logs [svc]   # follow logs (worker|enrichment|ui|all)
#   ./deploy/deploy.sh --no-pull ui # rebuild without git pull
#
# Optional env:
#   UI_DATA_DIR=/opt/grapes/ui/data
#   UI_LEGACY_ENV=/opt/grapes/ui/.env
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKER_DIR="${REPO_ROOT}/deploy/worker"
ENRICH_DIR="${REPO_ROOT}/deploy/enrichment"
UI_DIR="${REPO_ROOT}/deploy/ui"
UI_APP_DIR="${UI_DIR}/app"
UI_DATA_DIR="${UI_DATA_DIR:-/opt/grapes/ui/data}"
UI_LEGACY_ENV="${UI_LEGACY_ENV:-/opt/grapes/ui/.env}"

DO_PULL=1
TARGET=""
LOG_TARGET=""

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

log() { printf '+ %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "run as root (docker + /opt). Example: sudo $0 $*"
  fi
}

need_compose_dir() {
  local dir="$1" name="$2"
  [[ -f "${dir}/docker-compose.yml" ]] || die "missing ${dir}/docker-compose.yml"
  [[ -f "${dir}/.env" ]] || die "missing ${dir}/.env — copy from env.example and fill secrets"
  command -v docker >/dev/null || die "docker not found"
  docker compose version >/dev/null 2>&1 || die "docker compose plugin required"
}

git_pull() {
  cd "${REPO_ROOT}"
  [[ -d .git ]] || die "${REPO_ROOT} is not a git checkout"
  local before after branch
  before="$(git rev-parse --short HEAD)"
  branch="$(git rev-parse --abbrev-ref HEAD)"
  log "git pull origin ${branch} (was ${before})"
  git pull --ff-only origin "${branch}"
  after="$(git rev-parse --short HEAD)"
  if [[ "${before}" == "${after}" ]]; then
    log "already up to date (${after})"
  else
    log "updated ${before} → ${after}"
    git --no-pager log --oneline "${before}..${after}" || true
  fi
}

# grapes-worker / grapes-enrichment run as uid 1001. Docker creates bind-mount
# dirs as root, then FileHandler('/var/log/grapesnta/...') aborts the cron
# before any INSERT into traffic_dashboard_1m — empty graphs on a fresh box.
ensure_app_owned_dir() {
  local dir="$1"
  mkdir -p "${dir}"
  chown -R 1001:1001 "${dir}" 2>/dev/null || true
}

compose_up() {
  local dir="$1" name="$2"
  need_compose_dir "${dir}" "${name}"
  if [[ "${name}" == "grapes-worker" ]]; then
    ensure_app_owned_dir "${WORKER_DIR}/logs"
    ensure_app_owned_dir "${WORKER_DIR}/data"
  elif [[ "${name}" == "grapes-enrichment" ]]; then
    ensure_app_owned_dir "${ENRICH_DIR}/logs"
  fi
  log "rebuild ${name} in ${dir}"
  (
    cd "${dir}"
    docker compose up -d --build --remove-orphans
  )
  log "${name} is up"
}

ensure_ui_env() {
  if [[ -f "${UI_DIR}/.env" ]]; then
    return 0
  fi
  if [[ -f "${UI_LEGACY_ENV}" ]]; then
    log "bootstrap ${UI_DIR}/.env from ${UI_LEGACY_ENV}"
    cp "${UI_LEGACY_ENV}" "${UI_DIR}/.env"
    chmod 600 "${UI_DIR}/.env"
    return 0
  fi
  if [[ -f "${UI_DIR}/env.example" ]]; then
    die "missing ${UI_DIR}/.env — copy from env.example (or from ${UI_LEGACY_ENV}) and fill secrets"
  fi
  die "missing ${UI_DIR}/.env"
}

ensure_clickhouse_schema() {
  local script="${REPO_ROOT}/deploy/schema/ensure-live.sh"
  [[ -x "${script}" || -f "${script}" ]] || die "missing ${script}"
  log "ensure ClickHouse schema (from deploy/ui/.env)"
  bash "${script}"
}

ui_up() {
  [[ -f "${UI_APP_DIR}/Dockerfile" ]] || die "missing vendored UI app at ${UI_APP_DIR} (run scripts/sync-ui-from-ntadmin.sh on a dev machine and push)"
  [[ -f "${UI_APP_DIR}/package.json" ]] || die "missing ${UI_APP_DIR}/package.json"
  ensure_ui_env
  mkdir -p "${UI_DATA_DIR}"
  # uid 1001 = app user inside grapes-nta image
  if [[ -d "${UI_DATA_DIR}" ]]; then
    chown -R 1001:1001 "${UI_DATA_DIR}" 2>/dev/null || true
  fi
  need_compose_dir "${UI_DIR}" grapes-nta
  log "rebuild grapes-nta in ${UI_DIR} (data=${UI_DATA_DIR})"
  if [[ -f "${UI_DIR}/SOURCE.txt" ]]; then
    log "UI source: $(tr '\n' ' ' <"${UI_DIR}/SOURCE.txt")"
  fi
  (
    cd "${UI_DIR}"
    UI_DATA_DIR="${UI_DATA_DIR}" docker compose up -d --build --remove-orphans
  )
  log "grapes-nta is up"
  # brief wait for health
  local i
  for i in 1 2 3 4 5 6; do
    if curl -fsS --max-time 3 "http://127.0.0.1:3000/api/health" >/tmp/grapes-nta-health.json 2>/dev/null; then
      log "health: $(tr -d '\n' </tmp/grapes-nta-health.json | head -c 220)"
      return 0
    fi
    sleep 2
  done
  log "health check not ready yet — try: curl -sS http://127.0.0.1:3000/api/health"
}

show_repo_line() {
  local dir="$1" label="$2"
  if [[ -d "${dir}/.git" ]]; then
    printf '  %s path=%s branch=%s commit=%s %s\n' \
      "${label}" \
      "${dir}" \
      "$(git -C "${dir}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')" \
      "$(git -C "${dir}" rev-parse --short HEAD 2>/dev/null || echo '?')" \
      "$(git -C "${dir}" log -1 --pretty=%s 2>/dev/null || true)"
  else
    printf '  %s path=%s (no git)\n' "${label}" "${dir}"
  fi
}

show_status() {
  echo
  log "containers"
  docker ps \
    --filter name=grapes-worker \
    --filter name=grapes-enrichment \
    --filter name=grapes-nta \
    --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.RunningFor}}' || true
  echo
  log "repos"
  show_repo_line "${REPO_ROOT}" GrapesNTA
  if [[ -f "${UI_DIR}/SOURCE.txt" ]]; then
    printf '  UI vendored: %s\n' "$(tr '\n' ' ' <"${UI_DIR}/SOURCE.txt")"
  fi
  echo
  log "recent worker logs"
  docker logs --tail 10 grapes-worker 2>&1 || true
  echo
  log "recent enrichment logs"
  docker logs --tail 10 grapes-enrichment 2>&1 || true
  echo
  log "recent ui logs"
  docker logs --tail 10 grapes-nta 2>&1 || true
}

follow_logs() {
  local svc="${1:-all}"
  case "${svc}" in
    worker)      docker logs --tail 80 -f grapes-worker ;;
    enrichment)  docker logs --tail 80 -f grapes-enrichment ;;
    ui|nta)      docker logs --tail 80 -f grapes-nta ;;
    all|"")
      if docker ps --format '{{.Names}}' | grep -qx grapes-worker; then
        docker logs --tail 80 -f grapes-worker
      elif docker ps --format '{{.Names}}' | grep -qx grapes-nta; then
        docker logs --tail 80 -f grapes-nta
      else
        docker logs --tail 80 -f grapes-enrichment
      fi
      ;;
    *) die "unknown logs target: ${svc} (worker|enrichment|ui|all)" ;;
  esac
}

# --- args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage 0 ;;
    --no-pull) DO_PULL=0; shift ;;
    pull|worker|enrichment|ui|nta|all|full|schema|status|logs)
      if [[ -n "${TARGET}" && "$1" != "logs" ]]; then
        die "only one target allowed (got ${TARGET} and $1)"
      fi
      if [[ "$1" == "logs" ]]; then
        TARGET="logs"
        shift
        LOG_TARGET="${1:-all}"
        [[ $# -gt 0 ]] && shift
        continue
      fi
      if [[ "$1" == "nta" ]]; then
        TARGET="ui"
      else
        TARGET="$1"
      fi
      shift
      ;;
    *)
      die "unknown arg: $1 (try --help)"
      ;;
  esac
done

TARGET="${TARGET:-all}"

case "${TARGET}" in
  status)
    show_status
    exit 0
    ;;
  logs)
    follow_logs "${LOG_TARGET}"
    exit 0
    ;;
  pull)
    need_root
    git_pull
    exit 0
    ;;
  worker|enrichment|ui|all|full|schema)
    need_root
    if [[ "${DO_PULL}" -eq 1 ]]; then
      git_pull
    else
      log "skip git pull (--no-pull)"
    fi
    case "${TARGET}" in
      worker)      compose_up "${WORKER_DIR}" grapes-worker ;;
      enrichment)  compose_up "${ENRICH_DIR}" grapes-enrichment ;;
      schema)      ensure_clickhouse_schema ;;
      ui)
        ensure_clickhouse_schema
        ui_up
        ;;
      all)
        compose_up "${WORKER_DIR}" grapes-worker
        compose_up "${ENRICH_DIR}" grapes-enrichment
        ;;
      full)
        ensure_clickhouse_schema
        compose_up "${WORKER_DIR}" grapes-worker
        compose_up "${ENRICH_DIR}" grapes-enrichment
        ui_up
        ;;
    esac
    show_status
    log "done. examples: $0 logs ui | $0 logs worker"
    ;;
  *)
    die "unknown target: ${TARGET}"
    ;;
esac
