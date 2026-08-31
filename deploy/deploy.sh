#!/usr/bin/env bash
# Deploy GrapesNTA services from the server checkout.
#
# Expected layout on nta:
#   /opt/GrapesNTA                   ← this repo (git pull)
#   /opt/GrapesNTA/deploy/worker     ← grapes-worker compose + .env
#   /opt/GrapesNTA/deploy/enrichment ← grapes-enrichment compose + .env
#   /opt/GrapesNTA/deploy/ui         ← grapes-nta compose + vendored NTAdmin app/
#   /opt/GrapesNTA/deploy/detection  ← grapes-detection compose + .env
#   /opt/grapes/ui/.env              ← legacy secrets (copied once into deploy/ui/.env)
#   /opt/grapes/ui/data              ← UI data volume (default UI_DATA_DIR)
#
# Usage (as root on the server):
#   cd /opt/GrapesNTA
#   ./deploy/deploy.sh                 # интерактив: мультивыбор компонентов
#   ./deploy/deploy.sh worker          # only grapes-worker
#   ./deploy/deploy.sh enrichment      # only grapes-enrichment
#   ./deploy/deploy.sh ui              # pull + schema ensure + rebuild grapes-nta
#   ./deploy/deploy.sh detection       # only grapes-detection
#   ./deploy/deploy.sh ui detection    # несколько целей сразу
#   ./deploy/deploy.sh full            # schema + worker + enrichment + ui + detection
#   ./deploy/deploy.sh all             # worker + enrichment
#   ./deploy/deploy.sh schema          # only apply idempotent ClickHouse ensures
#   ./deploy/deploy.sh pull            # only git pull
#   ./deploy/deploy.sh status          # containers + repo head
#   ./deploy/deploy.sh logs [svc]      # follow logs (worker|enrichment|ui|detection|all)
#   ./deploy/deploy.sh --no-pull ui    # rebuild without git pull
#
# Run it directly on a root shell: `./deploy/deploy.sh …`, not through sudo.
# sudo resets HOME, git then loses root's stored GitHub credentials and the
# pull stops on a login prompt. A failed pull aborts the deploy instead of
# rebuilding the previous tree.
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
DETECTION_DIR="${REPO_ROOT}/deploy/detection"
UI_APP_DIR="${UI_DIR}/app"
UI_DATA_DIR="${UI_DATA_DIR:-/opt/grapes/ui/data}"
UI_LEGACY_ENV="${UI_LEGACY_ENV:-/opt/grapes/ui/.env}"

DO_PULL=1
ACTION=""
LOG_TARGET=""
SEL_WORKER=0
SEL_ENRICH=0
SEL_UI=0
SEL_DETECTION=0
SEL_SCHEMA=0

usage() {
  sed -n '2,37p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

log() { printf '+ %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "run as root (docker + /opt). Example: sudo $0 $*"
  fi
  # Warn once: through sudo the pull loses root's git credentials.
  if [[ -n "${SUDO_USER:-}" && "${DO_PULL}" -eq 1 ]]; then
    log "note: запущено через sudo. Если git pull попросит логин — выйдите и запустите из root-шелла: ./deploy/deploy.sh $*"
  fi
}

need_compose_dir() {
  local dir="$1" name="$2"
  [[ -f "${dir}/docker-compose.yml" ]] || die "missing ${dir}/docker-compose.yml"
  [[ -f "${dir}/.env" ]] || die "missing ${dir}/.env — copy from env.example and fill secrets"
  command -v docker >/dev/null || die "docker not found"
  docker compose version >/dev/null 2>&1 || die "docker compose plugin required"
}

# Checkout owned by another user makes git refuse with "dubious ownership".
ensure_safe_directory() {
  local owner
  owner="$(stat -c '%U' "${REPO_ROOT}" 2>/dev/null || true)"
  [[ -n "${owner}" && "${owner}" != "root" ]] || return 0
  if git config --global --get-all safe.directory 2>/dev/null | grep -qx -- "${REPO_ROOT}"; then
    return 0
  fi
  log "git config --global --add safe.directory ${REPO_ROOT} (owner=${owner})"
  git config --global --add safe.directory "${REPO_ROOT}" || true
}

git_pull() {
  cd "${REPO_ROOT}"
  [[ -d .git ]] || die "${REPO_ROOT} is not a git checkout"
  local before after branch home
  ensure_safe_directory
  before="$(git rev-parse --short HEAD)"
  branch="$(git rev-parse --abbrev-ref HEAD)"
  log "git pull origin ${branch} (was ${before})"

  # sudo wipes HOME, so ~/.git-credentials disappears and git falls back to a
  # login prompt. GIT_TERMINAL_PROMPT=0 turns that hang into a clean failure.
  home="${HOME:-/root}"
  [[ "${EUID}" -eq 0 ]] && home="$(getent passwd root | cut -d: -f6)"
  [[ -n "${home}" ]] || home=/root

  if ! HOME="${home}" GIT_TERMINAL_PROMPT=0 git pull --ff-only origin "${branch}"; then
    die "git pull не прошёл (HOME=${home}). Запускайте из root-шелла напрямую: cd ${REPO_ROOT} && ./deploy/deploy.sh …  (без sudo). Собрать текущее дерево без обновления: $0 --no-pull …"
  fi

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

ensure_detection_env() {
  if [[ -f "${DETECTION_DIR}/.env" ]]; then
    return 0
  fi
  if [[ -f "${UI_DIR}/.env" ]]; then
    log "bootstrap ${DETECTION_DIR}/.env from ${UI_DIR}/.env"
    cp "${UI_DIR}/.env" "${DETECTION_DIR}/.env"
    chmod 600 "${DETECTION_DIR}/.env"
  elif [[ -f "${UI_LEGACY_ENV}" ]]; then
    log "bootstrap ${DETECTION_DIR}/.env from ${UI_LEGACY_ENV}"
    cp "${UI_LEGACY_ENV}" "${DETECTION_DIR}/.env"
    chmod 600 "${DETECTION_DIR}/.env"
  elif [[ -f "${DETECTION_DIR}/env.example" ]]; then
    die "missing ${DETECTION_DIR}/.env — copy from env.example (or from ${UI_DIR}/.env) and fill secrets"
  else
    die "missing ${DETECTION_DIR}/.env"
  fi
  if ! grep -q '^DETECTION_TICK_SEC=' "${DETECTION_DIR}/.env" 2>/dev/null; then
    printf '\nDETECTION_TICK_SEC=20\n' >> "${DETECTION_DIR}/.env"
  fi
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

detection_up() {
  [[ -f "${DETECTION_DIR}/Dockerfile" ]] || die "missing ${DETECTION_DIR}/Dockerfile"
  [[ -f "${DETECTION_DIR}/server/detection-worker.js" ]] || die "missing ${DETECTION_DIR}/server/detection-worker.js"
  [[ -f "${DETECTION_DIR}/package-lock.json" ]] || die "missing ${DETECTION_DIR}/package-lock.json"
  ensure_detection_env
  compose_up "${DETECTION_DIR}" grapes-detection
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
    --filter name=grapes-detection \
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
  echo
  log "recent detection logs"
  docker logs --tail 10 grapes-detection 2>&1 || true
}

follow_logs() {
  local svc="${1:-all}"
  case "${svc}" in
    worker)      docker logs --tail 80 -f grapes-worker ;;
    enrichment)  docker logs --tail 80 -f grapes-enrichment ;;
    ui|nta)      docker logs --tail 80 -f grapes-nta ;;
    detection)   docker logs --tail 80 -f grapes-detection ;;
    all|"")
      if docker ps --format '{{.Names}}' | grep -qx grapes-detection; then
        docker logs --tail 80 -f grapes-detection
      elif docker ps --format '{{.Names}}' | grep -qx grapes-worker; then
        docker logs --tail 80 -f grapes-worker
      elif docker ps --format '{{.Names}}' | grep -qx grapes-nta; then
        docker logs --tail 80 -f grapes-nta
      else
        docker logs --tail 80 -f grapes-enrichment
      fi
      ;;
    *) die "unknown logs target: ${svc} (worker|enrichment|ui|detection|all)" ;;
  esac
}

any_deploy_selected() {
  [[ "${SEL_WORKER}" -eq 1 || "${SEL_ENRICH}" -eq 1 || "${SEL_UI}" -eq 1 || "${SEL_DETECTION}" -eq 1 || "${SEL_SCHEMA}" -eq 1 ]]
}

select_component() {
  local token="$1"
  case "${token}" in
    worker)     SEL_WORKER=1 ;;
    enrichment) SEL_ENRICH=1 ;;
    ui|nta)     SEL_UI=1 ;;
    detection)  SEL_DETECTION=1 ;;
    schema)     SEL_SCHEMA=1 ;;
    all)
      SEL_WORKER=1
      SEL_ENRICH=1
      ;;
    full)
      SEL_SCHEMA=1
      SEL_WORKER=1
      SEL_ENRICH=1
      SEL_UI=1
      SEL_DETECTION=1
      ;;
    *)
      return 1
      ;;
  esac
  return 0
}

apply_numeric_choice() {
  local raw="$1"
  raw="${raw//,/ }"
  local token
  for token in ${raw}; do
    case "${token}" in
      "" ) ;;
      a|A|all|full) select_component full ;;
      1|worker)     select_component worker ;;
      2|enrichment) select_component enrichment ;;
      3|ui|nta)     select_component ui ;;
      4|detection)  select_component detection ;;
      5|schema)     select_component schema ;;
      *)
        die "unknown component: ${token} (1 worker, 2 enrichment, 3 ui, 4 detection, 5 schema, a full)"
        ;;
    esac
  done
}

pick_components_interactive() {
  if [[ ! -t 0 || ! -t 1 ]]; then
    die "no target given and not a TTY. Pass components: worker|enrichment|ui|detection|schema|all|full"
  fi

  if command -v whiptail >/dev/null 2>&1; then
    local picked=""
    picked="$(
      whiptail --title "GrapesNTA deploy" --separate-output --checklist \
        "Что разворачивать (пробел — выбрать, Enter — дальше)" 18 74 6 \
        worker "grapes-worker (rollup / observations)" OFF \
        enrichment "grapes-enrichment" OFF \
        ui "grapes-nta UI/API" OFF \
        detection "grapes-detection" OFF \
        schema "ClickHouse schema ensure" OFF \
        3>&1 1>&2 2>&3
    )" || die "cancelled"
    local token
    while IFS= read -r token; do
      [[ -z "${token}" ]] && continue
      select_component "${token}" || die "unknown component: ${token}"
    done <<< "${picked}"
  else
    echo
    echo "Что разворачивать? Номера через пробел или запятую."
    echo "  1) worker       grapes-worker"
    echo "  2) enrichment   grapes-enrichment"
    echo "  3) ui           grapes-nta"
    echo "  4) detection    grapes-detection"
    echo "  5) schema       ClickHouse ensure"
    echo "  a) full         schema + worker + enrichment + ui + detection"
    echo
    local choice=""
    read -r -p "> " choice || die "cancelled"
    [[ -n "${choice}" ]] || die "nothing selected"
    apply_numeric_choice "${choice}"
  fi

  if ! any_deploy_selected; then
    die "nothing selected"
  fi
}

# --- args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage 0 ;;
    --no-pull) DO_PULL=0; shift ;;
    pull|status)
      if [[ -n "${ACTION}" ]]; then
        die "only one action allowed (got ${ACTION} and $1)"
      fi
      ACTION="$1"
      shift
      ;;
    logs)
      if [[ -n "${ACTION}" ]]; then
        die "only one action allowed (got ${ACTION} and $1)"
      fi
      ACTION="logs"
      shift
      LOG_TARGET="${1:-all}"
      if [[ $# -gt 0 && "$1" != --* ]]; then
        case "$1" in
          worker|enrichment|ui|nta|detection|all) shift ;;
        esac
      fi
      ;;
    worker|enrichment|ui|nta|detection|schema|all|full)
      ACTION="deploy"
      select_component "$1" || die "unknown arg: $1"
      shift
      ;;
    *)
      die "unknown arg: $1 (try --help)"
      ;;
  esac
done

if [[ -z "${ACTION}" ]]; then
  ACTION="deploy"
  pick_components_interactive
fi

case "${ACTION}" in
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
  deploy)
    if ! any_deploy_selected; then
      die "no components selected"
    fi
    need_root
    if [[ "${DO_PULL}" -eq 1 ]]; then
      git_pull
    else
      log "skip git pull (--no-pull)"
    fi
    if [[ "${SEL_SCHEMA}" -eq 1 || "${SEL_UI}" -eq 1 ]]; then
      ensure_clickhouse_schema
    fi
    if [[ "${SEL_WORKER}" -eq 1 ]]; then
      compose_up "${WORKER_DIR}" grapes-worker
    fi
    if [[ "${SEL_ENRICH}" -eq 1 ]]; then
      compose_up "${ENRICH_DIR}" grapes-enrichment
    fi
    if [[ "${SEL_DETECTION}" -eq 1 ]]; then
      detection_up
    fi
    if [[ "${SEL_UI}" -eq 1 ]]; then
      ui_up
    fi
    show_status
    log "done. examples: $0 logs ui | $0 logs detection | $0 logs worker"
    ;;
  *)
    die "unknown action: ${ACTION}"
    ;;
esac
