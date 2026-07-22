#!/usr/bin/env bash
# Deploy GrapesNTA services from the server checkout.
#
# Expected layout on nta:
#   /opt/GrapesNTA                   ← this repo (git pull)
#   /opt/GrapesNTA/deploy/worker     ← grapes-worker compose + .env
#   /opt/GrapesNTA/deploy/enrichment ← grapes-enrichment compose + .env
#   /opt/grapes/ui                   ← grapes-nta compose + .env
#   /opt/grapes/ui/app               ← NTAdmin build context (sources)
#   /opt/NTAdmin                     ← optional git mirror of NTAdmin (auto-cloned)
#
# Usage (as root on the server):
#   cd /opt/GrapesNTA
#   ./deploy/deploy.sh              # pull + rebuild worker + enrichment
#   ./deploy/deploy.sh worker       # only grapes-worker
#   ./deploy/deploy.sh enrichment   # only grapes-enrichment
#   ./deploy/deploy.sh ui           # pull NTAdmin + rebuild grapes-nta
#   ./deploy/deploy.sh full         # worker + enrichment + ui
#   ./deploy/deploy.sh pull         # only git pull (GrapesNTA; + NTAdmin if present)
#   ./deploy/deploy.sh status       # containers + repo heads
#   ./deploy/deploy.sh logs [svc]   # follow logs (worker|enrichment|ui|all)
#   ./deploy/deploy.sh --no-pull ui # rebuild UI without git pull
#
# Optional env:
#   UI_DIR=/opt/grapes/ui
#   UI_APP_DIR=/opt/grapes/ui/app
#   UI_MIRROR=/opt/NTAdmin
#   UI_GIT_URL=https://github.com/mavotronik/NTAdmin.git
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKER_DIR="${REPO_ROOT}/deploy/worker"
ENRICH_DIR="${REPO_ROOT}/deploy/enrichment"

UI_DIR="${UI_DIR:-/opt/grapes/ui}"
UI_APP_DIR="${UI_APP_DIR:-${UI_DIR}/app}"
UI_MIRROR="${UI_MIRROR:-/opt/NTAdmin}"
UI_GIT_URL="${UI_GIT_URL:-https://github.com/mavotronik/NTAdmin.git}"

DO_PULL=1
TARGET=""
LOG_TARGET=""

usage() {
  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
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

git_pull_dir() {
  local dir="$1" label="$2"
  [[ -d "${dir}/.git" ]] || die "${label}: ${dir} is not a git checkout"
  local before after branch
  before="$(git -C "${dir}" rev-parse --short HEAD)"
  branch="$(git -C "${dir}" rev-parse --abbrev-ref HEAD)"
  log "git pull ${label} origin ${branch} (was ${before})"
  git -C "${dir}" pull --ff-only origin "${branch}"
  after="$(git -C "${dir}" rev-parse --short HEAD)"
  if [[ "${before}" == "${after}" ]]; then
    log "${label}: already up to date (${after})"
  else
    log "${label}: updated ${before} → ${after}"
    git -C "${dir}" --no-pager log --oneline "${before}..${after}" || true
  fi
}

git_pull() {
  git_pull_dir "${REPO_ROOT}" GrapesNTA
}

# Sync NTAdmin sources into the UI build context.
# Prefer a git checkout inside UI_APP_DIR; otherwise keep a mirror at UI_MIRROR
# and rsync into app/ (preserves the historical tarball layout).
ui_pull() {
  command -v git >/dev/null || die "git not found"
  if [[ -d "${UI_APP_DIR}/.git" ]]; then
    git_pull_dir "${UI_APP_DIR}" NTAdmin
    return 0
  fi

  if [[ ! -d "${UI_MIRROR}/.git" ]]; then
    log "NTAdmin mirror missing — cloning ${UI_GIT_URL} → ${UI_MIRROR}"
    mkdir -p "$(dirname "${UI_MIRROR}")"
    if ! git clone --branch main "${UI_GIT_URL}" "${UI_MIRROR}"; then
      die "failed to clone NTAdmin. Set UI_GIT_URL or clone manually to ${UI_MIRROR} (private repo needs credentials)"
    fi
  else
    git_pull_dir "${UI_MIRROR}" "NTAdmin mirror"
  fi

  [[ -d "${UI_APP_DIR}" ]] || die "missing UI app dir ${UI_APP_DIR}"
  command -v rsync >/dev/null || die "rsync required to sync ${UI_MIRROR} → ${UI_APP_DIR}"
  log "rsync ${UI_MIRROR}/ → ${UI_APP_DIR}/"
  rsync -a --delete \
    --exclude '.git/' \
    --exclude 'node_modules/' \
    --exclude 'server/data/' \
    --exclude '.tmp/' \
    --exclude '.env' \
    --exclude '.env.*' \
    "${UI_MIRROR}/" "${UI_APP_DIR}/"
  if [[ -d "${UI_MIRROR}/.git" ]]; then
    printf '  ui_app synced from %s (%s)\n' \
      "${UI_MIRROR}" \
      "$(git -C "${UI_MIRROR}" rev-parse --short HEAD)"
  fi
}

compose_up() {
  local dir="$1" name="$2"
  need_compose_dir "${dir}" "${name}"
  log "rebuild ${name} in ${dir}"
  (
    cd "${dir}"
    docker compose up -d --build --remove-orphans
  )
  log "${name} is up"
}

ui_up() {
  need_compose_dir "${UI_DIR}" grapes-nta
  [[ -f "${UI_APP_DIR}/Dockerfile" || -f "${UI_DIR}/Dockerfile" ]] \
    || die "missing Dockerfile under ${UI_APP_DIR} or ${UI_DIR}"
  log "rebuild grapes-nta in ${UI_DIR}"
  (
    cd "${UI_DIR}"
    docker compose up -d --build --remove-orphans
  )
  log "grapes-nta is up"
  if curl -fsS --max-time 5 "http://127.0.0.1:3000/api/health" >/tmp/grapes-nta-health.json 2>/dev/null; then
    log "health: $(tr -d '\n' </tmp/grapes-nta-health.json | head -c 200)"
  else
    log "health check not ready yet — try: curl -sS http://127.0.0.1:3000/api/health"
  fi
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
  show_repo_line "${UI_APP_DIR}" "UI app"
  show_repo_line "${UI_MIRROR}" "UI mirror"
  echo
  log "recent worker logs"
  docker logs --tail 12 grapes-worker 2>&1 || true
  echo
  log "recent enrichment logs"
  docker logs --tail 12 grapes-enrichment 2>&1 || true
  echo
  log "recent ui logs"
  docker logs --tail 12 grapes-nta 2>&1 || true
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
    pull|worker|enrichment|ui|nta|all|full|status|logs)
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
    if [[ -d "${UI_APP_DIR}/.git" || -d "${UI_MIRROR}/.git" ]]; then
      ui_pull
    else
      log "skip UI pull (no ${UI_APP_DIR}/.git and no ${UI_MIRROR}/.git yet)"
    fi
    exit 0
    ;;
  worker|enrichment|ui|all|full)
    need_root
    case "${TARGET}" in
      worker|enrichment|all|full)
        if [[ "${DO_PULL}" -eq 1 ]]; then
          git_pull
        else
          log "skip GrapesNTA git pull (--no-pull)"
        fi
        ;;
    esac
    case "${TARGET}" in
      ui|full)
        if [[ "${DO_PULL}" -eq 1 ]]; then
          ui_pull
        else
          log "skip UI git pull (--no-pull)"
        fi
        ;;
    esac
    case "${TARGET}" in
      worker)      compose_up "${WORKER_DIR}" grapes-worker ;;
      enrichment)  compose_up "${ENRICH_DIR}" grapes-enrichment ;;
      ui)          ui_up ;;
      all)
        compose_up "${WORKER_DIR}" grapes-worker
        compose_up "${ENRICH_DIR}" grapes-enrichment
        ;;
      full)
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
