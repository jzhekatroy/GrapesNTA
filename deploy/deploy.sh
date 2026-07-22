#!/usr/bin/env bash
# Deploy GrapesNTA services from the server checkout.
#
# Expected layout on nta:
#   /opt/GrapesNTA                 ← this repo (git pull)
#   /opt/GrapesNTA/deploy/worker   ← grapes-worker compose + .env
#   /opt/GrapesNTA/deploy/enrichment ← grapes-enrichment compose + .env
#
# Usage (as root on the server):
#   cd /opt/GrapesNTA
#   ./deploy/deploy.sh              # pull + rebuild worker + enrichment
#   ./deploy/deploy.sh worker       # only grapes-worker
#   ./deploy/deploy.sh enrichment   # only grapes-enrichment
#   ./deploy/deploy.sh pull         # only git pull
#   ./deploy/deploy.sh status       # containers + last image build time
#   ./deploy/deploy.sh logs [svc]   # follow logs (worker|enrichment|all)
#   ./deploy/deploy.sh --no-pull worker   # rebuild without git pull
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKER_DIR="${REPO_ROOT}/deploy/worker"
ENRICH_DIR="${REPO_ROOT}/deploy/enrichment"

DO_PULL=1
TARGET=""
LOG_TARGET=""

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

log() { printf '+ %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "run as root (docker + /opt/GrapesNTA). Example: sudo $0 $*"
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

show_status() {
  echo
  log "containers"
  docker ps --filter name=grapes-worker --filter name=grapes-enrichment \
    --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.RunningFor}}' || true
  echo
  log "repo"
  cd "${REPO_ROOT}"
  printf '  path=%s\n  branch=%s\n  commit=%s %s\n' \
    "${REPO_ROOT}" \
    "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')" \
    "$(git rev-parse --short HEAD 2>/dev/null || echo '?')" \
    "$(git log -1 --pretty=%s 2>/dev/null || true)"
  echo
  log "recent worker logs"
  docker logs --tail 15 grapes-worker 2>&1 || true
  echo
  log "recent enrichment logs"
  docker logs --tail 15 grapes-enrichment 2>&1 || true
}

follow_logs() {
  local svc="${1:-all}"
  case "${svc}" in
    worker)      docker logs --tail 80 -f grapes-worker ;;
    enrichment)  docker logs --tail 80 -f grapes-enrichment ;;
    all|"")
      # Prefer worker if both exist; fall back.
      if docker ps --format '{{.Names}}' | grep -qx grapes-worker; then
        docker logs --tail 80 -f grapes-worker
      else
        docker logs --tail 80 -f grapes-enrichment
      fi
      ;;
    *) die "unknown logs target: ${svc} (worker|enrichment|all)" ;;
  esac
}

# --- args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage 0 ;;
    --no-pull) DO_PULL=0; shift ;;
    pull|worker|enrichment|all|status|logs)
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
      TARGET="$1"; shift
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
  worker|enrichment|all)
    need_root
    if [[ "${DO_PULL}" -eq 1 ]]; then
      git_pull
    else
      log "skip git pull (--no-pull)"
    fi
    case "${TARGET}" in
      worker)      compose_up "${WORKER_DIR}" grapes-worker ;;
      enrichment)  compose_up "${ENRICH_DIR}" grapes-enrichment ;;
      all)
        compose_up "${WORKER_DIR}" grapes-worker
        compose_up "${ENRICH_DIR}" grapes-enrichment
        ;;
    esac
    show_status
    log "done. follow: $0 logs worker"
    ;;
  *)
    die "unknown target: ${TARGET}"
    ;;
esac
