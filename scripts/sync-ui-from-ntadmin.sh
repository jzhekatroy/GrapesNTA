#!/usr/bin/env bash
# Sync NTAdmin UI sources into GrapesNTA/deploy/ui/app for vendored deploys.
#
# Usage:
#   ./scripts/sync-ui-from-ntadmin.sh                 # from ../NTAdmin
#   ./scripts/sync-ui-from-ntadmin.sh /path/to/NTAdmin
#   NTADMIN_GIT_URL=https://github.com/mavotronik/NTAdmin.git \
#     ./scripts/sync-ui-from-ntadmin.sh --clone
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${REPO_ROOT}/deploy/ui/app"
SOURCE_TXT="${REPO_ROOT}/deploy/ui/SOURCE.txt"
DEFAULT_SRC="$(cd "${REPO_ROOT}/.." && pwd)/NTAdmin"
NTADMIN_GIT_URL="${NTADMIN_GIT_URL:-https://github.com/mavotronik/NTAdmin.git}"

SRC=""
DO_CLONE=0

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

log() { printf '+ %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage 0 ;;
    --clone) DO_CLONE=1; shift ;;
    *)
      [[ -z "${SRC}" ]] || die "unexpected arg: $1"
      SRC="$1"; shift
      ;;
  esac
done

if [[ "${DO_CLONE}" -eq 1 ]]; then
  TMP="$(mktemp -d /tmp/ntadmin-sync.XXXXXX)"
  trap 'rm -rf "${TMP}"' EXIT
  log "clone ${NTADMIN_GIT_URL} → ${TMP}"
  GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch main "${NTADMIN_GIT_URL}" "${TMP}/NTAdmin" \
    || die "clone failed (private repo needs credentials on this machine)"
  SRC="${TMP}/NTAdmin"
elif [[ -z "${SRC}" ]]; then
  SRC="${DEFAULT_SRC}"
fi

[[ -d "${SRC}" ]] || die "NTAdmin source not found: ${SRC}"
[[ -f "${SRC}/package.json" ]] || die "not an NTAdmin tree (no package.json): ${SRC}"
command -v rsync >/dev/null || die "rsync required"

mkdir -p "${DEST}"
log "rsync ${SRC}/ → ${DEST}/"
rsync -a --delete \
  --exclude '.git/' \
  --exclude 'node_modules/' \
  --exclude '.tmp/' \
  --exclude '.tmp-*' \
  --exclude 'server/data/' \
  --exclude '.env' \
  --exclude '.env.docker.example' \
  --exclude '.DS_Store' \
  --exclude 'bounds-service/' \
  --exclude 'deploy/' \
  --exclude 'docs/' \
  --exclude 'scripts/' \
  --exclude 'Grapes NTA.html' \
  --exclude 'Dockerfile.analytics' \
  --exclude 'docker-compose.yml' \
  --exclude 'README.md' \
  "${SRC}/" "${DEST}/"

COMMIT="unknown"
if [[ -d "${SRC}/.git" ]]; then
  COMMIT="$(git -C "${SRC}" rev-parse HEAD)"
fi
{
  echo "synced_from=${NTADMIN_GIT_URL}"
  echo "synced_commit=${COMMIT}"
  echo "synced_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "synced_src=${SRC}"
} > "${SOURCE_TXT}"

# Keep compose-level env.example in sync with app template when present.
if [[ -f "${DEST}/.env.example" ]]; then
  cp "${DEST}/.env.example" "${REPO_ROOT}/deploy/ui/env.example"
fi

# grapes-worker vendors a subset of server/ modules. They must move together with
# the UI: a stale clickhouse.js/explorer.js pair makes the worker reject dimensions
# the UI happily saves ("Неизвестное измерение разреза: …").
#
# The first loop only refreshes files that already exist in the snapshot. After
# that, follow same-dir require() so a new sibling (explorer-cabinet-client.js)
# is copied instead of leaving the worker image to crash-loop on MODULE_NOT_FOUND.
copy_missing_worker_requires() {
  local dest="$1"
  local src_root="$2"
  local added=1
  local pass=0
  while [[ "${added}" -eq 1 ]]; do
    added=0
    pass=$((pass + 1))
    [[ "${pass}" -le 10 ]] || die "worker require() follow exceeded 10 passes"
    local spec name src
    while IFS= read -r spec; do
      [[ -z "${spec}" ]] && continue
      name="${spec%.js}.js"
      [[ -f "${dest}/${name}" ]] && continue
      src="${src_root}/server/${name}"
      [[ -f "${src}" ]] || die "worker require() has no NTAdmin counterpart: server/${name}"
      log "add worker module ${name}"
      cp "${src}" "${dest}/${name}"
      added=1
    done < <(
      { grep -hE "require\(['\"]\./[^'\"]+['\"]\)" "${dest}"/*.js || true; } \
        | sed -E "s/.*require\(['\"]\.\/([^'\"]+)['\"]\).*/\1/" \
        | sed 's/\.js$//' \
        | grep -v '/' \
        | awk '{ print $0 ".js" }' \
        | sort -u
    )
  done
}

WORKER_DEST="${REPO_ROOT}/deploy/analytics/server"
if [[ -d "${WORKER_DEST}" ]]; then
  log "sync worker modules → ${WORKER_DEST}/"
  for dst in "${WORKER_DEST}"/*.js; do
    [[ -e "${dst}" ]] || continue
    name="$(basename "${dst}")"
    src="${SRC}/server/${name}"
    [[ -f "${src}" ]] || die "worker module has no NTAdmin counterpart: server/${name}"
    cp "${src}" "${dst}"
  done
  copy_missing_worker_requires "${WORKER_DEST}" "${SRC}"
  node "${REPO_ROOT}/deploy/worker/bin/check-analytics-requires.js" "${WORKER_DEST}" \
    || die "worker analytics snapshot has missing require() siblings"
fi

log "done → ${DEST}"
log "SOURCE.txt:"
cat "${SOURCE_TXT}"
log "next: git add deploy/ui deploy/analytics && git commit && git push"
log "      on server: ./deploy/deploy.sh ui && ./deploy/deploy.sh --no-pull worker"
