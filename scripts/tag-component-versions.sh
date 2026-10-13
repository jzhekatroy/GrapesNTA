#!/usr/bin/env bash
# Ставит метки компонентов на коммит, который только что попал в main.
# Шаблон: detection-2026.10.13.1 — дата слияния по Москве и номер выпуска за этот день.
#
#   BEFORE=<sha до пуша> SHA=<sha пуша> scripts/tag-component-versions.sh
#   DRY_RUN=1 — только печатает метки, на GitHub не отправляет.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

BEFORE="${BEFORE:-}"
SHA="${SHA:-HEAD}"
DRY_RUN="${DRY_RUN:-0}"

if [[ -z "${BEFORE}" || "${BEFORE}" =~ ^0+$ ]]; then
  echo "нет предыдущего коммита, метки не ставим"
  exit 0
fi

if ! git rev-parse --verify --quiet "${BEFORE}^{commit}" >/dev/null; then
  echo "ERROR: нет коммита ${BEFORE}" >&2
  exit 1
fi
if ! git rev-parse --verify --quiet "${SHA}^{commit}" >/dev/null; then
  echo "ERROR: нет коммита ${SHA}" >&2
  exit 1
fi

component_of() {
  local path="$1"
  case "${path}" in
    deploy/ui/app/public/data/explorer-group-mask.js) echo "ui worker" ;;
    deploy/ui/*) echo ui ;;
    deploy/detection/*) echo detection ;;
    deploy/worker/*|deploy/analytics/*) echo worker ;;
    scripts/traffic_rollup_async.py|scripts/traffic_rollup_jobs.py|scripts/flow_thinning.py) echo worker ;;
    deploy/enrichment/*) echo enrichment ;;
    scripts/load_rir_geo.py|scripts/rebuild_bgp_origin_asn.py|scripts/load_asn_names.py|scripts/load_iptoasn_prefixes.py|scripts/snmp_iface_sync.py) echo enrichment ;;
    deploy/schema/*|deploy/clickhouse/*) echo schema ;;
    cmd/xdpflowd/*|cmd/flowcollectord/*|bpf/*|deploy/collector-dist/*) echo collector ;;
    deploy/systemd/xdpflowd*|deploy/systemd/flowcollectord*) echo collector ;;
    *) echo "" ;;
  esac
}

if [[ "${DRY_RUN}" -eq 0 ]]; then
  git fetch origin --tags --quiet
fi

day="$(TZ=Europe/Moscow date +%Y.%m.%d)"
changed="$(git diff --name-only "${BEFORE}" "${SHA}")"

hit=""
while IFS= read -r path; do
  [[ -z "${path}" ]] && continue
  for name in $(component_of "${path}"); do
    case " ${hit} " in
      *" ${name} "*) ;;
      *) hit="${hit} ${name}" ;;
    esac
  done
done <<< "${changed}"

if [[ -z "${hit// /}" ]]; then
  echo "компоненты не менялись, метки не нужны"
  exit 0
fi

for name in ui detection worker enrichment schema collector; do
  case " ${hit} " in
    *" ${name} "*) ;;
    *) continue ;;
  esac
  prefix="${name}-${day}."
  max=0
  while IFS= read -r existing; do
    [[ -z "${existing}" ]] && continue
    n="${existing##*.}"
    [[ "${n}" =~ ^[0-9]+$ ]] || continue
    if (( n > max )); then
      max="${n}"
    fi
  done < <(git tag -l "${prefix}*")
  tag="${prefix}$((max + 1))"
  if git rev-parse --verify --quiet "refs/tags/${tag}" >/dev/null; then
    echo "уже есть ${tag}"
    continue
  fi
  echo "метка ${tag} → ${SHA}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    continue
  fi
  git tag "${tag}" "${SHA}"
  git push origin "refs/tags/${tag}:refs/tags/${tag}"
done
