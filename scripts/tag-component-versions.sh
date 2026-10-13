#!/usr/bin/env bash
# Ставит метки версий компонентов: detection-v1.0.2.
#
# После слияния в main (последняя цифра +1 у изменившихся компонентов):
#   BEFORE=<sha до пуша> SHA=<sha пуша> scripts/tag-component-versions.sh
#
# Выпуск вручную (средняя или первая цифра):
#   COMPONENT=collector LEVEL=minor SHA=<sha> scripts/tag-component-versions.sh
#
#   DRY_RUN=1 — только печатает метки, на GitHub не отправляет.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
# shellcheck source=component-paths.sh
source "${ROOT}/scripts/component-paths.sh"

BEFORE="${BEFORE:-}"
SHA="${SHA:-HEAD}"
COMPONENT="${COMPONENT:-}"
LEVEL="${LEVEL:-patch}"
DRY_RUN="${DRY_RUN:-0}"

if ! git rev-parse --verify --quiet "${SHA}^{commit}" >/dev/null; then
  echo "ERROR: нет коммита ${SHA}" >&2
  exit 1
fi

if [[ "${DRY_RUN}" -eq 0 ]]; then
  git fetch origin --tags --quiet
fi

put_tag() {
  local name="$1" level="$2" base next tag
  base="$(latest_version "${name}")"
  next="$(next_version "${base}" "${level}")"
  tag="${name}-v${next}"
  echo "метка ${tag} → ${SHA}${base:+ (было v${base})}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return
  fi
  git tag "${tag}" "${SHA}"
  git push origin "refs/tags/${tag}:refs/tags/${tag}"
}

if [[ -n "${COMPONENT}" ]]; then
  case " ${COMPONENTS} " in
    *" ${COMPONENT} "*) ;;
    *) echo "ERROR: нет компонента ${COMPONENT}, есть: ${COMPONENTS}" >&2; exit 1 ;;
  esac
  put_tag "${COMPONENT}" "${LEVEL}"
  exit 0
fi

if [[ -z "${BEFORE}" || "${BEFORE}" =~ ^0+$ ]]; then
  echo "нет предыдущего коммита, метки не ставим"
  exit 0
fi
if ! git rev-parse --verify --quiet "${BEFORE}^{commit}" >/dev/null; then
  echo "ERROR: нет коммита ${BEFORE}" >&2
  exit 1
fi

hit=""
while IFS= read -r path; do
  [[ -z "${path}" ]] && continue
  for name in $(component_of "${path}"); do
    case " ${hit} " in
      *" ${name} "*) ;;
      *) hit="${hit} ${name}" ;;
    esac
  done
done <<< "$(git diff --name-only "${BEFORE}" "${SHA}")"

if [[ -z "${hit// /}" ]]; then
  echo "компоненты не менялись, метки не нужны"
  exit 0
fi

for name in ${COMPONENTS}; do
  case " ${hit} " in
    *" ${name} "*) put_tag "${name}" patch ;;
  esac
done
