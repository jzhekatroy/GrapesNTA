#!/usr/bin/env bash
# Печатает версию компонента в текущем коде: detection-v1.0.2.
# Если файлы компонента менялись после метки, добавляет коммит: detection-v1.0.2+ab12cd34.
#
#   scripts/component-version.sh detection

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
# shellcheck source=component-paths.sh
source "${ROOT}/scripts/component-paths.sh"

name="${1:?нужно имя компонента: ${COMPONENTS}}"

version="$(latest_version "${name}" --merged HEAD)"
if [[ -z "${version}" ]]; then
  echo "${name}-unknown"
  exit 0
fi

tag="${name}-v${version}"
while IFS= read -r path; do
  [[ -z "${path}" ]] && continue
  case " $(component_of "${path}") " in
    *" ${name} "*)
      echo "${tag}+$(git rev-parse --short=8 HEAD)"
      exit 0
      ;;
  esac
done <<< "$(git diff --name-only "${tag}" HEAD)"

echo "${tag}"
