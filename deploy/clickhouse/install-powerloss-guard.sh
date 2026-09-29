#!/usr/bin/env bash
# Idempotent. Puts the power-loss guard on the local ClickHouse:
#   config.d/broken_parts.xml  — attach the table even with thousands of broken parts
#   quarantine oneshot         — move all-empty parts aside before ClickHouse starts
# No-op when this host has no ClickHouse. Does not restart the server:
# the setting is read on the next start, which is when it matters.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config_dir=""
data_dir=""

if command -v docker >/dev/null 2>&1; then
  mounts="$(docker inspect -f '{{range .Mounts}}{{.Destination}} {{.Source}}{{"\n"}}{{end}}' grapes-clickhouse 2>/dev/null || true)"
  while read -r dest src; do
    [[ -n "${dest}" && -n "${src}" ]] || continue
    case "${dest}" in
      /var/lib/clickhouse) data_dir="${src}" ;;
      /etc/clickhouse-server) config_dir="${src}/config.d" ;;
      /etc/clickhouse-server/config.d) config_dir="${src}" ;;
    esac
  done <<<"${mounts}"
fi

if [[ -z "${config_dir}" && -d /etc/clickhouse-server/config.d ]]; then
  config_dir=/etc/clickhouse-server/config.d
  data_dir="${data_dir:-/var/lib/clickhouse}"
fi

if [[ -z "${config_dir}" || ! -d "${config_dir}" ]]; then
  echo "power-loss guard: no local ClickHouse, skip"
  exit 0
fi

data_dir="${data_dir:-/var/lib/clickhouse}"
install -m 644 "${REPO_ROOT}/deploy/clickhouse/broken_parts.xml" "${config_dir}/broken_parts.xml"
install -m 755 "${REPO_ROOT}/deploy/clickhouse/quarantine-empty-parts.sh" /usr/local/sbin/clickhouse-quarantine-empty-parts.sh

unit="$(mktemp)"
sed "s|^Environment=CH_DATA=.*|Environment=CH_DATA=${data_dir}|" \
  "${REPO_ROOT}/deploy/systemd/clickhouse-quarantine-empty-parts.service" >"${unit}"
install -m 644 "${unit}" /etc/systemd/system/clickhouse-quarantine-empty-parts.service
rm -f "${unit}"
systemctl daemon-reload
systemctl enable clickhouse-quarantine-empty-parts.service
echo "power-loss guard: config=${config_dir}/broken_parts.xml data=${data_dir}"
