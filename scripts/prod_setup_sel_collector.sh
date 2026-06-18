#!/usr/bin/env bash
# prod_setup_sel_collector.sh — sel as separate collector: xdp-sel + dns-sel.
#
# Prerequisites:
#   - xdpflowd already enabled (prod_enable_xdpflowd_sel.sh)
#   - ClickHouse catalog: deploy/clickhouse/register_sel_collector.sql applied
#   - /etc/xdpflowd/sel.env with XDP_CH_DSN
#
# Run on sel as root:
#   cd /root/GrapesNTA && sudo ./scripts/prod_setup_sel_collector.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
XDP_ENV="${XDP_ENV:-/etc/xdpflowd/sel.env}"
DNS_ENV="${DNS_ENV:-/etc/dnsflowd/sel.env}"
IFACE="${IFACE:-enp4s0np0}"
SAMPLER="${SAMPLER:-95.215.0.26}"

need_root() { [[ "${EUID:-}" -eq 0 ]] || { echo "run as root" >&2; exit 1; }; }

upsert_env() {
  local file="$1" key="$2" value="$3"
  touch "$file"
  chmod 0600 "$file"
  if grep -q "^${key}=" "$file" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    echo "${key}=${value}" >> "$file"
  fi
}

need_root

short="$(hostname -s 2>/dev/null || hostname | cut -d. -f1)"
if [[ "$short" != "sel" ]]; then
  echo "ERROR: expected hostname -s=sel, got $short" >&2
  exit 1
fi

if [[ ! -r "$XDP_ENV" ]]; then
  echo "ERROR: missing $XDP_ENV" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$XDP_ENV"
if [[ -z "${XDP_CH_DSN:-}" ]]; then
  echo "ERROR: XDP_CH_DSN not set in $XDP_ENV" >&2
  exit 1
fi

echo "[$(date +%T)] build dnsflowd..."
cd "$REPO_ROOT"
make build-dns

echo "[$(date +%T)] update xdpflowd env → source_id=xdp-sel, DNS passthrough on..."
upsert_env "$XDP_ENV" REPO_ROOT "$REPO_ROOT"
upsert_env "$XDP_ENV" XDPFLOWD_SOURCE_ID xdp-sel
upsert_env "$XDP_ENV" XDP_CH_SAMPLER_ADDR "$SAMPLER"
upsert_env "$XDP_ENV" XDP_DNS_PASSTHROUGH 1
upsert_env "$XDP_ENV" IFACE "$IFACE"

echo "[$(date +%T)] create dnsflowd env..."
mkdir -p /etc/dnsflowd
if [[ ! -f "$DNS_ENV" ]]; then
  cp "$REPO_ROOT/deploy/sel/dnsflowd.env.example" "$DNS_ENV"
fi

upsert_env "$DNS_ENV" REPO_ROOT "$REPO_ROOT"
upsert_env "$DNS_ENV" DNSFLOWD_BIN '${REPO_ROOT}/bin/dnsflowd'
upsert_env "$DNS_ENV" IFACE "$IFACE"
upsert_env "$DNS_ENV" DNSFLOWD_SOURCE_ID dns-sel
upsert_env "$DNS_ENV" DNS_CH_DSN "$XDP_CH_DSN"
upsert_env "$DNS_ENV" DNS_CH_TABLE default.dns_log
upsert_env "$DNS_ENV" DNS_CH_ANSWERS_TABLE default.dns_answers
upsert_env "$DNS_ENV" DNS_CH_SAMPLER_ADDR "$SAMPLER"
upsert_env "$DNS_ENV" DNSFLOWD_EXPECT_HOST_SHORT sel
upsert_env "$DNS_ENV" DNS_CH_RAW_ENABLED 1
upsert_env "$DNS_ENV" DNS_CH_ANSWERS_ENABLED 1

echo "[$(date +%T)] install dnsflowd systemd unit..."
TMP_UNIT="$(mktemp)"
sed "s|/opt/GrapesNTA|${REPO_ROOT}|g" "$REPO_ROOT/deploy/sel/dnsflowd.service" > "$TMP_UNIT"
install -m 0644 "$TMP_UNIT" /etc/systemd/system/dnsflowd.service
rm -f "$TMP_UNIT"
chmod +x "$REPO_ROOT/deploy/sel/dnsflowd-exec.sh"

systemctl daemon-reload

echo "[$(date +%T)] restart xdpflowd (enable DNS passthrough in BPF)..."
systemctl restart xdpflowd
sleep 3
if ! systemctl is-active --quiet xdpflowd; then
  journalctl -u xdpflowd -n 40 --no-pager >&2 || true
  exit 1
fi

echo "[$(date +%T)] start dnsflowd..."
systemctl enable dnsflowd
systemctl restart dnsflowd
sleep 3
if ! systemctl is-active --quiet dnsflowd; then
  journalctl -u dnsflowd -n 40 --no-pager >&2 || true
  exit 1
fi

echo ""
echo "======================================================================"
echo "sel collector ready"
echo "  xdpflowd:  source_id=xdp-sel  sampler=$SAMPLER  (systemctl status xdpflowd)"
echo "  dnsflowd:  source_id=dns-sel   sampler=$SAMPLER  (systemctl status dnsflowd)"
echo "  CH catalog: collector_id=sel, sources xdp-sel + dns-sel (include_in_total=0)"
echo ""
echo "Verify:"
echo "  journalctl -u xdpflowd -n 5 --no-pager | grep source_id"
echo "  journalctl -u dnsflowd -n 10 --no-pager"
echo "======================================================================"
