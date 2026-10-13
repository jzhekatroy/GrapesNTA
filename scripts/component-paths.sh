# Какие файлы к какому компоненту относятся. Подключается через source.

COMPONENTS="ui detection worker enrichment schema collector"

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

# Наибольшая версия компонента X.Y.Z по меткам name-vX.Y.Z.
# Дополнительные аргументы уходят в git tag, например --merged HEAD.
latest_version() {
  local name="$1"
  shift
  git tag "$@" -l "${name}-v*" \
    | sed -n "s/^${name}-v\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$/\1/p" \
    | sort -t. -k1,1n -k2,2n -k3,3n \
    | tail -n 1
}

# patch: 1.0.1 → 1.0.2, minor: 1.0.1 → 1.1.0, major: 1.0.1 → 2.0.0.
next_version() {
  local base="$1" level="$2" major minor patch
  if [[ -z "${base}" ]]; then
    echo "1.0.0"
    return
  fi
  IFS=. read -r major minor patch <<< "${base}"
  case "${level}" in
    patch) patch=$((patch + 1)) ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    major) major=$((major + 1)); minor=0; patch=0 ;;
    *) echo "ERROR: уровень ${level}, нужен patch, minor или major" >&2; return 1 ;;
  esac
  echo "${major}.${minor}.${patch}"
}
