#!/usr/bin/env bash
# Сравнивает раскладку flows_raw с раскладкой, которую использует Akvorado,
# на одной и той же выборке данных. Три варианта отличаются по одному шагу:
#   A — как сейчас: ключ сортировки только время, ZSTD, сырые типы
#   B — как сейчас по типам, но ключ сортировки как в Akvorado
#   C — как в Akvorado: плюс LowCardinality, DateTime вместо DateTime64(9), LZ4
# Так видно, что даёт порядок сортировки, а что типы и кодеки.
set -uo pipefail

CH() { sudo -n docker exec -i grapes-clickhouse clickhouse-client --max_execution_time 900 "$@"; }
# LowCardinality(IPv6) требует снятия предохранителя, как это делает сам Akvorado.
CHLC() { CH --allow_suspicious_low_cardinality_types 1 "$@"; }

HOURS=${HOURS:-1}
DB=default
FROM="toStartOfHour(now() - INTERVAL $((HOURS+1)) HOUR)"
TO="toStartOfHour(now() - INTERVAL 1 HOUR)"

SAMPLER_IP="if(length(sampler_address)=16 AND substring(sampler_address,5)=unhex('000000000000000000000000'),
      toString(toIPv4(reinterpretAsUInt32(reverse(substring(sampler_address,1,4))))), IPv6NumToString(sampler_address))"
IFIDX="if(in_if > 0 AND bitShiftRight(in_if,30)=0, bitAnd(in_if,1073741823), toUInt32(0))"

echo "### готовлю выборку за $HOURS ч"
# KEEP=1 оставляет уже наполненные таблицы и пересобирает только недостающие.
if [ "${KEEP:-0}" != 1 ]; then
  for t in a b c; do CH -q "DROP TABLE IF EXISTS ${DB}.layout_$t"; done
fi
have() { [ "$(CH -q "EXISTS TABLE ${DB}.layout_$1")" = 1 ]; }

# A: сегодняшняя раскладка.
have a || CH -q "CREATE TABLE ${DB}.layout_a (
  time_received_ns DateTime64(9) CODEC(DoubleDelta, ZSTD(1)),
  date Date,
  sampler_address FixedString(16),
  in_if UInt32, out_if UInt32,
  src_asn UInt32 CODEC(T64, ZSTD(1)), dst_asn UInt32 CODEC(T64, ZSTD(1)),
  proto UInt32 CODEC(T64, ZSTD(1)),
  direction LowCardinality(String),
  bytes UInt64 CODEC(T64, ZSTD(1)), packets UInt64 CODEC(T64, ZSTD(1))
) ENGINE = MergeTree PARTITION BY date ORDER BY time_received_ns"

# B: те же типы, ключ сортировки как в Akvorado.
have b || CH -q "CREATE TABLE ${DB}.layout_b AS ${DB}.layout_a
ENGINE = MergeTree PARTITION BY date
PRIMARY KEY toStartOfFiveMinutes(time_received_ns)
ORDER BY (toStartOfFiveMinutes(time_received_ns), sampler_address, in_if, out_if)"

# C: раскладка Akvorado целиком — имя порта колонкой, LowCardinality, DateTime, LZ4.
have c || CHLC -q "CREATE TABLE ${DB}.layout_c (
  TimeReceived DateTime CODEC(DoubleDelta, LZ4),
  ExporterAddress LowCardinality(IPv6),
  InIfName LowCardinality(String), OutIfName LowCardinality(String),
  InIfDescription LowCardinality(String),
  SrcAS UInt32, DstAS UInt32,
  Proto UInt32,
  FlowDirection LowCardinality(String),
  Bytes UInt64 CODEC(T64, LZ4), Packets UInt64 CODEC(T64, LZ4)
) ENGINE = MergeTree
PARTITION BY toYYYYMMDDhhmmss(toStartOfInterval(TimeReceived, INTERVAL 25920 SECOND))
PRIMARY KEY toStartOfFiveMinutes(TimeReceived)
ORDER BY (toStartOfFiveMinutes(TimeReceived), ExporterAddress, InIfName, OutIfName)"

SRC="FROM ${DB}.flows_raw PREWHERE date >= toDate($FROM)-1 AND date <= toDate($TO)
     WHERE time_received_ns >= $FROM AND time_received_ns < $TO"

empty() { [ "$(CH -q "SELECT count() FROM ${DB}.layout_$1")" = 0 ]; }

empty a && { CH -q "INSERT INTO ${DB}.layout_a SELECT time_received_ns, date, sampler_address, in_if, out_if,
  src_asn, dst_asn, proto, direction, bytes, packets $SRC" || exit 1; }
empty b && { CH -q "INSERT INTO ${DB}.layout_b SELECT * FROM ${DB}.layout_a" || exit 1; }
# Имя и описание порта подставляются на входе, как это делает Akvorado.
empty c && { CH -q "INSERT INTO ${DB}.layout_c
SELECT toDateTime(f.time_received_ns) AS TimeReceived,
       toIPv6($SAMPLER_IP) AS ExporterAddress,
       ifNull(nullIf(si.if_name,''),'') AS InIfName,
       ifNull(nullIf(so.if_name,''),'') AS OutIfName,
       ifNull(nullIf(si.if_alias,''),'') AS InIfDescription,
       f.src_asn, f.dst_asn, f.proto, f.direction, f.bytes, f.packets
FROM ${DB}.flows_raw AS f
LEFT JOIN ${DB}.net_interfaces_current AS si ON si.switch_ip = $SAMPLER_IP AND si.if_index = $IFIDX
LEFT JOIN ${DB}.net_interfaces_current AS so ON so.switch_ip = $SAMPLER_IP
  AND so.if_index = if(f.out_if > 0 AND bitShiftRight(f.out_if,30)=0, bitAnd(f.out_if,1073741823), toUInt32(0))
PREWHERE f.date >= toDate($FROM)-1 AND f.date <= toDate($TO)
WHERE f.time_received_ns >= $FROM AND f.time_received_ns < $TO" || exit 1; }

CH -q "SYSTEM FLUSH LOGS" >/dev/null

echo
echo "### сколько занимают на диске"
CH -q "SELECT table AS variant, formatReadableQuantity(sum(rows)) AS rows_n, formatReadableSize(sum(data_compressed_bytes)) AS on_disk, round(sum(data_uncompressed_bytes)/sum(data_compressed_bytes),1) AS ratio
FROM system.parts WHERE database='$DB' AND table LIKE 'layout_%' AND active
GROUP BY table ORDER BY table FORMAT PrettyCompactMonoBlock"

echo
echo "### сжатие колонок порта и ASN"
CH -q "SELECT table AS variant, name AS col, formatReadableSize(sum(data_compressed_bytes)) AS on_disk, round(sum(data_uncompressed_bytes)/sum(data_compressed_bytes),1) AS ratio
FROM system.parts_columns WHERE database='$DB' AND table LIKE 'layout_%' AND active
  AND name IN ('in_if','InIfName','src_asn','SrcAS','sampler_address','ExporterAddress','time_received_ns','TimeReceived')
GROUP BY table, name ORDER BY col, variant FORMAT PrettyCompactMonoBlock"

bench() {
  tag=$1; sql=$2; qid="layout-$tag-$RANDOM"
  CH --query_id "$qid" -q "$sql" >/dev/null 2>&1
  CH -q "SYSTEM FLUSH LOGS" >/dev/null
  CH -q "SELECT '$tag' AS variant, round(query_duration_ms/1000,2) AS sec,
    formatReadableQuantity(read_rows) AS rows_read, formatReadableSize(read_bytes) AS bytes_read
    FROM system.query_log WHERE query_id='$qid' AND type='QueryFinish' FORMAT TSV"
}

# Порт для фильтра берём из самих данных: самая нагруженная пара «адрес + порт»
# среди значений стандартного формата, у прочих ifIndex не определён.
read -r SAMP IF_RAW <<<"$(CH -q "SELECT hex(sampler_address), toString(in_if) FROM ${DB}.layout_a
  WHERE in_if > 0 AND bitShiftRight(in_if, 30) = 0
  GROUP BY sampler_address, in_if ORDER BY sum(bytes) DESC LIMIT 1" --format TSV)"
IF_NAME=$(CH -q "SELECT any(if_name) FROM ${DB}.net_interfaces_current
  WHERE switch_ip = toString(toIPv4(reinterpretAsUInt32(reverse(substring(unhex('$SAMP'), 1, 4)))))
    AND if_index = bitAnd($IF_RAW, 1073741823)")

echo "### фильтруем по порту: ifIndex=$((IF_RAW & 1073741823)), имя='$IF_NAME'"
[ -n "$IF_NAME" ] || { echo "не удалось сопоставить порт с инвентарём"; exit 1; }

echo
echo "### итог по одному порту"
bench "A_seychas"      "SELECT sum(bytes),sum(packets),count() FROM ${DB}.layout_a WHERE sampler_address=unhex('$SAMP') AND in_if=$IF_RAW"
bench "B_kluch_akv"    "SELECT sum(bytes),sum(packets),count() FROM ${DB}.layout_b WHERE sampler_address=unhex('$SAMP') AND in_if=$IF_RAW"
bench "C_vsyo_akv"     "SELECT sum(Bytes),sum(Packets),count() FROM ${DB}.layout_c WHERE InIfName='$IF_NAME'"

echo
echo "### топ ASN по этому порту"
bench "A_seychas"      "SELECT src_asn,sum(bytes) b FROM ${DB}.layout_a WHERE sampler_address=unhex('$SAMP') AND in_if=$IF_RAW GROUP BY src_asn ORDER BY b DESC LIMIT 25"
bench "B_kluch_akv"    "SELECT src_asn,sum(bytes) b FROM ${DB}.layout_b WHERE sampler_address=unhex('$SAMP') AND in_if=$IF_RAW GROUP BY src_asn ORDER BY b DESC LIMIT 25"
bench "C_vsyo_akv"     "SELECT SrcAS,sum(Bytes) b FROM ${DB}.layout_c WHERE InIfName='$IF_NAME' GROUP BY SrcAS ORDER BY b DESC LIMIT 25"

echo
echo "### весь период без фильтра — топ ASN"
bench "A_seychas"      "SELECT src_asn,sum(bytes) b FROM ${DB}.layout_a GROUP BY src_asn ORDER BY b DESC LIMIT 25"
bench "C_vsyo_akv"     "SELECT SrcAS,sum(Bytes) b FROM ${DB}.layout_c GROUP BY SrcAS ORDER BY b DESC LIMIT 25"

echo
echo "### отсев гранул фильтром по порту — сейчас"
CH -q "EXPLAIN indexes=1 SELECT sum(bytes) FROM ${DB}.layout_a WHERE sampler_address=unhex('$SAMP') AND in_if=$IF_RAW" | grep -A4 'PrimaryKey'
echo "### то же в раскладке Akvorado"
CH -q "EXPLAIN indexes=1 SELECT sum(Bytes) FROM ${DB}.layout_c WHERE InIfName='$IF_NAME'" | grep -A5 'PrimaryKey'
