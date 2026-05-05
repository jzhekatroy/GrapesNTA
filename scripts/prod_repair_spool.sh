#!/usr/bin/env bash
# prod_repair_spool.sh — offline-помощник для ремонта consumer.json у durable
# spool, если drainer завис на повреждённом фрейме (например, из-за torn
# write старой версии). Нужен только если в БОЕВОМ запуске нет авто-resync
# (см. drainerLoop в clickhouse_spool.go) — после внедрения авто-resync скрипт
# становится страховкой "на случай чего".
#
# Что делает:
#   1) Останавливает xdpflowd (без блокировки), при необходимости SIGKILL.
#   2) Бэкапит текущие consumer.json и подозрительный сегмент.
#   3) Сканирует подозрительный сегмент в поисках следующего PFLX-magic
#      после текущего offset; если нашёл — обновляет consumer.json. Если
#      следующего magic нет — катится на segment+1 offset=0.
#   4) Печатает план; --apply применяет, без него только dry-run.
#
# Использование:
#   sudo ./prod_repair_spool.sh                    # dry-run, ничего не меняет
#   sudo ./prod_repair_spool.sh --apply            # применить и стартовать
#   sudo SPOOL_DIR=/var/lib/xdpflowd/ch-spool ./prod_repair_spool.sh --apply
#
# Переменные окружения:
#   SPOOL_DIR        — путь к spool (default /var/lib/xdpflowd/ch-spool).
#   SERVICE          — имя systemd unit (default xdpflowd).
#   STOP_TIMEOUT_SEC — сколько ждать после `systemctl stop --no-block` перед
#                      SIGKILL (default 20).
#   START_AFTER      — если 1, после --apply поднять сервис (default 1).

set -Eeuo pipefail

readonly SPOOL_DIR="${SPOOL_DIR:-/var/lib/xdpflowd/ch-spool}"
readonly SERVICE="${SERVICE:-xdpflowd}"
readonly STOP_TIMEOUT_SEC="${STOP_TIMEOUT_SEC:-20}"
readonly START_AFTER="${START_AFTER:-1}"

APPLY=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    -h|--help)
      sed -n '2,28p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $arg"; exit 2 ;;
  esac
done

log() { printf '%s [repair] %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

[[ -d "$SPOOL_DIR" ]] || die "SPOOL_DIR=$SPOOL_DIR не существует"

readonly META="$SPOOL_DIR/meta"
readonly SEGS="$SPOOL_DIR/segments"
readonly CP="$META/consumer.json"

[[ -d "$SEGS" ]] || die "$SEGS не существует"

# 1) Стоп сервиса (idempotent).
if [[ "$APPLY" == "1" ]]; then
  if systemctl is-active --quiet "$SERVICE"; then
    log "stopping $SERVICE (with timeout ${STOP_TIMEOUT_SEC}s)"
    systemctl stop --no-block "$SERVICE" || true
    for ((i=0; i<STOP_TIMEOUT_SEC; i++)); do
      systemctl is-active --quiet "$SERVICE" || break
      sleep 1
    done
    if systemctl is-active --quiet "$SERVICE"; then
      log "service still active, sending SIGKILL"
      systemctl kill -s SIGKILL "$SERVICE" || true
      sleep 2
    fi
  fi
  if pgrep -x xdpflowd >/dev/null; then
    log "killing residual xdpflowd processes"
    pkill -9 -x xdpflowd || true
    sleep 1
  fi
fi

# 2) Текущий чекпоинт.
if [[ -s "$CP" ]]; then
  CUR_SEG=$(awk -F'[: ,}]+' '/segment/{print $3; exit}' "$CP")
  CUR_OFF=$(awk -F'[: ,}]+' '/offset/{print $3; exit}' "$CP")
else
  CUR_SEG=1
  CUR_OFF=0
fi
[[ "$CUR_SEG" =~ ^[0-9]+$ ]] || die "не смог распарсить segment из $CP"
[[ "$CUR_OFF" =~ ^[0-9]+$ ]] || die "не смог распарсить offset из $CP"

CUR_SEG_FILE="$SEGS/$(printf '%016d.seg' "$CUR_SEG")"
log "current checkpoint: segment=$CUR_SEG offset=$CUR_OFF"
log "segment file: $CUR_SEG_FILE"

# 3) Список доступных сегментов.
mapfile -t ALL_SEGS < <(ls -1 "$SEGS"/*.seg 2>/dev/null | sort)
if [[ ${#ALL_SEGS[@]} -eq 0 ]]; then
  die "в $SEGS нет .seg файлов — нечего чинить"
fi
LAST_SEG_BASENAME=$(basename "${ALL_SEGS[-1]}" .seg)
LAST_SEG=$((10#$LAST_SEG_BASENAME))
log "segments range: $(basename "${ALL_SEGS[0]}" .seg) .. $LAST_SEG_BASENAME (count=${#ALL_SEGS[@]})"

# 4) Поиск следующего PFLX-magic в текущем сегменте.
NEW_SEG="$CUR_SEG"
NEW_OFF="$CUR_OFF"
SCAN_STATUS="not-needed"

if [[ ! -e "$CUR_SEG_FILE" ]]; then
  log "current segment file missing → roll to next"
  NEW_SEG=$((CUR_SEG + 1))
  NEW_OFF=0
  SCAN_STATUS="rolled-no-file"
else
  SEG_SIZE=$(stat -c %s "$CUR_SEG_FILE")
  if [[ "$CUR_OFF" -ge "$SEG_SIZE" ]]; then
    if [[ "$CUR_SEG" -lt "$LAST_SEG" ]]; then
      NEW_SEG=$((CUR_SEG + 1))
      NEW_OFF=0
      SCAN_STATUS="rolled-eof"
    else
      log "checkpoint at EOF of last segment, nothing to repair"
      SCAN_STATUS="at-eof"
    fi
  else
    log "scanning $CUR_SEG_FILE from offset=$((CUR_OFF + 1)) for next PFLX magic..."
    # PFLX big-endian = 50 46 4c 58
    NEXT_HIT=$(LC_ALL=C tail -c +"$((CUR_OFF + 2))" "$CUR_SEG_FILE" \
      | od -An -v -tx1 -w16 \
      | awk -v base="$((CUR_OFF + 1))" '
          BEGIN { found = -1 }
          {
            line = ""
            for (i = 1; i <= NF; i++) line = line $i
            n = length(line) / 2
            for (i = 0; i + 4 <= n; i++) {
              s = substr(line, i*2 + 1, 8)
              if (s == "50464c58") {
                found = base + (NR - 1) * 16 + i
                print found
                exit
              }
            }
          }
          END { if (found == -1) print "" }
        ')
    if [[ -n "$NEXT_HIT" ]]; then
      NEW_OFF="$NEXT_HIT"
      SCAN_STATUS="found-magic"
      log "next magic found at offset=$NEW_OFF (skipping $((NEW_OFF - CUR_OFF)) bytes)"
    else
      if [[ "$CUR_SEG" -lt "$LAST_SEG" ]]; then
        NEW_SEG=$((CUR_SEG + 1))
        NEW_OFF=0
        SCAN_STATUS="rolled-no-magic"
        log "no magic in segment $CUR_SEG → rolling to segment $NEW_SEG"
      else
        SCAN_STATUS="stuck-in-tail"
        log "WARNING: no magic and this is the last segment — drainer would have to wait for more data"
      fi
    fi
  fi
fi

cat <<EOF

=== plan ===
spool dir : $SPOOL_DIR
service   : $SERVICE
old cp    : segment=$CUR_SEG offset=$CUR_OFF
new cp    : segment=$NEW_SEG offset=$NEW_OFF
status    : $SCAN_STATUS
apply     : $([[ "$APPLY" == "1" ]] && echo YES || echo NO)
EOF

if [[ "$APPLY" != "1" ]]; then
  log "dry-run completed; re-run with --apply to commit"
  exit 0
fi

if [[ "$NEW_SEG" == "$CUR_SEG" && "$NEW_OFF" == "$CUR_OFF" ]]; then
  log "checkpoint unchanged; nothing to write"
else
  TS=$(date +%Y%m%dT%H%M%SZ)
  if [[ -e "$CP" ]]; then
    cp -a "$CP" "${CP}.bak.${TS}"
    log "backup: ${CP}.bak.${TS}"
  fi
  if [[ -e "$CUR_SEG_FILE" && "$SCAN_STATUS" =~ ^(found-magic|rolled-no-magic|rolled-eof)$ ]]; then
    cp -a "$CUR_SEG_FILE" "${CUR_SEG_FILE}.suspect.${TS}"
    log "suspect segment archived: ${CUR_SEG_FILE}.suspect.${TS}"
  fi
  install -d -m 0755 "$META"
  printf '{\n  "segment": %d,\n  "offset": %d\n}\n' "$NEW_SEG" "$NEW_OFF" > "${CP}.tmp"
  mv "${CP}.tmp" "$CP"
  log "wrote new checkpoint: $CP"
fi

if [[ "$START_AFTER" == "1" ]]; then
  log "starting $SERVICE"
  systemctl start "$SERVICE"
  sleep 3
  if systemctl is-active --quiet "$SERVICE"; then
    log "$SERVICE is active"
  else
    log "WARNING: $SERVICE failed to start; check journalctl -u $SERVICE -n 80"
    exit 1
  fi
fi

log "done"
