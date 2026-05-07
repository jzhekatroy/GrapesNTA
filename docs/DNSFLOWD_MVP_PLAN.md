# dnsflowd — MVP план реализации

Документ для агента, который будет исполнять задачу. Все пути относительны корня
репозитория `GrapesNTA/`. Где это важно — пути на проде (`/opt/GrapesNTA`,
`/etc/xdpflowd/`, `/etc/dnsflowd/`).

## 1. Цель

Записывать DNS-запросы и ответы со SPAN/mirror-трафика в отдельную таблицу
ClickHouse `default.dns_log`. Поток flow-аналитики (`xdpflowd` → `flows_raw`)
**не трогаем** функционально — только добавляем гейтированный pass-through
для UDP/53.

### Что хотим в итоге

- Два независимых systemd-юнита: `xdpflowd.service` (как сейчас) и новый
  `dnsflowd.service` (новый).
- Две таблицы в одном инстансе ClickHouse: `default.flows_raw` (без изменений)
  и новая `default.dns_log`.
- `dnsflowd` слушает тот же mirror-интерфейс через `AF_PACKET` с kernel-BPF
  фильтром `udp port 53`.
- Откат — `systemctl stop dnsflowd && systemctl disable dnsflowd`. Это
  не влияет на `xdpflowd`.

### Не цели MVP

- Обогащение `flows_raw` доменом (дальнейший шаг — материализованная view
  `ip_to_domain` + JOIN). Делаем после MVP, когда увидим объёмы.
- Парсинг TLS ClientHello / SNI / JA3.
- Свой durable spool для `dnsflowd` — пока in-memory bounded queue с
  drop-on-overflow, как у `clickhouseSink` сейчас в `xdpflowd`.
- UI / алерты / DGA-детекция.

## 2. Архитектура

```
mirror traffic → enp4s0np0 (sel) / enp5s0d1 (netflow)
                   │
                   │ XDP отрабатывает первым
                   │
                   ├── XDP (xdpflowd, eBPF):
                   │     - обновляет flow_value в hash map
                   │     - возвращает XDP_DROP (если -xdp-action drop)
                   │     - НО для UDP/53, если включён dns_passthrough → XDP_PASS
                   │
                   └── (UDP/53 пакеты прошли мимо XDP_DROP)
                       │
                       ▼
                  AF_PACKET socket (dnsflowd) с BPF "udp port 53"
                       │
                       ▼
                  парсер DNS (golang.org/x/net/dns/dnsmessage)
                       │
                       ▼
                  bounded queue → batch INSERT → ClickHouse.dns_log
```

### Инварианты, которые нельзя нарушить

1. **С `XDP_DNS_PASSTHROUGH=0` поведение `xdpflowd` идентично текущему.**
   Значит `xdpflowd` без флага и старый `xdpflowd` ведут себя одинаково —
   safe rollout.
2. **DNS-пакеты по-прежнему попадают в `flows_raw`** (счётчики обновляются
   до `return XDP_PASS`) — мы не теряем UDP/53 во flow-аналитике.
3. `dnsflowd` пишет в **отдельную таблицу**, не блокирует основной путь.
   Падение `dnsflowd` — нулевое влияние на `xdpflowd` и `flows_raw`.

## 3. Изменения по файлам

### 3.1 ClickHouse-схема — новый файл

**Файл:** `deploy/clickhouse/dns_log.sql` (создать)

```sql
-- DNS log table for dnsflowd. One row per parsed DNS message
-- (query OR response — see is_response).
CREATE TABLE IF NOT EXISTS default.dns_log
(
    ts              DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
    sampler_address FixedString(16),

    client_ip       FixedString(16),  -- src IP пакета (для query — клиент;
                                       -- для response — resolver)
    server_ip       FixedString(16),  -- dst IP пакета
    client_port     UInt16,
    server_port     UInt16,
    is_response     UInt8,            -- 0 = query, 1 = response
    transport       LowCardinality(String) DEFAULT 'udp',  -- udp / tcp (MVP — udp only)

    txid            UInt16,
    rcode           UInt8,            -- 0 NOERROR, 3 NXDOMAIN, ...
    truncated       UInt8,
    recursion_desired   UInt8,
    recursion_available UInt8,

    query_name      String,           -- 'www.youtube.com.' (lowercased, with trailing dot)
    qtype           LowCardinality(String),  -- A / AAAA / CNAME / HTTPS / SVCB / PTR / TXT / ...
    qclass          LowCardinality(String) DEFAULT 'IN',

    answers_a       Array(FixedString(16)),  -- IPv4-mapped в IPv6 (как в flows_raw.src_addr)
    answers_aaaa    Array(FixedString(16)),
    answers_cname   Array(String),
    answer_ttls     Array(UInt32),
    answer_count    UInt16,

    raw_size        UInt16            -- размер UDP payload, для контроля
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, client_ip)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;
```

Замечания:
- `FixedString(16)` для IP, чтобы было совместимо с `flows_raw.src_addr` —
  упростит будущие JOIN.
- `is_response` отделяет запросы от ответов. На MVP писать оба, потом по
  данным решим, нужны ли запросы вообще (часто хватает только ответов).
- `TTL 30 DAY` — DNS-логи быстро теряют ценность; меняется отдельно.

### 3.2 eBPF — добавить условный pass-through для UDP/53

**Файл:** `bpf/xdp_flow.c` (правка)

После строки 43 (`const volatile __u32 xdp_final_action = XDP_PASS;`) добавить:

```c
/*
 * dns_passthrough — when set to 1, UDP packets with src_port=53 or dst_port=53
 * always return XDP_PASS regardless of xdp_final_action. Counters are still
 * updated before the return, so DNS flows still appear in the BPF flow map.
 *
 * Default 0 keeps existing behaviour bit-for-bit. Userspace flips this via
 * RewriteConstants only when dnsflowd is intended to read packets from the
 * same interface via AF_PACKET (XDP_PASS lets packets continue through the
 * kernel network path so the AF_PACKET socket can see them).
 */
const volatile __u32 dns_passthrough = 0;
```

Добавить inline-хелпер рядом с `is_ipv4_fragment` (строки ~148):

```c
/* Force XDP_PASS for UDP/53 when dns_passthrough is enabled. key->src_port and
 * key->dst_port are stored network-order in the flow_key, matching bpf_htons(53).
 */
static __always_inline int dns_must_pass(const struct flow_key *key)
{
	if (!dns_passthrough)
		return 0;
	if (key->proto != IPPROTO_UDP)
		return 0;
	if (key->src_port == bpf_htons(53) || key->dst_port == bpf_htons(53))
		return 1;
	return 0;
}
```

В IPv4 ветке заменить `return xdp_final_action;` (строка ~407) на:

```c
		if (dns_must_pass(&key))
			return XDP_PASS;
		return xdp_final_action;
```

То же самое в IPv6 ветке (строка ~497).

**Тест на регрессию:** компиляция должна пройти теми же командами что и сейчас
(см. Makefile, цель `bpf/xdp_flow.o`). Размер инструкций вырастет на ~20 — это
далеко от лимита verifier'а.

### 3.3 loader — добавить флаг

**Файл:** `internal/loader/loader.go` (правка)

В `Options` добавить поле:

```go
// DNSPassthrough enables forced XDP_PASS for UDP src_port=53 or dst_port=53.
// Required when running alongside dnsflowd, which captures DNS via AF_PACKET.
// 0 = leave compiled default (off), 1 = enable.
DNSPassthrough uint32
```

В `LoadObjectsWithOptions` после блока для `xdp_final_action` добавить:

```go
if opts.DNSPassthrough != 0 {
    if err := spec.RewriteConstants(map[string]interface{}{
        "dns_passthrough": opts.DNSPassthrough,
    }); err != nil {
        return nil, fmt.Errorf("rewrite dns_passthrough=%d: %w", opts.DNSPassthrough, err)
    }
}
```

### 3.4 xdpflowd — новый CLI флаг

**Файл:** `cmd/xdpflowd/main.go` (правка)

Рядом с `xdpAction := flag.String("xdp-action", ...)` (строка ~325):

```go
dnsPassthrough := flag.Bool("dns-passthrough", false, "force XDP_PASS for UDP/53 even when -xdp-action=drop, so a co-located dnsflowd can capture DNS via AF_PACKET. Counters still update; default off keeps current behaviour identical.")
```

В `loader.LoadObjectsWithOptions` добавить:

```go
opts := loader.Options{
    XDPFinalAction: xdpFinalAction,
}
if *dnsPassthrough {
    opts.DNSPassthrough = 1
}
objs, err := loader.LoadObjectsWithOptions(*bpfObj, opts)
```

В стартовом логе добавить поле `"dns_passthrough", *dnsPassthrough`.

### 3.5 wrapper-скрипт sel

**Файл:** `deploy/sel/xdpflowd-exec.sh` (правка)

После блока с `XDP_HEAVY_EXPORT` добавить:

```bash
DNS_PASSTHROUGH_ARGS=()
if [[ "${XDP_DNS_PASSTHROUGH:-0}" == "1" ]]; then
  DNS_PASSTHROUGH_ARGS=( -dns-passthrough )
fi
```

В финальный `exec` дописать `"${DNS_PASSTHROUGH_ARGS[@]}"` рядом с
`"${HEAVY_ARGS[@]}"`.

**Файл:** `deploy/sel/xdpflowd.env.example` (правка)

Добавить:

```bash
# Force XDP_PASS for UDP/53 so a co-located dnsflowd can capture DNS via AF_PACKET.
# Default 0 keeps current behaviour identical. Set to 1 only when running dnsflowd
# on the same interface.
XDP_DNS_PASSTHROUGH=0
```

То же самое продублировать в `deploy/systemd/xdpflowd-exec.sh` и
`deploy/systemd/xdpflowd.env.example` (для `netflow`).

### 3.6 Новый бинарь dnsflowd — структура

**Каталог:** `cmd/dnsflowd/` (создать)

Файлы:
- `main.go` — CLI, signal handling, lifecycle.
- `capture.go` — AF_PACKET сокет + BPF filter + read loop.
- `parser.go` — парсинг DNS через `golang.org/x/net/dns/dnsmessage`.
- `sink.go` — bounded queue + batch INSERT в ClickHouse (мини-копия
  `clickhouseSink` из `xdpflowd`, упрощённая до dns_log столбцов).
- `dns_row.go` — структура `DNSRow` под колонки `dns_log`.

#### 3.6.1 capture.go — AF_PACKET

Используем чистый stdlib + `golang.org/x/net/bpf` для сборки фильтра.
Никаких libpcap/gopacket. ~150 строк.

Псевдокод (готов для вставки):

```go
package main

import (
    "fmt"
    "net"
    "syscall"

    "golang.org/x/net/bpf"
    "golang.org/x/sys/unix"
)

const (
    ethPALL = 0x0003
)

// classicBPF returns kernel-BPF for "udp and (src port 53 or dst port 53)".
// IPv4 only for MVP (>99% DNS traffic). IPv6 — TODO.
func classicBPF() ([]bpf.RawInstruction, error) {
    prog, err := bpf.Assemble([]bpf.Instruction{
        bpf.LoadAbsolute{Off: 12, Size: 2},                       // EtherType
        bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 9},
        bpf.LoadAbsolute{Off: 23, Size: 1},                       // IPv4 proto
        bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 7}, // UDP
        bpf.LoadAbsolute{Off: 20, Size: 2},                       // frag_off
        bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 0, SkipFalse: 5, // not fragmented
            // (упростить: просто проверка на 0; если не 0 — отбрасываем,
            // фрагментированный DNS = редкий и его можно потерять)
        },
        bpf.LoadMemShift{Off: 14},                                // X = IHL*4
        bpf.LoadIndirect{Off: 14, Size: 2},                       // src port
        bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 2, SkipFalse: 0},
        bpf.LoadIndirect{Off: 16, Size: 2},                       // dst port
        bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 0, SkipFalse: 1},
        bpf.RetConstant{Val: 0xffff}, // accept (max snaplen)
        bpf.RetConstant{Val: 0},      // drop
    })
    if err != nil {
        return nil, err
    }
    return prog, nil
}

// openCapture opens an AF_PACKET socket bound to ifname and attaches the BPF
// filter. Returns the raw fd; caller closes.
func openCapture(ifname string) (int, error) {
    fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, htons(ethPALL))
    if err != nil {
        return -1, fmt.Errorf("socket: %w", err)
    }
    iface, err := net.InterfaceByName(ifname)
    if err != nil {
        unix.Close(fd)
        return -1, err
    }
    sa := &unix.SockaddrLinklayer{
        Protocol: htons(ethPALL),
        Ifindex:  iface.Index,
    }
    if err := unix.Bind(fd, sa); err != nil {
        unix.Close(fd)
        return -1, fmt.Errorf("bind %s: %w", ifname, err)
    }
    // Receive buffer: bump to ~16 MiB.
    _ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 16<<20)

    raw, err := classicBPF()
    if err != nil {
        unix.Close(fd)
        return -1, err
    }
    sf := make([]unix.SockFilter, len(raw))
    for i, ins := range raw {
        sf[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
    }
    fp := unix.SockFprog{Len: uint16(len(sf)), Filter: &sf[0]}
    if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fp); err != nil {
        unix.Close(fd)
        return -1, fmt.Errorf("attach filter: %w", err)
    }
    return fd, nil
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | (v>>8)&0x00ff }
```

Цикл чтения — `unix.Read(fd, buf)` в одной горутине, `buf` размером 64 KiB.
Распарсенные `DNSRow` шлются в `sink.ch`.

#### 3.6.2 parser.go — DNS

```go
package main

import (
    "strings"
    "time"

    "golang.org/x/net/dns/dnsmessage"
)

// parseEthernetUDP returns (clientIP, serverIP, srcPort, dstPort, udpPayload).
// Принимает фрейм с Ethernet+IPv4+UDP. Возвращает ошибку если не подходит.
// (~50 строк ручного парсинга — Ethernet 14 байт, IPv4 IHL*4, UDP 8 байт.)

// parseDNS parses udpPayload into a DNSRow.
func parseDNS(srcIP, dstIP [16]byte, sport, dport uint16, payload []byte, now time.Time) (DNSRow, error) {
    var p dnsmessage.Parser
    hdr, err := p.Start(payload)
    if err != nil {
        return DNSRow{}, err
    }

    // Question section — берём первый вопрос, остальные игнорируем (редкость).
    q, err := p.Question()
    if err == dnsmessage.ErrSectionDone {
        // header-only — пропускаем
        return DNSRow{}, errSkip
    }
    if err != nil {
        return DNSRow{}, err
    }
    _ = p.SkipAllQuestions()

    row := DNSRow{
        Ts:           now,
        ClientIP:     srcIP, // переопределится для response
        ServerIP:     dstIP,
        ClientPort:   sport,
        ServerPort:   dport,
        IsResponse:   boolU8(hdr.Response),
        Transport:    "udp",
        TXID:         hdr.ID,
        RCode:        uint8(hdr.RCode),
        Truncated:    boolU8(hdr.Truncated),
        RD:           boolU8(hdr.RecursionDesired),
        RA:           boolU8(hdr.RecursionAvailable),
        QueryName:    strings.ToLower(q.Name.String()),
        QType:        q.Type.String(),
        QClass:       q.Class.String(),
        RawSize:      uint16(len(payload)),
    }
    // Для query: client = src; для response: client = dst (ответ идёт от resolver к клиенту).
    if hdr.Response {
        row.ClientIP, row.ServerIP = dstIP, srcIP
        row.ClientPort, row.ServerPort = dport, sport
    }

    // Answers
    if hdr.Response {
        for {
            ah, err := p.AnswerHeader()
            if err == dnsmessage.ErrSectionDone {
                break
            }
            if err != nil {
                break
            }
            switch ah.Type {
            case dnsmessage.TypeA:
                a, err := p.AResource()
                if err == nil {
                    var v [16]byte
                    copy(v[:4], a.A[:])
                    row.AnswersA = append(row.AnswersA, v)
                    row.AnswerTTLs = append(row.AnswerTTLs, ah.TTL)
                }
            case dnsmessage.TypeAAAA:
                a, err := p.AAAAResource()
                if err == nil {
                    var v [16]byte
                    copy(v[:], a.AAAA[:])
                    row.AnswersAAAA = append(row.AnswersAAAA, v)
                    row.AnswerTTLs = append(row.AnswerTTLs, ah.TTL)
                }
            case dnsmessage.TypeCNAME:
                c, err := p.CNAMEResource()
                if err == nil {
                    row.AnswersCNAME = append(row.AnswersCNAME, strings.ToLower(c.CNAME.String()))
                    row.AnswerTTLs = append(row.AnswerTTLs, ah.TTL)
                }
            default:
                _ = p.SkipAnswer()
            }
        }
    }
    row.AnswerCount = uint16(len(row.AnswersA) + len(row.AnswersAAAA) + len(row.AnswersCNAME))
    return row, nil
}
```

Замечания:
- `dnsmessage` есть в `golang.org/x/net/dns/dnsmessage` (пакет уже в Go
  ecosystem, минимальные зависимости).
- При ошибке парсинга — счётчик `parseErrs` и продолжаем; пакет с битым
  DNS не должен валить процесс.

#### 3.6.3 sink.go — упрощённая копия `clickhouseSink`

Структура та же, но:
- Нет durable spool (in-memory queue с drop-on-overflow).
- INSERT в `default.dns_log` (колонки из 3.1).
- Метрики: `recordsQueued`, `recordsWritten`, `insertErrs`, `queueDrops`,
  `parseErrs`, `packetsSeen`.

Можно прямо скопировать `cmd/xdpflowd/clickhouse_sink.go` → переименовать,
поменять `FlowRow` на `DNSRow`, переписать `insertBatchRows` под колонки
`dns_log`. ~250 строк.

#### 3.6.4 main.go

Флаги:
```
-iface           string  (mirror interface, e.g. enp4s0np0)
-ch-dsn          string  (clickhouse://user:pass@host:port/default)
-ch-table        string  (default: default.dns_log)
-ch-batch-size   int     (default 500)
-ch-flush-interval duration (default 1s)
-ch-queue-size   int     (default 64)
-ch-sampler-addr string  (default 127.0.0.1)
-interval        duration (default 5s, periodic metrics log)
```

Жизненный цикл:
1. Открыть AF_PACKET (`openCapture`).
2. Открыть `clickhouseSink`.
3. Запустить read-loop горутиной.
4. Ждать SIGTERM/SIGINT → cancel context → close socket → close sink.

### 3.7 go.mod

Добавить зависимости (выполнить `go get` локально на машине разработки):

```
go get golang.org/x/net@latest
# golang.org/x/sys уже есть
```

`golang.org/x/net` нужен для `bpf` и `dns/dnsmessage`. Других deps не требуется.

### 3.8 Makefile

**Файл:** `Makefile` (правка)

Добавить рядом с `build-afxdp`:

```makefile
.PHONY: build-dns
build-dns: ensure-mod
	@mkdir -p bin
	@echo "Using Go: $(GO)" && $(GO) version
	$(GO) build -o bin/dnsflowd ./cmd/dnsflowd
```

В `clean` добавить `bin/dnsflowd`.

### 3.9 systemd unit для dnsflowd

**Файл:** `deploy/sel/dnsflowd.service` (создать)

```ini
[Unit]
Description=GrapesNTA dnsflowd (DNS capture → ClickHouse) — sel profile
Documentation=file:/opt/GrapesNTA/docs/DNSFLOWD_MVP_PLAN.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/GrapesNTA/deploy/sel/dnsflowd-exec.sh

KillSignal=SIGTERM
TimeoutStopSec=60
SendSIGKILL=yes

Restart=on-failure
RestartSec=5

# AF_PACKET требует CAP_NET_RAW + CAP_NET_ADMIN; проще под root.
LimitNOFILE=1048576
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

**Файл:** `deploy/sel/dnsflowd-exec.sh` (создать, +x)

```bash
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${DNSFLOWD_ENV_FILE:-/etc/dnsflowd/sel.env}"
if [[ ! -r "$ENV_FILE" ]]; then
  echo "ERROR: env file not readable: $ENV_FILE" >&2
  exit 1
fi
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

REPO_ROOT="${REPO_ROOT:-/opt/GrapesNTA}"
BIN="${DNSFLOWD_BIN:-$REPO_ROOT/bin/dnsflowd}"
IFACE="${IFACE:-enp4s0np0}"

if [[ ! -x "$BIN" ]]; then
  echo "ERROR: dnsflowd binary not executable: $BIN" >&2
  exit 1
fi
if [[ -z "${DNS_CH_DSN:-}" || -z "${DNS_CH_TABLE:-}" ]]; then
  echo "ERROR: DNS_CH_DSN and DNS_CH_TABLE must be set in $ENV_FILE" >&2
  exit 1
fi

exec "$BIN" \
  -iface "$IFACE" \
  -ch-dsn "$DNS_CH_DSN" \
  -ch-table "$DNS_CH_TABLE" \
  -ch-batch-size "${DNS_CH_BATCH_SIZE:-500}" \
  -ch-flush-interval "${DNS_CH_FLUSH_INTERVAL:-1s}" \
  -ch-queue-size "${DNS_CH_QUEUE_SIZE:-64}" \
  -ch-sampler-addr "${DNS_CH_SAMPLER_ADDR:-127.0.0.1}" \
  -interval "${DNS_INTERVAL:-5s}"
```

**Файл:** `deploy/sel/dnsflowd.env.example` (создать)

```bash
REPO_ROOT=/opt/GrapesNTA
DNSFLOWD_BIN=${REPO_ROOT}/bin/dnsflowd

IFACE=enp4s0np0

# Use the same ClickHouse instance as xdpflowd.
DNS_CH_DSN=
DNS_CH_TABLE=default.dns_log
DNS_CH_BATCH_SIZE=500
DNS_CH_FLUSH_INTERVAL=1s
DNS_CH_QUEUE_SIZE=64
DNS_CH_SAMPLER_ADDR=127.0.0.1

DNS_INTERVAL=5s
```

(Аналогичный набор `deploy/systemd/dnsflowd*` для netflow — не делать в MVP,
сначала обкатать на sel.)

## 4. Порядок выполнения и проверки

### 4.1 Локальная разработка (любая машина)

1. Создать ветку `feature/dnsflowd-mvp` от `feature/afxdp`.
2. Внести изменения 3.2 → 3.5 (eBPF + loader + xdpflowd флаг + wrapper).
3. Внести изменения 3.1 (SQL).
4. Создать `cmd/dnsflowd/` (3.6).
5. `go mod tidy`.
6. На Linux-машине: `make bpf && make build && make build-dns`. Проверить
   что и `bin/xdpflowd`, и `bin/dnsflowd` собираются.
7. Lint: `go vet ./...` — ошибок быть не должно.
8. Юнит-тест парсера DNS: добавить `cmd/dnsflowd/parser_test.go` с парой
   pcap-сэмплов (можно hex-литералом — пакет с запросом и ответом).
   Минимум: NXDOMAIN, A-ответ, CNAME-цепочка, AAAA. Цель — убедиться что
   парсер не падает и колонки `dns_log` заполняются.
9. Закоммитить, push в `feature/dnsflowd-mvp`.

### 4.2 Подготовка ClickHouse

Накатить `deploy/clickhouse/dns_log.sql` на тот же инстанс, куда пишет
`xdpflowd`:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 \
    --user develop --password '...' \
    --queries-file deploy/clickhouse/dns_log.sql
```

Проверка:
```sql
SHOW CREATE TABLE default.dns_log;
SELECT count() FROM default.dns_log;  -- 0
```

### 4.3 Раскатка xdpflowd с новым флагом (без активации)

Этот шаг безопасен — `XDP_DNS_PASSTHROUGH=0`, поведение не меняется.

На `sel`:
```bash
cd /opt/GrapesNTA
git fetch && git checkout feature/dnsflowd-mvp
make bpf && make build
sudo systemctl restart xdpflowd
sudo systemctl status xdpflowd
sudo journalctl -u xdpflowd -n 50
```

В логе должно появиться `dns_passthrough=false`. Поведение `xdpflowd`
идентично — сверить через `SELECT count() FROM flows_raw WHERE
time_received_ns > now() - INTERVAL 1 MINUTE` до и после.

### 4.4 Раскатка dnsflowd

```bash
cd /opt/GrapesNTA
make build-dns
sudo install -d /etc/dnsflowd /var/log/dnsflowd
sudo cp deploy/sel/dnsflowd.env.example /etc/dnsflowd/sel.env
sudo chmod 0600 /etc/dnsflowd/sel.env
sudoedit /etc/dnsflowd/sel.env   # вписать DNS_CH_DSN
sudo cp deploy/sel/dnsflowd.service /etc/systemd/system/
sudo systemctl daemon-reload
```

**ПОКА НЕ ЗАПУСКАЕМ.**

### 4.5 Активация DNS pass-through и старт dnsflowd

Это единственный шаг с реальным изменением поведения `xdpflowd`.

```bash
sudoedit /etc/xdpflowd/sel.env
# поменять XDP_DNS_PASSTHROUGH=0 → XDP_DNS_PASSTHROUGH=1

sudo systemctl restart xdpflowd
# В логе: dns_passthrough=true

sudo systemctl start dnsflowd
sudo systemctl enable dnsflowd
sudo journalctl -u dnsflowd -n 50 -f
```

В логе `dnsflowd` через 5-10 секунд должны появиться сообщения вида:
```
clickhouse records_queued=N records_written=N batches_ok=N
```

### 4.6 Acceptance criteria

```sql
-- 1. Данные пишутся
SELECT count() FROM default.dns_log
WHERE ts >= now() - INTERVAL 5 MINUTE;
-- ожидание: > 0

-- 2. Доменов разумно много
SELECT uniq(query_name) FROM default.dns_log
WHERE ts >= now() - INTERVAL 5 MINUTE;
-- ожидание: сотни-тысячи

-- 3. Топ доменов выглядит как реальный mix
SELECT query_name, count() AS hits
FROM default.dns_log
WHERE ts >= now() - INTERVAL 5 MINUTE AND is_response = 1
GROUP BY query_name
ORDER BY hits DESC
LIMIT 30;
-- ожидание: youtube.com / vk.com / mail.ru / google.com / yandex.ru / cloudfront.net и т.д.

-- 4. Распределение rcode здоровое
SELECT rcode, count() FROM default.dns_log
WHERE ts >= now() - INTERVAL 5 MINUTE AND is_response = 1
GROUP BY rcode ORDER BY count() DESC;
-- ожидание: 0 (NOERROR) подавляющее большинство, 3 (NXDOMAIN) — единицы процентов

-- 5. flows_raw не сломался
SELECT count() FROM default.flows_raw
WHERE time_received_ns > now() - INTERVAL 5 MINUTE;
-- ожидание: тот же порядок что был до раскатки

-- 6. Корреляция: IP из DNS-ответа должен встречаться в flows_raw
WITH (
    SELECT IPv6NumToString(answers_a[1]) FROM default.dns_log
    WHERE is_response = 1 AND length(answers_a) > 0
    ORDER BY ts DESC LIMIT 1
) AS ip
SELECT ip, count() FROM default.flows_raw
WHERE IPv6NumToString(dst_addr) = ip
  AND time_received_ns > now() - INTERVAL 1 HOUR;
-- ожидание: > 0 (доменный IP реально гоняется в трафике)
```

Если все 6 проверок зелёные — MVP принят.

## 5. Откат

### Полный откат до состояния «как было»

```bash
# 1. Остановить dnsflowd
sudo systemctl stop dnsflowd
sudo systemctl disable dnsflowd
sudo rm /etc/systemd/system/dnsflowd.service
sudo systemctl daemon-reload

# 2. Выключить DNS pass-through в xdpflowd
sudoedit /etc/xdpflowd/sel.env  # XDP_DNS_PASSTHROUGH=0
sudo systemctl restart xdpflowd

# 3. Опционально откатить код xdpflowd
cd /opt/GrapesNTA
git checkout feature/afxdp
make bpf && make build
sudo systemctl restart xdpflowd

# 4. Опционально удалить таблицу
clickhouse-client ... --query 'DROP TABLE default.dns_log'
```

### Откат только dnsflowd (xdpflowd с новой eBPF оставляем)

Шаг 1 + 2. Этого достаточно.

## 6. Метрики и мониторинг

### dnsflowd периодический лог (раз в `-interval`)

```
{
  "packets_seen":   42137,    // всего прочитано из AF_PACKET
  "parse_errs":     12,       // не смогли распарсить как DNS
  "records_queued": 42100,
  "records_written": 41800,
  "batches_ok":     84,
  "insert_errs":    0,
  "queue_drops":    0
}
```

Алерты на проде (на следующем шаге, не в MVP):
- `queue_drops > 0` → CH тормозит, можно увеличить `DNS_CH_QUEUE_SIZE`.
- `insert_errs > 5` за минуту → ClickHouse недоступен, проверить DSN.
- `packets_seen` падает к нулю при наличии трафика → `XDP_DNS_PASSTHROUGH`
  слетел, проверить `xdpflowd` env.

## 7. Известные ограничения MVP

1. **IPv4 only** для AF_PACKET BPF фильтра. IPv6 DNS — TODO (нужно добавить
   ветку в `classicBPF` для `EtherType=0x86DD` + `nexthdr=17`).
2. **UDP only**. TCP DNS (большие ответы, AXFR) не парсим. На реальном
   ISP-трафике это <1% DNS, можно жить без.
3. **Фрагментированный DNS** (UDP > 1500 байт без EDNS, редкость) —
   пропускается фильтром.
4. **Нет durable spool**. При падении ClickHouse теряем DNS-логи за время
   простоя. Приемлемо для MVP, потому что `flows_raw` остаётся источником
   правды для биллинга/СОРМ.
5. **Один процесс читает один интерфейс**. Если трафик на `enp4s0np0`
   разнесён по нескольким очередям и DNS-pps большой (>50 kpps), может
   потребоваться `PACKET_FANOUT` — отложено.
6. **Корреляция flows ↔ DNS пока в SQL руками**. Материализованная view
   `ip_to_domain` — следующий шаг.

## 8. Что после MVP (план следующих итераций)

- Материализованная view `default.ip_to_domain` с TTL ~1ч: «последний
  домен, отрезолвленный в этот IP, и за сколько секунд назад».
- `flows_with_domain` — view поверх `flows_raw JOIN ip_to_domain ON
  dst_addr = ip`.
- Парсинг TLS ClientHello (SNI) поверх того же AF_PACKET — расширяет
  фильтр до `tcp port 443 and (tcp[((tcp[12:1]&0xf0)>>2):1] = 0x16)`,
  парсер TLS handshake ClientHello.
- Durable spool для `dnsflowd` (вынести `clickhouse_spool.go` в
  `internal/chspool/` и переиспользовать).
- Раскатка на `netflow`.
- Алерты на DGA и DNS-туннели.

## 9. Чек-лист исполнителя

- [ ] Создана ветка `feature/dnsflowd-mvp`.
- [ ] Правка `bpf/xdp_flow.c` (3.2). `make bpf` ОК.
- [ ] Правка `internal/loader/loader.go` (3.3).
- [ ] Правка `cmd/xdpflowd/main.go` (3.4). `make build` ОК.
- [ ] Правка `deploy/sel/xdpflowd-exec.sh` + `xdpflowd.env.example` (3.5).
- [ ] Правка `deploy/systemd/xdpflowd-exec.sh` + `xdpflowd.env.example` (3.5).
- [ ] Создан `cmd/dnsflowd/{main,capture,parser,sink,dns_row}.go` (3.6).
- [ ] Создан `cmd/dnsflowd/parser_test.go` с DNS hex-сэмплами.
- [ ] `go.mod` обновлён, `go mod tidy` ОК (3.7).
- [ ] `Makefile` цель `build-dns` (3.8). `make build-dns` ОК.
- [ ] `deploy/sel/dnsflowd.service` + `dnsflowd-exec.sh` + `dnsflowd.env.example` (3.9).
- [ ] `deploy/clickhouse/dns_log.sql` (3.1).
- [ ] Коммит, push.
- [ ] На sel: применить SQL, раскатать новый xdpflowd с `DNS_PASSTHROUGH=0`,
      убедиться что `flows_raw` поток не изменился.
- [ ] На sel: раскатать `dnsflowd`, выставить `DNS_PASSTHROUGH=1`,
      перезапустить `xdpflowd`, запустить `dnsflowd`.
- [ ] Прогнать 6 SQL-проверок acceptance criteria (4.6).
- [ ] Документировать в `docs/SEL_PERMANENT_XDPFLOWD_RUNBOOK.md` факт
      что включён DNS pass-through.
