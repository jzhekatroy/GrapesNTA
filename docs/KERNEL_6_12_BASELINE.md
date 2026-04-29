# Kernel 6.12 investigation on `sel`

This document records the current investigation of Debian backports kernel
`6.12.74+deb12-amd64` on the less loaded `sel` host before long-running
`xdpflowd` replacement tests.

## Host

- host: `sel`
- kernel: `6.12.74+deb12-amd64`
- interface: `enp5s0d1`
- driver: `mlx4_en`
- firmware: `2.42.5000`
- PCIe: `5.0 GT/s x8`, while the card is capable of `8.0 GT/s x8`

## Baseline after reboot

The first baseline after the kernel upgrade looked bad:

- XDP attached: no
- `rx_pps`: about `164k`
- `rx_gbps`: about `1`
- `rx_fifo_errors`: about `31k/sec`
- CPU idle: about `92%`

This was not a kernel 6.12 regression by itself. The reboot reset the NIC to a
bad default-ish profile:

- RX ring: `1024`
- coalescing: `adaptive-rx on`, `rx-usecs 16`, `rx-frames 44`
- channels: `rx 16`, `tx 24`
- pause: `rx on`, `tx on`

The known good `sel` profile restored a clean baseline:

```bash
ip link set enp5s0d1 promisc on
ethtool -L enp5s0d1 rx 16 tx 24
ethtool -G enp5s0d1 rx 8192
ethtool -C enp5s0d1 adaptive-rx off rx-usecs 512 rx-frames 512
ethtool -A enp5s0d1 rx on tx on
```

Observed after re-applying this profile:

- `rx_pps`: about `236k`
- `rx_gbps`: about `1`
- `fifo_per_sec`: `0`

## IRQ spread check

Manual IRQ spread without XDP did not help and made the baseline worse:

- before IRQ spread: about `31k fifo/sec` on the reset NIC profile
- after IRQ spread: about `76k fifo/sec`

Current recommendation for `sel`: do not apply manual IRQ spread for the 60-minute
test. Keep the previous affinity mask (`03f03f`) and rely on RX ring/coalescing
tuning first.

## Native XDP checks

All native checks below were done after restoring clean baseline and preparing
memory for `mlx4_en` native XDP attach.

### `native/pass` with full `xdp_flow.o`

Baseline before XDP:

- `before_xdp_rx_pps`: about `199k`
- `before_xdp_rx_gbps`: about `1`
- `before_xdp_fifo_per_sec`: `0`
- buddyinfo had enough high-order pages

Result:

- XDP window: about `38k fifo/sec`
- full swap duration: about `52k fifo/sec`
- post-test baseline: about `57k fifo/sec`
- simple re-apply of ring/coalescing did not recover the baseline
- `modprobe -r mlx4_en && modprobe mlx4_en` recovered baseline back to `0 fifo/sec`

Important difference from kernel 6.1:

- no `Failed to allocate NIC resources`
- no `bpf_xdp_link_release` warning
- but native attach/detach still caused `mlx4_en` `Link Down/Up`

### `native/pass` with minimal `xdp_light.o`

The minimal program only increments a counter and returns `XDP_PASS`; it does not
parse packets and does not update the flow map.

Baseline before XDP:

- `before_light_pass_rx_pps`: about `206k`
- `before_light_pass_rx_gbps`: about `1`
- `before_light_pass_fifo_per_sec`: `0`

Result:

- XDP window: about `60k fifo/sec`
- full swap duration: about `71k fifo/sec`
- post-test baseline: about `23k fifo/sec`
- native attach/detach again caused `mlx4_en` `Link Down/Up`

This isolates the issue away from the full flow-tracking BPF program. The loss
appears in the native `mlx4_en` XDP path even with a minimal BPF program.

## Generic XDP control

`generic/pass` with the same minimal `xdp_light.o` was clean:

- baseline window: `0 fifo/sec`
- XDP window: `0 fifo/sec`
- full swap duration: `48` total fifo errors, rounded to `0 drops/sec`
- post-test windows: `0`, `0`, `0`
- RX rate stayed comparable: about `195k pps` before and during XDP

This is the key control result: kernel 6.12 can run the minimal XDP program
without RX loss when the `mlx4_en` native driver path is bypassed.

## Current conclusion

For `sel` on kernel `6.12.74+deb12-amd64`:

- The clean baseline depends on restoring the known NIC profile after reboot:
  `rx 8192` and `adaptive-rx off rx-usecs 512 rx-frames 512`.
- Manual IRQ spread is not useful for the current `sel` baseline.
- `native` should not be used for the next long-running test.
- The current safe direction is `XDP_MODE=generic`, `XDP_ACTION=drop`, with the
  full `xdp_flow.o` program, local `nfcapd` preserved via `127.0.0.1:9996`, and
  ClickHouse direct ingest protected by durable spool.

The native issue is not fully root-caused, but the practical decision for the
next 60-minute validation is to stop testing native and validate the generic
production-replacement path.
