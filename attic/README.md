# attic — archived, not part of a fresh install

Cutover leftovers. Git history still has everything; this folder keeps the files
reachable without mixing them into `deploy/`, `cmd/` or `scripts/`.

Do **not** enable anything here on a live GrapesNTA stand. Rollups and
enrichment run in Docker (`deploy/worker`, `deploy/enrichment`). Collectors are
the systemd units still in `deploy/systemd/` (`xdpflowd`, `dnsflowd`,
`flowcollectord`, `bmpgrapes`, `local-networks-loader`).

| Path | What |
|------|------|
| `scripts/prod_*.sh` | ipt_NETFLOW → xdpflowd A/B swap on an old ISP mirror |
| `scripts/afxdp_*.sh`, `cmd/afxdpflowd`, `internal/afxdp`, `internal/netv9` | experimental AF_XDP daemon, never production |
| `bpf/` | diagnostic XDP objects (`xdp_light`, `xdp_flow_fast`, `afxdp_redirect`) |
| `systemd/` | host timers replaced by grapes-worker / grapes-enrichment |
| `scripts/nta-unblock-rollups.sh` | one-shot against host `traffic-rollups.service` |

Nested `go.mod` so `go test ./...` in the main module does not compile AF_XDP.

Fresh install: [`docs/INSTALL.txt`](../docs/INSTALL.txt).
