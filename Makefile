# xdpflowd — XDP flow collector (eBPF + Go).
#
# Requires on Linux: clang, llvm, libbpf-dev, linux-libc-dev, Go 1.23+.
#   apt install clang llvm libbpf-dev linux-libc-dev build-essential
#
# Default BPF object path expected by the binary: bpf/xdp_flow.o (relative to CWD).

# Auto-detect a Go >= 1.21 binary even if the default /usr/bin/go is
# older (e.g. Debian 11 ships go 1.15). We need 1.21+ for log/slog and
# for cilium/ebpf v0.16. Override with `make GO=/path/to/go` if needed.
GO ?= $(shell \
  for p in $$(command -v go 2>/dev/null) /usr/local/go/bin/go /opt/go/bin/go /root/go/bin/go /usr/lib/go-1.22/bin/go /usr/lib/go-1.23/bin/go; do \
    [ -x "$$p" ] || continue; \
    if "$$p" version 2>/dev/null | grep -qE 'go1\.(2[1-9]|[3-9][0-9])'; then \
      echo "$$p"; exit 0; \
    fi; \
  done; \
  echo go)
CLANG  ?= clang
# Override FLOWS_MAP_SIZE at build time to fit peak concurrent flow count, e.g.:
#   make FLOWS_MAP_SIZE=8000000
FLOWS_MAP_SIZE ?= 4000000
BPF_CFLAGS := -O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu \
              -DFLOWS_MAP_SIZE=$(FLOWS_MAP_SIZE)

BPF_O := bpf/xdp_flow.o

.PHONY: all bpf build clean run tidy

all: build

tidy:
	$(GO) mod tidy

$(BPF_O): bpf/xdp_flow.c
	@mkdir -p bpf
	$(CLANG) $(BPF_CFLAGS) -c bpf/xdp_flow.c -o $(BPF_O)

bpf: $(BPF_O)

build: $(BPF_O)
	@mkdir -p bin
	@echo "Using Go: $(GO)" && $(GO) version
	$(GO) build -o bin/xdpflowd ./cmd/xdpflowd

run: build
	sudo ./bin/xdpflowd -iface ens18 -mode native -bpf $(BPF_O)

clean:
	rm -f bin/xdpflowd $(BPF_O)

.DEFAULT_GOAL := build
