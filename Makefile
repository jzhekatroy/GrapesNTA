# xdpflowd — XDP flow collector (eBPF + Go).
#
# Requires on Linux: clang, llvm, libbpf-dev, linux-libc-dev, Go 1.23+.
#   apt install clang llvm libbpf-dev linux-libc-dev build-essential
#
# Default BPF object path expected by the binary: bpf/xdp_flow.o (relative to CWD).

GO     ?= go
CLANG  ?= clang
BPF_CFLAGS := -O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu

BPF_O := bpf/xdp_flow.o

.PHONY: all bpf build clean run

all: build

$(BPF_O): bpf/xdp_flow.c
	@mkdir -p bpf
	$(CLANG) $(BPF_CFLAGS) -c bpf/xdp_flow.c -o $(BPF_O)

bpf: $(BPF_O)

build: $(BPF_O)
	@mkdir -p bin
	$(GO) build -o bin/xdpflowd ./cmd/xdpflowd

run: build
	sudo ./bin/xdpflowd -iface ens18 -mode native -bpf $(BPF_O)

clean:
	rm -f bin/xdpflowd $(BPF_O)

.DEFAULT_GOAL := build
