# eBPF WireMock Router - Build system
#
# Prerequisites:
#   - Go 1.21+
#   - clang/llvm (for compiling eBPF C)
#   - bpftool (for generating vmlinux.h)
#   - Linux kernel 4.17+ with BPF support
#
# On Ubuntu/Debian:
#   sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r)
#
# On Fedora:
#   sudo dnf install clang llvm libbpf-devel bpftool

CLANG     ?= clang
BPFTOOL   ?= bpftool
GO        ?= go
ARCH      := $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')

BPF_SRC   := bpf/redirect.c
BPF_OBJ   := bpf/redirect.o
VMLINUX_H := bpf/vmlinux.h
BINARY    := ebpf-wiremock-router

.PHONY: all clean generate build vmlinux

all: build

# Generate vmlinux.h from the running kernel's BTF info
vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

# Compile the eBPF C program to BPF bytecode
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H)
	$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-I bpf \
		-c $(BPF_SRC) \
		-o $(BPF_OBJ)

# Run bpf2go to generate Go bindings from the eBPF object
generate: $(BPF_OBJ)
	$(GO) generate ./...

# Build the Go binary
build: generate
	CGO_ENABLED=0 $(GO) build -o $(BINARY) .

clean:
	rm -f $(BPF_OBJ) $(VMLINUX_H) $(BINARY)
	rm -f *_bpfel.go *_bpfeb.go *_bpfel.o *_bpfeb.o

run: build
	sudo ./$(BINARY) -config config.yaml

# Quick test: show eBPF trace output
trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe | grep ebpf-wiremock
