GO ?= go
CLANG ?= clang
CFLAGS ?= -O2 -Wall -Werror
BPF_CFLAGS ?= -O2 -target bpf -D__TARGET_ARCH_x86 -g

KERNEL_RELEASE := $(shell uname -r)
KERNEL_HEADERS ?= /lib/modules/$(KERNEL_RELEASE)/build
BPFTOOL ?= bpftool

OUTPUT_DIR := output
BPF_OBJ_DIR := bpf/obj

GO_BIN := upf-gateway
BPF_SRC := bpf/upf_xdp_kern.c
BPF_OBJ := $(BPF_OBJ_DIR)/upf_xdp_kern.o

PKG_BPF := pkg/bpf
GENERATED_BPF := $(PKG_BPF)/upf_xdp_bpfel.go $(PKG_BPF)/upf_xdp_bpfeb.go

.PHONY: all clean generate bpf build run install check fmt help

all: generate build

generate: $(GENERATED_BPF)

$(GENERATED_BPF): $(BPF_SRC) bpf/upf_common.h
	@echo "Generating BPF Go bindings..."
	@mkdir -p $(PKG_BPF)
	@cd $(PKG_BPF) && $(GO) generate ./...

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) bpf/upf_common.h
	@echo "Compiling BPF program..."
	@mkdir -p $(BPF_OBJ_DIR)
	$(CLANG) $(BPF_CFLAGS) \
		-I./bpf \
		-I$(KERNEL_HEADERS)/include \
		-I$(KERNEL_HEADERS)/include/uapi \
		-I$(KERNEL_HEADERS)/arch/x86/include \
		-I$(KERNEL_HEADERS)/arch/x86/include/uapi \
		-c $< -o $@
	@llvm-strip -g $@

build: generate
	@echo "Building UPF gateway..."
	@mkdir -p $(OUTPUT_DIR)
	$(GO) build -o $(OUTPUT_DIR)/$(GO_BIN) ./cmd/upf

fmt:
	@echo "Formatting Go code..."
	$(GO) fmt ./...
	@echo "Formatting BPF code..."
	@clang-format -i $(BPF_SRC) bpf/upf_common.h

check: generate
	@echo "Running Go vet..."
	$(GO) vet ./...
	@echo "Running Go build check..."
	$(GO) build -o /dev/null ./cmd/upf

test: generate
	@echo "Running tests..."
	$(GO) test -v ./...

run: build
	@echo "Running UPF gateway..."
	@sudo $(OUTPUT_DIR)/$(GO_BIN) $(ARGS)

install: build
	@echo "Installing UPF gateway..."
	@install -D $(OUTPUT_DIR)/$(GO_BIN) /usr/local/bin/$(GO_BIN)
	@install -D $(BPF_OBJ) /usr/lib/bpf/upf_xdp_kern.o

uninstall:
	@echo "Uninstalling UPF gateway..."
	@rm -f /usr/local/bin/$(GO_BIN)
	@rm -f /usr/lib/bpf/upf_xdp_kern.o

clean:
	@echo "Cleaning..."
	@rm -rf $(OUTPUT_DIR) $(BPF_OBJ_DIR)
	@rm -f $(GENERATED_BPF)
	@rm -f $(PKG_BPF)/*.go.c
	@$(GO) clean

help:
	@echo "Available targets:"
	@echo "  all       - Generate BPF bindings and build UPF gateway"
	@echo "  generate  - Generate Go bindings from BPF source"
	@echo "  bpf       - Compile BPF program to .o file"
	@echo "  build     - Build UPF gateway binary"
	@echo "  fmt       - Format Go and C code"
	@echo "  check     - Run Go vet and build check"
	@echo "  test      - Run tests"
	@echo "  run       - Build and run UPF gateway (requires root)"
	@echo "  install   - Install UPF gateway to system"
	@echo "  uninstall - Uninstall UPF gateway from system"
	@echo "  clean     - Remove build artifacts"
	@echo "  help      - Show this help message"
