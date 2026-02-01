# Secure Infrastructure Makefile
# Build commands for all project binaries

# Output directory
BIN_DIR := bin

# Binary names
AEGIS := $(BIN_DIR)/aegis
AEGIS_ARM64 := $(BIN_DIR)/aegis-arm64
BLUECTL := $(BIN_DIR)/bluectl
NEXUS := $(BIN_DIR)/nexus
KM := $(BIN_DIR)/km
SENTRY := $(BIN_DIR)/sentry
SENTRY_AMD64 := $(BIN_DIR)/sentry-amd64
SENTRY_ARM64 := $(BIN_DIR)/sentry-arm64
DPUEMU := $(BIN_DIR)/dpuemu

# Version from git tag or "dev"
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# ldflags for embedding version
LDFLAGS := -X github.com/nmelo/secure-infra/internal/version.Version=$(VERSION)

.PHONY: all aegis bluectl nexus km sentry dpuemu test clean release help

# Default target: build all binaries
all: $(BIN_DIR)
	@echo "Building all binaries..."
	@go build -ldflags "$(LDFLAGS)" -o $(AEGIS) ./cmd/aegis
	@echo "  $(AEGIS)"
	@go build -ldflags "$(LDFLAGS)" -o $(BLUECTL) ./cmd/bluectl
	@echo "  $(BLUECTL)"
	@go build -ldflags "$(LDFLAGS)" -o $(KM) ./cmd/keymaker
	@echo "  $(KM)"
	@go build -ldflags "$(LDFLAGS)" -o $(NEXUS) ./cmd/nexus
	@echo "  $(NEXUS)"
	@go build -ldflags "$(LDFLAGS)" -o $(SENTRY) ./cmd/sentry
	@echo "  $(SENTRY)"
	@go build -ldflags "$(LDFLAGS)" -o $(DPUEMU) ./dpuemu/cmd/dpuemu
	@echo "  $(DPUEMU)"
	@echo "Done."

# Create bin directory if needed
$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Build aegis for local platform and cross-compile for BlueField (ARM64)
aegis: $(BIN_DIR)
	@echo "Building aegis..."
	@go build -ldflags "$(LDFLAGS)" -o $(AEGIS) ./cmd/aegis
	@echo "  $(AEGIS)"
	@echo "Cross-compiling aegis for BlueField (linux/arm64)..."
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(AEGIS_ARM64) ./cmd/aegis
	@echo "  $(AEGIS_ARM64)"

# Build bluectl CLI
bluectl: $(BIN_DIR)
	@echo "Building bluectl..."
	@go build -ldflags "$(LDFLAGS)" -o $(BLUECTL) ./cmd/bluectl
	@echo "  $(BLUECTL)"

# Build nexus
nexus: $(BIN_DIR)
	@echo "Building nexus..."
	@go build -ldflags "$(LDFLAGS)" -o $(NEXUS) ./cmd/nexus
	@echo "  $(NEXUS)"

# Build keymaker CLI
km: $(BIN_DIR)
	@echo "Building km (keymaker)..."
	@go build -ldflags "$(LDFLAGS)" -o $(KM) ./cmd/keymaker
	@echo "  $(KM)"

# Build sentry for local platform and cross-compile for Linux hosts
sentry: $(BIN_DIR)
	@echo "Building sentry..."
	@go build -ldflags "$(LDFLAGS)" -o $(SENTRY) ./cmd/sentry
	@echo "  $(SENTRY)"
	@echo "Cross-compiling sentry for Linux (amd64)..."
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(SENTRY_AMD64) ./cmd/sentry
	@echo "  $(SENTRY_AMD64)"
	@echo "Cross-compiling sentry for Linux (arm64)..."
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(SENTRY_ARM64) ./cmd/sentry
	@echo "  $(SENTRY_ARM64)"

# Build DPU emulator
dpuemu: $(BIN_DIR)
	@echo "Building dpuemu..."
	@go build -ldflags "$(LDFLAGS)" -o $(DPUEMU) ./dpuemu/cmd/dpuemu
	@echo "  $(DPUEMU)"

# Run all tests
test:
	@echo "Running tests..."
	@go test ./...

# =============================================================================
# New Test Suite Structure
# Organized by environment: dpu, workbench, integration, e2e, benchmark
# =============================================================================

# Run DPU tests (must run ON the BlueField DPU)
# SSH to the DPU first, then run: make test-dpu
test-dpu:
	@echo "Running DPU tests (requires BlueField hardware)..."
	go test -tags=dpu -v ./test/dpu/...

# Run workbench tests (runs on Linux workbench with TMFIFO access)
test-workbench:
	@echo "Running workbench component tests..."
	go test -tags=workbench -v ./test/workbench/...

# Run integration tests (requires VMs running)
# Use WORKBENCH_IP=192.168.1.235 to run on workbench instead of local
test-integration:
	@echo "Running integration tests..."
	go test -tags=integration -v -timeout 10m ./test/integration/...

# Run E2E hardware tests (full hardware validation)
test-e2e:
	@echo "Running E2E hardware tests..."
	go test -tags=hardware -v -timeout 15m ./test/e2e/...

# Run all hardware tests in sequence
test-hardware: test-dpu test-workbench test-integration test-e2e
	@echo "All hardware tests completed"

# Run benchmarks
benchmark:
	@echo "Running benchmarks..."
	go test -tags=benchmark -bench=. -benchmem ./test/benchmark/...

# Legacy test targets (aliases for backward compatibility)
test-integration-remote:
	WORKBENCH_IP=192.168.1.235 go test -tags=integration -v -timeout 5m ./test/integration/...

# Remove bin directory contents
clean:
	@echo "Cleaning bin/..."
	@rm -rf $(BIN_DIR)/*
	@echo "Done."

# Build release binaries for multiple platforms
release: $(BIN_DIR)
	@echo "Building release binaries..."
	@echo ""
	@echo "darwin/arm64:"
	@GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/aegis-darwin-arm64 ./cmd/aegis
	@echo "  $(BIN_DIR)/aegis-darwin-arm64"
	@GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/bluectl-darwin-arm64 ./cmd/bluectl
	@echo "  $(BIN_DIR)/bluectl-darwin-arm64"
	@GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/km-darwin-arm64 ./cmd/keymaker
	@echo "  $(BIN_DIR)/km-darwin-arm64"
	@echo ""
	@echo "linux/amd64:"
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/aegis-linux-amd64 ./cmd/aegis
	@echo "  $(BIN_DIR)/aegis-linux-amd64"
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/bluectl-linux-amd64 ./cmd/bluectl
	@echo "  $(BIN_DIR)/bluectl-linux-amd64"
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/km-linux-amd64 ./cmd/keymaker
	@echo "  $(BIN_DIR)/km-linux-amd64"
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/sentry-linux-amd64 ./cmd/sentry
	@echo "  $(BIN_DIR)/sentry-linux-amd64"
	@echo ""
	@echo "linux/arm64 (BlueField DPU):"
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/aegis-linux-arm64 ./cmd/aegis
	@echo "  $(BIN_DIR)/aegis-linux-arm64"
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/bluectl-linux-arm64 ./cmd/bluectl
	@echo "  $(BIN_DIR)/bluectl-linux-arm64"
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/km-linux-arm64 ./cmd/keymaker
	@echo "  $(BIN_DIR)/km-linux-arm64"
	@echo ""
	@echo "Release build complete."
