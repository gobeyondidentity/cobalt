# Secure Infrastructure Makefile
# Build commands for all project binaries

# Go binary (override with GO=/usr/local/go/bin/go for BlueField)
GO ?= go

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
LDFLAGS := -X github.com/gobeyondidentity/secure-infra/internal/version.Version=$(VERSION)

.PHONY: all aegis bluectl nexus km sentry dpuemu test clean \
	packages package-aegis package-sentry-doca \
	docker-sentry docker-nexus docker-aegis

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
# Environment variables for DOCA ComCh (BlueField-3 defaults)
DOCA_PCI_ADDR ?= 0000:03:00.0
DOCA_REP_PCI_ADDR ?= 0000:01:00.0
DOCA_SERVER_NAME ?= secure-infra

test-dpu:
	@echo "Running DPU tests (requires BlueField hardware)..."
	DOCA_PCI_ADDR=$(DOCA_PCI_ADDR) DOCA_REP_PCI_ADDR=$(DOCA_REP_PCI_ADDR) DOCA_SERVER_NAME=$(DOCA_SERVER_NAME) \
		$(GO) test -tags=dpu,doca -v ./test/dpu/...

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

# =============================================================================
# Package Builds for QA Validation
# Mirrors CI exactly so QA can test packages before release
# =============================================================================

# Build all standard packages (pure Go, no DOCA)
# Run anywhere. Output: dist/
packages:
	@if ! command -v goreleaser >/dev/null 2>&1; then \
		echo "Error: goreleaser not found"; \
		echo "Install: brew install goreleaser (macOS) or go install github.com/goreleaser/goreleaser/v2@latest"; \
		exit 1; \
	fi
	@echo "Building packages with goreleaser..."
	goreleaser release --snapshot --skip=publish --clean
	@echo "Packages built in dist/"

# Build aegis package with DOCA (run on BF3 only)
# Requires: DOCA SDK at /opt/mellanox/doca/, nfpm
package-aegis:
	@if [ "$$(uname -m)" != "aarch64" ]; then \
		echo "Error: package-aegis must run on BF3 (arm64)"; \
		exit 1; \
	fi
	@if ! command -v nfpm >/dev/null 2>&1; then \
		echo "Error: nfpm not found"; \
		echo "Install: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; \
		exit 1; \
	fi
	@echo "Building aegis with DOCA..."
	CGO_ENABLED=1 $(GO) build -tags doca \
		-ldflags "-s -w -X github.com/gobeyondidentity/secure-infra/internal/version.Version=$(VERSION)" \
		-o aegis ./cmd/aegis
	@echo "Copying DOCA runtime libraries..."
	mkdir -p doca-libs
	cp /opt/mellanox/doca/lib/aarch64-linux-gnu/libdoca_comch.so* doca-libs/
	cp /opt/mellanox/doca/lib/aarch64-linux-gnu/libdoca_common.so* doca-libs/
	@echo "Building packages..."
	VERSION=$(VERSION) nfpm package -p deb -f packaging/nfpm-aegis.yaml
	VERSION=$(VERSION) nfpm package -p rpm -f packaging/nfpm-aegis.yaml
	@echo "Built: aegis_$(VERSION)_arm64.deb, aegis-$(VERSION)-1.aarch64.rpm"

# Build sentry-doca package (run on workbench only)
# Requires: DOCA SDK at /opt/mellanox/doca/, nfpm
package-sentry-doca:
	@if [ "$$(uname -m)" != "x86_64" ]; then \
		echo "Error: package-sentry-doca must run on workbench (x86_64)"; \
		exit 1; \
	fi
	@if ! command -v nfpm >/dev/null 2>&1; then \
		echo "Error: nfpm not found"; \
		echo "Install: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; \
		exit 1; \
	fi
	@echo "Building sentry with DOCA..."
	CGO_ENABLED=1 CGO_LDFLAGS="-L/opt/mellanox/doca/lib/x86_64-linux-gnu" \
		$(GO) build -tags doca \
		-ldflags "-s -w -X github.com/gobeyondidentity/secure-infra/internal/version.Version=$(VERSION)" \
		-o sentry ./cmd/sentry
	@echo "Copying DOCA runtime libraries..."
	mkdir -p doca-libs
	cp /opt/mellanox/doca/lib/x86_64-linux-gnu/libdoca_comch.so* doca-libs/
	cp /opt/mellanox/doca/lib/x86_64-linux-gnu/libdoca_common.so* doca-libs/
	@echo "Building packages..."
	VERSION=$(VERSION) nfpm package -p deb -f packaging/nfpm-sentry-doca.yaml
	VERSION=$(VERSION) nfpm package -p rpm -f packaging/nfpm-sentry-doca.yaml
	@echo "Built: sentry-doca_$(VERSION)_amd64.deb, sentry-doca-$(VERSION)-1.x86_64.rpm"

# =============================================================================
# Docker Builds for QA Validation
# =============================================================================

# Build sentry container (run anywhere)
docker-sentry:
	@echo "Building sentry container..."
	docker build --provenance=false --build-arg VERSION=$(VERSION) -f Dockerfile.sentry -t sentry:dev .
	@echo "Built: sentry:dev (version: $(VERSION))"

# Build nexus container (run anywhere)
docker-nexus:
	@echo "Building nexus container..."
	docker build --provenance=false --build-arg VERSION=$(VERSION) -f Dockerfile.nexus -t nexus:dev .
	@echo "Built: nexus:dev (version: $(VERSION))"

# Build aegis container (run on BF3 only)
# Bundles DOCA and RDMA libs from host to avoid version mismatch with Ubuntu base
docker-aegis:
	@if [ "$$(uname -m)" != "aarch64" ]; then \
		echo "Error: docker-aegis must run on BF3 (arm64)"; \
		exit 1; \
	fi
	@echo "Building aegis binary with DOCA..."
	CGO_ENABLED=1 $(GO) build -tags doca \
		-ldflags "-s -w -X github.com/gobeyondidentity/secure-infra/internal/version.Version=$(VERSION)" \
		-o aegis ./cmd/aegis
	@echo "Bundling DOCA and RDMA libraries from host..."
	mkdir -p doca-libs
	cp /opt/mellanox/doca/lib/aarch64-linux-gnu/libdoca_comch.so* doca-libs/
	cp /opt/mellanox/doca/lib/aarch64-linux-gnu/libdoca_common.so* doca-libs/
	cp /usr/lib/aarch64-linux-gnu/libibverbs.so* doca-libs/
	cp /usr/lib/aarch64-linux-gnu/libmlx5.so* doca-libs/
	cp /usr/lib/aarch64-linux-gnu/libibverbs/*.so* doca-libs/ 2>/dev/null || true
	@echo "Building aegis container..."
	docker build --provenance=false -f Dockerfile.aegis -t aegis:dev .
	@echo "Built: aegis:dev (version: $(VERSION))"

# Remove bin directory contents
clean:
	@echo "Cleaning bin/..."
	@rm -rf $(BIN_DIR)/*
	@echo "Done."
