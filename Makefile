# Secure Infrastructure Makefile
# Build commands for all project binaries

# Output directory
BIN_DIR := bin

# Binary names
AGENT := $(BIN_DIR)/agent
AGENT_ARM64 := $(BIN_DIR)/agent-arm64
BLUECTL := $(BIN_DIR)/bluectl
SERVER := $(BIN_DIR)/server
KM := $(BIN_DIR)/km
HOST_AGENT := $(BIN_DIR)/host-agent
DPUEMU := $(BIN_DIR)/dpuemu

.PHONY: all agent bluectl server km host-agent dpuemu test clean release help

# Default target: build all binaries
all: $(BIN_DIR)
	@echo "Building all binaries..."
	@go build -o $(AGENT) ./cmd/agent
	@echo "  $(AGENT)"
	@go build -o $(BLUECTL) ./cmd/bluectl
	@echo "  $(BLUECTL)"
	@go build -o $(KM) ./cmd/keymaker
	@echo "  $(KM)"
	@go build -o $(SERVER) ./cmd/server
	@echo "  $(SERVER)"
	@go build -o $(HOST_AGENT) ./cmd/host-agent
	@echo "  $(HOST_AGENT)"
	@go build -o $(DPUEMU) ./dpuemu/cmd/dpuemu
	@echo "  $(DPUEMU)"
	@echo "Done."

# Create bin directory if needed
$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Build agent for local platform and cross-compile for BlueField (ARM64)
agent: $(BIN_DIR)
	@echo "Building agent..."
	@go build -o $(AGENT) ./cmd/agent
	@echo "  $(AGENT)"
	@echo "Cross-compiling agent for BlueField (linux/arm64)..."
	@GOOS=linux GOARCH=arm64 go build -o $(AGENT_ARM64) ./cmd/agent
	@echo "  $(AGENT_ARM64)"

# Build bluectl CLI
bluectl: $(BIN_DIR)
	@echo "Building bluectl..."
	@go build -o $(BLUECTL) ./cmd/bluectl
	@echo "  $(BLUECTL)"

# Build server
server: $(BIN_DIR)
	@echo "Building server..."
	@go build -o $(SERVER) ./cmd/server
	@echo "  $(SERVER)"

# Build keymaker CLI
km: $(BIN_DIR)
	@echo "Building km (keymaker)..."
	@go build -o $(KM) ./cmd/keymaker
	@echo "  $(KM)"

# Build host-agent
host-agent: $(BIN_DIR)
	@echo "Building host-agent..."
	@go build -o $(HOST_AGENT) ./cmd/host-agent
	@echo "  $(HOST_AGENT)"

# Build DPU emulator
dpuemu: $(BIN_DIR)
	@echo "Building dpuemu..."
	@go build -o $(DPUEMU) ./dpuemu/cmd/dpuemu
	@echo "  $(DPUEMU)"

# Run all tests
test:
	@echo "Running tests..."
	@go test ./...

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
	@GOOS=darwin GOARCH=arm64 go build -o $(BIN_DIR)/agent-darwin-arm64 ./cmd/agent
	@echo "  $(BIN_DIR)/agent-darwin-arm64"
	@GOOS=darwin GOARCH=arm64 go build -o $(BIN_DIR)/bluectl-darwin-arm64 ./cmd/bluectl
	@echo "  $(BIN_DIR)/bluectl-darwin-arm64"
	@GOOS=darwin GOARCH=arm64 go build -o $(BIN_DIR)/km-darwin-arm64 ./cmd/keymaker
	@echo "  $(BIN_DIR)/km-darwin-arm64"
	@echo ""
	@echo "linux/amd64:"
	@GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/agent-linux-amd64 ./cmd/agent
	@echo "  $(BIN_DIR)/agent-linux-amd64"
	@GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/bluectl-linux-amd64 ./cmd/bluectl
	@echo "  $(BIN_DIR)/bluectl-linux-amd64"
	@GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/km-linux-amd64 ./cmd/keymaker
	@echo "  $(BIN_DIR)/km-linux-amd64"
	@GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/host-agent-linux-amd64 ./cmd/host-agent
	@echo "  $(BIN_DIR)/host-agent-linux-amd64"
	@echo ""
	@echo "linux/arm64 (BlueField DPU):"
	@GOOS=linux GOARCH=arm64 go build -o $(BIN_DIR)/agent-linux-arm64 ./cmd/agent
	@echo "  $(BIN_DIR)/agent-linux-arm64"
	@GOOS=linux GOARCH=arm64 go build -o $(BIN_DIR)/bluectl-linux-arm64 ./cmd/bluectl
	@echo "  $(BIN_DIR)/bluectl-linux-arm64"
	@GOOS=linux GOARCH=arm64 go build -o $(BIN_DIR)/km-linux-arm64 ./cmd/keymaker
	@echo "  $(BIN_DIR)/km-linux-arm64"
	@echo ""
	@echo "Release build complete."

# Show available targets
help:
	@echo "Secure Infrastructure Build Targets:"
	@echo ""
	@echo "  make all        Build all binaries (default)"
	@echo "  make agent      Build agent (local + ARM64 for BlueField)"
	@echo "  make bluectl    Build bluectl CLI"
	@echo "  make server     Build server"
	@echo "  make km         Build keymaker CLI"
	@echo "  make host-agent Build host-agent"
	@echo "  make dpuemu     Build DPU emulator"
	@echo "  make test       Run all tests"
	@echo "  make clean      Remove bin/ contents"
	@echo "  make release    Build release binaries for all platforms"
	@echo "  make help       Show this help"
