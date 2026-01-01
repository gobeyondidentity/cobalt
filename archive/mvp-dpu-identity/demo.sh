#!/bin/bash
# DPU Identity Demo - PKA Key Generation
set -e

echo "=== Bluefield DPU Identity Generator ==="
echo ""

# Device info
echo "[Device]"
cat /sys/class/infiniband/mlx5_0/node_desc 2>/dev/null || echo "N/A"
echo ""

# PKA engine check
echo "[PKA Engine]"
openssl engine pka 2>&1
echo ""

# Generate ECDSA key with PKA
echo "[Key Generation]"
openssl genpkey -engine pka -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/dpu.key
echo "Generated: /tmp/dpu.key"

# Show public key
echo ""
echo "[Public Key]"
openssl ec -in /tmp/dpu.key -pubout 2>/dev/null
