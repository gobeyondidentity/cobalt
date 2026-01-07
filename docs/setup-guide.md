# Secure Infrastructure Setup

Choose your setup path based on your environment.

## Quickstart: Emulator

**No hardware required.** Run everything locally with the DPU emulator.

Best for:
- Learning the system
- Development and testing
- CI/CD pipelines
- Product evaluation

Limitations:
- No trust relationships between hosts
- No hardware-secured credential delivery
- Mock attestation only

**[Start with the Emulator Quickstart](quickstart-emulator.md)**

---

## Hardware Setup: BlueField DPU

**Full production deployment** with real BlueField DPUs.

Best for:
- Real environments
- Design partners with hardware
- Testing trust relationships
- Real attestation flows

Requirements:
- NVIDIA BlueField-3 DPU
- Linux host paired with DPU
- SSH access to DPU

**[Start with the Hardware Setup Guide](setup-hardware.md)**
