# BCM in GB200 NVL72 Clusters

This document describes how NVIDIA Base Command Manager (BCM) is used in production GB200 NVL72 AI infrastructure, and how it relates to our lab environment.

## Overview

BCM serves as the **foundational cluster management layer** in NVIDIA's GB200 NVL72 infrastructure. NVIDIA Mission Control 2.0 builds on top of BCM, adding workload orchestration, fabric management, and observability.

## Software Stack Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  NVIDIA Mission Control 2.0                                         │
│  ├── Run:ai 2.22 (workload orchestration)                           │
│  ├── Autonomous Recovery Engine                                     │
│  ├── NVLink Fabric Management (NMX-M)                               │
│  └── Observability / Dashboards                                     │
├─────────────────────────────────────────────────────────────────────┤
│  Base Command Manager 11 (BCM)                                       │
│  ├── Node provisioning (PXE boot, image deployment)                 │
│  ├── Software image management                                      │
│  ├── User/group administration (LDAP integration)                   │
│  ├── Network configuration (bcm-netautogen)                         │
│  └── Slurm job scheduling                                           │
├─────────────────────────────────────────────────────────────────────┤
│  GB200 NVL72 Hardware (per rack)                                     │
│  ├── 18 compute trays (72 Blackwell GPUs + Grace CPUs)              │
│  ├── NVLink switches (72-GPU NVLink domain)                         │
│  ├── BlueField-3 DPUs (2 per tray)                                  │
│  └── Liquid cooling infrastructure                                  │
└─────────────────────────────────────────────────────────────────────┘
```

### BCM's Role

BCM handles foundational cluster-management tasks:

| Responsibility | Description |
|----------------|-------------|
| **Node provisioning** | PXE boot, OS deployment, image management |
| **Software images** | Creating, updating, distributing OS/software configurations |
| **User administration** | Managing authentication through integrated or external LDAP |
| **Role assignments** | Controlling access and permissions across the cluster |
| **Network configuration** | Automated network generation via bcm-netautogen |
| **Job scheduling** | Slurm integration for workload distribution |

### Mission Control Additions

Mission Control builds on BCM's foundation:

- Workload management integration (Slurm, Run:ai)
- Hardware management (out-of-band, high-speed fabric, leak detection)
- Observability and monitoring dashboards
- Autonomous job and hardware recovery
- NVLink fabric management via NMX-M

## GB200 NVL72 Network Architecture

### Network Segments

| Network | Subnet | Purpose | Notes |
|---------|--------|---------|-------|
| **internalnet** | Site-specific | Control plane provisioning | DHCP enabled, PXE boot |
| **dgxnet** | Site-specific | GB200 compute node provisioning | 2 subnets per 8-rack SU |
| **ipminet** | Site-specific | Out-of-band BMC management | PDUs, switches, racks |
| **computenet** | 100.126.0.0/16 | East-West GPU traffic | Non-routable, MTU 4092 |
| **storagenet** | 100.127.0.0/16 | Converged Ethernet storage | Uses BlueField-3 port 2 |
| **failovernet** | Site-specific | Head node HA heartbeat | Between head node pair |
| **globalnet** | Site-specific | External connectivity | Default automatic network |

### Network Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Management Plane (BCM Head Nodes)                                           │
│  ├── internalnet: Control plane provisioning                                 │
│  ├── ipminet: BMC/IPMI management                                            │
│  └── failovernet: HA heartbeat                                               │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              │ PXE Boot / Provisioning
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  GB200 Compute Trays (18 per rack)                                           │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │  BlueField-3 DPU #1                    BlueField-3 DPU #2               │ │
│  │  ├── Port 1: dgxnet (provisioning)     ├── Port 1: dgxnet               │ │
│  │  └── Port 2: computenet (GPU traffic)  └── Port 2: storagenet           │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                              │                                               │
│                              │ NVLink                                        │
│                              ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │  4x Blackwell GPUs per tray (72 total per rack)                         │ │
│  │  Connected via NVLink switches (NVL72 domain)                           │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## BCM Installation for GB200

### Requirements

- **BCM 11** with **Ubuntu 24.04** base distribution
- **Mixed architecture**: Both x86_64 (head nodes) and aarch64 (Grace CPUs) ISOs required
- **License**: NVIDIA Mission Control or DGX-enabled license for ISO download

### Head Node Setup

1. Install via BMC virtual media or bootable USB
2. Select **Type 3 network topology** (DGX SuperPOD standard)
3. Configure networks: `internalnet` and `managementnet` (dgxnet)
4. Select RAID1 for M.2 drives
5. Activate license with `request-license` command

### Compute Node Provisioning

GB200 compute trays boot via their **BlueField-3 DPUs**, not the Grace CPU directly:

1. BlueField-3 defaults to PXE boot mode
2. BCM DHCP/TFTP serves the BF3 NICs
3. BF3 loads the provisioning image
4. Image is deployed to local storage
5. Grace CPU boots from local disk

## NVLink Fabric Management

### Default Configuration

The GB200 NVL72 rack creates a **72-GPU NVLink Domain** by default. All GPUs can communicate with each other through the NVLink switches.

### GPU Partitioning

Administrators can create **User Partitions** for multi-tenancy:

```bash
# View current partitions
nv show sdn partition

# Create a new partition
nv action create sdn partition <partition-name>
```

### Fabric Monitoring

BCM integrates with NMX-M (NVLink Management Software-Manager) to expose:

- GPU health counts (healthy, degraded, non-vlink)
- Domain health status
- Switch health and port counts
- Compute allocation metrics

## Comparison: Lab vs Production

| Aspect | Lab (TrueNAS VMs) | Production GB200 NVL72 |
|--------|-------------------|------------------------|
| **Compute nodes** | VMs on TrueNAS | 18 physical compute trays per rack |
| **PXE boot** | iPXE ISO workaround | Native PXE via BlueField-3 |
| **Head nodes** | Single head node | HA head node pair (failovernet) |
| **Scale** | 2 compute nodes | 72 GPUs per rack, 8 racks per SU (576 GPUs) |
| **Network isolation** | br0 isolated bridge | Multiple VLANs (dgxnet, computenet, storagenet) |
| **Workload manager** | Slurm only | Slurm + Run:ai + autonomous recovery |
| **DPU role** | N/A (VMs) | Network boot, storage traffic, fabric enforcement |

## Relevance to Identity Fabric Project

The BlueField-3 DPUs in GB200 NVL72 are the **exact hardware target** for our identity fabric work.

### Current BF3 Functions in GB200

Each compute tray has 2 BlueField-3 DPUs handling:

1. **Network boot** (PXE provisioning via dgxnet)
2. **GPU traffic** (computenet via BF3 #1, port 2)
3. **Storage traffic** (storagenet via BF3 #2, port 2)

### Identity Fabric Value Add

Our solution adds to the BF3's responsibilities:

| Function | Current State | With Identity Fabric |
|----------|---------------|---------------------|
| **Authentication** | Network-based (IP/VLAN) | mTLS with TPM-bound certs |
| **Authorization** | Slurm/Run:ai policies | OVS flow rules per identity |
| **Attestation** | None | DICE/SPDM verification |
| **Encryption** | Optional | PKA-accelerated TLS offload |

### Integration Points

```
┌─────────────────────────────────────────────────────────────────────┐
│  Data Scientist Workstation                                          │
│  └── Beyond Identity: TPM-bound passkey/certificate                  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ mTLS (cert bound to endpoint TPM)
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  GB200 Compute Tray - BlueField-3 DPU                                │
│  ├── TLS Offload: Validate client cert (PKA accelerated)            │
│  ├── OVS Policy: Apply identity-based flow rules                    │
│  ├── Attestation: DICE/SPDM verify infrastructure identity          │
│  └── Enforce: GPU access, model boundaries, data isolation          │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ Authorized access only
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  GPU Cluster (NVL72 Domain)                                          │
│  └── Model training/inference with hardware-enforced boundaries      │
└─────────────────────────────────────────────────────────────────────┘
```

## References

- [Mission Control Software Stack](https://docs.nvidia.com/mission-control/docs/systems-administration-guide/2.0.0/software-stack.html)
- [BCM Software Installation](https://docs.nvidia.com/mission-control/docs/rack-bring-up-install/2.0.0/bcm-installation.html)
- [BCM Networking Setup](https://docs.nvidia.com/mission-control/docs/rack-bring-up-install/2.0.0/bcm-networking.html)
- [High-Speed Fabric Management](https://docs.nvidia.com/mission-control/docs/systems-administration-guide/2.0.0/high-speed-fabric-management.html)
- [Mission Control 2.0.0 Release Notes](https://docs.nvidia.com/mission-control/docs/systems-quick-start-guide/2.0.0/nmc-release-notes.html)
- [GB200/GB300 Rack Bring Up](https://docs.nvidia.com/mission-control/docs/rack-bring-up-install/2.0.0/rack-bring-up.html)
