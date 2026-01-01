# BlueField DPU Management Dashboard: The Landscape in December 2025

**Source**: Claude (Anthropic) Deep Research
**Date**: December 2025

---

**No unified management dashboard for NVIDIA BlueField DPUs exists today.** The closest options are NVIDIA's DOCA BlueMan (single-DPU web UI), the DOCA Platform Framework (Kubernetes-based fleet orchestration without GUI), and Cisco Secure Workload (third-party with OVS flow visibility). This creates a clear market opportunity for a comprehensive DPU management platform that combines multi-DPU orchestration, OVS flow visualization, and security attestation in a single interface.

The BlueField management ecosystem is fragmented across several purpose-built tools rather than consolidated into a single pane of glass. NVIDIA provides the foundational components—BlueMan for single-node monitoring, DPF for Kubernetes orchestration, and DOCA Telemetry for metrics export—but leaves the unified dashboard problem unsolved. Security vendors like Cisco, Fortinet, and Xage have built integrations focused on their specific use cases, while open-source projects like OPI aim for cross-vendor standardization at the API level.

---

## NVIDIA's official tools span monitoring to orchestration

### DOCA BlueMan: The only NVIDIA-provided web UI

DOCA BlueMan is NVIDIA's **sole web-based GUI** for BlueField monitoring, accessible at the DPU's out-of-band IP address. It consolidates three tabs of information: system info (OS, kernel, firmware, DOCA version, mlxconfig parameters), health monitoring (services, kernel modules, dmesg, port status, CPU/memory/disk usage, temperatures), and telemetry (all DTS counters with custom graph building).

**Critical limitations**: BlueMan monitors only one DPU at a time with no fleet aggregation, displays OVS counters but not individual flow entries, lacks any DICE/SPDM attestation visualization, and provides no host introspection view from the DPU perspective. It requires BlueField image version 3.9.3.1+ and depends on DOCA Telemetry Service (DTS) and DOCA Privileged Executor (DPE) running.

### DOCA Platform Framework: Kubernetes-native at scale

DPF represents NVIDIA's strategic direction for multi-DPU management—a Kubernetes-native orchestration framework using CRDs (DPUSet, DPU, DPUService, BFB, DPUDeployment). It automates BFB firmware flashing, DPU configuration, host reboots, and service deployment including OVN-Kubernetes and Host-Based Networking. The latest release is **v25.10.0** (December 2025) with dual-port BlueField-3 support.

DPF provides no built-in GUI—management occurs entirely through kubectl and the Kubernetes API. It integrates with Red Hat OpenShift and Canonical Kubernetes LTS but relies on standard Kubernetes tooling for visualization. For organizations building cloud-native infrastructure, DPF offers comprehensive lifecycle management; for traditional IT teams wanting dashboards, it creates a gap.

### DOCA Telemetry Service: Export-only metrics

DTS collects real-time system and workload metrics from BlueField including sysfs, ethtool, diagnostic data, and OVS metrics via the ovs-exporter service. Export options include Prometheus endpoint, Fluent Bit push, NetFlow, OpenTelemetry, and gRPC. While DTS enables comprehensive monitoring, **NVIDIA provides no pre-built Grafana dashboards**—organizations must create their own visualizations.

### Other NVIDIA tools and their boundaries

**Base Command Manager (BCM)** provides cluster-level DPU management through cm-dpu-setup and cm-dpu-manage tools, handling firmware and network configurations across fleets. However, BCM focuses on cluster operations rather than DPU introspection—no OVS flows, no DOCA telemetry integration, no attestation UI.

**UFM (Unified Fabric Manager)** manages InfiniBand fabric, recognizing BlueField DPUs as endpoints but providing no DPU-specific service visibility. **Mission Control** targets DGX SuperPOD systems exclusively, unavailable for standalone BlueField deployments. **DOCA Management Service (DMS)** offers gNMI/OpenConfig-based configuration but remains CLI-only and alpha-level.

---

## Third-party vendors fill security-focused gaps

### Cisco Secure Workload: Deepest OVS integration

Cisco Secure Workload (versions 3.9 and 3.10) provides the **most comprehensive third-party DPU introspection**, running an agent on BlueField-3's Arm cores. Key capabilities include OVS flow telemetry via ASAP2 framework from eSwitch hardware, connection tracking with allowed/denied packet telemetry, microsegmentation policy enforcement programmed into OpenFlow rules, and hardware-accelerated ACL processing.

The Cisco Secure Workload console delivers full workload visibility with AI-powered policy automation. This represents the closest existing solution to "seeing OVS flows through a web UI"—though it's designed for microsegmentation enforcement rather than general DPU management.

### Fortinet FortiGate: Firewall-centric management

Fortinet's December 2025 announcement brings FortiGate VM directly onto BlueField-3 DPUs, accessible through standard FortiGate GUI at port 443. FortiManager provides centralized visibility and policy enforcement. This integration focuses on firewalling and zero-trust segmentation rather than general DPU management—**for FortiGate on BlueField, not BlueField management broadly**.

### VMware vSphere Distributed Services Engine

VMware's Project Monterey (now vSphere Distributed Services Engine) integrates BlueField management into vCenter, offering DPU lifecycle management through vSphere Web UI, firmware updates via vSphere Lifecycle Manager, and NSX Distributed Firewall visibility for offloaded rules. Currently supports BlueField-2 in production with BlueField-3 support in development.

### Security vendor ecosystem expansion

The October 2025 GTC Washington D.C. announcements revealed significant security vendor activity:

- **Xage Security Fabric Platform**: Zero-trust identity-based segmentation for AI agents and data flows, running directly on BlueField with Xage console management
- **Check Point AI Cloud Protect**: AI factory security with host-level visibility via DOCA Argus, currently piloting with financial services
- **CrowdStrike Falcon**: XDR agent integration for real-time threat detection
- **Palo Alto Networks VM-Series**: Intelligent Traffic Offload achieving 5x performance with 80% traffic offload to BlueField
- **Trend Micro Vision One EDR**: Live memory analysis via DMA, reverse shell detection

These integrations uniformly focus on **security enforcement rather than general DPU management**. Each vendor maintains their own management console without providing unified BlueField visibility.

---

## Open source projects lack GUI dashboards

### NVIDIA doca-platform on GitHub

The official NVIDIA repository (github.com/NVIDIA/doca-platform, 64 stars, Apache-2.0 license) provides the Kubernetes operators for DPF. It's actively maintained but offers no GUI component—purely CRDs and operator logic.

### OpenShift DPU Network Operator

Red Hat's operator (github.com/openshift/dpu-network-operator) manages OVN-kube components on BlueField-2, enabling OVS hardware offloading via ASAP2. It implements a two-cluster architecture with ARM-based infra cluster and x86 tenant cluster. Currently in developer preview with production support expected to follow.

### OPI Project: Cross-vendor standardization

The Linux Foundation's Open Programmable Infrastructure project (opiproject.org) represents the **most significant effort toward vendor-agnostic DPU management**, with Dell, F5, Intel, Keysight, Marvell, NVIDIA, and Red Hat as members. OPI defines gRPC-based APIs for networking, storage, and security across DPUs/IPUs. However, OPI provides reference implementations rather than production management tools—no GUI, purely API standardization.

### OVS visualization options

**ovs-flowviz** (part of openvswitch package) generates HTML tables and Graphviz graphs for flow visualization, but runs as a CLI tool producing static output rather than a live dashboard. **Open vMonitor** from PLVision offers a web GUI for basic OVS monitoring but lacks BlueField-specific ASAP2 awareness. The **DOCA OVS Metrics Exporter** exposes hardware counters to Prometheus but requires custom Grafana dashboard creation.

---

## Standards-based management through Redfish and SPDM

### BlueField BMC Redfish is production-ready

BlueField's integrated AST2600 BMC provides comprehensive Redfish support through OpenBMC. Available endpoints include system management (/redfish/v1/Systems/Bluefield), firmware inventory, account services with LDAP/AD, and critically, component integrity for SPDM attestation targets. Remote firmware updates, sensor telemetry, power management, and serial-over-LAN are fully functional.

The OpenBMC **webui-vue** interface provides basic BMC management but lacks DPU-specific features like OVS flow visualization or DOCA telemetry integration.

### SPDM attestation exists without visualization

BlueField-3 supports SPDM v1.1 attestation via the Platform Security Controller (PSC) as hardware root of trust. Two attestation targets are exposed: Bluefield_DPU_IRoT (containing Arm and NIC measurements) and Bluefield_ERoT (BMC measurements). Certificate chains and signed measurements are accessible via Redfish endpoints at /redfish/v1/ComponentIntegrity/.

**No dedicated GUI exists for SPDM visualization.** Attestation verification requires custom scripts parsing JSON responses from Redfish, using tools like libspdm (DMTF reference implementation) or spdm-dump. The Mellanox spdm-test repository provides BlueField-specific testing utilities. NVIDIA acts as Endorser and Reference Value Provider using CoRIM/CoMID format for reference measurements.

### gNMI support remains experimental

DOCA Management Service offers gNMI protocol support (Get, Set) but Subscribe for streaming telemetry is not yet functional. The DOCA YANG model remains experimental. gNMIc can connect to DMS for configuration but real-time telemetry streaming awaits future releases.

---

## The competitive landscape beyond NVIDIA

### Intel IPU uses IPDK without enterprise management

Intel's Infrastructure Processing Unit (E2100 with 16 Arm cores and P4 pipeline) relies on the open-source **IPDK** framework building on DPDK and SPDK. Intel provides no enterprise management platform—IPDK is developer-focused. Google Cloud is a key customer using FPGA-based IPUs.

### AMD Pensando offers PSM for its hardware only

AMD Pensando Policy and Services Manager (PSM) provides full-stack management but exclusively for Pensando DPUs (Elba, Giglio, upcoming Salina 400). The Software-in-Silicon Development Kit includes P4 compiler, simulators, and debugging tools. Integration with VMware Project Monterey demonstrates enterprise viability, but PSM doesn't address multi-vendor scenarios.

### Cloud providers keep management internal

AWS Nitro, Microsoft Azure Catapult, and similar cloud-provider SmartNICs use proprietary management fully integrated into internal control planes. **No third-party management platforms serve these systems**, and cloud providers don't expose DPU management interfaces to customers.

---

## Answering the specific questions

**1. OVS flows through web UI?** Cisco Secure Workload comes closest, providing OVS flow telemetry and microsegmentation visibility through its console. For native NVIDIA tools, the combination of DOCA Telemetry Service + custom Grafana dashboards can visualize OVS metrics but not individual flow entries. ovs-flowviz generates static HTML visualizations but isn't a live dashboard.

**2. DICE certificate chain visualization?** No tool currently visualizes DICE certificate chains from BlueField attestation. SPDM measurements are accessible only via Redfish API calls returning JSON. Verification requires custom scripts or integration with libspdm-based tooling.

**3. Single pane of glass for multiple DPUs?** DOCA Platform Framework provides Kubernetes-based multi-DPU orchestration without a GUI. Base Command Manager offers cluster-level management for firmware and configurations. For a traditional dashboard experience managing multiple DPUs, no solution exists—this is a clear market gap.

**4. Closest BlueField-specific dashboard?** **DOCA BlueMan** is NVIDIA's official single-DPU web dashboard with health, telemetry, and system info. For multi-DPU scenarios with third-party integration, VMware vSphere Distributed Services Engine provides vCenter-based management with DPU visibility.

**5. Startups or open source building DPU management?** No active startups are building unified DPU management platforms—the market is dominated by silicon vendors. **Fungible** attempted this but was acquired by Microsoft for $190M in 2023. The **OPI Project** standardizes APIs across vendors but doesn't provide production management tools. NVIDIA's DPF is open source but Kubernetes-native without traditional dashboards.

---

## Gaps and differentiation opportunities

The research reveals significant gaps for a DPU management dashboard:

- **Unified multi-DPU web dashboard**: No existing tool provides traditional IT-style dashboard management across multiple BlueField DPUs
- **OVS flow table visualization**: While metrics exist, no tool displays actual flow entries with hardware offload status through a web interface
- **SPDM/DICE attestation dashboard**: Certificate chain visualization and measurement verification lack any GUI tooling
- **Host introspection from DPU**: DOCA App Shield provides the capability but exports to telemetry without visualization
- **Multi-tenant DPU grouping**: DPF handles Kubernetes namespaces but no tool provides enterprise multi-tenancy management
- **Cross-vendor DPU management**: OPI standardizes APIs but no production tool manages NVIDIA, Intel, and AMD DPUs together

Building on DPF for orchestration, DOCA Telemetry for metrics, and Redfish/SPDM for attestation, a management dashboard could differentiate by providing what NVIDIA explicitly doesn't: a web-based unified interface combining fleet visibility, OVS flow introspection, security attestation visualization, and multi-tenant organization for AI infrastructure operations teams.
