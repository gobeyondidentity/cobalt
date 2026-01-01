# Unified BlueField DPU Management Dashboard Landscape Analysis

## Executive Summary

The current market lacks a true "single pane of glass" solution for unified BlueField DPU management. While NVIDIA provides several management tools, each addresses specific aspects of DPU operations without delivering comprehensive, multi-DPU visibility. **DOCA BlueMan** represents the only native DPU web dashboard, but operates at the individual DPU level. **DOCA Platform Framework (DPF)** offers the closest approximation to unified management through Kubernetes orchestration, yet remains a control plane rather than a visualization interface. Third-party integrations from Xage Security, Fortinet, and Cisco focus exclusively on security workload offloading rather than general DPU management.

***

## NVIDIA Native Management Tools Assessment

### 1. DOCA BlueMan Service - The Only Native DPU Dashboard

**What it does:**
- Runs directly on each BlueField DPU as a standalone web dashboard accessible via the DPU's OOB management IP
- Consolidates system information, health status, and telemetry counters into a single web interface
- Provides real-time visibility into CPU usage, memory consumption, disk utilization, temperature, and port status
- Displays installed packages, kernel modules, DPU operation mode, and firmware information
- Integrates with DOCA Telemetry Service (DTS) to present telemetry counters in tabular and graphical formats
- Enables users to build custom graphs of specific performance counters

**What it doesn't do:**
- **No multi-DPU aggregation** - Each BlueMan instance is isolated to its host DPU; cannot manage or display data from multiple DPUs simultaneously
- **No OVS flow visualization** - Does not expose Open vSwitch flow rules or bridge configurations
- **No DICE/SPDM attestation display** - Lacks certificate chain visualization or attestation status
- **No host introspection** - Cannot view host system firmware, OS, or security posture from the DPU perspective
- **No multi-tenant grouping** - No concept of logical DPU groupings or tenant isolation in the UI

**DPU-level introspection:** Yes, but limited to the local DPU only. Provides deep visibility into DPU internals but no cross-DPU or host-context awareness.

**Deployment:** Available as a default service in BlueField BSP, located at `/opt/mellanox/doca/services/blueman/`[1][2]

***

### 2. DOCA Platform Framework (DPF) - Orchestration Control Plane

**What it does:**
- Provides Kubernetes-native orchestration for fleets of BlueField DPUs across clusters
- Maintains real-time state for each DPU, enabling dynamic responsiveness to DPU health events
- Supports automated rolling updates with batch controls to update specified percentages of DPUs at a time
- Enables proactive node draining during maintenance to minimize workload impact
- Exposes APIs and Custom Resource Definitions (CRDs) for automating DPU lifecycle management
- Integrates with monitoring stack (Prometheus, Grafana, Parca) for centralized telemetry collection
- Supports predeployment verification with meaningful error messages when DPU requirements aren't met

**What it doesn't do:**
- **No native GUI** - DPF is a control plane framework, not a visualization dashboard
- **No DPU-specific telemetry visualization** - Relies on external tools (Grafana) for data presentation
- **No OVS flow management** - Does not expose virtual switch configurations or flow rules
- **No attestation visualization** - No built-in DICE/SPDM certificate chain display
- **Limited host context** - Focuses on DPU orchestration rather than host-DPU relationship mapping

**DPU-level introspection:** Partial. Provides health monitoring and resource availability status but delegates detailed telemetry to DTS and visualization to external tools.

**Architecture:** Implements a secondary Kubernetes control plane on DPUs, managed by the DPF Operator running on the primary cluster[3][4]

---

### 3. DOCA Telemetry Service (DTS) - Data Collection Engine

**What it does:**
- Collects telemetry data from built-in providers (sysfs, ethtool, DCGM, RDMA, etc.) and external applications
- Supports multiple export mechanisms: Prometheus endpoint (pull), Fluent Bit (push), OpenTelemetry (push), Prometheus Remote Write
- Enables NetFlow export when integrated with DOCA Telemetry Exporter NetFlow API
- Provides aggregation providers for collecting data from other applications via TCP or IPC
- Runs natively on both hosts and BlueField DPUs with DPU-specific providers

**What it doesn't do:**
- **No visualization layer** - Pure data collection service; requires integration with Grafana or similar tools
- **No configuration management** - Cannot modify DPU settings or OVS configurations
- **No attestation data** - Does not collect DICE/SPDM certificate information
- **No multi-DPU correlation** - Each DTS instance operates independently; aggregation requires external tooling

**DPU-level introspection:** Extensive. Provides deep telemetry on DPU performance, networking, and system metrics, but lacks a presentation layer[5][6][7]

---

### 4. Base Command Manager (BCM) - Cluster Management

**What it does:**
- Manages firmware, network configurations, and health monitoring for BlueField-2 and BlueField-3 DPUs within AI/HPC clusters
- Provides cluster-wide provisioning and workload management capabilities
- Includes system images for DGX A100 and HGX H100 platforms with integrated DPU support

**What it doesn't do:**
- **No DPU-specific dashboard** - General cluster management tool without DPU-introspection features
- **No OVS flow visibility** - Cannot display virtual switch configurations
- **No attestation management** - No DICE/SPDM certificate handling
- **Limited to DGX environments** - Primarily designed for NVIDIA's DGX systems rather than general-purpose BlueField deployments

**DPU-level introspection:** Basic. Provides health checks and firmware management but lacks detailed DPU operational visibility[8][9]

---

### 5. Unified Fabric Manager (UFM) - Network Fabric Focus

**What it does:**
- Provides real-time monitoring, provisioning, and optimization for InfiniBand and Ethernet fabrics
- Offers granular traffic analysis, congestion detection, and threshold-based alerting
- Supports fabric segmentation, QoS policies, and routing optimizations
- Integrates with Mission Control for AI factory observability

**What it doesn't do:**
- **No DPU-specific management** - Focuses on fabric-level operations, not DPU internals
- **No OVS flow display** - Cannot visualize virtual switch configurations
- **No attestation features** - No DICE/SPDM support
- **No host introspection** - Lacks host-DPU relationship mapping

**DPU-level introspection:** Minimal. Monitors DPU network ports as fabric endpoints but doesn't expose DPU-internal state[10][11][12]

***

### 6. Mission Control - AI Factory Operations

**What it does:**
- Provides scalable control plane for AI infrastructure with integrated observability
- Leverages UFM and NMX Manager for telemetry collection across GPUs, switches, and DPUs
- Offers centralized dashboards for infrastructure monitoring and alerting
- Supports automated workload recovery and hardware anomaly detection

**What it doesn't do:**
- **No DPU-specific dashboards** - Infrastructure-wide view without DPU-level drill-down capabilities
- **No OVS flow management** - Cannot configure or visualize virtual switch flows
- **No attestation visualization** - No DICE/SPDM certificate chain display
- **Limited DPU introspection** - Treats DPUs as infrastructure components rather than manageable entities

**DPU-level introspection:** Limited. Provides telemetry collection but lacks DPU-specific operational controls[13][14]

***

## Third-Party Integration Analysis

### Xage Security Fabric Platform

**What it does:**
- Integrates with BlueField DPUs to enforce hardware-accelerated, identity-based Zero Trust controls
- Provides real-time, line-speed enforcement of access policies between AI agents, models, and data
- Enables role-based segmentation and policy-based privilege de-escalation
- Delivers audit trails for compliance with NIST, NERC CIP, EU NIS2, and U.S. Zero Trust mandates

**What it doesn't do:**
- **Not a general DPU management tool** - Security-focused only; no OVS, telemetry, or attestation visualization
- **No multi-DPU dashboard** - Integration is at the policy enforcement layer, not management UI
- **No host introspection** - Focuses on data flow governance, not host-DPU relationship mapping

**DPU-level introspection:** No. Operates as a security policy engine leveraging DPU acceleration without exposing DPU internals[15][16][17]

---

### Fortinet FortiGate VM on BlueField-3

**What it does:**
- Runs FortiGate virtual firewall directly on BlueField-3 DPUs (supported from FortiOS 7.6.3)
- Offloads firewalling, segmentation, and zero-trust policy enforcement to DPU hardware
- Provides isolated infrastructure acceleration for AI data centers and private clouds
- Enables line-rate security inspection without impacting GPU/CPU workloads

**What it doesn't do:**
- **Not a DPU management interface** - FortiManager manages firewall policies, not DPU resources
- **No OVS flow visibility** - Cannot display or manage Open vSwitch configurations
- **No attestation support** - No DICE/SPDM certificate chain functionality
- **No telemetry integration** - Does not consume or display DOCA telemetry data

**DPU-level introspection:** No. FortiGate runs as a workload on the DPU without exposing DPU management capabilities[18][19][20]

***

### Cisco Secure Workload (Tetration)

**What it does:**
- Offloads Secure Workload Agent functionality from hosts to BlueField-3 DPUs
- Gathers flow telemetry and enforces microsegmentation policies on the DPU
- Leverages BlueField hardware accelerators for enhanced performance and scalability
- Integrates with OVS for traffic processing and policy enforcement

**What it doesn't do:**
- **Not a DPU management dashboard** - Focuses on workload security, not DPU operations
- **No OVS flow visualization** - While it uses OVS, it doesn't expose flow rules in a GUI
- **No attestation features** - No DICE/SPDM certificate handling
- **Limited DPU telemetry** - Consumes flow data but doesn't display comprehensive DPU metrics

**DPU-level introspection:** Minimal. Uses DPU as an enforcement point without exposing DPU-internal state[21][22][23]

---

## Open Source and Standards-Based Tools

### OVS Flow Visualization

**Available tools:**
- `ovs-flowviz`: Utility script for visualizing OpenFlow and datapath flows, generating interactive HTML tables and graphviz graphs
- `ovs-appctl dpctl/dump-flows`: Command-line tool for displaying offloaded flows on BlueField

**Limitations:**
- **Generic OVS tools** - Not DPU-aware; cannot distinguish BlueField-specific flow offloading characteristics
- **No centralized multi-DPU view** - Operates on individual OVS instances
- **Complex output** - Requires significant manual interpretation; lacks user-friendly GUI

**DPU-level introspection:** Partial. Can display flows offloaded to BlueField hardware but doesn't correlate with DPU telemetry or health status[24][25]

---

### Redfish-Based Management

**What it does:**
- DPU BMC provides Redfish APIs for out-of-band management
- Supports firmware updates, power control, BIOS settings, and Secure Boot configuration
- Enables SPDM attestation via Redfish endpoints (`/redfish/v1/Systems/Bluefield/TrustedComponents`)
- Provides certificate chain retrieval and signed measurement collection

**What it doesn't do:**
- **No unified dashboard** - Requires custom tooling to aggregate data from multiple DPUs
- **No OVS integration** - Cannot access virtual switch configurations
- **No telemetry correlation** - BMC data is separate from DOCA telemetry streams
- **Complex authentication** - Requires token management and HTTPS client implementation

**DPU-level introspection:** Extensive for hardware/firmware, but lacks integration with runtime DPU services and OVS[26][27][28][29]

---

### SPDM/DICE Attestation Tools

**Current state:**
- NVIDIA provides Redfish APIs for retrieving DICE certificate chains and signed measurements
- BlueField-3 stores attestation measurements in SPDM certificate slot 0
- Supports TPM_ALG_SHA_512 hashing and TPM_ALG_ECDSA_ECC_NIST_P384 signing algorithms

**Gap:** No visualization tools or dashboards exist for DICE certificate chain validation or attestation status monitoring. All interaction is via Redfish API calls or `ipmitool` commands[29][30][31]

***

## Specific Questions Answered

### 1. Does any existing tool let you see OVS flows on a BlueField DPU through a web UI?

**No.** While generic OVS visualization tools like `ovs-flowviz` can display flows, no DPU-specific web UI exists that:
- Shows flows offloaded to BlueField hardware acceleration
- Correlates flows with DPU telemetry metrics
- Provides multi-DPU OVS topology visualization
- Displays flow performance counters from DOCA telemetry

The closest capability is `ovs-appctl dpctl/dump-flows type=offloaded` on each DPU, which requires CLI access[25]

***

### 2. Does any tool visualize DICE certificate chains from BlueField attestation?

**No.** NVIDIA provides Redfish APIs to retrieve certificate chains via:
```
GET /redfish/v1/Systems/Bluefield/TrustedComponents/{ComponentName}
```
However, no GUI tool exists to:
- Display certificate chain hierarchies visually
- Validate attestation signatures
- Monitor attestation status across DPUs
- Correlate attestation with runtime measurements

This remains an API-driven capability requiring custom tooling[29]

***

### 3. Is there a "single pane of glass" for managing multiple BlueField DPUs across a cluster?

**No comprehensive solution exists.** The closest approximations are:

- **DPF with external monitoring**: Provides unified orchestration but requires integrating Grafana/Prometheus for visualization
- **Mission Control**: Offers AI factory dashboards but treats DPUs as infrastructure components without DPU-specific drill-down
- **Base Command Manager**: Manages DPUs within DGX clusters but lacks DPU-introspection features

All existing tools have significant gaps in OVS flow visibility, attestation display, and host-DPU relationship mapping[4][13][3]

---

### 4. What's the closest thing to a BlueField-specific management dashboard today?

**DOCA BlueMan** is the only native DPU dashboard, but it's limited to single-DPU management. For multi-DPU scenarios, the combination of **DPF + Grafana** provides the most complete (though fragmented) solution:

**DPF + Grafana Architecture:**
- DPF orchestrates DPU fleet and deploys DTS on each DPU
- DTS collects telemetry and exports to Prometheus
- Grafana visualizes metrics with custom dashboards
- Requires significant manual integration; no pre-built DPU-specific Grafana templates exist

**Limitations of this approach:**
- No OVS flow visualization in Grafana
- No attestation data in telemetry pipeline
- No host introspection correlation
- Complex setup requiring Kubernetes expertise[32][33][7]

---

### 5. Are there any startups or open-source projects building DPU management platforms?

**No active projects identified.** The search revealed:
- **No open-source DPU management platforms** on GitHub or similar repositories
- **No startups** exclusively focused on BlueField DPU management dashboards
- Third-party integrations (Xage, Fortinet, Cisco) are security-focused rather than general management tools

The ecosystem remains nascent, with NVIDIA providing only foundational building blocks (DPF, DTS, BlueMan) rather than a turnkey management solution[15][18][21]

---

## Gap Analysis and Differentiation Opportunities

### Critical Gaps in Current Tooling

| Requirement | Existing Solution | Gap Severity |
|-------------|-------------------|--------------|
| Multi-DPU aggregation

[1](https://docs.nvidia.com/doca/archive/doca-v2.2.0/pdf/doca-blueman-service.pdf)
[2](https://docs.nvidia.com/doca/sdk/doca-blueman-service-guide/index.html)
[3](https://developer.nvidia.com/blog/powering-the-next-wave-of-dpu-accelerated-cloud-infrastructures-with-nvidia-doca-platform-framework/)
[4](https://docs.nvidia.com/networking/display/public/SOL/RDG+for+Centralized+DPU+Monitoring+Solution+using+DPF+and+DTS)
[5](https://docs.nvidia.com/doca/sdk/DOCA-Telemetry-Service-Guide/index.html)
[6](https://docs.nvidia.com/doca/archive/2-5-3/nvidia-doca-telemetry-service-guide.pdf)
[7](https://docs.nvidia.com/networking/display/dpf2507/doca+telemetry+service)
[8](https://docs.nvidia.com/base-command-manager/bcm-10-release-notes/overview.html)
[9](https://www.nvidia.com/en-us/data-center/base-command-manager/)
[10](https://xenon.com.au/products-and-solutions/nvidia-united-fabric-manager/)
[11](https://www.nvidia.com/en-us/networking/infiniband/ufm/)
[12](https://www.nvidia.com/en-eu/networking/infiniband/ufm2/)
[13](https://developer.nvidia.com/blog/automating-ai-factory-operations-with-nvidia-mission-control/)
[14](https://www.zadara.com/wp-content/uploads/NVIDIA-multi-tenant-WP.pdf)
[15](https://www.linkedin.com/posts/xage-security_zerotrust-activity-7389010947983720448-Go_e)
[16](https://siliconangle.com/2025/10/28/xage-extends-zero-trust-ai-agents-data-centers-nvidia-bluefield-integration/)
[17](https://xage.com/press/xage-integrates-nvidia-bluefield-to-deliver-unified-zero-trust-for-ai/)
[18](https://www.investing.com/news/company-news/fortinet-integrates-firewall-solution-with-nvidia-bluefield3-dpus-93CH-4410875)
[19](https://securitybrief.com.au/story/fortinet-moves-ai-data-centre-security-onto-nvidia-dpus)
[20](https://docs.fortinet.com/document/fortigate-private-cloud/7.6.0/bluefield-3-deployment-guide/489491/fortigate-vm-on-nvidia-bluefield-3)
[21](https://developer.nvidia.com/blog/spotlight-cisco-enhances-workload-security-and-operational-efficiency-with-nvidia-bluefield-3-dpus/)
[22](https://yappit.org/partners/cisco-secure-workload/)
[23](https://www.cisco.com/c/en/us/td/docs/security/workload_security/secure_workload/whats-new/whats_new_cisco_secure_workload_release_3_9_1_1.html)
[24](https://docs.openvswitch.org/en/stable/topics/flow-visualization/)
[25](https://docs.nvidia.com/networking/display/BlueFieldDPUOSv385/Virtual+Switch+on+BlueField+DPU)
[26](https://docs.nvidia.com/networking/display/bluefielddpuosv397/Intelligent+Platform+Management+Interface)
[27](https://docs.nvidia.com/networking/display/bluefielddpuosv470/Intelligent+Platform+Management+Interface)
[28](https://docs.nvidia.com/networking/display/BlueFieldBMCv2307/Intelligent+Platform+Management+Interface)
[29](https://docs.nvidia.com/networking/display/bluefieldbmcv2507/DPU+BMC+SPDM+Attestation+via+Redfish)
[30](https://trustedcomputinggroup.org/wp-content/uploads/TCG-DICE-Concise-Evidence-Binding-for-SPDM-Version-1.0-Revision-53_1August2023.pdf)
[31](https://docs.nvidia.com/networking/display/nvidia-device-attestation-and-corim-based-reference-measurement-sharing-v4-0.0.pdf)
[32](https://docs.nvidia.com/networking/display/dpf2504/Observability)
[33](https://forums.developer.nvidia.com/t/how-to-analyze-data-collected-by-doca-telemetry-service/294767)
[34](https://catalog.ngc.nvidia.com/orgs/nvidia/teams/doca/containers/doca_telemetry)
[35](https://docs.nvidia.com/networking/display/BF3DPU/BlueField+DPU+Administrator+Quick+Start+Guide)
[36](https://futurumgroup.com/insights/computex-2021-nvidias-bluefield-2-dpus-and-base-command-ai/)
[37](https://support.brightcomputing.com/manuals/10/admin-manual.pdf)
[38](https://docs.nvidia.com/nvidia-ufm-enterprise-user-manual-v6-11-2.pdf)
[39](https://docs.nvidia.com/doca/archive/2-9-1/DOCA+Telemetry+Service+Guide/)
[40](https://docs.nvidia.com/ai-enterprise/planning-resource/ai-factory-reference-design-for-government-white-paper/latest/observability.html)
[41](https://www.nvidia.com/en-us/networking/products/data-processing-unit/)
[42](https://www.dynatrace.com/news/blog/unlocking-productivity-and-trust-dynatrace-observability-in-nvidia-ai-factory-environments/)
[43](https://docs.nvidia.com/networking/display/bluefieldbmcv2507/Installation+for+DPU+Mode)
[44](https://docs.nvidia.com/doca/archive/2-5-4/nvidia+doca+telemetry+service+guide/index.html)
[45](https://docs.nvidia.com/networking/display/BlueField2DPUENUG/BlueField+DPU+Administrator+Quick+Start+Guide)
[46](https://docs.nvidia.com/networking/display/BlueFieldDPUBSPv422/SoC+Management+Interface)
[47](https://docs.nvidia.com/networking/display/public/SOL/RDG%20for%20DPF%20with%20OVN-Kubernetes%20and%20HBN%20Services/Connecting+to+BlueMan+Web+Interface)
[48](https://docs.nvidia.com/networking/display/bluefieldbmcv2410ltsu1/BlueField+Management)
[49](https://docs.nvidia.com/networking/display/dpf2507/doca+blueman+service)
[50](https://tutorial.j3soon.com/hpc/extras/bluefield-dpu-setup-notes/)
[51](https://academy.nvidia.com/en/training_by_format/self-paced/management-sw/)
[52](https://uvation.com/articles/nvidia-ufm-cyber-ai-transforming-fabric-management-for-secure-intelligent-data-centers)
[53](https://www.sahmcapital.com/news/content/fortinet-partners-with-nvidia-to-integrate-security-on-bluefield-3-dpus-2025-12-16)
[54](https://x.com/xageinc/status/1983245568911810775)
[55](https://www.cisco.com/c/en/us/td/docs/security/workload_security/secure_workload/user-guide/3_9/cisco-secure-workload-user-guide-on-prem-v39/deploy-software-agents-on-workloads.html)
[56](https://xage.com/products/technology-integrations/)
[57](https://itbrief.ca/story/fortinet-nvidia-embed-firewall-security-in-ai-fabrics)
[58](https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2025/m03/cisco-and-nvidia-secure-AI-factory.html)
[59](https://www.fortinet.com/corporate/about-us/newsroom/press-releases/2025/fortinet-delivers-isolated-infrastructure-acceleration-for-the-ai-factory-with-nvidia)
[60](https://www.wwt.com/product/nvidia-bluefield-dpu/explore)
[61](https://www.scfpartners.com/news/xage-security-announces-collaboration-with-nvidia-bluefield/)
[62](https://www.scworld.com/brief/fortinet-and-nvidia-integrate-cloud-firewall-with-data-processing-unit-for-ai-security)
[63](https://catalog.ngc.nvidia.com/orgs/nvidia/teams/doca/helm-charts/doca-blueman)
[64](https://docs.nvidia.com/networking/display/dpf2507)
[65](https://docs.nvidia.com/doca/archive/2-9-0/NVIDIA+BlueField+DPU+Scalable+Function+User+Guide/index.html)
[66](https://www.youtube.com/watch?v=qO2BrMZZy2Y)
[67](https://docs.nvidia.com/doca/archive/doca-v2.2.0/doca-services-overview/index.html)
[68](https://docs.nvidia.com/networking/display/dpf2507/DOCA+Platform+Framework+v25-7-0)
[69](https://insujang.github.io/2022-01-17/open-vswitch-in-nvidia-bluefield-smartnic/)
[70](https://docs.nvidia.com/networking/display/dpf2504/DOCA+Blueman+Service)
[71](https://www.spectrocloud.com/blog/how-palette-accelerates-kubernetes-clusters-with-nvidia-bluefield-3-dpus)
[72](https://research.cec.sc.edu/files/cyberinfra/files/dup-programming-using-p4-lab-series.pdf)
[73](https://www.youtube.com/watch?v=RJHd3Mqk4Uw)