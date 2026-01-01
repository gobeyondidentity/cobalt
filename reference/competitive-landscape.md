# Competitive Landscape: AI Infrastructure Security

**Purpose**: Consolidated competitive intelligence for Beyond Identity + BlueField DPU initiative
**Last Updated**: 2025-12-29

---

## Quick Reference: Positioning Matrix

| Vendor | Layer | Primary Function | Identity Method | BlueField Integration | Competitive Relationship |
|--------|-------|------------------|-----------------|----------------------|--------------------------|
| **Beyond Identity** | Authentication | Prove WHO is connecting | TPM-bound keys + DICE | Planned (our product) | N/A |
| **Xage Security** | Network Segmentation | Control WHERE traffic flows | MAC/IP mapping | Announced | Complementary |
| **Fortinet FortiGate-VM** | Firewalling | Inspect WHAT traffic contains | Network zones | Announced (Dec 2025) | Complementary |
| **Cisco Secure Workload** | Microsegmentation | Isolate workloads | Flow-based | Announced | Complementary |
| **Armis Centrix** | Detection | Discover WHAT devices exist | Behavioral fingerprint | Announced | Complementary |

**Key Insight**: All competitors operate at network/detection layers. None provide cryptographic identity verification with hardware-backed credentials. This is our unique moat.

---

## Our Unique Position: The Identity Gap

### What We Provide That No One Else Does

| Capability | Beyond Identity | Xage | Fortinet | Cisco | Armis |
|------------|-----------------|------|----------|-------|-------|
| TPM-bound credentials (endpoint) | Yes | No | No | No | No |
| DPU DICE attestation (infrastructure) | Yes | No | No | No | No |
| Cryptographic identity proof | Yes | No | No | No | No |
| Phishing-resistant authentication | Yes | No | No | No | No |
| Device health validation | Yes | No | No | No | No |
| Short-lived certificates | Yes | No | No | No | No |

### The Hardware Trust Chain

```
┌──────────────────────────────────────────────────────────────────────┐
│                     BEYOND IDENTITY UNIQUE VALUE                      │
│                                                                       │
│   User Device                              GPU Node                   │
│   ┌─────────────┐         mTLS            ┌─────────────┐            │
│   │ TPM-bound   │ ───────────────────────►│ DPU DICE    │            │
│   │ private key │   cryptographic proof   │ validates   │            │
│   │ (cannot     │   of identity           │ certificate │            │
│   │  extract)   │                         │ (cannot     │            │
│   └─────────────┘                         │  bypass)    │            │
│                                           └─────────────┘            │
│                                                                       │
│   RESULT: Hardware-to-hardware trust. Both ends prove integrity.     │
│           Stolen password? Useless. Compromised host? Can't disable. │
└──────────────────────────────────────────────────────────────────────┘
```

### Competitors' Trust Models (Weaker)

| Competitor | Trust Anchor | Weakness |
|------------|--------------|----------|
| Xage | Xage Fabric (software) | Centralized; if compromised, all enforcement fails |
| Fortinet | FortiOS VM (software) | Runs on ARM cores; root access can disable |
| Cisco | Flow patterns (heuristic) | No cryptographic proof; can be spoofed |
| Armis | Behavioral fingerprint | Sophisticated attacker can replay patterns |

---

## BlueField Ecosystem Partners

### Xage Security

**What they do**: Network segmentation and workload isolation via OVS flow rules on BlueField DPU.

**Technical approach**:
- XEP software runs on BF3 ARM cores
- Acts as OpenFlow controller for OVS
- Programs L2/3/4 segmentation rules
- IPsec tunneling between Bluefields

**Target market**: Legacy OT/ICS (energy, utilities, manufacturing), AI workload isolation

**NVIDIA relationship**: Technical collaboration, quote from NVIDIA cybersecurity architect

**Key differentiator from us**:
- Xage: "WHERE can this MAC/IP address send traffic?" (network authorization)
- Beyond Identity: "WHO is connecting, proven cryptographically?" (authentication)

**Attack scenario Xage cannot prevent**:
```
1. Attacker compromises VM with legitimate network identity
2. VM has MAC address aa:bb:cc:dd:ee:ff
3. Xage allows traffic from that MAC (it's "authorized")
4. Attacker exfiltrates data using legitimate network identity
5. Xage sees "normal" authorized traffic

Root cause: Network identity can be inherited. Cryptographic identity cannot.
```

---

### Fortinet FortiGate-VM

**What they do**: Next-gen firewall running on BlueField-3 ARM cores, announced December 2025.

**Technical approach**:
- FortiGate-VM runs as VM on DPU ARM cores
- Full FortiOS firewall (NGFW, IPS, threat detection)
- OVS integration for WAN/VXLAN bridges
- SSL/TLS inspection for threat detection
- eSwitch offload for line-rate forwarding

**Target market**: AI factories, GPU clusters, high-performance computing

**NVIDIA relationship**: Formal partnership, joint press release Dec 2025

**Key differentiator from us**:
- Fortinet: "WHAT does this traffic contain?" (threat inspection)
- Beyond Identity: "WHO is connecting?" (identity verification)

**Market validation**: Fortinet's $5B+ revenue and BF3 investment confirms DPU security market is real.

**OSI layer positioning**:
```
Layer 7+: Identity (Beyond Identity)     ← We operate here
Layer 3-7: Firewalling (Fortinet)        ← Fortinet operates here
Layer 2-3: Segmentation (Xage)           ← Xage operates here
Hardware: BlueField DPU                  ← Shared platform
```

---

### Cisco Secure Workload

**What they do**: Microsegmentation for VM-to-VM and container-to-container traffic (east-west).

**Technical approach**:
- Agent runs on BF3 DPU (not in VMs)
- 12-tuple flow matching (L2-L4 attributes)
- AI-powered policy suggestions from traffic patterns
- Hardware-accelerated encryption via DPU
- ASAP2 + OVS offload

**Target market**: Multi-tier applications, Kubernetes, enterprise data centers

**Key differentiator from us**:
- Cisco: East-west traffic (workload-to-workload)
- Beyond Identity: North-south traffic (user/device-to-infrastructure)

**Complementary architecture**:
```
User Device (TPM)
      ↓
[Beyond Identity: Authentication]  ← North-south (our layer)
      ↓
NVIDIA BlueField DPU
      ↓
[Cisco: Microsegmentation]         ← East-west (their layer)
      ↓
Application Workloads
```

---

### Armis Centrix

**What they do**: OT/ICS asset discovery and threat detection via deep packet inspection (DPI) and behavioral analysis.

**Technical approach**:
- DPI on BF3 ARM cores
- Protocol decoding (Modbus, BACnet, DNP3, OPC-UA)
- Behavioral fingerprinting of devices
- Risk scoring and vulnerability assessment
- Cloud-based analysis

**Target market**: Energy, utilities, manufacturing, healthcare (legacy OT/ICS)

**Key differentiator from us**:
- Armis: "What IS this device?" (discovery/detection)
- Beyond Identity: "IS this device who it claims to be?" (authentication)

**Different device populations**:
- Armis: Unmanaged, legacy devices that CANNOT authenticate
- Beyond Identity: Managed, modern devices that CAN prove identity

**Complementary positioning**: "Armis detects. We authenticate."

---

## Gap Analysis: What No One Does

### The Unfilled Identity Gap

Every vendor in the BlueField ecosystem addresses network-layer security. None address cryptographic identity:

| Security Question | Who Answers It |
|-------------------|----------------|
| What devices are on my network? | Armis |
| What threats are in my traffic? | Fortinet |
| Which workloads can communicate? | Cisco, Xage |
| **Who is connecting, proven cryptographically?** | **Nobody (our opportunity)** |

### Why This Gap Exists

1. **Network vendors think in packets, not identities**: Cisco, Fortinet, Xage come from networking heritage. They solve "what traffic should flow" not "who is connecting."

2. **OT/ICS legacy**: Armis, Xage serve legacy industrial systems that cannot authenticate. They build for devices without TPMs.

3. **Identity vendors think in perimeters**: Traditional ZTNA (Zscaler, Netskope) secures access TO the network, not WITHIN the network fabric.

4. **DPU is new territory**: BlueField is recent. Identity vendors haven't explored hardware-level enforcement yet.

### Our Competitive Moat

| Moat Component | Why It's Defensible |
|----------------|---------------------|
| TPM-bound credentials | Requires endpoint platform (Beyond Identity has 10+ years) |
| DPU DICE integration | Requires DOCA expertise (we have lab + prototype) |
| OVS policy integration | Jasson Casey (CEO) founded Flowgrammable |
| Certificate issuance API | Existing Beyond Identity platform capability |
| Device posture + identity | No competitor has both endpoint and infrastructure |

---

## Current Market: How AI Infrastructure Authenticates Today

From Evercore ISI report on CoreWeave (Sept 2025):

> "CoreWeave ensures that customers operate within a secure and resilient environment by implementing a Zero Trust model for data access and employing advanced security technologies, including Extended Detection and Response (XDR) and Data Loss Prevention (DLP) across all endpoints. The platform leverages Single Sign-On (SSO) and Multi-Factor Authentication (MFA) to defend against identity-based cyber threats."

**Translation**: Software-based authentication. SSO/MFA tokens that can be phished or stolen. XDR/DLP that detects AFTER compromise. No hardware-backed identity.

**CoreWeave's DPU usage**: "CoreWeave's infrastructure integrates DPUs to connect GPU and CPU nodes to the control plane, offloading tasks related to networking, storage, and security."

**The gap we fill**: DPUs are deployed. Security is offloaded. But identity remains software-based. We add the hardware-backed authentication layer.

---

## Competitive Response Playbook

### Objection: "We're evaluating Xage for Zero Trust"

**Response**: "Xage is excellent for workload segmentation. Where does human access authentication fit? Beyond Identity provides the identity layer with device-bound credentials that complements Xage's network segmentation."

**Follow-up questions**:
- How do you authenticate data scientists accessing GPU clusters today?
- What prevents credential theft if a developer's laptop is compromised?
- How do you verify devices are healthy before granting access?

### Objection: "Fortinet provides Zero Trust on BlueField"

**Response**: "Fortinet provides firewall inspection, not identity verification. They answer 'what threats are in this traffic?' We answer 'who is connecting, proven with hardware-backed credentials?' Authentication must come before inspection."

**Demo scenario**: Show that Fortinet allows traffic from any device with valid network access. Show Beyond Identity blocking access from device with stolen credentials.

### Objection: "Xage/Fortinet provides identity-based access"

**Response**: "They provide identity-based AUTHORIZATION. We provide identity-based AUTHENTICATION. Their 'identity' is network identity (IP/MAC). Our identity is cryptographic proof from hardware (TPM). Network identity can be spoofed. Cryptographic identity cannot."

### Objection: "We already use SSO/MFA for our AI infrastructure"

**Response**: "SSO/MFA protects the initial login. What happens after? Your tokens live in software. They can be stolen from memory, intercepted in transit, phished via fake login pages. TPM-bound credentials never leave the hardware. They can't be stolen because they can't be extracted."

---

## NVIDIA Partnership Landscape

### Current State

| Vendor | NVIDIA Relationship | Focus Area |
|--------|---------------------|------------|
| Xage | Technical collaboration | AI workload segmentation |
| Fortinet | Formal partnership (Dec 2025) | AI factory firewalling |
| Cisco | Integration announced | Microsegmentation |
| Armis | Partnership announced | OT/ICS visibility |
| **Beyond Identity** | **None yet (opportunity)** | **Identity/authentication** |

### Our Opportunity

NVIDIA's Zero Trust positioning lacks an identity layer:
- DOCA 3.2 announced "Zero Trust" capabilities
- DPF (DOCA Platform Framework) for deployment
- But no partner provides cryptographic authentication

**Pitch to NVIDIA**: "Xage does segmentation. Fortinet does firewalling. Armis does detection. Who does identity? Beyond Identity provides the missing authentication layer, completing the Zero Trust stack on BlueField."

### Partnership Path

1. **Technical validation**: Demonstrate mTLS on BF3 in lab (done)
2. **Reference architecture**: Document Beyond Identity + Xage + Fortinet on shared DPU
3. **NVIDIA engagement**: Contact DPF team via DevRel
4. **Joint marketing**: GTC presentation on complete Zero Trust

---

## Expert Validation

### Prashanth Kalika (Cisco VP AI DC)

> "You guys are doing the certificate from endpoint. You have TPMs. You guys are the right people to solve this problem. Nobody else can solve it. You just need to land onto the back end network. That means you need to land on a DPU and then orchestrate that policy and microsegment it. Boom."

> "Security for AI cannot be done at a perimeter level. The models talk at the network level. That's where the DPUs come into picture. You guys are the right people to solve this problem."

### Market Timing

Fortinet's December 2025 announcement confirms:
- Major vendors investing in DPU security
- AI infrastructure is the target market
- OVS is the integration path
- The market is real and growing

---

## Summary

**Competitive position**: All BlueField security vendors are complementary, not competitive. They do network/detection; we do identity.

**Our unique value**: Hardware-to-hardware trust chain (endpoint TPM + DPU DICE) that no competitor can match.

**Market gap**: Cryptographic authentication for AI infrastructure is unaddressed. We fill it.

**Strategic approach**: Partner, don't compete. Position as the identity layer above network security.

---

## References

**Consolidated from**:
- Beyond Identity vs Xage Competitive Analysis (2025-12-04)
- Cisco Secure Workload Competitive Brief (2025-12-04)
- Armis Competitive Analysis (2024-12-23)
- Fortinet BlueField-3 Integration (2025-12-28)
- Expert Call Insights (2025-12-05)
- Evercore ISI CoreWeave Report (2025-09-30)

**Related documents**:
- [Market Entry Angles](market-entry-angles.md)
- [Design Partners](design-partners.md)
- [NVIDIA Management Tools Landscape](../docs/nvidia-management-tools-landscape.md)
