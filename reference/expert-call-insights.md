# Expert Call Insights: AI Infrastructure Security

**Source**: Meeting with Prashanth Kalika (Cisco VP AI DC), December 5, 2025
**Supplemental**: Technical design document authored by Prashanth Kalika
**Purpose**: Catalog insights relevant to Beyond Identity + DPU initiative for Q1 validation

---

## Executive Summary

The expert call with Prashanth Kalika, Cisco VP for AI Data Center, provided strong validation for the Beyond Identity + Bluefield DPU thesis while significantly refining the target use case. The core insight: **AI workload security cannot be done at the perimeter level; enforcement must happen at the network fabric where models communicate.**

**Key Shift**: Move from "secure human access to GPU clusters" to "secure model-to-model communication at the fabric level."

---

## Key Insights

### 1. Perimeter Security Fails for AI Workloads

**Quote (Prashanth)**:
> "Security for AI cannot be done at a perimeter level. The models actually talk at the network level, between scale out and scale across. That's where the enforcement points have to be created. And that's where the DPUs come into picture."

**Implication**: Traditional ZTNA solutions (Zscaler, Netskope, Palo Alto) are positioned incorrectly for AI infrastructure. The threat model is fundamentally different: AI workloads communicate internally at massive scale, not through an external perimeter.

**Application to Threat Model**: This validates our "Model Isolation Failure" threat (TM-002) and elevates its priority. The attack surface is not human access to the cluster; it is unauthorized communication between AI workloads within the cluster.

### 2. OVS on DPU is the Enforcement Point

**Quote (Prashanth)**:
> "You can talk about segmentation, but where do you enforce it? You have to enforce it in the path. That's where the DPUs come into picture."

**Technical Insight**: Open vSwitch (OVS) running on Bluefield DPU controls traffic flow in GPU clusters. Identity-based policies can be translated into OVS flow rules to enforce model boundaries at line rate.

**Action Item**: Explore OVS integration for Beyond Identity policy enforcement. Leverage Jasson Casey's Flowgrammable expertise.

### 3. Identity Problem Compounds with Agentic AI

**Quote (Prashanth)**:
> "The agentic world is completely chaos. AI has agents also. It's a nonhuman identity. It's not like 10 users or 100 users. Like, millions of users. The problem is going to compound like anything."

**Implication**: Beyond Identity's device-bound credentials are necessary but not sufficient. The identity problem extends to:
- **Operator identity** (human data scientist)
- **Device identity** (workstation, GPU node)
- **Workload identity** (agent, model, service)

**Application to Threat Model**: Our Workload Identity Attacks category (TM-004, TM-005) addresses this, but we need to expand thinking to include agent-to-agent trust chains.

### 4. RoCE Traffic Flows Through DPU

**Technical Insight**: RoCE (RDMA over Converged Ethernet), the low-latency protocol for GPU-to-GPU communication, flows through the Bluefield DPU. This means the DPU is in the critical path for all AI workload traffic.

**Implication**: The DPU can inspect and enforce policy on the most sensitive traffic (model weights, gradients, inference data) without adding latency. This is the "inside the network" enforcement point that perimeter security cannot provide.

### 5. Application-Layer Security is "Too Far"

**Quote (Prashanth)**:
> "App level, I think people have solved it. I don't even want to go at app level because app is too far now for AI."

**Implication**: Do not position against API security, WAF, or LLM firewalls. Focus on network-level enforcement tied to identity. This is a different layer of the stack.

**Competitive Positioning**: Xage operates at network protocol level (Layer 3-4), which aligns with Prashanth's thesis. However, Xage lacks the hardware-bound identity from endpoints (TPM) that Beyond Identity provides.

---

## Quotes That Validate Our Hypotheses

### Beyond Identity's Unique Position

> "You guys are doing the certificate from endpoint. You have TPMs. You guys are the right people to solve this problem. Nobody else can solve it. You just need to land onto the back end network. That means you need to land on a DPU and then orchestrate that policy and microsegment it. Boom."

**Validation**: Our hypothesis that device-bound credentials + DPU enforcement creates a unique competitive moat is explicitly validated by Prashanth.

### Market Timing

> "This is the first time I feel like I'm looking at some frontier things. It typically doesn't happen accidentally. You always do incremental innovations, but this is like, 'What the hell, man?'"

**Validation**: Cisco VP sees this as a genuine frontier opportunity, not incremental. Suggests market timing is favorable.

### Identity + Network Convergence

> "You guys are different. Identity is not just about user data, but having identity coming from a device is a different game itself. Which actually completely bridges it."

**Validation**: The convergence of device-bound identity with network enforcement is recognized as a differentiator by someone who has spent his career trying to bridge user identity with network/device identity.

---

## Challenges to Our Assumptions

### Challenge 1: AI Workload Security May Be Too Early

**Risk Identified**: "AI workload security is cutting-edge, may be too early for market."

**Mitigation**: Start with Pattern A (mTLS for human access to GPU clusters) as the beachhead. Progress to Pattern B (OVS + model boundaries) once the simpler use case is proven.

### Challenge 2: OVS Expertise Gap

**Risk Identified**: "Team needs deep OVS knowledge."

**Mitigation**: Jasson Casey (Beyond Identity CEO) co-founded Flowgrammable, an OVS documentation company. Leverage his expertise for architecture decisions.

### Challenge 3: NVIDIA Partnership Dependency

**Risk Identified**: "Success depends on NVIDIA partnership and DPF roadmap."

**Mitigation**: DOCA 3.2 Zero Trust announcement provides explicit alignment. Build MVP on public APIs to demonstrate value before formal partnership discussions.

---

## Customer Pain Points Identified

### Pain Point 1: Model Boundary Enforcement

**Use Case**: Large AI cloud (CoreWeave, Lambda Labs, NVIDIA AI factories) with multiple clusters:
- Cluster 1: Training models
- Cluster 2: Inference models
- Cluster 3: Reinforcement learning
- Cluster 4: RAG models

**Problem**: Need to create "model boundaries" that prevent unauthorized cross-cluster communication. Different fine-tuning levels and datasets have different sensitivity.

**Implication**: Identity-based segmentation at the fabric level is the solution. Not perimeter firewalls.

### Pain Point 2: Token-Level Identity (Emerging)

**Prashanth's Vision** (admittedly speculative):
> "If we go completely granular, how can you have identity for tokens and who owns the tokens from a workload perspective? And maybe enforce that."

**Example**: Prashanth runs inference on Model X. Inference generates tokens (API calls, data requests). How do we segment and enforce policies on those tokens at the network level?

**Implication**: Future opportunity beyond current scope. Watch for market demand.

### Pain Point 3: Non-Human Identity Scale

**Problem**: Traditional IAM handles tens of thousands of users. AI infrastructure creates millions of non-human identities (agents, models, services). Existing tools do not scale.

**Implication**: Platform must be designed for machine-scale identity, not human-scale.

---

## Technical Deployment Reality

### How AI Infrastructure Actually Works

1. **Scale-Up Networking**: GPU-to-GPU within a node via NVLink (no DPU involvement)
2. **Scale-Out Networking**: Node-to-node via InfiniBand or RoCE (flows through DPU)
3. **Scale-Across Networking**: Cluster-to-cluster via Ethernet (flows through DPU)

**Key Insight**: DPU enforcement applies to scale-out and scale-across, where the most sensitive inter-workload communication occurs. NVLink (within-node) is not in scope.

### Integration Patterns (from Prashanth's Technical Document)

**Pattern A: mTLS Client Certificate Enforcement**
- Best for: Interactive human access (SSH, web APIs, management consoles)
- Trust Chain: Endpoint TPM (Beyond Identity) to DPU TLS offload (PKA validation)
- Complexity: Low (standard mTLS)

**Pattern B: OIDC/JWT + DPU Attestation**
- Best for: Service meshes, microservices, agent-to-agent
- Trust Chain: OIDC token + DPU DICE/SPDM attestation
- Complexity: Medium (requires attestation chain validation)

**Pattern C: OVS + Identity for AI Workloads** (from meeting discussion)
- Best for: Model-to-model communication, model boundaries
- Trust Chain: Identity token to OVS flow rules on DPU to GPU cluster segmentation
- Complexity: High (requires OVS integration)

### Critical Technical Requirements

1. **OCSP/CRL Scale**: At line rate, DPU must cache revocation data. Real-time OCSP may add latency.
2. **Clock Sync**: Certificate validation requires synchronized time across all DPUs.
3. **Failover Behavior**: Fail-closed for high-security enclaves; ensure out-of-band management access.
4. **Trust Anchor Provisioning**: Must securely load Beyond Identity CA cert into thousands of DPUs.

---

## Competitive Intelligence

### Xage Security

**Positioning**: "Unified Zero Trust for AI systems" with network protocol-level enforcement

**Technical Approach**:
- Overlay mesh network (distributed nodes as proxies)
- OpenFlow controller + OvS on Bluefield DPU
- Hardware-accelerated IPsec tunneling
- Software wrappers for AI agents

**Strengths**:
- First mover in "AI Zero Trust" messaging
- MCP (Model Context Protocol) security positioning
- Bluefield integration already announced
- OT/industrial heritage (Petronas, Kinder Morgan, US Space Force)

**Weaknesses**:
- No endpoint TPM binding (network-based identity, not device-bound)
- "Jailbreak-proof" claim is marketing, not technical (still proxy-based)
- Overlay architecture adds latency compared to native DPU enforcement

**Beyond Identity Differentiator**:
> Xage provides "WHO is making the request" via network proxies. Beyond Identity provides cryptographic proof that the request comes from a specific device with intact security posture (TPM-bound credential).

### Market Positioning Matrix

| Capability | Traditional ZTNA | Xage | Beyond Identity + DPU |
|------------|------------------|------|----------------------|
| Human identity | Yes | Yes | Yes |
| Device-bound credential | No | No | **Yes (TPM)** |
| Network enforcement | Perimeter | Overlay mesh | **Native DPU** |
| AI workload identity | No | Yes (agent wrappers) | Planned (OVS integration) |
| Hardware attestation | No | No | **Yes (DICE/SPDM)** |
| Line-rate performance | No | Partial | **Yes (PKA/FPGA)** |

---

## Recommendations for Our Approach

### 1. Refine Target Use Case

**Current**: "Hardware-enforced Zero Trust authentication for AI infrastructure"

**Recommended**: "Identity-based model boundary enforcement for GPU clusters"

**Rationale**: Prashanth's insight moves us from generic "authentication" to specific "segmentation" at the AI workload level. This is a clearer value proposition for AI cloud providers.

### 2. Adopt Phased Approach

**Phase 1**: Pattern A (mTLS for human access)
- Build MVP with existing DOCA TLS offload
- Prove line-rate cert validation
- Target: Data scientists accessing GPU nodes

**Phase 2**: Pattern B (OIDC + DPU attestation)
- Add DICE/SPDM integration
- Prove mutual attestation
- Target: Service mesh deployments

**Phase 3**: Pattern C (OVS + model boundaries)
- Integrate with OVS on Bluefield
- Identity-based flow rules
- Target: AI cloud providers (CoreWeave, Lambda Labs)

### 3. Leverage OVS Expertise

**Action**: Schedule working session with Jasson Casey to:
- Review OVS integration architecture
- Identify policy expression requirements
- Define MVP scope for OVS-based enforcement

### 4. Update Threat Model

**Add**: Model-to-model communication threats
- Unauthorized cross-cluster communication
- Model weight exfiltration via RoCE
- Gradient poisoning via compromised training node

**Elevate**: TM-002 (Model Isolation Failure) to high priority

### 5. Competitive Response

**Xage Counterpositioning**:
- Emphasize cryptographic device-bound credentials (TPM) vs. Xage's network-based identity
- Position native DPU enforcement vs. overlay mesh latency
- Highlight DICE/SPDM hardware attestation (Xage does not have this)

**Messaging**: "Zero Trust at the silicon level, not the software level."

---

## Integration with Leadership Materials

### For CEO One-Pager

**Key Narrative Points**:
1. AI security cannot be perimeter-based; enforcement must be at the fabric
2. Cisco VP validates Beyond Identity as "the right people to solve this problem"
3. Unique moat: endpoint TPM + DPU DICE creates end-to-end hardware trust chain
4. Target market: AI cloud providers need model boundary enforcement

**Quote to Include**:
> "You guys are doing the certificate from endpoint. You have TPMs. You just need to land onto the back end network. That means you need to land on a DPU and then orchestrate that policy and microsegment it. Boom." - Prashanth Kalika, Cisco VP AI DC

### For Threat Model

**Priority Adjustments**:
- Elevate model isolation threats
- Add agent-to-agent identity compromise scenarios
- Include RoCE/RDMA traffic as attack vector

**Trust Chain Documentation**:
- Endpoint: TPM-bound passkey (Beyond Identity)
- DPU: DICE/SPDM attestation (Bluefield)
- Network: OVS flow rules (identity-based)

---

## Open Questions for Follow-Up

1. **OVS Policy Expression**: How do we translate Beyond Identity policies (user, device, posture) into OVS flow rules?
2. **RDMA Inspection**: Can Bluefield inspect RoCE traffic at line rate, or only forward/drop?
3. **Multi-DPU Coordination**: In a large cluster, how do DPUs synchronize identity state?
4. **NVIDIA Partnership**: What level of partnership is required for OVS/DPF integration?
5. **Customer Discovery**: Which AI cloud providers have explicit demand for model boundary enforcement?

---

## Appendix: Expert Background

### Prashanth Kalika

**Current Role**: VP AI DC, Cisco (2 months at time of call)

**Career Journey**:
1. 12 years in networking (routing/switching, BGP, MPLS, VxLAN, EVPN)
2. Ordr (startup): IoT security via network traffic analysis, 9th employee, 120+ healthcare customers
3. AWS: Threat protection, manageable groups, IOCs/IOAs for firewalls
4. Cisco: AI data center networking and security

**Key Expertise**:
- Microsegmentation (deep experience from Ordr and Cisco ISE)
- Identity + network convergence
- AI infrastructure networking

**Personal Connections**:
- Knows Nikesh (Beyond Identity) for 10+ years
- Knows Hosnen from SDN/networking world
- Introduced to Beyond Identity by Louis

**Engagement Model**: Advisory capacity, "out of my bounds" for Cisco role but sees frontier opportunity
