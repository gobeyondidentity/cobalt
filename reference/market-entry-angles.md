# Market Entry Angles

**Purpose**: Consolidated list of potential entry points for Beyond Identity + DPU in AI infrastructure security. Each angle represents a specific problem/customer/use case combination we could lead with.

**Last Updated**: 2025-12-28

---

## Angle Evaluation Criteria

Each angle is evaluated on:
- **Pain Clarity**: How clearly does the customer feel this pain today?
- **Beyond Identity Fit**: How well does our existing platform address this?
- **DPU Requirement**: How essential is DPU-level enforcement?
- **Competition**: Who else is solving this and how well?
- **Time to Value**: How quickly can we demonstrate value?

---

## Angle 1: Training Cluster Human Access (Slurm/HPC)

**The Problem**: Data scientists and ML engineers access GPU training clusters via SSH with long-lived keys and MUNGE authentication. Both are weak against credential theft and phishing.

**Target Customer**:
- Enterprise AI teams with on-prem GPU clusters
- AI cloud providers offering bare-metal GPU rental
- HPC centers with AI workloads (national labs, pharma)

**Current State**:
- SSH keys stored in software (can be extracted)
- MUNGE uses shared symmetric key across all nodes
- No device attestation for access
- Flat network inside cluster enables lateral movement

**Beyond Identity Value**:
- TPM-bound SSH certificates (cannot be extracted)
- FIDO2 passkeys (phishing-resistant)
- Device posture verification before access
- Short-lived certs with auto-renewal

**DPU Value**:
- mTLS validation at line rate (200+ Gbps)
- OVS policy enforcement (identity-based flow rules)
- Hardware-isolated from compromised host OS
- DICE attestation proves enforcement layer integrity

**Competition**:
- Xage: Network segmentation, but no cryptographic user identity
- Fortinet: Firewalling, but no device authentication
- HashiCorp Vault: Secret management, but no hardware binding

**ATLAS Techniques Mitigated**:
- AML.T0012 Valid Accounts
- AML.T0052 Phishing
- AML.T0055 Unsecured Credentials

**Validation Status**: Hypothesis (needs customer discovery)

**Source**: [AI Infrastructure Threat Model](../research/ai-infrastructure-threat-model.md), MVP Priority 1

---

## Angle 2: Kubeflow Multi-Tenant Isolation

**The Problem**: AI cloud providers run multi-tenant Kubeflow clusters where tenant isolation relies entirely on software (Kubernetes namespaces + Istio policies). A compromise in one tenant can access another.

**Target Customer**:
- AI cloud providers (CoreWeave, Lambda Labs, Together AI)
- Enterprise shared GPU clusters
- ML platform teams serving multiple internal teams

**Current State**:
- OIDC tokens (software, can be exfiltrated)
- Istio mTLS (kernel-level, bypassable with host compromise)
- Kubernetes RBAC (API server decisions, not network enforcement)
- Cloud workload identity (provider-specific, no hardware attestation)

**Beyond Identity Value**:
- TPM-bound credentials for Kubeflow Dashboard access
- Hardware-attested user identity (not just OIDC tokens)
- Integration with Istio AuthService for identity validation

**DPU Value**:
- Hardware-level tenant isolation (not just namespace boundaries)
- TLS offload with PKA acceleration
- Per-tenant OVS flow rules at line rate
- DICE attestation for workload identity

**Competition**:
- Kubeflow native: Istio + Dex (software only)
- Cloud providers: Workload Identity (cloud-specific, no hardware)
- No one doing hardware-attested identity for Kubeflow

**Integration Pattern**:
```
Data Scientist (TPM-bound cert) → DPU TLS Offload → OVS Policy → Kubeflow Dashboard
```

**Validation Status**: Research complete, needs customer validation

**Source**: [Kubeflow Landscape Analysis](../research/kubeflow-landscape.md)

---

## Angle 3: Model Registry and Checkpoint Access

**The Problem**: Trained model weights are the crown jewels. Access to model registries (S3, MLflow, Weights & Biases) uses static API keys that can be stolen or leaked.

**Target Customer**:
- Foundation model labs (OpenAI, Anthropic competitors)
- Enterprise AI teams with proprietary models
- AI cloud providers storing customer models

**Current State**:
- API keys in code, config files, environment variables
- No device binding for cloud access
- Overprivileged service accounts
- Audit logging exists but prevention is weak

**Beyond Identity Value**:
- Short-lived certificates instead of static API keys
- Device posture required for model access
- Audit trail tied to verified human identity

**DPU Value**:
- Enforce model access policies at egress
- Block exfiltration attempts at network level
- Validate identity for every model download request

**Competition**:
- Cloud IAM: Role-based, but no device binding
- Vault: Secret management, but no identity layer
- DLP tools: Detection, not prevention

**ATLAS Techniques Mitigated**:
- AML.T0035 AI Artifact Collection
- AML.T0036 Data from Information Repositories
- AML.T0048.004 AI Intellectual Property Theft

**Validation Status**: Hypothesis (needs customer discovery)

**Source**: [AI Infrastructure Threat Model](../research/ai-infrastructure-threat-model.md), MVP Priority 2

---

## Angle 4: Inference Endpoint Protection

**The Problem**: Model serving endpoints (KServe, TensorFlow Serving, Triton) are exposed to internal or external clients. API keys are easily shared or stolen, enabling abuse or model extraction.

**Target Customer**:
- AI SaaS companies serving inference APIs
- Enterprise internal ML platforms
- Edge AI deployments

**Current State**:
- API keys or OAuth tokens (software)
- Rate limiting (reactive, not preventive)
- Service mesh mTLS (depends on pod identity)

**Beyond Identity Value**:
- Device-bound API access (client must prove device identity)
- Per-request identity validation
- Revocation propagates immediately

**DPU Value**:
- Line-rate API authentication (zero latency impact at scale)
- OVS flow rules for per-model access control
- Block unauthorized inference requests at network level

**Competition**:
- API gateways: Authentication, but no device binding
- Service mesh: mTLS, but software-defined trust

**Validation Status**: Conceptual (lower priority than training/storage)

**Source**: [AI Infrastructure Threat Model](../research/ai-infrastructure-threat-model.md)

---

## Angle 5: Agentic AI / Model-to-Model Communication

**The Problem**: AI agents and multi-model systems communicate with each other. There's no standard for proving one model/agent's identity to another.

**Target Customer**:
- Agentic AI platforms
- Multi-model orchestration systems
- Research labs building autonomous AI systems

**Current State**:
- No established identity standards for AI-to-AI
- Trust based on network location or API keys
- Emerging concern, not yet acute pain

**Beyond Identity Value**:
- Workload identity certificates for AI agents
- OIDC + attestation for agent authentication
- Chain-of-custody for multi-agent workflows

**DPU Value**:
- DICE attestation proves agent runs on trusted infrastructure
- OVS enforces agent communication policies
- Model boundary enforcement at network level

**Competition**:
- SPIFFE/SPIRE: Workload identity, but no AI-specific features
- No established players in AI agent identity

**Validation Status**: Speculative (future opportunity)

**Source**: [Expert Call Insights](../research/expert-call-insights.md), Pattern C

---

## Angle Prioritization Matrix

| Angle | Pain Clarity | BI Fit | DPU Need | Competition | Time to Value |
|-------|--------------|--------|----------|-------------|---------------|
| 1. Training Cluster | HIGH | HIGH | HIGH | Medium | 12-16 weeks |
| 2. Kubeflow Multi-tenant | HIGH | HIGH | HIGH | Low | 16-20 weeks |
| 3. Model Registry | HIGH | Medium | Medium | Medium | 8-12 weeks |
| 4. Inference Endpoints | Medium | Medium | High | Medium | 12-16 weeks |
| 5. Agentic AI | Low | Low | High | Low | 24+ weeks |

---

## Recommended Sequence

Based on the matrix:

### Phase 1: Training Cluster Human Access
- Clearest pain (SSH/MUNGE is demonstrably weak)
- Best Beyond Identity fit (existing platform)
- Strong DPU story (hardware isolation matters)
- Differentiated from Xage (they do network, we do identity)

### Phase 2: Kubeflow Multi-Tenancy
- Natural expansion from Phase 1 (same customers often have both)
- Unique positioning (no one doing hardware-attested Kubeflow identity)
- Istio integration is tractable

### Phase 3: Model Registry Access
- Could run parallel with Phase 1 as simpler proof point
- Less DPU-dependent (could work without DPU initially)
- Good for customers not ready for full DPU deployment

### Future: Workload Identity / Agentic AI
- Requires more R&D
- Market not yet demanding
- Monitor for timing

---

## Slurm vs Kubernetes: Why This Split Matters

**Source**: [Slurm vs Kubernetes Analysis](../research/slurm-vs-kubernetes-training.md) (unverified, treat as hypothesis)

### Claimed Market Split for Training (Late 2025)

| Orchestrator | Share | Workload Type |
|--------------|-------|---------------|
| Kubernetes | 55-65% | Fine-tuning, LoRA, small jobs (<16 GPUs), data prep |
| Slurm | 30-40% | Large-scale pretraining, multi-week runs, 100s-1000s GPUs |
| Other (Ray, managed) | 5-10% | Elastic training, hyperparameter sweeps |

### The Hybrid Pattern

Many mature orgs run BOTH intentionally:

```
┌─────────────────────────────────────┐
│           Kubernetes                │
│  - Data prep, feature engineering   │
│  - Fine-tuning, LoRA adapters       │
│  - Small jobs (<16 GPUs)            │
│  - Inference (KServe, Triton)       │
└─────────────────┬───────────────────┘
                  │ Model artifacts
                  ▼
┌─────────────────────────────────────┐
│             Slurm                   │
│  - Large-scale pretraining          │
│  - Massive DDP (100s-1000s GPUs)    │
│  - Multi-week training runs         │
│  - Million-dollar jobs              │
└─────────────────────────────────────┘
```

### Why Lead with Slurm (Angle 1) Despite Smaller Market

| Factor | Slurm (30-40%) | Kubernetes (55-65%) |
|--------|----------------|---------------------|
| Auth baseline | Terrible (MUNGE, SSH keys) | Adequate (Istio, OIDC) |
| Target value | Highest (million-dollar jobs) | Mixed (fine-tuning to inference) |
| Adversary interest | Nation-state priority | Criminal/opportunistic |
| Competition | None in HPC auth space | Crowded (Istio, service mesh) |
| Pain clarity | Acute (everyone knows MUNGE is bad) | Moderate (Istio "works") |
| Customer concentration | High (national labs, pharma, quant) | Diffuse (every enterprise) |

**Strategic Logic**: Smaller market with sharper pain, higher-value targets, and zero competition beats larger market with adequate solutions and crowded competition.

### Slurm-Dominant Industries (Design Partner Targets)

- National labs / research institutions (Texas A&M, TACC, Oak Ridge)
- Pharma & life sciences (drug discovery, molecular simulation)
- Quant finance (model training for trading)
- Climate & physics simulation
- Autonomous driving training
- Defense / aerospace

### Land-and-Expand Motion

1. **Land** with Slurm angle (training cluster human access)
2. **Discover** that same customer also runs Kubeflow for fine-tuning/inference
3. **Expand** to Kubeflow multi-tenancy (Angle 2)
4. **Upsell** model registry protection (Angle 3)

This sequence works because:
- Slurm customers are often sophisticated orgs with hybrid infrastructure
- Proving value on the hardest problem (HPC auth) builds credibility
- Same DPU infrastructure serves both Slurm and K8s workloads

### Convergence: Slurm-on-Kubernetes

The split may be converging. CoreWeave's SUNK (Slurm on Kubernetes Integration) runs Slurm jobs inside Kubernetes, released early 2024.

From CoreWeave S-1:
> "We have eliminated the need to choose between Slurm or Kubernetes... Different AI workloads can be co-located on the same cluster, including training, inference, and experimentation... Solved a major infrastructure pain point for our customers."

**What this means for us**:
- Auth complexity increases (need to secure BOTH MUNGE and OIDC)
- DPU value strengthens (single enforcement point regardless of scheduler)
- Target customer simplifies (CoreWeave-style hybrid environments)
- Positioning shifts from "Slurm OR K8s" to "unified identity for hybrid environments"

See: [Slurm vs Kubernetes Analysis](../research/slurm-vs-kubernetes-training.md#convergence-slurm-on-kubernetes-initiatives)

### Validation Questions for This Hypothesis

1. What percentage of your training runs on Slurm vs Kubernetes?
2. Do you use different auth mechanisms for each?
3. Which environment has more security incidents?
4. Would you adopt a unified identity layer across both?
5. Are you running or evaluating Slurm-on-Kubernetes (SUNK, Run:ai, Kueue)?

---

## Customer Discovery Questions by Angle

### Angle 1 (Training Cluster)
1. How do you manage SSH keys for your training cluster today?
2. Have you experienced credential theft or unauthorized access?
3. What would it take to adopt a different authentication mechanism?
4. Do you trust your host OS as a security enforcement point?

### Angle 2 (Kubeflow)
1. How do you isolate tenants in your Kubeflow deployment?
2. Are you concerned about cross-tenant data access?
3. Have you evaluated hardware-based isolation mechanisms?
4. Would you pay premium for hardware-attested tenant isolation?

### Angle 3 (Model Registry)
1. How do you control access to your trained model weights?
2. Have you had incidents of model or checkpoint theft?
3. Do you use static API keys for model registry access?
4. How would you know if someone exfiltrated a model?

---

## References

- [AI Infrastructure Threat Model](../research/ai-infrastructure-threat-model.md)
- [Kubeflow Landscape Analysis](../research/kubeflow-landscape.md)
- [Slurm vs Kubernetes Analysis](../research/slurm-vs-kubernetes-training.md) - Market split hypothesis
- [Expert Call Insights](../research/expert-call-insights.md)
- [Fortinet BlueField-3 Integration](../research/fortinet-bluefield3-integration.md)

---

*Document created 2025-12-28. Update as customer discovery validates or invalidates angles.*
