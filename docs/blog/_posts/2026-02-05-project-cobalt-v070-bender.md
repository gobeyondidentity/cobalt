---
layout: post
title: "Project Cobalt v0.7.0: Bender"
date: 2026-02-05
author: Beyond Identity
---

Bender makes the Cobalt control plane production-ready for security review. API authentication, policy-driven authorization, identity lifecycle controls, and SIEM-ready audit logging all ship in this release. If your team is evaluating hardware-enforced credential management for GPU infrastructure, this is the starting point.

## Cryptographic API Authentication

API callers now prove their identity on every request using hardware-bound Ed25519 keys. Each request signature is tied to the HTTP method, URI, and timestamp, so a captured token can't be replayed or redirected. Bearer tokens are gone entirely. If an attacker intercepts a request, they still can't use it without the signing key.

## Tamper-Proof Enrollment

Operators and DPUs enroll through a challenge-response protocol. The server issues a cryptographic challenge, and the caller proves key possession by signing it. This prevents key substitution attacks where an adversary tries to register their own key during the enrollment window.

DPU enrollment goes a step further: the server verifies the device's hardware serial against its claim token before accepting it. Invite codes are single-use and time-limited. The first administrator bootstrap locks after setup and stays locked across restarts.

## Attestation-Gated Authorization

Authorization runs through Cedar policies with deny-by-default enforcement. Three roles scope access: operators receive explicit per-resource grants, tenant admins operate within their tenant, and super admins get cross-tenant access for break-glass scenarios.

The piece that matters most: credential distribution won't proceed unless the target DPU passes attestation. A node with stale or missing attestation gets blocked. A node with failed attestation gets blocked permanently, with no bypass path. Super admins can force through a stale attestation check, but that action leaves a security warning in the audit log. There's no way to silently override it.

Credentials don't reach infrastructure that can't prove it's healthy. That's the enforcement layer that separates Cobalt from conventional identity systems.

## Incident Response

When something goes wrong, you have three levers that all take effect on the next API call:

**Suspend** an operator to lock them out instantly while you investigate. Reversible. Their enrollment stays intact, so you can restore access once they're cleared.

**Revoke** a key when it's confirmed compromised. Permanent, no reactivation. Self-revocation is blocked, and last-key protection prevents you from accidentally locking yourself out.

**Decommission** a DPU to block its authentication and scrub its credentials from the control plane. The audit trail stays. A super admin can re-activate the device later if it's cleared, which resets it to a fresh enrollment state.

No propagation delay. No cache to wait on.

## SIEM Integration

Security events write to syslog in RFC 5424 structured format, ready for Grafana Loki, Splunk, or any standards-compliant SIEM. Events cover authentication, enrollment, lifecycle actions, and attestation bypasses, each tagged with caller identity, client IP, request path, and latency.

Local audit storage still works for CLI queries, so you get both real-time SIEM ingestion and local investigation tools. Private keys and credentials are validated to never appear in log output.

## Get Started

```bash
brew install gobeyondidentity/cobalt/bluectl
```

Also available via Docker and Linux packages. Source and full changelog on [GitHub](https://github.com/gobeyondidentity/cobalt).

---

*Project Cobalt v0.7.0 "Bender" - February 2026*
