# SSH Key Discovery

Audit existing SSH keys across your infrastructure before migrating to certificate-based authentication.

## Why Discovery?

Most environments have accumulated SSH keys over years: personal keys, service accounts, deployment keys, forgotten test keys. Before migrating to certificates, you need to know what exists.

Discovery answers:
- How many static keys are authorized across hosts?
- Which keys are duplicated across multiple hosts?
- Are there unknown or suspicious keys?
- Which service accounts need certificate migration?

## Prerequisites

- `km` CLI initialized (`km init` completed)
- SSH access to target hosts, OR
- Host agents running on target hosts

## Bootstrap Mode (No Agent)

Scan hosts directly via SSH without deploying host-agent first. Useful for initial audits and migration planning.

```bash
bin/km discover scan <HOST> --ssh --ssh-user <USER> --ssh-key <KEY_PATH>
# Expected:
# HOST           METHOD  USER  TYPE        FINGERPRINT                                   COMMENT
# 192.168.1.235  ssh           ssh-ed2...  SHA256:wxW686dl+4sjpMTltHxZ0omAYax1tTDTkx...  fabric-agent@bf3-...
# 192.168.1.235  ssh           ssh-rsa     SHA256:5EY6l2867TSH0ZfHdUhnsj9ZJYI/MYRPOe...  deploy-key
# ...
#
# Found 12 keys on 1 host (ssh)
# Warning: Bootstrap mode. Install host-agent for production use.
```

Options:
- `--ssh`: Force SSH mode (required for bootstrap)
- `--ssh-user`: SSH username (default: current user)
- `--ssh-key`: Path to SSH private key
- `--timeout`: Per-host timeout in seconds (default: 30)

## Agent Mode (Production)

Once host-agents are deployed, scan through the secure agent channel instead of SSH.

### Scan a single host

```bash
bin/km discover scan <HOSTNAME>
# Expected:
# HOST        METHOD  USER    TYPE        FINGERPRINT                                   COMMENT
# gpu-node-1  agent   root    ssh-ed2...  SHA256:abc123...                              admin@company.com
# gpu-node-1  agent   ubuntu  ssh-ed2...  SHA256:def456...                              deploy-bot
```

### Scan all registered hosts

```bash
bin/km discover scan --all
# Expected:
# HOST        METHOD  USER    TYPE        FINGERPRINT                                   COMMENT
# gpu-node-1  agent   root    ssh-ed2...  SHA256:abc123...                              admin@company.com
# gpu-node-2  agent   root    ssh-ed2...  SHA256:abc123...                              admin@company.com
# gpu-node-2  agent   ubuntu  ssh-rsa     SHA256:xyz789...                              jenkins
#
# Found 3 keys on 2 hosts (agent)
```

Options:
- `--all`: Scan all registered hosts
- `--parallel`: Max concurrent scans (default: 10)
- `--ssh-fallback`: Use SSH for hosts without running agents

## Output Formats

### Table (default)

Human-readable format for interactive use.

```bash
bin/km discover scan --all
```

### JSON

Machine-readable format for scripts and integrations.

```bash
bin/km discover scan --all -o json
```

```json
{
  "scan_time": "2026-01-09T16:56:22Z",
  "hosts_scanned": 2,
  "hosts_succeeded": 2,
  "hosts_failed": 0,
  "total_keys": 15,
  "method_breakdown": {
    "agent": 2
  },
  "keys": [
    {
      "host": "gpu-node-1",
      "method": "agent",
      "user": "root",
      "key_type": "ssh-ed25519",
      "key_bits": 256,
      "fingerprint": "SHA256:abc123...",
      "comment": "admin@company.com",
      "file_path": "/root/.ssh/authorized_keys"
    }
  ]
}
```

## Common Workflows

### Pre-migration audit

Before deploying certificate-based auth, inventory all static keys:

```bash
# Export full inventory
bin/km discover scan --all -o json > ssh-key-inventory.json

# Count keys by host
cat ssh-key-inventory.json | jq '.keys | group_by(.host) | map({host: .[0].host, count: length})'
```

### Find duplicate keys

Keys shared across hosts may indicate service accounts that need certificate migration:

```bash
bin/km discover scan --all -o json | jq '
  .keys | group_by(.fingerprint) |
  map(select(length > 1)) |
  map({fingerprint: .[0].fingerprint, comment: .[0].comment, hosts: [.[].host]})'
```

### Bootstrap a new environment

Audit hosts before deploying agents:

```bash
# Scan multiple hosts via SSH
for host in gpu-node-{1..10}; do
  bin/km discover scan $host --ssh --ssh-user ubuntu --ssh-key ~/.ssh/id_ed25519
done
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `SSH authentication failed` | Wrong key or user | Verify `--ssh-user` and `--ssh-key` |
| `connection refused` | SSH not running or firewall | Check SSH service and network |
| `no hosts registered` | No host-agents connected | Use `--ssh` bootstrap mode |
| `timeout` | Host unreachable or slow | Increase `--timeout` value |

## What's Next?

After auditing existing keys:

1. **Deploy host-agents** - Switch from SSH bootstrap to agent-based scanning
2. **Create SSH CA** - Set up certificate authority (`km ssh-ca create`)
3. **Migrate users** - Issue certificates to replace static keys
4. **Remove static keys** - Clean up authorized_keys after migration
