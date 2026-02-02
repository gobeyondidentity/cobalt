# Encryption Key Management

Project Cobalt encrypts all local databases at rest. This document explains how encryption keys work and when you might need to manage them manually.

## How It Works

On first run, `bluectl` and `km` automatically generate a 256-bit encryption key and store it in your home directory:

```
~/.local/share/bluectl/key
```

The key file has restricted permissions (0600) in a restricted directory (0700). All databases for your user account share this key.

You don't need to configure anything for single-user local development.

## Key Resolution Order

When any command needs the encryption key, it checks these sources in order:

1. **SECURE_INFRA_KEY environment variable** (if set)
2. **Existing key file** at `~/.local/share/bluectl/key`
3. **Generate new key** and save to the file

The environment variable always wins. This lets you override the file-based key for specific scenarios.

## When to Set SECURE_INFRA_KEY Manually

For local development on a single machine, auto-generation handles everything. Set the environment variable manually when:

| Scenario | Reason |
|----------|--------|
| CI/CD pipelines | Inject a consistent key across build jobs |
| Multi-machine setup | Share encrypted databases between machines |
| Team collaboration | Multiple people accessing the same encrypted data |
| Backup and restore | Restore an encrypted database on a new machine |

### CI/CD Example

```bash
# In your CI configuration
export SECURE_INFRA_KEY="your-hex-encoded-32-byte-key"
```

### Generating a Key

```bash
openssl rand -hex 32
```

This produces a 64-character hex string (32 bytes).

## Migrating from Environment Variable to File

If you previously set SECURE_INFRA_KEY in your shell profile and want to switch to file-based storage:

1. Copy your existing key to the file:
   ```bash
   echo "$SECURE_INFRA_KEY" > ~/.local/share/bluectl/key
   chmod 600 ~/.local/share/bluectl/key
   ```

2. Remove from your shell profile (`~/.zshrc` or `~/.bashrc`)

3. Restart your shell

Your encrypted databases continue working unchanged.

## File Locations

The key file location follows the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html):

| Variable | Default | Key Path |
|----------|---------|----------|
| XDG_DATA_HOME unset | `~/.local/share` | `~/.local/share/bluectl/key` |
| XDG_DATA_HOME set | `$XDG_DATA_HOME` | `$XDG_DATA_HOME/bluectl/key` |

## Troubleshooting

### "encryption key not configured"

This error appears when the key file doesn't exist and can't be created. Check:

- Directory permissions on `~/.local/share/bluectl/`
- Disk space
- File system is writable

### Database won't open after moving machines

The database was encrypted with a different key. Either:

- Copy the key file from the original machine
- Set SECURE_INFRA_KEY to match the original key
- Delete the database and start fresh (see [Clean Slate](../guides/quickstart-emulator.md#appendix-a-clean-slate))
