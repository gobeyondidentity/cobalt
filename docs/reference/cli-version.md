# CLI Version Commands

Check installed version and available updates for `bluectl` and `km`.

## 1. Basic Usage

### Show Version

```bash
bluectl version
# Output: bluectl version 0.6.0

km version
# Output: km version 0.6.0
```

### Check for Updates

```bash
bluectl version --check
# Output:
# bluectl version 0.6.0
#
# A newer version is available: 0.7.0
#   Release notes: https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.7.0
#
# To upgrade:
#   brew upgrade nmelo/tap/bluectl
```

If already on latest:

```bash
bluectl version --check
# Output:
# bluectl version 0.6.0
# You are running the latest version.
```

## 2. Flags

| Flag | Description |
|------|-------------|
| `--check` | Check for available updates and show upgrade instructions |
| `--skip-update-check` | Only show version, skip any update check |

## 3. Update Check Behavior

### Caching

Version checks are cached for 24 hours to avoid repeated API calls:

- Cache location: `~/.config/secureinfra/version-cache.json`
- Or `$XDG_CACHE_HOME/secureinfra/version-cache.json` if set

### Timeout

API requests timeout after 2 seconds. If the GitHub API is unreachable:

```bash
bluectl version --check
# Output:
# bluectl version 0.6.0
# (Could not check for updates)
```

The CLI continues without error. Stale cache is used if available.

### Offline Mode

If you need to skip update checks entirely (air-gapped environments):

```bash
bluectl version --skip-update-check
```

## 4. Upgrade Instructions

The CLI detects how it was installed and shows the appropriate upgrade command:

| Install Method | Detection | Upgrade Command |
|----------------|-----------|-----------------|
| Homebrew | Path contains `/Cellar/` or `/homebrew/` | `brew upgrade nmelo/tap/bluectl` |
| Apt (Debian/Ubuntu) | `/var/lib/dpkg/info/bluectl.list` exists | `sudo apt update && sudo apt upgrade bluectl` |
| RPM (RHEL/Fedora) | RPM database query | `sudo dnf upgrade bluectl` |
| Docker | `/.dockerenv` exists | `docker pull ghcr.io/gobeyondidentity/sentry:<version>` |
| Direct download | Default fallback | Download from GitHub releases |

## 5. Examples

### CI/CD Pipeline

Skip update check in automated environments:

```bash
bluectl version --skip-update-check
```

### Interactive Check

Check and upgrade if needed:

```bash
bluectl version --check
# If update available, run the suggested command
```

### Scripting Version

Get just the version for scripts:

```bash
bluectl version | awk '{print $3}'
# Output: 0.6.0
```

## 6. Troubleshooting

### "Could not check for updates"

**Cause:** GitHub API unreachable (network issue, firewall, timeout)

**Solutions:**
1. Check network connectivity
2. Try again later
3. Use `--skip-update-check` to proceed without checking

### Upgrade command doesn't match your setup

**Cause:** Install method detection failed

**Solution:** Manually check releases at https://github.com/gobeyondidentity/secure-infra/releases

### Cache issues

Clear the cache to force a fresh check:

```bash
rm ~/.config/secureinfra/version-cache.json
bluectl version --check
```
