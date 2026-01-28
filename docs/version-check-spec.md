# Version Check Specification

Reference: si-853.6

## Overview

CLI tools (bluectl, km) should notify users when newer versions are available, with platform-appropriate upgrade instructions.

## Version Source

Use GitHub Releases API. No custom endpoint needed.

```
GET https://api.github.com/repos/gobeyondidentity/secure-infra/releases/latest
```

Response fields used:
- `tag_name`: Latest version (e.g., "v0.5.2")
- `html_url`: Release page URL for changelog

Benefits:
- Zero infrastructure to maintain
- Always reflects actual releases
- Works without authentication for public repos

## CLI Commands

### `bluectl version` / `km version`

Display current version (existing behavior via Cobra).

```
bluectl version 0.5.1
```

### `bluectl version --check` / `km version --check`

Check for updates and display upgrade instructions.

```
bluectl version 0.5.1

A newer version is available: 0.5.2
  Release notes: https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.5.2

To upgrade:
  brew upgrade nmelo/tap/bluectl
```

If current version equals or exceeds latest:
```
bluectl version 0.5.2
You are running the latest version.
```

If check fails (timeout, network error):
```
bluectl version 0.5.1
(Could not check for updates)
```

## Install Method Detection

The CLI must detect how it was installed to provide correct upgrade instructions.

### Detection Logic

Check in order (first match wins):

1. **Homebrew**: Check if binary path contains `/Cellar/` or `/homebrew/`
2. **Debian/Ubuntu**: Check if `/var/lib/dpkg/info/bluectl.list` exists
3. **RPM**: Check if `rpm -q bluectl` succeeds
4. **Docker**: Check if running inside container (`/.dockerenv` exists)
5. **Direct download**: Default fallback

### Implementation

```go
func DetectInstallMethod() InstallMethod {
    execPath, _ := os.Executable()

    // Homebrew
    if strings.Contains(execPath, "/Cellar/") ||
       strings.Contains(execPath, "/homebrew/") {
        return Homebrew
    }

    // Debian/Ubuntu
    if _, err := os.Stat("/var/lib/dpkg/info/bluectl.list"); err == nil {
        return Apt
    }

    // RPM
    if err := exec.Command("rpm", "-q", "bluectl").Run(); err == nil {
        return Rpm
    }

    // Docker
    if _, err := os.Stat("/.dockerenv"); err == nil {
        return Docker
    }

    return DirectDownload
}
```

## Upgrade Instructions by Install Method

| Install Method | bluectl | km |
|---------------|---------|-----|
| Homebrew | `brew upgrade nmelo/tap/bluectl` | `brew upgrade nmelo/tap/km` |
| Apt | `sudo apt update && sudo apt upgrade bluectl` | `sudo apt update && sudo apt upgrade km` |
| RPM | `sudo dnf upgrade bluectl` | `sudo dnf upgrade km` |
| Docker | `docker pull ghcr.io/gobeyondidentity/sentry:VERSION` | N/A |
| Direct | `Download from https://github.com/gobeyondidentity/secure-infra/releases` | Same |

For Docker, replace VERSION with the actual new version number.

## Timeout and Error Handling

Requirements:
- HTTP timeout: 2 seconds
- Never block CLI startup or normal operation
- Fail silently on network errors (just show current version)
- Log errors at debug level for troubleshooting

```go
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()

resp, err := client.Do(req.WithContext(ctx))
if err != nil {
    // Log at debug level, don't show to user
    return "", fmt.Errorf("version check failed: %w", err)
}
```

## Caching (Optional)

Cache the version check result to avoid repeated API calls.

### Cache Location

```
~/.config/secureinfra/version-cache.json
```

Or respect `XDG_CACHE_HOME` if set:
```
$XDG_CACHE_HOME/secureinfra/version-cache.json
```

### Cache Format

```json
{
  "latest_version": "0.5.2",
  "release_url": "https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.5.2",
  "checked_at": "2026-01-20T15:04:05Z"
}
```

### Cache TTL

- Default: 24 hours
- After TTL expires, next `--check` fetches fresh data
- Cache is per-user, not system-wide

### Cache Behavior

| Scenario | Action |
|----------|--------|
| Cache valid (< 24h old) | Use cached version |
| Cache expired or missing | Fetch from GitHub API |
| Fetch fails, cache exists | Use stale cache with warning |
| Fetch fails, no cache | Show error message |

## Version Comparison

Use semantic versioning comparison. Handle:
- `v` prefix stripping: "v0.5.2" -> "0.5.2"
- Pre-release versions: "0.5.2-rc1" < "0.5.2"
- Build metadata ignored: "0.5.2+build123" == "0.5.2"

Recommend using `golang.org/x/mod/semver` or `github.com/Masterminds/semver`.

## Background Check (Future Enhancement)

Not in initial scope. If added later:
- Check once per day on CLI startup
- Only show notification if update available
- Don't delay startup (async check)
- Respect `BLUECTL_NO_UPDATE_CHECK=1` env var to disable
