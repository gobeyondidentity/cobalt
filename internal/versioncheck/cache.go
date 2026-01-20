package versioncheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// CacheEntry represents a cached version check result.
type CacheEntry struct {
	// LatestVersion is the cached latest version (without v prefix).
	LatestVersion string `json:"latest_version"`
	// ReleaseURL is the URL to the release page.
	ReleaseURL string `json:"release_url"`
	// CheckedAt is when the version was last checked.
	CheckedAt time.Time `json:"checked_at"`
}

// IsValid returns true if the cache entry is fresh (within TTL).
func (c *CacheEntry) IsValid(ttl time.Duration) bool {
	if c == nil {
		return false
	}
	return time.Since(c.CheckedAt) < ttl
}

// ReadCacheFile reads a cache entry from the given file path.
func ReadCacheFile(path string) (*CacheEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

// WriteCacheFile writes a cache entry to the given file path.
// Creates parent directories if they don't exist.
func WriteCacheFile(path string, entry *CacheEntry) error {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}
