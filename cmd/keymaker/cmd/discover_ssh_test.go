package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test keys (same as in pkg/sshscan/parser_test.go)
const (
	testSSHEd25519Key  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test-ed25519"
	testSSHRSA2048Key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAUGZx+2UmVBvfcjF9lWMlDbae4vSjLJtDWrfNX3jFNcfugZhYiLA63wV3qvhrB4dmf4Pl1IkNafXm8JwAe+ALqbEDnUZ738uD9/CWMB6GJg5KqZ25x9IAsO/sqeMkp6U6XBP+Ntzh1gPjV7WCq06EafZGUq+yxKTbPFnTVpr6EB1ktaApQp5wkPhndM4BeYdxw4/rONndmmZCNBgqZb/3D3AQJIjhH2+ZHWpyISUTPNyfWqW9gOcocBcfzV4MK0DEC8iW6xO8uzKdD/2GAbOMoj7NDguJlE/9LsPrAHQX7zrKvuMIxTM4yuMujrXFu8aS0igWcQrSBmJeHAV6qYlp test-rsa-2048"
	testSSHECDSA256Key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg= test-ecdsa-256"
)

func TestParseSSHOutput(t *testing.T) {
	t.Parallel()
	t.Run("parse output with file paths", func(t *testing.T) {
		// Simulate output from: cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys
		output := `/root/.ssh/authorized_keys:` + testSSHEd25519Key + `
/home/ubuntu/.ssh/authorized_keys:` + testSSHRSA2048Key + `
/home/slurm/.ssh/authorized_keys:` + testSSHECDSA256Key

		keys := parseSSHOutput(output, "test-host")

		if len(keys) != 3 {
			t.Fatalf("expected 3 keys, got %d", len(keys))
		}

		// Check first key (root)
		if keys[0].User != "root" {
			t.Errorf("key 0 user = %q, want %q", keys[0].User, "root")
		}
		if keys[0].FilePath != "/root/.ssh/authorized_keys" {
			t.Errorf("key 0 filepath = %q, want %q", keys[0].FilePath, "/root/.ssh/authorized_keys")
		}
		if keys[0].KeyType != "ssh-ed25519" {
			t.Errorf("key 0 type = %q, want %q", keys[0].KeyType, "ssh-ed25519")
		}

		// Check second key (ubuntu)
		if keys[1].User != "ubuntu" {
			t.Errorf("key 1 user = %q, want %q", keys[1].User, "ubuntu")
		}
		if keys[1].FilePath != "/home/ubuntu/.ssh/authorized_keys" {
			t.Errorf("key 1 filepath = %q, want %q", keys[1].FilePath, "/home/ubuntu/.ssh/authorized_keys")
		}

		// Check third key (slurm)
		if keys[2].User != "slurm" {
			t.Errorf("key 2 user = %q, want %q", keys[2].User, "slurm")
		}
	})

	t.Run("parse output without file path prefix", func(t *testing.T) {
		// When cat outputs single file without prefix
		output := testSSHEd25519Key + "\n" + testSSHRSA2048Key

		keys := parseSSHOutput(output, "test-host")

		if len(keys) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(keys))
		}

		// Without path prefix, user should be empty (unknown)
		if keys[0].User != "" {
			t.Errorf("key 0 user = %q, want empty", keys[0].User)
		}
	})

	t.Run("skip empty lines and errors", func(t *testing.T) {
		output := `
/root/.ssh/authorized_keys:` + testSSHEd25519Key + `

cat: /home/missing/.ssh/authorized_keys: No such file or directory
/home/ubuntu/.ssh/authorized_keys:` + testSSHRSA2048Key

		keys := parseSSHOutput(output, "test-host")

		if len(keys) != 2 {
			t.Fatalf("expected 2 keys (skipping errors), got %d", len(keys))
		}
	})

	t.Run("parse multiple keys from same file", func(t *testing.T) {
		output := `/home/ubuntu/.ssh/authorized_keys:` + testSSHEd25519Key + `
/home/ubuntu/.ssh/authorized_keys:` + testSSHRSA2048Key

		keys := parseSSHOutput(output, "test-host")

		if len(keys) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(keys))
		}

		// Both should have ubuntu as user
		for i, k := range keys {
			if k.User != "ubuntu" {
				t.Errorf("key %d user = %q, want %q", i, k.User, "ubuntu")
			}
		}
	})

	t.Run("empty output returns empty slice", func(t *testing.T) {
		keys := parseSSHOutput("", "test-host")
		if len(keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(keys))
		}
	})
}

func TestExtractPathAndKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		line     string
		wantPath string
		wantKey  string
	}{
		{
			name:     "root path with key",
			line:     "/root/.ssh/authorized_keys:ssh-ed25519 AAAAC3 comment",
			wantPath: "/root/.ssh/authorized_keys",
			wantKey:  "ssh-ed25519 AAAAC3 comment",
		},
		{
			name:     "home path with key",
			line:     "/home/ubuntu/.ssh/authorized_keys:ssh-rsa AAAAB3 comment",
			wantPath: "/home/ubuntu/.ssh/authorized_keys",
			wantKey:  "ssh-rsa AAAAB3 comment",
		},
		{
			name:     "no path prefix",
			line:     "ssh-ed25519 AAAAC3 comment",
			wantPath: "",
			wantKey:  "ssh-ed25519 AAAAC3 comment",
		},
		{
			name:     "key with colon in comment",
			line:     "/home/user/.ssh/authorized_keys:ssh-ed25519 AAAAC3 user:key@host",
			wantPath: "/home/user/.ssh/authorized_keys",
			wantKey:  "ssh-ed25519 AAAAC3 user:key@host",
		},
		{
			name:     "error message",
			line:     "cat: /root/.ssh/authorized_keys: Permission denied",
			wantPath: "",
			wantKey:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotKey := extractPathAndKey(tt.line)
			if gotPath != tt.wantPath {
				t.Errorf("path = %q, want %q", gotPath, tt.wantPath)
			}
			if gotKey != tt.wantKey {
				t.Errorf("key = %q, want %q", gotKey, tt.wantKey)
			}
		})
	}
}

func TestBuildSSHCommand(t *testing.T) {
	t.Parallel()
	t.Run("command format", func(t *testing.T) {
		cmd := buildAuthorizedKeysCommand(true)
		if !strings.Contains(cmd, "sudo") {
			t.Error("command should contain sudo when useSudo=true")
		}
		if !strings.Contains(cmd, "grep -H") {
			t.Error("command should use grep -H to prepend file paths")
		}
		if !strings.Contains(cmd, "/root/.ssh/authorized_keys") {
			t.Error("command should include root authorized_keys path")
		}
		if !strings.Contains(cmd, "/home/*/.ssh/authorized_keys") {
			t.Error("command should include home authorized_keys glob")
		}
	})

	t.Run("command without sudo", func(t *testing.T) {
		cmd := buildAuthorizedKeysCommand(false)
		if strings.Contains(cmd, "sudo") {
			t.Error("command should not contain sudo when useSudo=false")
		}
	})
}

func TestParseSSHOutputHostField(t *testing.T) {
	t.Parallel()
	// Verify the host field is correctly set on all keys
	output := `/root/.ssh/authorized_keys:` + testSSHEd25519Key

	keys := parseSSHOutput(output, "gpu-node-01")

	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	if keys[0].Host != "gpu-node-01" {
		t.Errorf("host = %q, want %q", keys[0].Host, "gpu-node-01")
	}
}

func TestParseSSHOutputMethod(t *testing.T) {
	t.Parallel()
	// Verify the method field is correctly set on all keys
	output := `/root/.ssh/authorized_keys:` + testSSHEd25519Key

	keys := parseSSHOutput(output, "test-host")

	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	if keys[0].Method != "ssh" {
		t.Errorf("method = %q, want %q", keys[0].Method, "ssh")
	}
}

func TestValidateSSHKeyPath(t *testing.T) {
	t.Parallel()
	// Get home and cwd for constructing test paths
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	tests := []struct {
		name      string
		path      string
		wantError bool
	}{
		{
			name:      "path in ~/.ssh directory",
			path:      filepath.Join(home, ".ssh", "id_rsa"),
			wantError: false,
		},
		{
			name:      "path in ~/.ssh with subdirectory",
			path:      filepath.Join(home, ".ssh", "keys", "mykey"),
			wantError: false,
		},
		{
			name:      "path in current directory",
			path:      filepath.Join(cwd, "my_key"),
			wantError: false,
		},
		{
			name:      "relative path in current directory",
			path:      "./my_key",
			wantError: false,
		},
		{
			name:      "common key name id_rsa anywhere",
			path:      "/some/other/path/id_rsa",
			wantError: false,
		},
		{
			name:      "common key name id_ed25519 anywhere",
			path:      "/opt/keys/id_ed25519",
			wantError: false,
		},
		{
			name:      "common key name with extension",
			path:      "/some/path/id_rsa.pub",
			wantError: false,
		},
		{
			name:      "path traversal to /etc/passwd",
			path:      "/etc/passwd",
			wantError: true,
		},
		{
			name:      "path traversal with ../",
			path:      "../../../etc/shadow",
			wantError: true,
		},
		{
			name:      "arbitrary system file",
			path:      "/var/log/syslog",
			wantError: true,
		},
		{
			name:      "path outside allowed directories",
			path:      "/tmp/random_file",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSSHKeyPath(tt.path)
			if tt.wantError && err == nil {
				t.Errorf("validateSSHKeyPath(%q) = nil, want error", tt.path)
			}
			if !tt.wantError && err != nil {
				t.Errorf("validateSSHKeyPath(%q) = %v, want nil", tt.path, err)
			}
			// If we expect an error, verify it contains the expected message
			if tt.wantError && err != nil {
				if !strings.Contains(err.Error(), "invalid SSH key path") {
					t.Errorf("error message = %q, want to contain %q", err.Error(), "invalid SSH key path")
				}
			}
		})
	}
}

func TestIsCommonKeyFileName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want bool
	}{
		{"id_rsa", true},
		{"id_ed25519", true},
		{"id_ecdsa", true},
		{"id_dsa", true},
		{"identity", true},
		{"id_rsa.pub", true},
		{"id_ed25519.bak", true},
		{"my_custom_key", false},
		{"passwd", false},
		{"shadow", false},
		{"config", false},
		{"rsa_id", false}, // wrong order
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCommonKeyFileName(tt.name)
			if got != tt.want {
				t.Errorf("isCommonKeyFileName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
