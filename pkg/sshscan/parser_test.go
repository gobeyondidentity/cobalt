package sshscan

import (
	"testing"
)

// Test SSH keys (real format, generated for testing)
const (
	// ssh-keygen -t ed25519 -C "test-ed25519"
	testEd25519Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test-ed25519"

	// ssh-keygen -t rsa -b 2048 -C "test-rsa-2048"
	testRSA2048Key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAUGZx+2UmVBvfcjF9lWMlDbae4vSjLJtDWrfNX3jFNcfugZhYiLA63wV3qvhrB4dmf4Pl1IkNafXm8JwAe+ALqbEDnUZ738uD9/CWMB6GJg5KqZ25x9IAsO/sqeMkp6U6XBP+Ntzh1gPjV7WCq06EafZGUq+yxKTbPFnTVpr6EB1ktaApQp5wkPhndM4BeYdxw4/rONndmmZCNBgqZb/3D3AQJIjhH2+ZHWpyISUTPNyfWqW9gOcocBcfzV4MK0DEC8iW6xO8uzKdD/2GAbOMoj7NDguJlE/9LsPrAHQX7zrKvuMIxTM4yuMujrXFu8aS0igWcQrSBmJeHAV6qYlp test-rsa-2048"

	// ssh-keygen -t ecdsa -b 256 -C "test-ecdsa-256"
	testECDSA256Key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg= test-ecdsa-256"

	// Key without comment
	testKeyNoComment = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
)

func TestParseLine(t *testing.T) {
	t.Parallel()
	t.Run("parse ed25519 key with comment", func(t *testing.T) {
		key, err := ParseLine(testEd25519Key)
		if err != nil {
			t.Fatalf("ParseLine failed: %v", err)
		}

		if key.KeyType != "ssh-ed25519" {
			t.Errorf("KeyType = %q, want %q", key.KeyType, "ssh-ed25519")
		}

		if key.KeyBits != 256 {
			t.Errorf("KeyBits = %d, want 256", key.KeyBits)
		}

		if key.Comment != "test-ed25519" {
			t.Errorf("Comment = %q, want %q", key.Comment, "test-ed25519")
		}

		if key.Fingerprint == "" {
			t.Error("Fingerprint should not be empty")
		}
	})

	t.Run("parse RSA key", func(t *testing.T) {
		key, err := ParseLine(testRSA2048Key)
		if err != nil {
			t.Fatalf("ParseLine failed: %v", err)
		}

		if key.KeyType != "ssh-rsa" {
			t.Errorf("KeyType = %q, want %q", key.KeyType, "ssh-rsa")
		}

		if key.Comment != "test-rsa-2048" {
			t.Errorf("Comment = %q, want %q", key.Comment, "test-rsa-2048")
		}
	})

	t.Run("parse ECDSA key", func(t *testing.T) {
		key, err := ParseLine(testECDSA256Key)
		if err != nil {
			t.Fatalf("ParseLine failed: %v", err)
		}

		if key.KeyType != "ecdsa-sha2-nistp256" {
			t.Errorf("KeyType = %q, want %q", key.KeyType, "ecdsa-sha2-nistp256")
		}

		if key.KeyBits != 256 {
			t.Errorf("KeyBits = %d, want 256", key.KeyBits)
		}

		if key.Comment != "test-ecdsa-256" {
			t.Errorf("Comment = %q, want %q", key.Comment, "test-ecdsa-256")
		}
	})

	t.Run("parse key without comment", func(t *testing.T) {
		key, err := ParseLine(testKeyNoComment)
		if err != nil {
			t.Fatalf("ParseLine failed: %v", err)
		}

		if key.Comment != "" {
			t.Errorf("Comment = %q, want empty string", key.Comment)
		}
	})

	t.Run("skip empty line", func(t *testing.T) {
		key, err := ParseLine("")
		if err != nil {
			t.Fatalf("ParseLine should not error on empty line: %v", err)
		}
		if key != nil {
			t.Error("ParseLine should return nil for empty line")
		}
	})

	t.Run("skip whitespace-only line", func(t *testing.T) {
		key, err := ParseLine("   \t  ")
		if err != nil {
			t.Fatalf("ParseLine should not error on whitespace line: %v", err)
		}
		if key != nil {
			t.Error("ParseLine should return nil for whitespace-only line")
		}
	})

	t.Run("skip comment line", func(t *testing.T) {
		key, err := ParseLine("# This is a comment")
		if err != nil {
			t.Fatalf("ParseLine should not error on comment line: %v", err)
		}
		if key != nil {
			t.Error("ParseLine should return nil for comment line")
		}
	})

	t.Run("skip comment line with leading whitespace", func(t *testing.T) {
		key, err := ParseLine("   # This is a comment with leading space")
		if err != nil {
			t.Fatalf("ParseLine should not error on comment line: %v", err)
		}
		if key != nil {
			t.Error("ParseLine should return nil for comment line")
		}
	})

	t.Run("handle malformed line gracefully", func(t *testing.T) {
		key, err := ParseLine("not-a-valid-key")
		if err != nil {
			t.Fatalf("ParseLine should not error on malformed line: %v", err)
		}
		if key != nil {
			t.Error("ParseLine should return nil for malformed line")
		}
	})

	t.Run("handle invalid base64 gracefully", func(t *testing.T) {
		key, err := ParseLine("ssh-ed25519 not-valid-base64 comment")
		if err != nil {
			t.Fatalf("ParseLine should not error on invalid base64: %v", err)
		}
		if key != nil {
			t.Error("ParseLine should return nil for invalid base64")
		}
	})
}

func TestParseAuthorizedKeys(t *testing.T) {
	t.Parallel()
	t.Run("parse multiple keys", func(t *testing.T) {
		content := testEd25519Key + "\n" +
			"# comment line\n" +
			"\n" +
			testECDSA256Key + "\n" +
			"invalid line\n" +
			testKeyNoComment

		keys, err := ParseAuthorizedKeys(content, "testuser", "/home/testuser/.ssh/authorized_keys")
		if err != nil {
			t.Fatalf("ParseAuthorizedKeys failed: %v", err)
		}

		if len(keys) != 3 {
			t.Errorf("got %d keys, want 3", len(keys))
		}

		// Verify user and filepath are set
		for _, key := range keys {
			if key.User != "testuser" {
				t.Errorf("User = %q, want %q", key.User, "testuser")
			}
			if key.FilePath != "/home/testuser/.ssh/authorized_keys" {
				t.Errorf("FilePath = %q, want %q", key.FilePath, "/home/testuser/.ssh/authorized_keys")
			}
		}
	})

	t.Run("empty content returns empty slice", func(t *testing.T) {
		keys, err := ParseAuthorizedKeys("", "user", "/path")
		if err != nil {
			t.Fatalf("ParseAuthorizedKeys failed: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("got %d keys, want 0", len(keys))
		}
	})

	t.Run("all comments returns empty slice", func(t *testing.T) {
		content := "# comment 1\n# comment 2\n"
		keys, err := ParseAuthorizedKeys(content, "user", "/path")
		if err != nil {
			t.Fatalf("ParseAuthorizedKeys failed: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("got %d keys, want 0", len(keys))
		}
	})
}

func TestExtractUsername(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path string
		want string
	}{
		{"/home/nelson/.ssh/authorized_keys", "nelson"},
		{"/home/slurm/.ssh/authorized_keys", "slurm"},
		{"/root/.ssh/authorized_keys", "root"},
		{"/var/lib/myuser/.ssh/authorized_keys", "myuser"},
		{"/some/weird/path/authorized_keys", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := ExtractUsername(tt.path)
			if got != tt.want {
				t.Errorf("ExtractUsername(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
