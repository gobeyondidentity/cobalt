package version

import "testing"

func TestString_NormalizesPrefix(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
	}{
		{"no prefix", "1.0.0", "v1.0.0"},
		{"with v prefix", "v1.0.0", "v1.0.0"},
		{"double v prefix", "vv1.0.0", "vv1.0.0"}, // TrimPrefix only removes one v
		{"dev", "dev", "vdev"},
		{"snapshot", "0.6.12-snapshot", "v0.6.12-snapshot"},
		{"git describe", "v0.6.12-1-gabcdef", "v0.6.12-1-gabcdef"},
		{"dirty", "v0.6.12-dirty", "v0.6.12-dirty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := Version
			defer func() { Version = original }()

			Version = tt.input
			got := String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
