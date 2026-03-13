package entropy

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		minEnt float64
		maxEnt float64
	}{
		{"empty string", "", 0, 0},
		{"single char", "a", 0, 0},
		{"repeated char", "aaaaaaaaaa", 0, 0.01},
		{"two chars alternating", "abababababababab", 0.99, 1.01},
		{"hex string", "abcdef0123456789", 3.5, 4.5},
		{"high entropy", "kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j", 4.0, 6.0},
		{"base64", "SGVsbG8gV29ybGQ=", 3.0, 5.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Shannon(tt.input)
			if got < tt.minEnt || got > tt.maxEnt {
				t.Errorf("Shannon(%q) = %f, expected in [%f, %f]", tt.input, got, tt.minEnt, tt.maxEnt)
			}
		})
	}
}

func TestShannonKnownValues(t *testing.T) {
	// "ab" repeated: exactly 1.0 bits of entropy
	ent := Shannon("abababababababab")
	if math.Abs(ent-1.0) > 0.01 {
		t.Errorf("Shannon(abababababababab) = %f, expected ~1.0", ent)
	}

	// All unique chars should have high entropy
	ent = Shannon("abcdefghijklmnop")
	if ent < 3.5 {
		t.Errorf("Shannon(abcdefghijklmnop) = %f, expected > 3.5", ent)
	}
}

func TestDetectCharset(t *testing.T) {
	tests := []struct {
		input    string
		expected CharsetType
	}{
		{"abcdef0123456789", CharsetHex},
		{"ABCDEF", CharsetHex},
		{"abcdefgh", CharsetBase64}, // all lowercase letters are valid base64 chars
		{"SGVsbG8gV29ybGQ=", CharsetBase64},
		{"abc-def_ghi", CharsetBase64URL},
		{"Hello World!", CharsetPrintableASCII},
		{"", CharsetUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := DetectCharset(tt.input)
			if got != tt.expected {
				t.Errorf("DetectCharset(%q) = %v, expected %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsHighEntropy(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"short", false},                // Too short
		{"aaaaaaaaaa", false},           // Low entropy
		{"AKIAIOSFODNN7EXAMPLE", false}, // entropy 3.68 < base64 threshold 4.0
		{"password", false},             // Too short
		{"kJ9mN2pR5tW8xY1zA3bCd", true}, // Random-looking
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsHighEntropy(tt.input)
			if got != tt.expected {
				t.Errorf("IsHighEntropy(%q) = %v, expected %v (entropy=%.2f)", tt.input, got, tt.expected, Shannon(tt.input))
			}
		})
	}
}

func TestEntropyScore(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore float64
	}{
		{"short string", "abc", 0.0},
		{"low entropy", "aaaaaaaaaaaa", 0.0},
		{"high entropy key", "kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j", 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EntropyScore(tt.input)
			if got < tt.minScore {
				t.Errorf("EntropyScore(%q) = %f, expected >= %f", tt.input, got, tt.minScore)
			}
			if got < 0 || got > 1 {
				t.Errorf("EntropyScore(%q) = %f, should be in [0, 1]", tt.input, got)
			}
		})
	}
}

func TestExtractHighEntropyWords(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		minLen    int
		wantCount int // minimum expected matches
	}{
		{
			name:      "config with secret",
			input:     `api_key = "kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j"`,
			minLen:    8,
			wantCount: 1,
		},
		{
			name:      "no secrets",
			input:     `name = "hello world"`,
			minLen:    8,
			wantCount: 0,
		},
		{
			name:      "multiple tokens",
			input:     `KEY=aB3cD4eF5gH6iJ7kL8mN9 OTHER=xY1zA3bC6dE7fG8hI9jK0`,
			minLen:    8,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractHighEntropyWords(tt.input, tt.minLen)
			if len(got) < tt.wantCount {
				t.Errorf("ExtractHighEntropyWords got %d matches, expected >= %d", len(got), tt.wantCount)
			}
		})
	}
}

func TestCharsetThresholds(t *testing.T) {
	// Verify thresholds are reasonable
	charsets := []CharsetType{CharsetHex, CharsetBase64, CharsetBase64URL, CharsetAlphanumeric, CharsetPrintableASCII}
	for _, cs := range charsets {
		thresh := cs.Threshold()
		high := cs.HighThreshold()
		if thresh <= 0 {
			t.Errorf("Charset %v has non-positive threshold: %f", cs, thresh)
		}
		if high <= thresh {
			t.Errorf("Charset %v high threshold (%f) should be > threshold (%f)", cs, high, thresh)
		}
		if thresh > 6.0 || high > 8.0 {
			t.Errorf("Charset %v thresholds seem too high: %f / %f", cs, thresh, high)
		}
	}
}
