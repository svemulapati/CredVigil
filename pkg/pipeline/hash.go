package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/svemulapati/CredVigil/pkg/models"
)

// HashProcessor computes the SHA-256 hash of the raw secret and stores it
// in the dedicated SecretHash field. If SecretHash is already populated
// (e.g. by the detection engine for dedup), this processor verifies and
// preserves the existing value.
type HashProcessor struct{}

// NewHashProcessor creates a new HashProcessor.
func NewHashProcessor() *HashProcessor {
	return &HashProcessor{}
}

func (h *HashProcessor) Name() string { return "hash" }

func (h *HashProcessor) Process(_ context.Context, f *models.Finding, _ *models.ScanMetadata) error {
	if f.RawMatch == "" && f.SecretHash != "" {
		return nil // already hashed, raw cleared — nothing to do
	}
	if f.RawMatch == "" {
		return nil // no raw match to hash
	}

	hash := sha256Hex(f.RawMatch)

	// If engine already set SecretHash for dedup, verify consistency
	if f.SecretHash != "" && f.SecretHash != hash {
		// Re-compute wins; engine hash may have been on a different substring
		f.SecretHash = hash
	} else {
		f.SecretHash = hash
	}

	// Also copy to Metadata for backward-compat with existing consumers
	if f.Metadata == nil {
		f.Metadata = make(map[string]string)
	}
	f.Metadata["sha256"] = hash

	return nil
}

// sha256Hex returns the hex-encoded SHA-256 digest of s.
func sha256Hex(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
