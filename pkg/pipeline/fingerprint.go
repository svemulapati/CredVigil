package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/svemulapati/CredVigil/pkg/models"
)

// FingerprintProcessor generates a stable, reproducible fingerprint for each
// finding. The fingerprint is derived from:
//
//   - RuleID (which rule detected it)
//   - Source location (file path + line number)
//   - SecretHash (SHA-256 of the raw secret)
//
// This fingerprint remains constant across scan runs for the same secret
// at the same location, enabling cross-scan deduplication, trend tracking,
// and suppression workflows.
type FingerprintProcessor struct{}

// NewFingerprintProcessor creates a new FingerprintProcessor.
func NewFingerprintProcessor() *FingerprintProcessor {
	return &FingerprintProcessor{}
}

func (fp *FingerprintProcessor) Name() string { return "fingerprint" }

func (fp *FingerprintProcessor) Process(_ context.Context, f *models.Finding, _ *models.ScanMetadata) error {
	// Build fingerprint input from stable components
	input := fmt.Sprintf("%s:%s:%d:%s",
		f.RuleID,
		f.Source.Location,
		f.Source.Line,
		f.SecretHash,
	)

	h := sha256.New()
	h.Write([]byte(input))
	f.Fingerprint = hex.EncodeToString(h.Sum(nil))

	return nil
}
