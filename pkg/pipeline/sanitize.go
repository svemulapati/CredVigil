package pipeline

import (
	"context"

	"github.com/svemulapati/CredVigil/pkg/models"
)

// SanitizeProcessor is the final pipeline stage that enforces zero-trust
// by removing the raw secret text from the finding. After this processor runs,
// only the redacted preview and the SHA-256 hash remain.
//
// This processor MUST be the last one in the chain. Any processor that needs
// the raw match must run before it.
type SanitizeProcessor struct {
	// ClearMetadataSHA controls whether to remove the legacy
	// Metadata["sha256"] entry (now that SecretHash is the canonical field).
	// Default: false (keep for backward compatibility).
	ClearMetadataSHA bool
}

// NewSanitizeProcessor creates a SanitizeProcessor with default settings.
func NewSanitizeProcessor() *SanitizeProcessor {
	return &SanitizeProcessor{ClearMetadataSHA: false}
}

func (s *SanitizeProcessor) Name() string { return "sanitize" }

func (s *SanitizeProcessor) Process(_ context.Context, f *models.Finding, _ *models.ScanMetadata) error {
	// Clear the raw secret — the core zero-trust guarantee
	f.RawMatch = ""

	// Optionally remove the legacy sha256 from Metadata
	// (it now lives in the dedicated SecretHash field)
	if s.ClearMetadataSHA {
		delete(f.Metadata, "sha256")
		if len(f.Metadata) == 0 {
			f.Metadata = nil
		}
	}

	return nil
}
