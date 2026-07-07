package pipeline

import (
	"context"
	"fmt"

	"github.com/svemulapati/CredVigil/pkg/models"
)

// RedactProcessor creates a masked preview of the raw secret for safe
// display. This replaces the inline Redact() call that was previously
// embedded in the detection engine.
//
// Redaction rules:
//   - > 12 chars: first 4 + "****" + last 4
//   - 5–12 chars: first 2 + "****"
//   - ≤ 4 chars:  "****"
type RedactProcessor struct{}

// NewRedactProcessor creates a new RedactProcessor.
func NewRedactProcessor() *RedactProcessor {
	return &RedactProcessor{}
}

func (r *RedactProcessor) Name() string { return "redact" }

func (r *RedactProcessor) Process(_ context.Context, f *models.Finding, _ *models.ScanMetadata) error {
	// If already redacted (defensive), keep it
	if f.RedactedMatch != "" {
		return nil
	}
	if f.RawMatch == "" {
		f.RedactedMatch = "****"
		return nil
	}

	raw := f.RawMatch
	switch {
	case len(raw) > 12:
		f.RedactedMatch = fmt.Sprintf("%s****%s", raw[:4], raw[len(raw)-4:])
	case len(raw) > 4:
		f.RedactedMatch = fmt.Sprintf("%s****", raw[:2])
	default:
		f.RedactedMatch = "****"
	}
	return nil
}
