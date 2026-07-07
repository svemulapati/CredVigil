package pipeline

import (
	"context"

	"github.com/svemulapati/CredVigil/pkg/models"
)

// VerificationHook is an optional processor interface for verifying
// whether a detected secret is still active/valid. Implementations
// make live API calls (e.g. checking if an AWS key is still active)
// and set the Finding.Verified field accordingly.
//
// This is NOT included in the default pipeline. Consumers opt in by
// registering a VerificationHook implementation:
//
//	pipeline.AddProcessor(myVerifier)
type VerificationHook interface {
	Processor

	// CanVerify reports whether this hook can verify the given secret type.
	CanVerify(secretType models.SecretType) bool
}

// NoOpVerifier is a placeholder implementation that marks all findings
// as unverified. It exists for testing and as a template for custom verifiers.
type NoOpVerifier struct{}

// NewNoOpVerifier creates a NoOpVerifier.
func NewNoOpVerifier() *NoOpVerifier {
	return &NoOpVerifier{}
}

func (n *NoOpVerifier) Name() string { return "verify-noop" }

func (n *NoOpVerifier) CanVerify(_ models.SecretType) bool { return false }

func (n *NoOpVerifier) Process(_ context.Context, _ *models.Finding, _ *models.ScanMetadata) error {
	// No-op — Verified field stays nil (unverified)
	return nil
}
