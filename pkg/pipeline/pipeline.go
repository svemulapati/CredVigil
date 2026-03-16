// Package pipeline provides a composable post-processing pipeline for
// credential findings. It implements the zero-trust principle by ensuring
// all findings are hashed, redacted, enriched, fingerprinted, and sanitized
// before they leave the detection engine.
//
// The pipeline is the boundary between raw detection output and any
// consumer (CLI output, storage, API, dashboard). No raw secret should
// ever cross this boundary.
package pipeline

import (
	"context"
	"fmt"
	"sync"

	"github.com/credvigil/credvigil/pkg/models"
)

// Processor is the interface every pipeline stage must implement.
// Each processor receives a single finding plus scan-level metadata
// and may mutate the finding in place.
type Processor interface {
	// Name returns a human-readable identifier for this processor.
	Name() string
	// Process mutates a finding in place. Return an error to abort
	// the pipeline for this finding (the finding will be dropped).
	Process(ctx context.Context, finding *models.Finding, meta *models.ScanMetadata) error
}

// Pipeline chains multiple Processors and runs them in order on every finding.
type Pipeline struct {
	mu         sync.RWMutex
	processors []Processor
}

// New creates a Pipeline with the given processors.
// Processors run in the order provided.
func New(processors ...Processor) *Pipeline {
	return &Pipeline{
		processors: processors,
	}
}

// NewDefault creates a Pipeline with the standard zero-trust processor chain:
//
//	Hash → Redact → Enrich → Fingerprint → Sanitize
func NewDefault() *Pipeline {
	return New(
		NewHashProcessor(),
		NewRedactProcessor(),
		NewEnrichProcessor(),
		NewFingerprintProcessor(),
		NewSanitizeProcessor(),
	)
}

// AddProcessor appends a processor to the end of the pipeline.
func (p *Pipeline) AddProcessor(proc Processor) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.processors = append(p.processors, proc)
}

// InsertProcessor inserts a processor at the given index (0-based).
// Returns an error if index is out of range.
func (p *Pipeline) InsertProcessor(index int, proc Processor) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if index < 0 || index > len(p.processors) {
		return fmt.Errorf("pipeline: insert index %d out of range [0, %d]", index, len(p.processors))
	}
	p.processors = append(p.processors, nil)
	copy(p.processors[index+1:], p.processors[index:])
	p.processors[index] = proc
	return nil
}

// Processors returns the ordered list of processors in the pipeline.
func (p *Pipeline) Processors() []Processor {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Processor, len(p.processors))
	copy(out, p.processors)
	return out
}

// ProcessFindings runs every finding through the full processor chain.
// Findings that cause a processor error are dropped and the error is
// collected in the returned error slice. The findings slice is modified
// in place; dropped findings are removed.
func (p *Pipeline) ProcessFindings(ctx context.Context, findings []models.Finding, meta *models.ScanMetadata) ([]models.Finding, []error) {
	p.mu.RLock()
	processors := make([]Processor, len(p.processors))
	copy(processors, p.processors)
	p.mu.RUnlock()

	var (
		kept   []models.Finding
		errors []error
	)
	for i := range findings {
		dropped := false
		for _, proc := range processors {
			if err := proc.Process(ctx, &findings[i], meta); err != nil {
				errors = append(errors, fmt.Errorf("processor %q on finding %s: %w", proc.Name(), findings[i].ID, err))
				dropped = true
				break
			}
		}
		if !dropped {
			kept = append(kept, findings[i])
		}
	}
	return kept, errors
}

// ProcessResult processes all findings inside a ScanResult and returns the
// updated result. This is a convenience method for the common case.
func (p *Pipeline) ProcessResult(ctx context.Context, result *models.ScanResult, meta *models.ScanMetadata) []error {
	kept, errs := p.ProcessFindings(ctx, result.Findings, meta)
	result.Findings = kept
	result.TotalFindings = len(kept)
	// Recompute severity counts
	result.CountBySeverity = make(map[models.Severity]int)
	for _, f := range kept {
		result.CountBySeverity[f.Severity]++
	}
	return errs
}
