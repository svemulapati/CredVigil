// Package storage defines the Repository interface for persisting scan results,
// findings, and audit logs.  The interface is implementation-agnostic; the only
// concrete backend today is PostgreSQL + TimescaleDB (see postgres.go).
//
// All methods accept a context.Context for timeout / cancellation propagation.
package storage

import (
	"context"
	"io"
	"time"

	"github.com/svemulapati/CredVigil/pkg/models"
)

// Repository is the central storage abstraction.  Every persistence operation
// that CredVigil needs goes through this interface so that the detection engine
// and CLI remain decoupled from the database layer.
type Repository interface {
	// ── Findings ─────────────────────────────────────────────────────────

	// SaveFinding persists a single finding.
	SaveFinding(ctx context.Context, f *models.StoredFinding) error

	// SaveFindings persists a batch of findings in a single transaction.
	SaveFindings(ctx context.Context, findings []models.StoredFinding) error

	// GetFindingByID retrieves a single finding by its unique ID.
	GetFindingByID(ctx context.Context, id string) (*models.StoredFinding, error)

	// FindByFingerprint returns every finding that shares the given fingerprint.
	FindByFingerprint(ctx context.Context, fingerprint string) ([]models.StoredFinding, error)

	// FindBySecretHash returns every finding that shares the given secret hash.
	FindBySecretHash(ctx context.Context, secretHash string) ([]models.StoredFinding, error)

	// FindByFilter returns findings matching the given filter criteria.
	FindByFilter(ctx context.Context, filter models.FindingFilter) ([]models.StoredFinding, error)

	// CountFindings returns the total count of findings matching a filter.
	CountFindings(ctx context.Context, filter models.FindingFilter) (int64, error)

	// ── Scan Results ─────────────────────────────────────────────────────

	// SaveScanResult persists a scan result and all its findings atomically.
	SaveScanResult(ctx context.Context, scan *models.StoredScanResult, findings []models.StoredFinding) error

	// GetScanResult retrieves a scan result by its unique ID.
	GetScanResult(ctx context.Context, scanID string) (*models.StoredScanResult, error)

	// ListScanResults returns recent scan results ordered by time (newest first).
	ListScanResults(ctx context.Context, limit, offset int) ([]models.StoredScanResult, error)

	// ── Audit Logs ───────────────────────────────────────────────────────

	// LogEvent records a security-relevant audit event.
	LogEvent(ctx context.Context, log *models.AuditLog) error

	// ListAuditLogs returns audit logs filtered by time range and optional event type.
	ListAuditLogs(ctx context.Context, since, until time.Time, eventType string, limit, offset int) ([]models.AuditLog, error)

	// ── Analytics / Trends ───────────────────────────────────────────────

	// GetRiskTrends returns aggregated counts bucketed by a time interval.
	GetRiskTrends(ctx context.Context, since, until time.Time, interval string) ([]models.RiskTrend, error)

	// GetCategoryBreakdown returns finding counts grouped by category.
	GetCategoryBreakdown(ctx context.Context, since, until time.Time) ([]models.CategoryBreakdown, error)

	// GetTopSecretTypes returns the most frequently detected secret types.
	GetTopSecretTypes(ctx context.Context, limit int, since, until time.Time) ([]SecretTypeCount, error)

	// ── Lifecycle ────────────────────────────────────────────────────────

	// HealthCheck verifies that the database connection is alive.
	HealthCheck(ctx context.Context) error

	// Close releases all resources held by the repository (e.g. connection pool).
	Close() error
}

// SecretTypeCount pairs a secret type with its occurrence count.
type SecretTypeCount struct {
	SecretType string
	Count      int64
}

// Compile-time check: every Repository must also satisfy io.Closer.
var _ io.Closer = (Repository)(nil)
