// Package storage — PostgreSQL + TimescaleDB implementation of the Repository interface.
//
// Uses pgx/v5 for connection pooling, prepared statements, and native PostgreSQL
// types. All write operations that span multiple rows use explicit transactions.
//
// TimescaleDB hypertables partition the findings table by scanned_at for
// efficient time-series queries (risk trends, audit windows).
package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/svemulapati/CredVigil/pkg/models"
)

// ──────────────────────────────────────────────────────────────────────────────
// PostgresRepository implements Repository using pgx connection pool.
// ──────────────────────────────────────────────────────────────────────────────

type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository creates a new PostgreSQL repository from a connection string.
// The connection string should be a PostgreSQL DSN:
//
//	postgres://user:pass@host:port/dbname?sslmode=disable
//
// The pool is configured with sensible defaults for a scanning workload.
func NewPostgresRepository(ctx context.Context, connString string) (*PostgresRepository, error) {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("storage: invalid connection string: %w", err)
	}

	// Pool tuning for scan workloads (bursty writes, rare reads)
	config.MaxConns = 10
	config.MinConns = 2
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to create connection pool: %w", err)
	}

	// Verify connectivity
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("storage: database ping failed: %w", err)
	}

	return &PostgresRepository{pool: pool}, nil
}

// Close releases all connections in the pool.
func (r *PostgresRepository) Close() error {
	r.pool.Close()
	return nil
}

// HealthCheck verifies the database connection is alive.
func (r *PostgresRepository) HealthCheck(ctx context.Context) error {
	return r.pool.Ping(ctx)
}

// ──────────────────────────────────────────────────────────────────────────────
// Findings
// ──────────────────────────────────────────────────────────────────────────────

const insertFindingSQL = `
INSERT INTO findings (
    id, scan_id, rule_id, secret_type, description, severity, confidence,
    secret_hash, fingerprint, redacted_match, entropy, bpe_efficiency,
    bpe_tokens, file_type, environment, category, source_type,
    source_location, source_line, commit_hash, author, branch, scanned_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12,
    $13, $14, $15, $16, $17,
    $18, $19, $20, $21, $22, $23
)
ON CONFLICT (id) DO NOTHING`

// SaveFinding persists a single finding.
func (r *PostgresRepository) SaveFinding(ctx context.Context, f *models.StoredFinding) error {
	_, err := r.pool.Exec(ctx, insertFindingSQL,
		f.ID, f.ScanID, f.RuleID, f.SecretType, f.Description, f.Severity,
		f.Confidence, f.SecretHash, f.Fingerprint, f.RedactedMatch, f.Entropy,
		f.BPEEfficiency, f.BPETokens, f.FileType, f.Environment, f.Category,
		f.SourceType, f.SourceLocation, f.SourceLine, f.CommitHash, f.Author,
		f.Branch, f.ScannedAt,
	)
	if err != nil {
		return fmt.Errorf("storage: save finding: %w", err)
	}
	return nil
}

// SaveFindings persists multiple findings in a single transaction using COPY.
func (r *PostgresRepository) SaveFindings(ctx context.Context, findings []models.StoredFinding) error {
	if len(findings) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for i := range findings {
		f := &findings[i]
		_, err := tx.Exec(ctx, insertFindingSQL,
			f.ID, f.ScanID, f.RuleID, f.SecretType, f.Description, f.Severity,
			f.Confidence, f.SecretHash, f.Fingerprint, f.RedactedMatch, f.Entropy,
			f.BPEEfficiency, f.BPETokens, f.FileType, f.Environment, f.Category,
			f.SourceType, f.SourceLocation, f.SourceLine, f.CommitHash, f.Author,
			f.Branch, f.ScannedAt,
		)
		if err != nil {
			return fmt.Errorf("storage: save finding %s: %w", f.ID, err)
		}
	}

	return tx.Commit(ctx)
}

// GetFindingByID retrieves a single finding by ID.
func (r *PostgresRepository) GetFindingByID(ctx context.Context, id string) (*models.StoredFinding, error) {
	f := &models.StoredFinding{}
	err := r.pool.QueryRow(ctx, `SELECT * FROM findings WHERE id = $1`, id).Scan(
		&f.ID, &f.ScanID, &f.RuleID, &f.SecretType, &f.Description, &f.Severity,
		&f.Confidence, &f.SecretHash, &f.Fingerprint, &f.RedactedMatch, &f.Entropy,
		&f.BPEEfficiency, &f.BPETokens, &f.FileType, &f.Environment, &f.Category,
		&f.SourceType, &f.SourceLocation, &f.SourceLine, &f.CommitHash, &f.Author,
		&f.Branch, &f.ScannedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: get finding %s: %w", id, err)
	}
	return f, nil
}

// FindByFingerprint returns all findings matching a fingerprint.
func (r *PostgresRepository) FindByFingerprint(ctx context.Context, fingerprint string) ([]models.StoredFinding, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT * FROM findings WHERE fingerprint = $1 ORDER BY scanned_at DESC`,
		fingerprint,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: find by fingerprint: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

// FindBySecretHash returns all findings matching a secret hash.
func (r *PostgresRepository) FindBySecretHash(ctx context.Context, secretHash string) ([]models.StoredFinding, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT * FROM findings WHERE secret_hash = $1 ORDER BY scanned_at DESC`,
		secretHash,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: find by secret hash: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

// FindByFilter returns findings matching the given filter criteria.
func (r *PostgresRepository) FindByFilter(ctx context.Context, filter models.FindingFilter) ([]models.StoredFinding, error) {
	query, args := buildFilterQuery("SELECT * FROM findings", filter)
	query += " ORDER BY scanned_at DESC"

	if filter.Limit > 0 {
		args = append(args, filter.Limit)
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	if filter.Offset > 0 {
		args = append(args, filter.Offset)
		query += fmt.Sprintf(" OFFSET $%d", len(args))
	}

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: find by filter: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

// CountFindings returns the total number of findings matching a filter.
func (r *PostgresRepository) CountFindings(ctx context.Context, filter models.FindingFilter) (int64, error) {
	query, args := buildFilterQuery("SELECT COUNT(*) FROM findings", filter)
	var count int64
	err := r.pool.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("storage: count findings: %w", err)
	}
	return count, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Scan Results
// ──────────────────────────────────────────────────────────────────────────────

const insertScanResultSQL = `
INSERT INTO scan_results (
    id, scanner_version, scan_type, scan_target, started_at, finished_at,
    duration_ms, total_findings, severity_counts, files_scanned, rule_count,
    config_hash, machine_name, exit_code, is_ci, ci_job_ref
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11,
    $12, $13, $14, $15, $16
)
ON CONFLICT (id) DO NOTHING`

// SaveScanResult persists a scan result and all its findings atomically.
func (r *PostgresRepository) SaveScanResult(ctx context.Context, scan *models.StoredScanResult, findings []models.StoredFinding) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Insert scan result
	sevJSON, err := scan.SeverityCounts.Value()
	if err != nil {
		return fmt.Errorf("storage: marshal severity counts: %w", err)
	}

	_, err = tx.Exec(ctx, insertScanResultSQL,
		scan.ID, scan.ScannerVersion, scan.ScanType, scan.ScanTarget,
		scan.StartedAt, scan.FinishedAt, scan.DurationMs, scan.TotalFindings,
		sevJSON, scan.FilesScanned, scan.RuleCount, scan.ConfigHash,
		scan.MachineName, scan.ExitCode, scan.IsCI, scan.CIJobRef,
	)
	if err != nil {
		return fmt.Errorf("storage: save scan result: %w", err)
	}

	// Insert all findings in the same transaction
	for i := range findings {
		f := &findings[i]
		_, err := tx.Exec(ctx, insertFindingSQL,
			f.ID, f.ScanID, f.RuleID, f.SecretType, f.Description, f.Severity,
			f.Confidence, f.SecretHash, f.Fingerprint, f.RedactedMatch, f.Entropy,
			f.BPEEfficiency, f.BPETokens, f.FileType, f.Environment, f.Category,
			f.SourceType, f.SourceLocation, f.SourceLine, f.CommitHash, f.Author,
			f.Branch, f.ScannedAt,
		)
		if err != nil {
			return fmt.Errorf("storage: save finding %s in scan: %w", f.ID, err)
		}
	}

	return tx.Commit(ctx)
}

// GetScanResult retrieves a scan result by ID.
func (r *PostgresRepository) GetScanResult(ctx context.Context, scanID string) (*models.StoredScanResult, error) {
	s := &models.StoredScanResult{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, scanner_version, scan_type, scan_target, started_at, finished_at,
		        duration_ms, total_findings, severity_counts, files_scanned, rule_count,
		        config_hash, machine_name, exit_code, is_ci, ci_job_ref
		 FROM scan_results WHERE id = $1`, scanID,
	).Scan(
		&s.ID, &s.ScannerVersion, &s.ScanType, &s.ScanTarget, &s.StartedAt,
		&s.FinishedAt, &s.DurationMs, &s.TotalFindings, &s.SeverityCounts,
		&s.FilesScanned, &s.RuleCount, &s.ConfigHash, &s.MachineName,
		&s.ExitCode, &s.IsCI, &s.CIJobRef,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: get scan result %s: %w", scanID, err)
	}
	return s, nil
}

// ListScanResults returns recent scan results ordered by started_at DESC.
func (r *PostgresRepository) ListScanResults(ctx context.Context, limit, offset int) ([]models.StoredScanResult, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, scanner_version, scan_type, scan_target, started_at, finished_at,
		        duration_ms, total_findings, severity_counts, files_scanned, rule_count,
		        config_hash, machine_name, exit_code, is_ci, ci_job_ref
		 FROM scan_results ORDER BY started_at DESC LIMIT $1 OFFSET $2`, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: list scan results: %w", err)
	}
	defer rows.Close()

	var results []models.StoredScanResult
	for rows.Next() {
		var s models.StoredScanResult
		if err := rows.Scan(
			&s.ID, &s.ScannerVersion, &s.ScanType, &s.ScanTarget, &s.StartedAt,
			&s.FinishedAt, &s.DurationMs, &s.TotalFindings, &s.SeverityCounts,
			&s.FilesScanned, &s.RuleCount, &s.ConfigHash, &s.MachineName,
			&s.ExitCode, &s.IsCI, &s.CIJobRef,
		); err != nil {
			return nil, fmt.Errorf("storage: scan row: %w", err)
		}
		results = append(results, s)
	}
	return results, rows.Err()
}

// ──────────────────────────────────────────────────────────────────────────────
// Audit Logs
// ──────────────────────────────────────────────────────────────────────────────

// LogEvent records a security-relevant audit event.
func (r *PostgresRepository) LogEvent(ctx context.Context, log *models.AuditLog) error {
	detailsJSON, err := log.Details.Value()
	if err != nil {
		return fmt.Errorf("storage: marshal audit details: %w", err)
	}

	_, err = r.pool.Exec(ctx,
		`INSERT INTO audit_logs (timestamp, event_type, actor, scan_id, finding_id, details, severity, source_ip)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		log.Timestamp, log.EventType, log.Actor, log.ScanID, log.FindingID,
		detailsJSON, log.Severity, log.SourceIP,
	)
	if err != nil {
		return fmt.Errorf("storage: log event: %w", err)
	}
	return nil
}

// ListAuditLogs returns audit logs filtered by time range and optional event type.
func (r *PostgresRepository) ListAuditLogs(ctx context.Context, since, until time.Time, eventType string, limit, offset int) ([]models.AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}

	var args []interface{}
	query := `SELECT id, timestamp, event_type, actor, scan_id, finding_id, details, severity, source_ip
	          FROM audit_logs WHERE timestamp >= $1 AND timestamp <= $2`
	args = append(args, since, until)

	if eventType != "" {
		args = append(args, eventType)
		query += fmt.Sprintf(" AND event_type = $%d", len(args))
	}

	args = append(args, limit, offset)
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list audit logs: %w", err)
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		if err := rows.Scan(
			&l.ID, &l.Timestamp, &l.EventType, &l.Actor, &l.ScanID,
			&l.FindingID, &l.Details, &l.Severity, &l.SourceIP,
		); err != nil {
			return nil, fmt.Errorf("storage: scan audit row: %w", err)
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

// ──────────────────────────────────────────────────────────────────────────────
// Analytics / Trends (TimescaleDB optimized)
// ──────────────────────────────────────────────────────────────────────────────

// GetRiskTrends returns aggregated finding counts bucketed by time interval.
// Uses TimescaleDB's time_bucket function for efficient time-series aggregation.
func (r *PostgresRepository) GetRiskTrends(ctx context.Context, since, until time.Time, interval string) ([]models.RiskTrend, error) {
	// Validate interval to prevent SQL injection
	validIntervals := map[string]bool{
		"1 hour": true, "1 day": true, "1 week": true, "1 month": true,
		"6 hours": true, "12 hours": true,
	}
	if !validIntervals[interval] {
		return nil, fmt.Errorf("storage: invalid interval %q (valid: 1 hour, 6 hours, 12 hours, 1 day, 1 week, 1 month)", interval)
	}

	query := fmt.Sprintf(`
		SELECT
			time_bucket('%s', scanned_at) AS time_bucket,
			COUNT(*)                       AS finding_count,
			COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical_count,
			COUNT(*) FILTER (WHERE severity = 'HIGH')     AS high_count,
			COUNT(*) FILTER (WHERE severity = 'MEDIUM')   AS medium_count,
			COUNT(*) FILTER (WHERE severity = 'LOW')      AS low_count,
			COUNT(*) FILTER (WHERE severity = 'INFO')     AS info_count,
			COALESCE(AVG(confidence), 0)                  AS avg_confidence,
			COALESCE(AVG(entropy), 0)                     AS avg_entropy,
			COUNT(DISTINCT secret_type)                   AS unique_types
		FROM findings
		WHERE scanned_at >= $1 AND scanned_at <= $2
		GROUP BY time_bucket
		ORDER BY time_bucket ASC
	`, interval)

	rows, err := r.pool.Query(ctx, query, since, until)
	if err != nil {
		return nil, fmt.Errorf("storage: risk trends: %w", err)
	}
	defer rows.Close()

	var trends []models.RiskTrend
	for rows.Next() {
		var t models.RiskTrend
		if err := rows.Scan(
			&t.TimeBucket, &t.FindingCount, &t.CriticalCount, &t.HighCount,
			&t.MediumCount, &t.LowCount, &t.InfoCount, &t.AvgConfidence,
			&t.AvgEntropy, &t.UniqueTypes,
		); err != nil {
			return nil, fmt.Errorf("storage: scan trend row: %w", err)
		}
		trends = append(trends, t)
	}
	return trends, rows.Err()
}

// GetCategoryBreakdown returns finding counts grouped by category.
func (r *PostgresRepository) GetCategoryBreakdown(ctx context.Context, since, until time.Time) ([]models.CategoryBreakdown, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT
			COALESCE(category, 'unknown') AS category,
			COUNT(*)                       AS finding_count,
			COALESCE(AVG(confidence), 0)   AS avg_confidence,
			MAX(severity)                  AS max_severity
		FROM findings
		WHERE scanned_at >= $1 AND scanned_at <= $2
		GROUP BY category
		ORDER BY finding_count DESC
	`, since, until)
	if err != nil {
		return nil, fmt.Errorf("storage: category breakdown: %w", err)
	}
	defer rows.Close()

	var breakdown []models.CategoryBreakdown
	for rows.Next() {
		var cb models.CategoryBreakdown
		if err := rows.Scan(&cb.Category, &cb.FindingCount, &cb.AvgConfidence, &cb.MaxSeverity); err != nil {
			return nil, fmt.Errorf("storage: scan category row: %w", err)
		}
		breakdown = append(breakdown, cb)
	}
	return breakdown, rows.Err()
}

// GetTopSecretTypes returns the most frequently detected secret types.
func (r *PostgresRepository) GetTopSecretTypes(ctx context.Context, limit int, since, until time.Time) ([]SecretTypeCount, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := r.pool.Query(ctx, `
		SELECT secret_type, COUNT(*) AS count
		FROM findings
		WHERE scanned_at >= $1 AND scanned_at <= $2
		GROUP BY secret_type
		ORDER BY count DESC
		LIMIT $3
	`, since, until, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: top secret types: %w", err)
	}
	defer rows.Close()

	var types []SecretTypeCount
	for rows.Next() {
		var t SecretTypeCount
		if err := rows.Scan(&t.SecretType, &t.Count); err != nil {
			return nil, fmt.Errorf("storage: scan type row: %w", err)
		}
		types = append(types, t)
	}
	return types, rows.Err()
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

// scanFindings reads all rows from a query into a slice of StoredFinding.
func scanFindings(rows pgx.Rows) ([]models.StoredFinding, error) {
	var findings []models.StoredFinding
	for rows.Next() {
		var f models.StoredFinding
		if err := rows.Scan(
			&f.ID, &f.ScanID, &f.RuleID, &f.SecretType, &f.Description, &f.Severity,
			&f.Confidence, &f.SecretHash, &f.Fingerprint, &f.RedactedMatch, &f.Entropy,
			&f.BPEEfficiency, &f.BPETokens, &f.FileType, &f.Environment, &f.Category,
			&f.SourceType, &f.SourceLocation, &f.SourceLine, &f.CommitHash, &f.Author,
			&f.Branch, &f.ScannedAt,
		); err != nil {
			return nil, fmt.Errorf("storage: scan finding row: %w", err)
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// buildFilterQuery appends WHERE clauses to a base query from a FindingFilter.
func buildFilterQuery(base string, filter models.FindingFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if filter.ScanID != "" {
		args = append(args, filter.ScanID)
		conditions = append(conditions, fmt.Sprintf("scan_id = $%d", len(args)))
	}
	if filter.MinSeverity != nil {
		args = append(args, filter.MinSeverity.String())
		// Use severity ordering: compare as text with a CASE expression
		conditions = append(conditions, fmt.Sprintf(
			`CASE severity
				WHEN 'CRITICAL' THEN 5
				WHEN 'HIGH' THEN 4
				WHEN 'MEDIUM' THEN 3
				WHEN 'LOW' THEN 2
				WHEN 'INFO' THEN 1
				ELSE 0
			END >= CASE $%d
				WHEN 'CRITICAL' THEN 5
				WHEN 'HIGH' THEN 4
				WHEN 'MEDIUM' THEN 3
				WHEN 'LOW' THEN 2
				WHEN 'INFO' THEN 1
				ELSE 0
			END`, len(args)))
	}
	if filter.MinConfidence != nil {
		args = append(args, *filter.MinConfidence)
		conditions = append(conditions, fmt.Sprintf("confidence >= $%d", len(args)))
	}
	if filter.SecretType != "" {
		args = append(args, filter.SecretType)
		conditions = append(conditions, fmt.Sprintf("secret_type = $%d", len(args)))
	}
	if filter.Category != "" {
		args = append(args, filter.Category)
		conditions = append(conditions, fmt.Sprintf("category = $%d", len(args)))
	}
	if filter.RuleID != "" {
		args = append(args, filter.RuleID)
		conditions = append(conditions, fmt.Sprintf("rule_id = $%d", len(args)))
	}
	if filter.Fingerprint != "" {
		args = append(args, filter.Fingerprint)
		conditions = append(conditions, fmt.Sprintf("fingerprint = $%d", len(args)))
	}
	if filter.SecretHash != "" {
		args = append(args, filter.SecretHash)
		conditions = append(conditions, fmt.Sprintf("secret_hash = $%d", len(args)))
	}
	if filter.Since != nil {
		args = append(args, *filter.Since)
		conditions = append(conditions, fmt.Sprintf("scanned_at >= $%d", len(args)))
	}
	if filter.Until != nil {
		args = append(args, *filter.Until)
		conditions = append(conditions, fmt.Sprintf("scanned_at <= $%d", len(args)))
	}

	query := base
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	return query, args
}

// Compile-time check that PostgresRepository implements Repository.
var _ Repository = (*PostgresRepository)(nil)
