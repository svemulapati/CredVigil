// Package models — database models for the storage layer.
// These types map directly to PostgreSQL + TimescaleDB tables.
package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// StoredFinding is the persistent, database-friendly representation of a Finding.
// It flattens nested structs (Source) into top-level columns for efficient
// querying and indexing in PostgreSQL / TimescaleDB.
// ──────────────────────────────────────────────────────────────────────────────

type StoredFinding struct {
	// Primary key (UUID v4, set by the application)
	ID string `json:"id" db:"id"`

	// Foreign key to the scan that produced this finding
	ScanID string `json:"scan_id" db:"scan_id"`

	// Detection rule that fired
	RuleID string `json:"rule_id" db:"rule_id"`

	// What kind of secret (aws-access-key-id, stripe-api-key, etc.)
	SecretType string `json:"secret_type" db:"secret_type"`

	// Human-readable description
	Description string `json:"description" db:"description"`

	// Severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)
	Severity string `json:"severity" db:"severity"`

	// Confidence score 0.0 – 1.0
	Confidence float64 `json:"confidence" db:"confidence"`

	// SHA-256 hash of the raw secret (zero-trust: raw never stored)
	SecretHash string `json:"secret_hash" db:"secret_hash"`

	// Stable cross-scan fingerprint for deduplication
	Fingerprint string `json:"fingerprint" db:"fingerprint"`

	// Redacted/masked version safe for display
	RedactedMatch string `json:"redacted_match" db:"redacted_match"`

	// Shannon entropy of the matched string
	Entropy float64 `json:"entropy" db:"entropy"`

	// BPE token efficiency (nullable — only set when BPE is enabled)
	BPEEfficiency *float64 `json:"bpe_efficiency,omitempty" db:"bpe_efficiency"`

	// BPE token count (nullable)
	BPETokens *int `json:"bpe_tokens,omitempty" db:"bpe_tokens"`

	// Detected file type / programming language
	FileType string `json:"file_type" db:"file_type"`

	// Detected environment (production, staging, development, ci, unknown)
	Environment string `json:"environment" db:"environment"`

	// Secret category for grouping (cloud, auth, database, etc.)
	Category string `json:"category" db:"category"`

	// ─── Source fields (flattened from Source struct) ───

	// Source type: file, git-commit, stdin, etc.
	SourceType string `json:"source_type" db:"source_type"`

	// File path or resource identifier
	SourceLocation string `json:"source_location" db:"source_location"`

	// Line number (1-based)
	SourceLine int `json:"source_line" db:"source_line"`

	// Git commit hash (if from git scan)
	CommitHash string `json:"commit_hash,omitempty" db:"commit_hash"`

	// Git author (if from git scan)
	Author string `json:"author,omitempty" db:"author"`

	// Git branch (if from git scan)
	Branch string `json:"branch,omitempty" db:"branch"`

	// Timestamp when this finding was detected (TimescaleDB partition key)
	ScannedAt time.Time `json:"scanned_at" db:"scanned_at"`
}

// ToStoredFinding converts an in-memory Finding to a StoredFinding.
// Requires scanID and scannedAt to be provided by the caller.
func ToStoredFinding(f *Finding, scanID string, scannedAt time.Time) StoredFinding {
	sf := StoredFinding{
		ID:             f.ID,
		ScanID:         scanID,
		RuleID:         f.RuleID,
		SecretType:     string(f.SecretType),
		Description:    f.Description,
		Severity:       f.Severity.String(),
		Confidence:     f.Confidence,
		SecretHash:     f.SecretHash,
		Fingerprint:    f.Fingerprint,
		RedactedMatch:  f.RedactedMatch,
		Entropy:        f.Entropy,
		FileType:       f.FileType,
		Environment:    f.Environment,
		Category:       f.Category,
		SourceType:     f.Source.Type,
		SourceLocation: f.Source.Location,
		SourceLine:     f.Source.Line,
		CommitHash:     f.Source.CommitHash,
		Author:         f.Source.Author,
		Branch:         f.Source.Branch,
		ScannedAt:      scannedAt,
	}

	// Extract BPE metadata if present
	if f.Metadata != nil {
		if eff, ok := f.Metadata["bpe_efficiency"]; ok {
			var v float64
			if _, err := fmt.Sscanf(eff, "%f", &v); err == nil {
				sf.BPEEfficiency = &v
			}
		}
		if tok, ok := f.Metadata["bpe_tokens"]; ok {
			var v int
			if _, err := fmt.Sscanf(tok, "%d", &v); err == nil {
				sf.BPETokens = &v
			}
		}
	}

	return sf
}

// ──────────────────────────────────────────────────────────────────────────────
// StoredScanResult holds scan-level metadata persisted to the database.
// One row per scan invocation (CLI run, CI/CD job, pre-commit).
// ──────────────────────────────────────────────────────────────────────────────

type StoredScanResult struct {
	// Primary key (UUID v4)
	ID string `json:"id" db:"id"`

	// CredVigil version that performed this scan
	ScannerVersion string `json:"scanner_version" db:"scanner_version"`

	// What was scanned: file, directory, stdin, git
	ScanType string `json:"scan_type" db:"scan_type"`

	// Root path or identifier being scanned
	ScanTarget string `json:"scan_target" db:"scan_target"`

	// When the scan started
	StartedAt time.Time `json:"started_at" db:"started_at"`

	// When the scan finished
	FinishedAt time.Time `json:"finished_at" db:"finished_at"`

	// How long the scan took in milliseconds
	DurationMs int64 `json:"duration_ms" db:"duration_ms"`

	// Total number of findings
	TotalFindings int `json:"total_findings" db:"total_findings"`

	// Counts by severity as JSON: {"CRITICAL":1,"HIGH":3}
	SeverityCounts JSONMap `json:"severity_counts" db:"severity_counts"`

	// Total files scanned
	FilesScanned int `json:"files_scanned" db:"files_scanned"`

	// Number of rules loaded
	RuleCount int `json:"rule_count" db:"rule_count"`

	// SHA-256 hash of the effective scan configuration
	ConfigHash string `json:"config_hash,omitempty" db:"config_hash"`

	// Hostname of the machine that ran the scan
	MachineName string `json:"machine_name,omitempty" db:"machine_name"`

	// Scan exit code (0=clean, 1=findings, 2=error)
	ExitCode int `json:"exit_code" db:"exit_code"`

	// Whether this was a CI/CD run
	IsCI bool `json:"is_ci" db:"is_ci"`

	// CI/CD job reference (e.g. GitHub Actions run URL)
	CIJobRef string `json:"ci_job_ref,omitempty" db:"ci_job_ref"`
}

// ──────────────────────────────────────────────────────────────────────────────
// AuditLog records security-relevant events for compliance and forensics.
// Examples: "scan completed", "secret rotated", "finding suppressed".
// ──────────────────────────────────────────────────────────────────────────────

type AuditLog struct {
	// Primary key (auto-increment bigint)
	ID int64 `json:"id" db:"id"`

	// When this event occurred
	Timestamp time.Time `json:"timestamp" db:"timestamp"`

	// Event type: scan.completed, finding.suppressed, secret.rotated, etc.
	EventType string `json:"event_type" db:"event_type"`

	// Who or what triggered the event (username, CI bot, system)
	Actor string `json:"actor" db:"actor"`

	// Optional: related scan ID
	ScanID *string `json:"scan_id,omitempty" db:"scan_id"`

	// Optional: related finding ID
	FindingID *string `json:"finding_id,omitempty" db:"finding_id"`

	// Structured event details as JSON
	Details JSONMap `json:"details" db:"details"`

	// Severity of the audit event (info, warning, critical)
	Severity string `json:"severity" db:"severity"`

	// Source IP or hostname (for API-triggered events)
	SourceIP string `json:"source_ip,omitempty" db:"source_ip"`
}

// ──────────────────────────────────────────────────────────────────────────────
// JSONMap is a helper type that stores a map[string]interface{} as JSONB
// in PostgreSQL. Implements sql.Scanner and driver.Valuer.
// ──────────────────────────────────────────────────────────────────────────────

type JSONMap map[string]interface{}

// Value converts the map to a JSON byte slice for PostgreSQL JSONB storage.
func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}

// Scan reads a JSON byte slice from PostgreSQL into the map.
func (m *JSONMap) Scan(src interface{}) error {
	if src == nil {
		*m = make(JSONMap)
		return nil
	}
	var data []byte
	switch v := src.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("JSONMap.Scan: unsupported type %T", src)
	}
	return json.Unmarshal(data, m)
}

// ──────────────────────────────────────────────────────────────────────────────
// RiskTrend holds aggregated risk data for trend analysis.
// ──────────────────────────────────────────────────────────────────────────────

type RiskTrend struct {
	// Time bucket (hourly, daily, weekly — depends on query)
	TimeBucket time.Time `json:"time_bucket" db:"time_bucket"`

	// Total findings in this bucket
	FindingCount int `json:"finding_count" db:"finding_count"`

	// Counts by severity
	CriticalCount int `json:"critical_count" db:"critical_count"`
	HighCount     int `json:"high_count" db:"high_count"`
	MediumCount   int `json:"medium_count" db:"medium_count"`
	LowCount      int `json:"low_count" db:"low_count"`
	InfoCount     int `json:"info_count" db:"info_count"`

	// Average confidence for this bucket
	AvgConfidence float64 `json:"avg_confidence" db:"avg_confidence"`

	// Average entropy for this bucket
	AvgEntropy float64 `json:"avg_entropy" db:"avg_entropy"`

	// Number of unique secret types found
	UniqueTypes int `json:"unique_types" db:"unique_types"`
}

// ──────────────────────────────────────────────────────────────────────────────
// CategoryBreakdown holds per-category aggregation for dashboards.
// ──────────────────────────────────────────────────────────────────────────────

type CategoryBreakdown struct {
	Category      string  `json:"category" db:"category"`
	FindingCount  int     `json:"finding_count" db:"finding_count"`
	AvgConfidence float64 `json:"avg_confidence" db:"avg_confidence"`
	MaxSeverity   string  `json:"max_severity" db:"max_severity"`
}

// ──────────────────────────────────────────────────────────────────────────────
// FindingFilter specifies query predicates for finding lookups.
// ──────────────────────────────────────────────────────────────────────────────

type FindingFilter struct {
	// Filter by scan ID
	ScanID string

	// Filter by severity (minimum)
	MinSeverity *Severity

	// Filter by confidence (minimum)
	MinConfidence *float64

	// Filter by secret type
	SecretType string

	// Filter by category
	Category string

	// Filter by rule ID
	RuleID string

	// Filter by fingerprint (exact match)
	Fingerprint string

	// Filter by secret hash (exact match)
	SecretHash string

	// Time range
	Since *time.Time
	Until *time.Time

	// Pagination
	Limit  int
	Offset int
}
