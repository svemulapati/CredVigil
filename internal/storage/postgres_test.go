package storage

import (
	"strings"
	"testing"
	"time"

	"github.com/svemulapati/CredVigil/pkg/models"
)

func TestBuildFilterQuery_EmptyFilter(t *testing.T) {
	q, args := buildFilterQuery("SELECT * FROM findings", models.FindingFilter{})
	if q != "SELECT * FROM findings" {
		t.Errorf("query = %q, want no WHERE clause", q)
	}
	if len(args) != 0 {
		t.Errorf("args = %v, want empty", args)
	}
}

func TestBuildFilterQuery_ScanID(t *testing.T) {
	q, args := buildFilterQuery("SELECT * FROM findings", models.FindingFilter{
		ScanID: "scan-123",
	})
	if !strings.Contains(q, "scan_id = $1") {
		t.Errorf("query %q missing scan_id clause", q)
	}
	if len(args) != 1 || args[0] != "scan-123" {
		t.Errorf("args = %v, want [scan-123]", args)
	}
}

func TestBuildFilterQuery_SecretType(t *testing.T) {
	q, args := buildFilterQuery("SELECT * FROM findings", models.FindingFilter{
		SecretType: "aws-access-key-id",
	})
	if !strings.Contains(q, "secret_type = $1") {
		t.Errorf("query %q missing secret_type clause", q)
	}
	if args[0] != "aws-access-key-id" {
		t.Errorf("args[0] = %v", args[0])
	}
}

func TestBuildFilterQuery_Category(t *testing.T) {
	q, args := buildFilterQuery("SELECT * FROM findings", models.FindingFilter{
		Category: "cloud",
	})
	if !strings.Contains(q, "category = $1") {
		t.Errorf("query %q missing category clause", q)
	}
	if args[0] != "cloud" {
		t.Errorf("args[0] = %v", args[0])
	}
}

func TestBuildFilterQuery_RuleID(t *testing.T) {
	q, args := buildFilterQuery("SELECT * FROM findings", models.FindingFilter{
		RuleID: "rule-42",
	})
	if !strings.Contains(q, "rule_id = $1") {
		t.Errorf("query %q missing rule_id clause", q)
	}
	if args[0] != "rule-42" {
		t.Errorf("args[0] = %v", args[0])
	}
}

func TestBuildFilterQuery_Fingerprint(t *testing.T) {
	q, args := buildFilterQuery("SELECT * FROM findings", models.FindingFilter{
		Fingerprint: "fp-abc",
	})
	if !strings.Contains(q, "fingerprint = $1") {
		t.Errorf("query %q missing fingerprint clause", q)
	}
	if args[0] != "fp-abc" {
		t.Errorf("args[0] = %v", args[0])
	}
}

func TestBuildFilterQuery_SecretHash(t *testing.T) {
	q, args := buildFilterQuery("SELECT * FROM findings", models.FindingFilter{
		SecretHash: "hash-xyz",
	})
	if !strings.Contains(q, "secret_hash = $1") {
		t.Errorf("query %q missing secret_hash clause", q)
	}
	if args[0] != "hash-xyz" {
		t.Errorf("args[0] = %v", args[0])
	}
}

func TestBuildFilterQuery_MinConfidence(t *testing.T) {
	conf := 0.8
	q, args := buildFilterQuery("SELECT * FROM findings", models.FindingFilter{
		MinConfidence: &conf,
	})
	if !strings.Contains(q, "confidence >= $1") {
		t.Errorf("query %q missing confidence clause", q)
	}
	if args[0].(float64) != 0.8 {
		t.Errorf("args[0] = %v, want 0.8", args[0])
	}
}

func TestBuildFilterQuery_MinSeverity(t *testing.T) {
	sev := models.SeverityHigh
	q, args := buildFilterQuery("SELECT * FROM findings", models.FindingFilter{
		MinSeverity: &sev,
	})
	if !strings.Contains(q, "CASE severity") {
		t.Errorf("query %q missing CASE severity expression", q)
	}
	if args[0] != "HIGH" {
		t.Errorf("args[0] = %v, want HIGH", args[0])
	}
}

func TestBuildFilterQuery_TimeRange(t *testing.T) {
	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2025, 6, 30, 0, 0, 0, 0, time.UTC)
	q, args := buildFilterQuery("SELECT * FROM findings", models.FindingFilter{
		Since: &since,
		Until: &until,
	})
	if !strings.Contains(q, "scanned_at >= $1") {
		t.Errorf("query %q missing since clause", q)
	}
	if !strings.Contains(q, "scanned_at <= $2") {
		t.Errorf("query %q missing until clause", q)
	}
	if len(args) != 2 {
		t.Fatalf("len(args) = %d, want 2", len(args))
	}
}

func TestBuildFilterQuery_MultipleFilters(t *testing.T) {
	conf := 0.7
	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	q, args := buildFilterQuery("SELECT * FROM findings", models.FindingFilter{
		ScanID:        "scan-999",
		SecretType:    "stripe-api-key",
		MinConfidence: &conf,
		Category:      "payment",
		Since:         &since,
	})
	if !strings.Contains(q, "WHERE") {
		t.Error("missing WHERE")
	}
	if !strings.Contains(q, " AND ") {
		t.Error("missing AND")
	}
	if len(args) != 5 {
		t.Fatalf("len(args) = %d, want 5", len(args))
	}
}

func TestBuildFilterQuery_CountBase(t *testing.T) {
	q, _ := buildFilterQuery("SELECT COUNT(*) FROM findings", models.FindingFilter{
		ScanID: "scan-1",
	})
	if !strings.Contains(q, "SELECT COUNT(*)") {
		t.Error("missing COUNT base")
	}
	if !strings.Contains(q, "scan_id") {
		t.Error("missing scan_id clause")
	}
}

func TestBuildFilterQuery_ParameterIndexing(t *testing.T) {
	conf := 0.5
	_, args := buildFilterQuery("SELECT * FROM findings", models.FindingFilter{
		ScanID:        "a",
		MinConfidence: &conf,
		SecretType:    "b",
		Category:      "c",
		RuleID:        "d",
		Fingerprint:   "e",
		SecretHash:    "f",
	})
	if len(args) != 7 {
		t.Fatalf("len(args) = %d, want 7", len(args))
	}
}

func TestSecretTypeCount_ZeroValue(t *testing.T) {
	var stc SecretTypeCount
	if stc.SecretType != "" {
		t.Error("zero SecretType should be empty string")
	}
	if stc.Count != 0 {
		t.Error("zero Count should be 0")
	}
}

func TestPostgresRepository_ImplementsRepository(t *testing.T) {
	var _ Repository = (*PostgresRepository)(nil)
}
