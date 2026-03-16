package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/credvigil/credvigil/pkg/models"
)

func testFinding(raw string) models.Finding {
	return models.Finding{
		ID:         "test-001",
		RuleID:     "aws-access-key",
		SecretType: models.SecretAWSAccessKey,
		RawMatch:   raw,
		Confidence: 0.95,
		Severity:   models.SeverityHigh,
		Source: models.Source{
			Type:     "file",
			Location: "src/config/database.go",
			Line:     42,
		},
	}
}

func sha256Of(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func TestHashProcessor_Basic(t *testing.T) {
	p := NewHashProcessor()
	f := testFinding("AKIAIOSFODNN7EXAMPLE")
	if err := p.Process(context.Background(), &f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedHash := sha256Of("AKIAIOSFODNN7EXAMPLE")
	if f.SecretHash != expectedHash {
		t.Errorf("SecretHash = %q, want %q", f.SecretHash, expectedHash)
	}
	if f.Metadata["sha256"] != expectedHash {
		t.Errorf("Metadata[sha256] = %q, want %q", f.Metadata["sha256"], expectedHash)
	}
}

func TestHashProcessor_PresetHash(t *testing.T) {
	p := NewHashProcessor()
	f := testFinding("AKIAIOSFODNN7EXAMPLE")
	f.SecretHash = sha256Of("AKIAIOSFODNN7EXAMPLE")
	if err := p.Process(context.Background(), &f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.SecretHash != sha256Of("AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("SecretHash changed unexpectedly")
	}
}

func TestHashProcessor_EmptyRawMatch(t *testing.T) {
	p := NewHashProcessor()
	f := testFinding("")
	if err := p.Process(context.Background(), &f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.SecretHash != "" {
		t.Errorf("SecretHash should be empty for empty RawMatch, got %q", f.SecretHash)
	}
}

func TestHashProcessor_Name(t *testing.T) {
	p := NewHashProcessor()
	if p.Name() != "hash" {
		t.Errorf("Name() = %q, want %q", p.Name(), "hash")
	}
}

func TestRedactProcessor_LongSecret(t *testing.T) {
	p := NewRedactProcessor()
	f := testFinding("AKIAIOSFODNN7EXAMPLE")
	if err := p.Process(context.Background(), &f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "AKIA****MPLE"
	if f.RedactedMatch != want {
		t.Errorf("RedactedMatch = %q, want %q", f.RedactedMatch, want)
	}
}

func TestRedactProcessor_MediumSecret(t *testing.T) {
	p := NewRedactProcessor()
	f := testFinding("Secret!")
	if err := p.Process(context.Background(), &f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "Se****"
	if f.RedactedMatch != want {
		t.Errorf("RedactedMatch = %q, want %q", f.RedactedMatch, want)
	}
}

func TestRedactProcessor_ShortSecret(t *testing.T) {
	p := NewRedactProcessor()
	f := testFinding("pass")
	if err := p.Process(context.Background(), &f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.RedactedMatch != "****" {
		t.Errorf("RedactedMatch = %q, want %q", f.RedactedMatch, "****")
	}
}

func TestRedactProcessor_EmptyRawMatch(t *testing.T) {
	p := NewRedactProcessor()
	f := testFinding("")
	if err := p.Process(context.Background(), &f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.RedactedMatch != "****" {
		t.Errorf("RedactedMatch = %q, want %q", f.RedactedMatch, "****")
	}
}

func TestRedactProcessor_PresetRedaction(t *testing.T) {
	p := NewRedactProcessor()
	f := testFinding("AKIAIOSFODNN7EXAMPLE")
	f.RedactedMatch = "already_redacted"
	if err := p.Process(context.Background(), &f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.RedactedMatch != "already_redacted" {
		t.Errorf("RedactedMatch changed: %q", f.RedactedMatch)
	}
}

func TestRedactProcessor_Name(t *testing.T) {
	p := NewRedactProcessor()
	if p.Name() != "redact" {
		t.Errorf("Name() = %q, want %q", p.Name(), "redact")
	}
}

func TestEnrichProcessor_FileType(t *testing.T) {
	p := NewEnrichProcessor()
	cases := []struct {
		location string
		want     string
	}{
		{"src/config.go", "go"},
		{"app/main.py", "python"},
		{"lib/utils.js", "javascript"},
		{"app.ts", "typescript"},
		{"Dockerfile", "dockerfile"},
		{".env", "env"},
		{"docker-compose.yml", "yaml"},
		{"config.json", "json"},
		{"unknown.xyz", "unknown"},
	}
	for _, tc := range cases {
		f := testFinding("SECRET")
		f.Source.Location = tc.location
		if err := p.Process(context.Background(), &f, nil); err != nil {
			t.Fatalf("unexpected error for %s: %v", tc.location, err)
		}
		if f.FileType != tc.want {
			t.Errorf("FileType for %q = %q, want %q", tc.location, f.FileType, tc.want)
		}
	}
}

func TestEnrichProcessor_Environment(t *testing.T) {
	p := NewEnrichProcessor()
	cases := []struct {
		location string
		want     string
	}{
		{"config/prod/database.yml", "production"},
		{"deploy/production/secrets.env", "production"},
		{".env.production", "production"},
		{"config/staging/app.yml", "staging"},
		{".env.development", "development"},
		{"config/dev/local.yml", "development"},
		{".github/workflows/ci.yml", "ci"},
		{"test/fixtures/secrets.txt", "test"},
		{"src/app.go", "unknown"},
	}
	for _, tc := range cases {
		f := testFinding("SECRET")
		f.Source.Location = tc.location
		if err := p.Process(context.Background(), &f, nil); err != nil {
			t.Fatalf("unexpected error for %s: %v", tc.location, err)
		}
		if f.Environment != tc.want {
			t.Errorf("Environment for %q = %q, want %q", tc.location, f.Environment, tc.want)
		}
	}
}

func TestEnrichProcessor_Category(t *testing.T) {
	p := NewEnrichProcessor()
	cases := []struct {
		secretType models.SecretType
		want       string
	}{
		{models.SecretAWSAccessKey, "cloud"},
		{models.SecretGitHubToken, "scm"},
		{models.SecretPostgresURI, "database"},
		{models.SecretStripeKey, "payment"},
		{models.SecretOpenAIKey, "ai-ml"},
		{models.SecretJWT, "generic"},
		{models.SecretPrivateKeyRSA, "private-key"},
		{models.SecretHighEntropy, "entropy"},
	}
	for _, tc := range cases {
		f := testFinding("SECRET")
		f.SecretType = tc.secretType
		if err := p.Process(context.Background(), &f, nil); err != nil {
			t.Fatalf("unexpected error for %s: %v", tc.secretType, err)
		}
		if f.Category != tc.want {
			t.Errorf("Category for %q = %q, want %q", tc.secretType, f.Category, tc.want)
		}
	}
}

func TestEnrichProcessor_ScanMetadata(t *testing.T) {
	p := NewEnrichProcessor()
	f := testFinding("SECRET")
	meta := &models.ScanMetadata{
		ScanID:         "scan-abc-123",
		ScannerVersion: "0.1.0",
		ConfigHash:     "cfghash",
	}
	if err := p.Process(context.Background(), &f, meta); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Metadata["scan_id"] != "scan-abc-123" {
		t.Errorf("scan_id = %q", f.Metadata["scan_id"])
	}
	if f.Metadata["scanner_version"] != "0.1.0" {
		t.Errorf("scanner_version = %q", f.Metadata["scanner_version"])
	}
	if f.Metadata["config_hash"] != "cfghash" {
		t.Errorf("config_hash = %q", f.Metadata["config_hash"])
	}
}

func TestEnrichProcessor_Name(t *testing.T) {
	p := NewEnrichProcessor()
	if p.Name() != "enrich" {
		t.Errorf("Name() = %q, want %q", p.Name(), "enrich")
	}
}

func TestFingerprintProcessor_Deterministic(t *testing.T) {
	p := NewFingerprintProcessor()
	makeF := func() models.Finding {
		f := testFinding("AKIAIOSFODNN7EXAMPLE")
		f.SecretHash = sha256Of("AKIAIOSFODNN7EXAMPLE")
		return f
	}
	f1 := makeF()
	f2 := makeF()
	p.Process(context.Background(), &f1, nil)
	p.Process(context.Background(), &f2, nil)
	if f1.Fingerprint == "" {
		t.Fatal("Fingerprint should not be empty")
	}
	if len(f1.Fingerprint) != 64 {
		t.Errorf("Fingerprint should be 64 hex chars, got %d", len(f1.Fingerprint))
	}
	if f1.Fingerprint != f2.Fingerprint {
		t.Error("Same input should produce same fingerprint")
	}
}

func TestFingerprintProcessor_DifferentLocation(t *testing.T) {
	p := NewFingerprintProcessor()
	f1 := testFinding("SECRET")
	f1.SecretHash = sha256Of("SECRET")
	f1.Source.Line = 10
	f2 := testFinding("SECRET")
	f2.SecretHash = sha256Of("SECRET")
	f2.Source.Line = 20
	p.Process(context.Background(), &f1, nil)
	p.Process(context.Background(), &f2, nil)
	if f1.Fingerprint == f2.Fingerprint {
		t.Error("Different line numbers should produce different fingerprints")
	}
}

func TestFingerprintProcessor_Name(t *testing.T) {
	p := NewFingerprintProcessor()
	if p.Name() != "fingerprint" {
		t.Errorf("Name() = %q, want %q", p.Name(), "fingerprint")
	}
}

func TestSanitizeProcessor_ClearsRawMatch(t *testing.T) {
	p := NewSanitizeProcessor()
	f := testFinding("AKIAIOSFODNN7EXAMPLE")
	if err := p.Process(context.Background(), &f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.RawMatch != "" {
		t.Errorf("RawMatch should be empty, got %q", f.RawMatch)
	}
}

func TestSanitizeProcessor_KeepsMetadataSHA(t *testing.T) {
	p := NewSanitizeProcessor()
	f := testFinding("SECRET")
	f.Metadata = map[string]string{"sha256": "abc123", "other": "keep"}
	if err := p.Process(context.Background(), &f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Metadata["sha256"] != "abc123" {
		t.Error("sha256 should be kept by default")
	}
}

func TestSanitizeProcessor_ClearMetadataSHA(t *testing.T) {
	p := &SanitizeProcessor{ClearMetadataSHA: true}
	f := testFinding("SECRET")
	f.Metadata = map[string]string{"sha256": "abc123"}
	if err := p.Process(context.Background(), &f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := f.Metadata["sha256"]; ok {
		t.Error("sha256 should have been removed")
	}
	if f.Metadata != nil {
		t.Errorf("Metadata should be nil when empty, got %v", f.Metadata)
	}
}

func TestSanitizeProcessor_Name(t *testing.T) {
	p := NewSanitizeProcessor()
	if p.Name() != "sanitize" {
		t.Errorf("Name() = %q, want %q", p.Name(), "sanitize")
	}
}

func TestNoOpVerifier(t *testing.T) {
	v := NewNoOpVerifier()
	if v.Name() != "verify-noop" {
		t.Errorf("Name() = %q", v.Name())
	}
	if v.CanVerify(models.SecretAWSAccessKey) {
		t.Error("NoOpVerifier should not report CanVerify")
	}
	f := testFinding("SECRET")
	if err := v.Process(context.Background(), &f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPipeline_NewDefault(t *testing.T) {
	pipe := NewDefault()
	names := make([]string, 0)
	for _, p := range pipe.Processors() {
		names = append(names, p.Name())
	}
	want := []string{"hash", "redact", "enrich", "fingerprint", "sanitize"}
	if len(names) != len(want) {
		t.Fatalf("default pipeline has %d processors, want %d", len(names), len(want))
	}
	for i, n := range names {
		if n != want[i] {
			t.Errorf("processor[%d] = %q, want %q", i, n, want[i])
		}
	}
}

func TestPipeline_FullChain(t *testing.T) {
	pipe := NewDefault()
	findings := []models.Finding{
		testFinding("AKIAIOSFODNN7EXAMPLE"),
	}
	meta := &models.ScanMetadata{
		ScannerVersion: "0.1.0",
		ScanID:         "test-run-001",
	}
	kept, errs := pipe.ProcessFindings(context.Background(), findings, meta)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(kept) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(kept))
	}
	f := kept[0]
	if f.SecretHash == "" {
		t.Error("SecretHash should be set")
	}
	if len(f.SecretHash) != 64 {
		t.Errorf("SecretHash length = %d, want 64", len(f.SecretHash))
	}
	if f.RedactedMatch == "" {
		t.Error("RedactedMatch should be set")
	}
	if !strings.Contains(f.RedactedMatch, "****") {
		t.Errorf("RedactedMatch should contain ****: %s", f.RedactedMatch)
	}
	if f.FileType != "go" {
		t.Errorf("FileType = %q, want go", f.FileType)
	}
	if f.Category != "cloud" {
		t.Errorf("Category = %q, want cloud", f.Category)
	}
	if f.Metadata["scanner_version"] != "0.1.0" {
		t.Errorf("scanner_version = %q", f.Metadata["scanner_version"])
	}
	if f.Fingerprint == "" {
		t.Error("Fingerprint should be set")
	}
	if len(f.Fingerprint) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(f.Fingerprint))
	}
	if f.RawMatch != "" {
		t.Errorf("RawMatch should be empty after sanitize, got %q", f.RawMatch)
	}
}

func TestPipeline_ProcessResult(t *testing.T) {
	pipe := NewDefault()
	result := models.ScanResult{
		Findings: []models.Finding{
			testFinding("AKIAIOSFODNN7EXAMPLE"),
			testFinding("sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz"),
		},
		TotalFindings: 2,
		CountBySeverity: map[models.Severity]int{
			models.SeverityHigh: 2,
		},
	}
	meta := &models.ScanMetadata{ScannerVersion: "0.1.0"}
	errs := pipe.ProcessResult(context.Background(), &result, meta)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if result.TotalFindings != 2 {
		t.Errorf("TotalFindings = %d, want 2", result.TotalFindings)
	}
	for _, f := range result.Findings {
		if f.RawMatch != "" {
			t.Error("RawMatch should be cleared")
		}
		if f.SecretHash == "" {
			t.Error("SecretHash should be set")
		}
		if f.RedactedMatch == "" {
			t.Error("RedactedMatch should be set")
		}
		if f.Fingerprint == "" {
			t.Error("Fingerprint should be set")
		}
	}
	if result.Findings[0].Fingerprint == result.Findings[1].Fingerprint {
		t.Error("Different secrets should produce different fingerprints")
	}
}

func TestPipeline_AddProcessor(t *testing.T) {
	pipe := New()
	if len(pipe.Processors()) != 0 {
		t.Fatalf("empty pipeline should have 0 processors")
	}
	pipe.AddProcessor(NewHashProcessor())
	if len(pipe.Processors()) != 1 {
		t.Fatalf("expected 1 processor after add")
	}
}

func TestPipeline_InsertProcessor(t *testing.T) {
	pipe := NewDefault()
	v := NewNoOpVerifier()
	if err := pipe.InsertProcessor(4, v); err != nil {
		t.Fatalf("InsertProcessor returned unexpected error: %v", err)
	}
	procs := pipe.Processors()
	if len(procs) != 6 {
		t.Fatalf("expected 6 processors, got %d", len(procs))
	}
	if procs[4].Name() != "verify-noop" {
		t.Errorf("processor[4] = %q", procs[4].Name())
	}
	if procs[5].Name() != "sanitize" {
		t.Errorf("processor[5] = %q", procs[5].Name())
	}
}

func TestPipeline_InsertProcessorReturnsError(t *testing.T) {
	pipe := New()
	err := pipe.InsertProcessor(5, NewHashProcessor())
	if err == nil {
		t.Error("expected error for out-of-range insert")
	}
}

type errorProcessor struct{}

func (e *errorProcessor) Name() string { return "error" }
func (e *errorProcessor) Process(_ context.Context, _ *models.Finding, _ *models.ScanMetadata) error {
	return fmt.Errorf("deliberate test error")
}

func TestPipeline_ErrorDropsFinding(t *testing.T) {
	pipe := New(&errorProcessor{})
	findings := []models.Finding{
		testFinding("SECRET1"),
		testFinding("SECRET2"),
	}
	kept, errs := pipe.ProcessFindings(context.Background(), findings, nil)
	if len(kept) != 0 {
		t.Errorf("expected 0 kept findings, got %d", len(kept))
	}
	if len(errs) != 2 {
		t.Errorf("expected 2 errors, got %d", len(errs))
	}
}

type conditionalErrorProcessor struct {
	failAt  int
	counter *int
}

func (c *conditionalErrorProcessor) Name() string { return "conditional-error" }
func (c *conditionalErrorProcessor) Process(_ context.Context, _ *models.Finding, _ *models.ScanMetadata) error {
	idx := *c.counter
	*c.counter++
	if idx == c.failAt {
		return fmt.Errorf("deliberate failure at index %d", idx)
	}
	return nil
}

func TestPipeline_PartialError(t *testing.T) {
	counter := 0
	pipe := New(&conditionalErrorProcessor{failAt: 1, counter: &counter})
	findings := []models.Finding{
		testFinding("OK"),
		testFinding("FAIL"),
	}
	kept, errs := pipe.ProcessFindings(context.Background(), findings, nil)
	if len(kept) != 1 {
		t.Errorf("expected 1 kept finding, got %d", len(kept))
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
}

func TestPipeline_ZeroTrustGuarantee(t *testing.T) {
	pipe := NewDefault()
	findings := []models.Finding{
		testFinding("AKIAIOSFODNN7EXAMPLE"),
		testFinding("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"),
		testFinding("sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz"),
		testFinding("SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"),
	}
	kept, _ := pipe.ProcessFindings(context.Background(), findings, nil)
	for i, f := range kept {
		if f.RawMatch != "" {
			t.Errorf("finding[%d] RawMatch not cleared: %q", i, f.RawMatch)
		}
		if f.SecretHash == "" {
			t.Errorf("finding[%d] missing SecretHash", i)
		}
		if f.RedactedMatch == "" {
			t.Errorf("finding[%d] missing RedactedMatch", i)
		}
		if f.Fingerprint == "" {
			t.Errorf("finding[%d] missing Fingerprint", i)
		}
	}
}

func TestPipeline_EmptyFindings(t *testing.T) {
	pipe := NewDefault()
	kept, errs := pipe.ProcessFindings(context.Background(), nil, nil)
	if len(kept) != 0 {
		t.Errorf("expected 0 kept, got %d", len(kept))
	}
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d", len(errs))
	}
}
