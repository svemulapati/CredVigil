package models

import (
"testing"
"time"
)

func TestJSONMap_Value_NonNil(t *testing.T) {
	m := JSONMap{"critical": 3, "high": 5}
	v, err := m.Value()
	if err != nil {
		t.Fatalf("Value() error: %v", err)
	}
	b, ok := v.([]byte)
	if !ok {
		t.Fatalf("Value() type = %T, want []byte", v)
	}
	s := string(b)
	if len(s) < 2 || s[0] != '{' {
		t.Fatalf("Value() = %s, want JSON object", s)
	}
}

func TestJSONMap_Value_Nil(t *testing.T) {
	var m JSONMap
	v, err := m.Value()
	if err != nil {
		t.Fatalf("Value() error: %v", err)
	}
	b := v.([]byte)
	if string(b) != "{}" {
		t.Fatalf("Value() = %s, want {}", string(b))
	}
}

func TestJSONMap_Scan_Bytes(t *testing.T) {
	m := make(JSONMap)
	err := m.Scan([]byte(`{"key":"value","n":42}`))
	if err != nil {
		t.Fatalf("Scan([]byte) error: %v", err)
	}
	if m["key"] != "value" {
		t.Errorf("m[key] = %v, want value", m["key"])
	}
	if m["n"].(float64) != 42 {
		t.Errorf("m[n] = %v, want 42", m["n"])
	}
}

func TestJSONMap_Scan_String(t *testing.T) {
	m := make(JSONMap)
	err := m.Scan(`{"a":"b"}`)
	if err != nil {
		t.Fatalf("Scan(string) error: %v", err)
	}
	if m["a"] != "b" {
		t.Errorf("m[a] = %v, want b", m["a"])
	}
}

func TestJSONMap_Scan_Nil(t *testing.T) {
	m := make(JSONMap)
	err := m.Scan(nil)
	if err != nil {
		t.Fatalf("Scan(nil) error: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("len(m) = %d after Scan(nil), want 0", len(m))
	}
}

func TestJSONMap_Scan_UnsupportedType(t *testing.T) {
	m := make(JSONMap)
	err := m.Scan(12345)
	if err == nil {
		t.Fatal("Scan(int) should return error")
	}
}

func TestJSONMap_Roundtrip(t *testing.T) {
	original := JSONMap{"severity": "HIGH", "count": float64(7)}
	v, err := original.Value()
	if err != nil {
		t.Fatalf("Value() error: %v", err)
	}
	restored := make(JSONMap)
	if err := restored.Scan(v); err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if restored["severity"] != "HIGH" {
		t.Errorf("roundtrip severity = %v, want HIGH", restored["severity"])
	}
	if restored["count"].(float64) != 7 {
		t.Errorf("roundtrip count = %v, want 7", restored["count"])
	}
}

func newTestFinding() *Finding {
	return &Finding{
		ID:            "f-001",
		SecretType:    SecretAWSAccessKey,
		Description:   "AWS Access Key ID detected",
		Severity:      SeverityHigh,
		RuleID:        "rule-aws-key",
		Confidence:    0.95,
		SecretHash:    "abc123hash",
		Fingerprint:   "fp-001",
		RedactedMatch: "AKIA****WXYZ",
		Entropy:       4.5,
		FileType:      "yaml",
		Environment:   "production",
		Category:      "cloud",
		Source: Source{
			Type:       "file",
			Location:   "config/secrets.yaml",
			Line:       42,
			CommitHash: "deadbeef",
			Author:     "dev@example.com",
			Branch:     "main",
		},
		Metadata: map[string]string{
			"bpe_efficiency": "0.650",
			"bpe_tokens":     "12",
		},
	}
}

func assertStrEq(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", field, got, want)
	}
}

func TestToStoredFinding_BasicFields(t *testing.T) {
	f := newTestFinding()
	scanID := "scan-001"
	scannedAt := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)

	sf := ToStoredFinding(f, scanID, scannedAt)

	assertStrEq(t, "ID", sf.ID, "f-001")
	assertStrEq(t, "ScanID", sf.ScanID, scanID)
	assertStrEq(t, "RuleID", sf.RuleID, "rule-aws-key")
	assertStrEq(t, "SecretType", sf.SecretType, "aws-access-key-id")
	assertStrEq(t, "Description", sf.Description, "AWS Access Key ID detected")
	assertStrEq(t, "Severity", sf.Severity, "HIGH")
	assertStrEq(t, "SecretHash", sf.SecretHash, "abc123hash")
	assertStrEq(t, "Fingerprint", sf.Fingerprint, "fp-001")
	assertStrEq(t, "RedactedMatch", sf.RedactedMatch, "AKIA****WXYZ")
	assertStrEq(t, "FileType", sf.FileType, "yaml")
	assertStrEq(t, "Environment", sf.Environment, "production")
	assertStrEq(t, "Category", sf.Category, "cloud")

	if sf.Confidence != 0.95 {
		t.Errorf("Confidence = %f, want 0.95", sf.Confidence)
	}
	if sf.Entropy != 4.5 {
		t.Errorf("Entropy = %f, want 4.5", sf.Entropy)
	}
}

func TestToStoredFinding_SourceFlattening(t *testing.T) {
	f := newTestFinding()
	sf := ToStoredFinding(f, "scan-001", time.Now())

	assertStrEq(t, "SourceType", sf.SourceType, "file")
	assertStrEq(t, "SourceLocation", sf.SourceLocation, "config/secrets.yaml")
	if sf.SourceLine != 42 {
		t.Errorf("SourceLine = %d, want 42", sf.SourceLine)
	}
	assertStrEq(t, "CommitHash", sf.CommitHash, "deadbeef")
	assertStrEq(t, "Author", sf.Author, "dev@example.com")
	assertStrEq(t, "Branch", sf.Branch, "main")
}

func TestToStoredFinding_BPEMetadata(t *testing.T) {
	f := newTestFinding()
	sf := ToStoredFinding(f, "scan-001", time.Now())

	if sf.BPEEfficiency == nil {
		t.Fatal("BPEEfficiency = nil, want 0.65")
	}
	if *sf.BPEEfficiency != 0.65 {
		t.Errorf("BPEEfficiency = %f, want 0.65", *sf.BPEEfficiency)
	}
	if sf.BPETokens == nil {
		t.Fatal("BPETokens = nil, want 12")
	}
	if *sf.BPETokens != 12 {
		t.Errorf("BPETokens = %d, want 12", *sf.BPETokens)
	}
}

func TestToStoredFinding_NoBPEMetadata(t *testing.T) {
	f := newTestFinding()
	f.Metadata = nil
	sf := ToStoredFinding(f, "scan-001", time.Now())

	if sf.BPEEfficiency != nil {
		t.Errorf("BPEEfficiency should be nil (no metadata)")
	}
	if sf.BPETokens != nil {
		t.Errorf("BPETokens should be nil (no metadata)")
	}
}

func TestToStoredFinding_EmptyMetadata(t *testing.T) {
	f := newTestFinding()
	f.Metadata = map[string]string{}
	sf := ToStoredFinding(f, "scan-001", time.Now())

	if sf.BPEEfficiency != nil {
		t.Errorf("BPEEfficiency should be nil with empty metadata")
	}
}

func TestToStoredFinding_MalformedBPE(t *testing.T) {
	f := newTestFinding()
	f.Metadata = map[string]string{
		"bpe_efficiency": "not-a-number",
		"bpe_tokens":     "also-bad",
	}
	sf := ToStoredFinding(f, "scan-001", time.Now())

	if sf.BPEEfficiency != nil {
		t.Errorf("BPEEfficiency should be nil for malformed input")
	}
	if sf.BPETokens != nil {
		t.Errorf("BPETokens should be nil for malformed input")
	}
}

func TestToStoredFinding_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityInfo, "INFO"},
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
	}
	for _, tc := range tests {
		f := newTestFinding()
		f.Severity = tc.severity
		sf := ToStoredFinding(f, "scan-001", time.Now())
		if sf.Severity != tc.want {
			t.Errorf("Severity(%d) = %s, want %s", tc.severity, sf.Severity, tc.want)
		}
	}
}

func TestToStoredFinding_ScannedAtPropagated(t *testing.T) {
	f := newTestFinding()
	ts := time.Date(2025, 1, 15, 12, 30, 0, 0, time.UTC)
	sf := ToStoredFinding(f, "scan-001", ts)

	if !sf.ScannedAt.Equal(ts) {
		t.Errorf("ScannedAt = %v, want %v", sf.ScannedAt, ts)
	}
}

func TestToStoredFinding_NoGitFields(t *testing.T) {
	f := newTestFinding()
	f.Source.CommitHash = ""
	f.Source.Author = ""
	f.Source.Branch = ""
	sf := ToStoredFinding(f, "scan-001", time.Now())

	assertStrEq(t, "CommitHash", sf.CommitHash, "")
	assertStrEq(t, "Author", sf.Author, "")
	assertStrEq(t, "Branch", sf.Branch, "")
}
