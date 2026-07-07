package baseline

import (
	"strings"
	"testing"

	"github.com/svemulapati/CredVigil/pkg/models"
)

func mkResult(findings ...models.Finding) models.ScanResult {
	counts := map[models.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return models.ScanResult{
		Findings:        findings,
		TotalFindings:   len(findings),
		CountBySeverity: counts,
	}
}

func TestParse(t *testing.T) {
	in := `
# comment line
deadbeefcafe1234

*.env
testdata/  # trailing comment
`
	b, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.fingerprints["deadbeefcafe1234"]; !ok {
		t.Errorf("fingerprint not parsed: %v", b.fingerprints)
	}
	if len(b.pathGlobs) != 2 {
		t.Errorf("expected 2 path globs, got %v", b.pathGlobs)
	}
}

func TestSuppressedByFingerprint(t *testing.T) {
	b, _ := Parse(strings.NewReader("abc123"))
	f := &models.Finding{Fingerprint: "abc123", Severity: models.SeverityHigh}
	if !b.Suppressed(f) {
		t.Error("expected fingerprint match to suppress")
	}
	f2 := &models.Finding{Fingerprint: "other", Severity: models.SeverityHigh}
	if b.Suppressed(f2) {
		t.Error("unexpected suppression of non-matching fingerprint")
	}
}

func TestSuppressedByPathGlob(t *testing.T) {
	b, _ := Parse(strings.NewReader("*.env\nsecrets/\n"))
	cases := []struct {
		loc  string
		want bool
	}{
		{"config.env", true},
		{"./nested/dir/prod.env", true},
		{"secrets/keys.txt", true},
		{"src/main.go", false},
	}
	for _, c := range cases {
		f := &models.Finding{Source: models.Source{Location: c.loc}}
		if got := b.Suppressed(f); got != c.want {
			t.Errorf("Suppressed(%q) = %v, want %v", c.loc, got, c.want)
		}
	}
}

func TestApplyRecomputesCounts(t *testing.T) {
	b, _ := Parse(strings.NewReader("kill-me"))
	results := []models.ScanResult{mkResult(
		models.Finding{Fingerprint: "kill-me", Severity: models.SeverityCritical},
		models.Finding{Fingerprint: "keep", Severity: models.SeverityHigh},
	)}
	n := b.Apply(results)
	if n != 1 {
		t.Fatalf("expected 1 suppressed, got %d", n)
	}
	r := results[0]
	if r.TotalFindings != 1 || len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding retained, got %d", r.TotalFindings)
	}
	if r.CountBySeverity[models.SeverityCritical] != 0 {
		t.Error("critical count should be recomputed to 0")
	}
	if r.CountBySeverity[models.SeverityHigh] != 1 {
		t.Error("high count should be 1")
	}
}

func TestEmptyBaselineNoOp(t *testing.T) {
	b, _ := Parse(strings.NewReader("# only comments\n"))
	if !b.Empty() {
		t.Error("expected empty baseline")
	}
	results := []models.ScanResult{mkResult(models.Finding{Fingerprint: "x"})}
	if n := b.Apply(results); n != 0 {
		t.Errorf("empty baseline should suppress nothing, got %d", n)
	}
}
