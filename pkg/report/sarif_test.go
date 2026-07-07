package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/svemulapati/CredVigil/pkg/models"
)

func sampleFindings() []models.Finding {
	return []models.Finding{
		{
			RuleID:      "aws-secret-access-key",
			SecretType:  models.SecretAWSSecretKey,
			Description: "AWS Secret Access Key",
			Severity:    models.SeverityCritical,
			Confidence:  0.9,
			Entropy:     4.6,
			Fingerprint: "fp-1",
			Source:      models.Source{Location: "./config.env", Line: 7, Column: 3},
			Category:    "cloud",
		},
		{
			RuleID:      "aws-secret-access-key", // same rule -> dedup
			SecretType:  models.SecretAWSSecretKey,
			Description: "AWS Secret Access Key",
			Severity:    models.SeverityMedium,
			Confidence:  0.5,
			Source:      models.Source{Location: "other.env", Line: 0}, // no line -> nil region
		},
	}
}

func TestBuildSARIFStructure(t *testing.T) {
	log := BuildSARIF(sampleFindings(), "9.9.9")

	if log.Version != "2.1.0" {
		t.Errorf("version = %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Version != "9.9.9" {
		t.Errorf("driver version = %q", run.Tool.Driver.Version)
	}
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 deduped rule, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}

	r0 := run.Results[0]
	if r0.Level != "error" {
		t.Errorf("critical should map to error, got %q", r0.Level)
	}
	if r0.RuleIndex != 0 {
		t.Errorf("ruleIndex = %d", r0.RuleIndex)
	}
	region := run.Results[0].Locations[0].PhysicalLocation.Region
	if region == nil || region.StartLine != 7 {
		t.Errorf("expected startLine 7, got %+v", region)
	}
	if got := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "config.env" {
		t.Errorf("uri should strip ./, got %q", got)
	}
	if run.Results[0].PartialFingerprints["credvigil/v1"] != "fp-1" {
		t.Errorf("missing partial fingerprint")
	}

	// Second finding has no line -> region must be omitted, level warning.
	if run.Results[1].Level != "warning" {
		t.Errorf("medium should map to warning, got %q", run.Results[1].Level)
	}
	if run.Results[1].Locations[0].PhysicalLocation.Region != nil {
		t.Errorf("region should be nil when line unknown")
	}
}

func TestWriteSARIFValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleFindings(), "1.0.0"); err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out["$schema"] == nil {
		t.Error("missing $schema")
	}
}

func TestEmptyFindings(t *testing.T) {
	log := BuildSARIF(nil, "1.0.0")
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 0 {
		t.Errorf("empty scan should produce a run with 0 results")
	}
}
