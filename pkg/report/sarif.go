// Package report renders scan findings into machine-readable interchange
// formats. SARIF 2.1.0 is the format ingested by GitHub Code Scanning,
// GitLab, Azure DevOps, and most IDE security extensions — emitting it lets
// CredVigil findings surface inline on pull requests and in the Security tab.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/svemulapati/CredVigil/pkg/models"
)

// SARIF schema constants.
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	toolName     = "CredVigil"
	toolURI      = "https://github.com/svemulapati/CredVigil"
)

// SARIFLog is the root object of a SARIF 2.1.0 document.
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription SARIFText         `json:"shortDescription"`
	FullDescription  *SARIFText        `json:"fullDescription,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       *SARIFRuleProps   `json:"properties,omitempty"`
	DefaultConfig    *SARIFRuleDefault `json:"defaultConfiguration,omitempty"`
}

type SARIFRuleDefault struct {
	Level string `json:"level"`
}

type SARIFRuleProps struct {
	Category string   `json:"category,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

type SARIFText struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID              string                 `json:"ruleId"`
	RuleIndex           int                    `json:"ruleIndex"`
	Level               string                 `json:"level"`
	Message             SARIFText              `json:"message"`
	Locations           []SARIFLocation        `json:"locations"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
}

// severityToLevel maps CredVigil severities onto the three SARIF levels.
// Code-scanning treats "error" as blocking, "warning" as advisory, "note" as informational.
func severityToLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium, models.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}

// BuildSARIF converts a flat list of findings into a SARIF log. Rules are
// deduplicated by RuleID and referenced by index from each result, as the spec
// requires. The scanner version populates the tool driver.
func BuildSARIF(findings []models.Finding, scannerVersion string) SARIFLog {
	ruleIndex := make(map[string]int)
	var rules []SARIFRule
	results := make([]SARIFResult, 0, len(findings))

	for i := range findings {
		f := &findings[i]

		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			idx = len(rules)
			ruleIndex[f.RuleID] = idx
			rules = append(rules, SARIFRule{
				ID:               f.RuleID,
				Name:             string(f.SecretType),
				ShortDescription: SARIFText{Text: f.Description},
				HelpURI:          toolURI,
				DefaultConfig:    &SARIFRuleDefault{Level: severityToLevel(f.Severity)},
				Properties: &SARIFRuleProps{
					Category: f.Category,
					Tags:     []string{"security", "secret", string(f.SecretType)},
				},
			})
		}

		region := &SARIFRegion{StartLine: f.Source.Line}
		if f.Source.Column > 0 {
			region.StartColumn = f.Source.Column
		}
		if f.Source.EndLine > 0 {
			region.EndLine = f.Source.EndLine
		}
		// SARIF requires startLine >= 1; omit the region entirely when unknown.
		if region.StartLine <= 0 {
			region = nil
		}

		props := map[string]interface{}{
			"confidence": f.Confidence,
			"entropy":    f.Entropy,
			"severity":   f.Severity.String(),
			"secretType": string(f.SecretType),
		}
		if f.Environment != "" {
			props["environment"] = f.Environment
		}

		results = append(results, SARIFResult{
			RuleID:    f.RuleID,
			RuleIndex: idx,
			Level:     severityToLevel(f.Severity),
			Message: SARIFText{Text: fmt.Sprintf("%s detected (%.0f%% confidence, %s)",
				f.Description, f.Confidence*100, f.Severity.String())},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: locationURI(f.Source.Location)},
					Region:           region,
				},
			}},
			PartialFingerprints: fingerprints(f),
			Properties:          props,
		})
	}

	return SARIFLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           toolName,
				Version:        scannerVersion,
				InformationURI: toolURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// fingerprints supplies SARIF partialFingerprints so code-scanning can track a
// finding across commits without re-alerting. CredVigil's stable fingerprint is
// the ideal key when present.
func fingerprints(f *models.Finding) map[string]string {
	if f.Fingerprint == "" {
		return nil
	}
	return map[string]string{"credvigil/v1": f.Fingerprint}
}

// locationURI normalizes a path into a relative URI. SARIF consumers resolve
// URIs against the repository root, so leading "./" is stripped.
func locationURI(loc string) string {
	if loc == "" {
		return "unknown"
	}
	for len(loc) > 2 && loc[0] == '.' && loc[1] == '/' {
		loc = loc[2:]
	}
	return loc
}

// WriteSARIF renders findings as indented SARIF JSON to w.
func WriteSARIF(w io.Writer, findings []models.Finding, scannerVersion string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(BuildSARIF(findings, scannerVersion))
}
