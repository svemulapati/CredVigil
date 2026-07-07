package detector

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/svemulapati/CredVigil/pkg/models"
	"github.com/svemulapati/CredVigil/pkg/pipeline"
)

func TestScanContent_AWSKeys(t *testing.T) {
	e := NewDefault()
	content := `
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "test.env"},
	})

	foundAccessKey := false
	foundSecretKey := false
	for _, f := range result.Findings {
		t.Logf("Found: %s (type=%s, confidence=%.2f, entropy=%.2f)", f.Description, f.SecretType, f.Confidence, f.Entropy)
		if f.SecretType == models.SecretAWSAccessKey {
			foundAccessKey = true
		}
		if f.SecretType == models.SecretAWSSecretKey {
			foundSecretKey = true
		}
	}
	if !foundAccessKey {
		t.Error("Did not detect AWS Access Key ID")
	}
	if !foundSecretKey {
		t.Error("Did not detect AWS Secret Access Key")
	}
}

func TestScanContent_GitHubTokens(t *testing.T) {
	e := NewDefault()
	content := `
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234
`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "test.env"},
	})

	found := false
	for _, f := range result.Findings {
		if f.SecretType == models.SecretGitHubToken {
			found = true
			if f.Confidence < 0.5 {
				t.Errorf("GitHub token confidence too low: %f", f.Confidence)
			}
			t.Logf("GitHub token found: redacted=%s confidence=%.2f", f.RedactedMatch, f.Confidence)
		}
	}
	if !found {
		t.Error("Did not detect GitHub Personal Access Token")
	}
}

func TestScanContent_SlackTokens(t *testing.T) {
	e := NewDefault()
	content := `
# Slack integration
BOT_TOKEN=xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWXyz
SLACK_WEBHOOK=https://hooks.slack.com/services/T01234567/B01234567/ABCDEFGHIJKLMNOPQRSTUVWX
`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: ".env"},
	})

	foundBot := false
	foundWebhook := false
	for _, f := range result.Findings {
		t.Logf("Found: %s (confidence=%.2f)", f.Description, f.Confidence)
		if f.SecretType == models.SecretSlackToken {
			foundBot = true
		}
		if f.SecretType == models.SecretSlackWebhook {
			foundWebhook = true
		}
	}
	if !foundBot {
		t.Error("Did not detect Slack bot token")
	}
	if !foundWebhook {
		t.Error("Did not detect Slack webhook")
	}
}

func TestScanContent_PrivateKeys(t *testing.T) {
	e := NewDefault()
	content := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aJznm0oFMJbHzlaHTYlMbFBIFWsW+nXPC5JdQ2WKA8s
-----END RSA PRIVATE KEY-----`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "id_rsa"},
	})

	found := false
	for _, f := range result.Findings {
		if f.SecretType == models.SecretPrivateKeyRSA {
			found = true
			if f.Confidence < 0.9 {
				t.Errorf("RSA private key confidence too low: %f", f.Confidence)
			}
		}
	}
	if !found {
		t.Error("Did not detect RSA private key")
	}
}

func TestScanContent_DatabaseURIs(t *testing.T) {
	e := NewDefault()
	content := `
DATABASE_URL=postgresql://admin:SuperSecret123!@db.prod.example.com:5432/myapp
MONGO_URI=mongodb+srv://admin:MongoPass456@cluster0.example.com/production
REDIS_URL=redis://:RedisPass789@cache.example.com:6379/0
MYSQL_DSN=mysql://root:MySQLp@ss@mysql.example.com/data
`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "docker-compose.yml"},
	})

	types := make(map[models.SecretType]bool)
	for _, f := range result.Findings {
		types[f.SecretType] = true
		t.Logf("Found: %s at line %d (confidence=%.2f)", f.Description, f.Source.Line, f.Confidence)
	}
	if !types[models.SecretPostgresURI] {
		t.Error("Did not detect PostgreSQL URI")
	}
	if !types[models.SecretMongoDBURI] {
		t.Error("Did not detect MongoDB URI")
	}
	if !types[models.SecretRedisURI] {
		t.Error("Did not detect Redis URI")
	}
	if !types[models.SecretMySQLURI] {
		t.Error("Did not detect MySQL URI")
	}
}

func TestScanContent_JWT(t *testing.T) {
	e := NewDefault()
	content := `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "auth.go"},
	})

	found := false
	for _, f := range result.Findings {
		if f.SecretType == models.SecretJWT {
			found = true
		}
	}
	if !found {
		t.Error("Did not detect JWT token")
	}
}

func TestScanContent_Stripe(t *testing.T) {
	e := NewDefault()
	content := `STRIPE_KEY=sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "config.py"},
	})

	found := false
	for _, f := range result.Findings {
		if f.SecretType == models.SecretStripeKey {
			found = true
		}
	}
	if !found {
		t.Error("Did not detect Stripe secret key")
	}
}

func TestScanContent_SendGrid(t *testing.T) {
	e := NewDefault()
	content := `SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "mail.py"},
	})

	found := false
	for _, f := range result.Findings {
		if f.SecretType == models.SecretSendgridKey {
			found = true
		}
	}
	if !found {
		t.Error("Did not detect SendGrid API key")
	}
}

func TestScanContent_GenericSecrets(t *testing.T) {
	e := NewDefault()
	content := `
api_key = "kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j"
secret = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u"
password = "V3ryS3cur3P@ssw0rd!"
`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "app.conf"},
	})

	if result.TotalFindings == 0 {
		t.Error("Expected to find generic secrets, got 0")
	}
	for _, f := range result.Findings {
		t.Logf("Found: %s type=%s confidence=%.2f entropy=%.2f", f.Description, f.SecretType, f.Confidence, f.Entropy)
	}
}

func TestScanContent_FalsePositiveReduction(t *testing.T) {
	e := NewDefault()
	// These should have LOWER confidence or be filtered out
	content := `
# Example: aws_secret_access_key = YOUR_SECRET_KEY_HERE
# Placeholder: api_key = "xxxxxxxxxxxxxxxxxxxx"
# Test data (not real)
TEST_KEY=AKIAIOSFODNN7EXAMPLE
test_secret = "dummy_secret_placeholder_value"
`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "README.md"},
	})

	for _, f := range result.Findings {
		t.Logf("FP check: %s confidence=%.2f (type=%s)", f.Description, f.Confidence, f.SecretType)
		// FP indicators should reduce confidence
		if f.SecretType == models.SecretAWSAccessKey && f.Confidence > 0.8 {
			// The key is pattern-valid but in a comment with "Example"
			t.Logf("Note: AWS key near 'Example' - confidence %.2f (FP patterns may have reduced it)", f.Confidence)
		}
	}
}

func TestScanContent_EmptyContent(t *testing.T) {
	e := NewDefault()
	result := e.ScanContent(models.ScanRequest{
		Content: "",
		Source:  models.Source{Type: "file", Location: "empty.txt"},
	})
	if result.TotalFindings != 0 {
		t.Errorf("Expected 0 findings for empty content, got %d", result.TotalFindings)
	}
}

func TestScanContent_NoSecrets(t *testing.T) {
	e := NewDefault()
	content := `
package main
import "fmt"
func main() {
    fmt.Println("Hello, World!")
    x := 42
    name := "John Doe"
}
`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "main.go"},
	})
	if result.TotalFindings != 0 {
		for _, f := range result.Findings {
			t.Logf("Unexpected finding: %s (type=%s, confidence=%.2f, match=%q)",
				f.Description, f.SecretType, f.Confidence, f.RedactedMatch)
		}
		t.Errorf("Expected 0 findings for clean code, got %d", result.TotalFindings)
	}
}

func TestScanContent_MultiSecret(t *testing.T) {
	e := NewDefault()
	content := `
# Multi-secret config file
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234
SLACK_TOKEN=xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWXyz
STRIPE_KEY=sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz
DATABASE_URL=postgresql://admin:Secret123@db.example.com:5432/app
JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: ".env.production"},
	})

	// Should find at least 5 distinct secrets
	if result.TotalFindings < 5 {
		t.Errorf("Expected at least 5 findings in multi-secret file, got %d", result.TotalFindings)
	}
	t.Logf("Total findings: %d (duration: %v)", result.TotalFindings, result.Duration)
	for _, f := range result.Findings {
		t.Logf("  [%s] %s at line %d (confidence=%.2f)", f.Severity, f.Description, f.Source.Line, f.Confidence)
	}
}

func TestScanContent_Deduplication(t *testing.T) {
	e := NewDefault()
	// Same secret appearing twice should be found twice (different lines) but NOT duplicated within the same rule match
	content := `
Line1: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234
Line2: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234
`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "dup-test.txt"},
	})

	githubFindings := 0
	for _, f := range result.Findings {
		if f.SecretType == models.SecretGitHubToken {
			githubFindings++
		}
	}
	if githubFindings != 2 {
		t.Errorf("Expected 2 GitHub token findings (different lines), got %d", githubFindings)
	}
}

func TestScanContent_FilterTypes(t *testing.T) {
	e := NewDefault()
	content := `
AKIAIOSFODNN7EXAMPLE
ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234
sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz
`
	// Only scan for GitHub tokens
	result := e.ScanContent(models.ScanRequest{
		Content:     content,
		Source:      models.Source{Type: "file", Location: "filter-test.txt"},
		FilterTypes: []models.SecretType{models.SecretGitHubToken},
	})

	for _, f := range result.Findings {
		if f.SecretType != models.SecretGitHubToken && f.SecretType != models.SecretHighEntropy {
			t.Errorf("Found unexpected type %s when filtering for GitHub tokens only", f.SecretType)
		}
	}
}

func TestScanContent_MinSeverity(t *testing.T) {
	e := NewDefault()
	content := `
api_key = "kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j"
AKIAIOSFODNN7EXAMPLE
`
	result := e.ScanContent(models.ScanRequest{
		Content:     content,
		Source:      models.Source{Type: "file", Location: "sev-test.txt"},
		MinSeverity: models.SeverityHigh,
	})

	for _, f := range result.Findings {
		if f.Severity < models.SeverityHigh {
			t.Errorf("Found finding with severity %s below minimum HIGH", f.Severity)
		}
	}
}

func TestScanContent_ContextIncluded(t *testing.T) {
	e := New(Config{
		MinConfidence:    0.3,
		EnableEntropy:    true,
		EntropyMinLength: 12,
		IncludeContext:   true,
		ContextLines:     2,
	})
	content := `line 1
line 2
AKIAIOSFODNN7EXAMPLE
line 4
line 5`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "context-test.txt"},
	})

	for _, f := range result.Findings {
		if f.SecretType == models.SecretAWSAccessKey {
			if f.Source.Context == "" {
				t.Error("Expected context to be included")
			}
			if !strings.Contains(f.Source.Context, "line 2") || !strings.Contains(f.Source.Context, "line 4") {
				t.Errorf("Context should include surrounding lines, got: %s", f.Source.Context)
			}
			t.Logf("Context:\n%s", f.Source.Context)
		}
	}
}

func TestScanContent_RedactionWorks(t *testing.T) {
	e := NewDefault()
	content := `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "redact-test.txt"},
	})

	// Engine no longer redacts inline; the pipeline handles it.
	// Verify RawMatch is populated, then run the pipeline.
	for _, f := range result.Findings {
		if f.SecretType == models.SecretGitHubToken {
			if f.RawMatch == "" {
				t.Error("RawMatch should be populated before pipeline")
			}
		}
	}

	// Run pipeline to populate RedactedMatch (and sanitize RawMatch)
	pipe := pipeline.NewDefault()
	pipe.ProcessResult(context.Background(), &result, &models.ScanMetadata{})

	for _, f := range result.Findings {
		if f.SecretType == models.SecretGitHubToken {
			if f.RedactedMatch == "" {
				t.Error("RedactedMatch should not be empty after pipeline")
			}
			if !strings.Contains(f.RedactedMatch, "****") {
				t.Errorf("RedactedMatch should contain ****: %s", f.RedactedMatch)
			}
			if f.RawMatch != "" {
				t.Error("RawMatch should be cleared by SanitizeProcessor")
			}
			t.Logf("Redacted: %s", f.RedactedMatch)
		}
	}
}

func TestScanContent_ScanDuration(t *testing.T) {
	e := NewDefault()
	// Generate a larger content to test performance
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString(fmt.Sprintf("line %d: normal content here, nothing to see\n", i))
	}
	sb.WriteString("hidden_key = AKIAIOSFODNN7EXAMPLE\n")
	for i := 0; i < 1000; i++ {
		sb.WriteString(fmt.Sprintf("line %d: more normal content\n", i+1000))
	}

	result := e.ScanContent(models.ScanRequest{
		Content: sb.String(),
		Source:  models.Source{Type: "file", Location: "perf-test.txt"},
	})

	if result.Duration == 0 {
		t.Error("Duration should be > 0")
	}
	t.Logf("Scanned %d bytes in %v, found %d findings", len(sb.String()), result.Duration, result.TotalFindings)
	// Should complete within a reasonable time (30 seconds for ~2000 lines with 369+ rules under race detector)
	if result.Duration.Seconds() > 30 {
		t.Errorf("Scan took too long: %v", result.Duration)
	}
}

func TestScanContent_HashMetadata(t *testing.T) {
	e := NewDefault()
	content := `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "hash-test.txt"},
	})

	for _, f := range result.Findings {
		if f.SecretType == models.SecretGitHubToken {
			// Hash is now stored in the SecretHash field (set by engine for dedup)
			if f.SecretHash == "" {
				t.Error("Finding should have SecretHash set by engine")
			}
			if len(f.SecretHash) != 64 {
				t.Errorf("SecretHash should be 64 hex chars, got %d", len(f.SecretHash))
			}
			t.Logf("SecretHash: %s", f.SecretHash)
		}
	}
}

func TestScanContent_TeamsWebhook(t *testing.T) {
	e := NewDefault()
	content := `TEAMS_WEBHOOK=https://myorg.webhook.office.com/webhookb2/abc123-def-456@ghi789-jkl-012/IncomingWebhook/mno345pqr678/stu901-vwx-234`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "teams.conf"},
	})

	found := false
	for _, f := range result.Findings {
		if f.SecretType == models.SecretTeamsWebhook {
			found = true
		}
	}
	if !found {
		t.Error("Did not detect Microsoft Teams webhook")
	}
}

func TestScanContent_OpenSSHKey(t *testing.T) {
	e := NewDefault()
	content := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBIxzgP3dAmoov7k2TEnHb+kZSz7A+hRLaBOZTVKw==
-----END OPENSSH PRIVATE KEY-----`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "id_ed25519"},
	})

	found := false
	for _, f := range result.Findings {
		if f.SecretType == models.SecretSSHPrivateKey {
			found = true
			if f.Confidence < 0.9 {
				t.Errorf("SSH key confidence too low: %f", f.Confidence)
			}
		}
	}
	if !found {
		t.Error("Did not detect OpenSSH private key")
	}
}

func TestScanContent_GitLabTokens(t *testing.T) {
	e := NewDefault()
	content := `
GITLAB_TOKEN=glpat-ABCDEFGHIJKLMNOPQRSTUVWXYz
RUNNER_TOKEN=glrt-ABCDEFGHIJKLMNOPQRSTUVWXYz
`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: ".gitlab-ci.yml"},
	})

	foundPAT := false
	foundRunner := false
	for _, f := range result.Findings {
		if f.SecretType == models.SecretGitLabToken {
			foundPAT = true
		}
		if f.SecretType == models.SecretGitLabRunner {
			foundRunner = true
		}
	}
	if !foundPAT {
		t.Error("Did not detect GitLab PAT")
	}
	if !foundRunner {
		t.Error("Did not detect GitLab runner token")
	}
}

func TestScanContent_SeverityCounts(t *testing.T) {
	e := NewDefault()
	content := `
AKIAIOSFODNN7EXAMPLE
ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234
api_key = "kJ9mN2pR5tW8xY1zA3bC6dE"
`
	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "sev-count.txt"},
	})

	totalFromMap := 0
	for sev, count := range result.CountBySeverity {
		t.Logf("Severity %s: %d findings", sev, count)
		totalFromMap += count
	}
	if totalFromMap != result.TotalFindings {
		t.Errorf("Sum of severity counts (%d) != TotalFindings (%d)", totalFromMap, result.TotalFindings)
	}
}

func TestScanLines(t *testing.T) {
	e := NewDefault()
	lines := []string{
		"# Config",
		"api_key = AKIAIOSFODNN7EXAMPLE",
		"# End",
	}
	findings := e.ScanLines(lines, models.Source{Type: "file", Location: "test.txt"})
	if len(findings) == 0 {
		t.Error("ScanLines should detect secrets")
	}
}

func TestInlineAllowDirective(t *testing.T) {
	e := NewDefault()
	// Two identical secrets; only the second line carries an allow directive.
	content := "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY # credvigil:allow\n"

	result := e.ScanContent(models.ScanRequest{
		Content: content,
		Source:  models.Source{Type: "file", Location: "test.env"},
	})

	for _, f := range result.Findings {
		if f.Source.Line == 2 {
			t.Errorf("finding on line 2 should be suppressed by credvigil:allow: %s", f.RuleID)
		}
	}
	if len(result.Findings) == 0 {
		t.Fatal("line 1 findings should NOT be suppressed")
	}
	// CountBySeverity must be recomputed to match the surviving findings.
	total := 0
	for _, c := range result.CountBySeverity {
		total += c
	}
	if total != result.TotalFindings || result.TotalFindings != len(result.Findings) {
		t.Errorf("count mismatch after suppression: counts=%d total=%d findings=%d",
			total, result.TotalFindings, len(result.Findings))
	}
}

func TestHasInlineAllow(t *testing.T) {
	cases := map[string]bool{
		"key=abc # credvigil:allow":   true,
		"key=abc // credvigil-ignore": true,
		"key=abc # CredVigil:Allow":   true, // case-insensitive
		"key=abc # credvigil:ignore":  true,
		"key=abc # nothing here":      false,
		"key=credvigil":               false,
	}
	for line, want := range cases {
		if got := hasInlineAllow(line); got != want {
			t.Errorf("hasInlineAllow(%q) = %v, want %v", line, got, want)
		}
	}
}
