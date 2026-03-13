// Package rules defines the detection rules (regex patterns + metadata) for secret types.
package rules

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/credvigil/credvigil/pkg/models"
)

// Rule defines a single detection rule for identifying a type of secret.
type Rule struct {
	// Unique identifier for this rule
	ID string
	// Human-readable description
	Description string
	// The type of secret this rule detects
	SecretType models.SecretType
	// Severity if this rule matches
	Severity models.Severity
	// Compiled regex pattern
	Pattern *regexp.Regexp
	// Optional: secondary patterns that must also match (AND logic)
	SecondaryPatterns []*regexp.Regexp
	// Optional: patterns that if found near the match, REDUCE confidence
	FalsePositivePatterns []*regexp.Regexp
	// Keywords that should appear near the match to boost confidence
	Keywords []string
	// Whether this is a multi-line pattern (e.g., PEM blocks)
	MultiLine bool
	// Base confidence score (0.0 - 1.0) when pattern matches
	BaseConfidence float64
	// Whether this secret type can be verified via API
	Verifiable bool
	// Minimum entropy required for the captured group (0 = no requirement)
	MinEntropy float64
}

// RuleSet holds all compiled detection rules.
type RuleSet struct {
	mu    sync.RWMutex
	rules []Rule
	byID  map[string]*Rule
}

// NewRuleSet creates a new RuleSet with the default built-in rules.
func NewRuleSet() *RuleSet {
	rs := &RuleSet{
		byID: make(map[string]*Rule),
	}
	rs.loadBuiltinRules()
	return rs
}

// Rules returns all rules (thread-safe).
func (rs *RuleSet) Rules() []Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	result := make([]Rule, len(rs.rules))
	copy(result, rs.rules)
	return result
}

// GetRule returns a rule by ID.
func (rs *RuleSet) GetRule(id string) (*Rule, bool) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	r, ok := rs.byID[id]
	return r, ok
}

// AddRule adds a custom rule to the ruleset.
func (rs *RuleSet) AddRule(r Rule) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if _, exists := rs.byID[r.ID]; exists {
		return fmt.Errorf("rule with ID %q already exists", r.ID)
	}
	rs.rules = append(rs.rules, r)
	rs.byID[r.ID] = &rs.rules[len(rs.rules)-1]
	return nil
}

// Count returns the number of rules.
func (rs *RuleSet) Count() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return len(rs.rules)
}

// Common false positive indicator patterns
var fpPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)example|sample|test|dummy|placeholder|fake|mock|xxxx|your[_-]|my[_-]|insert[_-]|change[_-]me|replace[_-]|TODO|FIXME`),
	regexp.MustCompile(`(?i)documentation|template|tutorial|readme`),
}

func (rs *RuleSet) addRule(r Rule) {
	if r.FalsePositivePatterns == nil {
		r.FalsePositivePatterns = fpPatterns
	}
	rs.rules = append(rs.rules, r)
	rs.byID[r.ID] = &rs.rules[len(rs.rules)-1]
}

func (rs *RuleSet) loadBuiltinRules() {
	// ═══════════════════════════════════════
	// AWS
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "aws-access-key-id",
		Description:    "AWS Access Key ID",
		SecretType:     models.SecretAWSAccessKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?m)(?:^|[^A-Za-z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9]|$)`),
		Keywords:       []string{"aws", "access", "key", "AKIA"},
		BaseConfidence: 0.95,
		Verifiable:     true,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "aws-secret-access-key",
		Description:    "AWS Secret Access Key",
		SecretType:     models.SecretAWSSecretKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
		Keywords:       []string{"aws", "secret", "key"},
		BaseConfidence: 0.90,
		Verifiable:     true,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "aws-session-token",
		Description:    "AWS Session Token",
		SecretType:     models.SecretAWSSessionToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:aws_session_token|aws_security_token)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{100,500})['"]?`),
		Keywords:       []string{"aws", "session", "token", "security"},
		BaseConfidence: 0.85,
		MinEntropy:     4.0,
	})

	// ═══════════════════════════════════════
	// GCP
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "gcp-service-account-key",
		Description:    "GCP Service Account Key (JSON)",
		SecretType:     models.SecretGCPServiceAccount,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)"type"\s*:\s*"service_account"[\s\S]*?"private_key"\s*:\s*"(-----BEGIN [A-Z ]*PRIVATE KEY-----[^"]+-----END [A-Z ]*PRIVATE KEY-----\\n?)"`),
		Keywords:       []string{"service_account", "private_key", "gcp", "google"},
		BaseConfidence: 0.98,
		MultiLine:      true,
		Verifiable:     true,
	})
	rs.addRule(Rule{
		ID:             "gcp-oauth-token",
		Description:    "GCP OAuth Access Token",
		SecretType:     models.SecretGCPOAuth,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`ya29\.[0-9A-Za-z_-]{20,}`),
		Keywords:       []string{"google", "oauth", "gcp"},
		BaseConfidence: 0.85,
		Verifiable:     true,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════
	// Azure
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "azure-client-secret",
		Description:    "Azure AD Client Secret",
		SecretType:     models.SecretAzureClientSecret,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:azure|client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9~._-]{34,40})['"]?`),
		Keywords:       []string{"azure", "client_secret", "tenant"},
		BaseConfidence: 0.75,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "azure-storage-key",
		Description:    "Azure Storage Account Key",
		SecretType:     models.SecretAzureStorageKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:AccountKey|azure_storage_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{86,88})['"]?`),
		Keywords:       []string{"azure", "storage", "AccountKey"},
		BaseConfidence: 0.90,
		MinEntropy:     4.0,
	})

	// ═══════════════════════════════════════
	// GitHub
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "github-pat-classic",
		Description:    "GitHub Personal Access Token (Classic)",
		SecretType:     models.SecretGitHubToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
		Keywords:       []string{"github", "token", "pat"},
		BaseConfidence: 0.95,
		Verifiable:     true,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "github-fine-grained-pat",
		Description:    "GitHub Fine-Grained Personal Access Token",
		SecretType:     models.SecretGitHubFinegrained,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`),
		Keywords:       []string{"github", "token", "pat"},
		BaseConfidence: 0.98,
		Verifiable:     true,
	})
	rs.addRule(Rule{
		ID:             "github-oauth",
		Description:    "GitHub OAuth Access Token",
		SecretType:     models.SecretGitHubOAuth,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
		Keywords:       []string{"github", "oauth"},
		BaseConfidence: 0.95,
		Verifiable:     true,
	})
	rs.addRule(Rule{
		ID:             "github-app-token",
		Description:    "GitHub App Installation Token",
		SecretType:     models.SecretGitHubApp,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`),
		Keywords:       []string{"github", "app", "installation"},
		BaseConfidence: 0.95,
		Verifiable:     true,
	})
	rs.addRule(Rule{
		ID:             "github-app-refresh-token",
		Description:    "GitHub App User-to-Server Token",
		SecretType:     models.SecretGitHubApp,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`ghu_[A-Za-z0-9]{36}`),
		Keywords:       []string{"github", "refresh"},
		BaseConfidence: 0.95,
		Verifiable:     true,
	})

	// ═══════════════════════════════════════
	// GitLab
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "gitlab-pat",
		Description:    "GitLab Personal Access Token",
		SecretType:     models.SecretGitLabToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`),
		Keywords:       []string{"gitlab", "token"},
		BaseConfidence: 0.95,
		Verifiable:     true,
	})
	rs.addRule(Rule{
		ID:             "gitlab-pipeline-trigger",
		Description:    "GitLab Pipeline Trigger Token",
		SecretType:     models.SecretGitLabToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`glptt-[A-Za-z0-9]{40,}`),
		Keywords:       []string{"gitlab", "pipeline", "trigger"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "gitlab-runner-token",
		Description:    "GitLab Runner Registration Token",
		SecretType:     models.SecretGitLabRunner,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`glrt-[A-Za-z0-9_-]{20,}`),
		Keywords:       []string{"gitlab", "runner"},
		BaseConfidence: 0.95,
	})

	// ═══════════════════════════════════════
	// Slack
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "slack-bot-token",
		Description:    "Slack Bot Token",
		SecretType:     models.SecretSlackToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}`),
		Keywords:       []string{"slack", "bot", "token", "xoxb"},
		BaseConfidence: 0.95,
		Verifiable:     true,
	})
	rs.addRule(Rule{
		ID:             "slack-user-token",
		Description:    "Slack User OAuth Token",
		SecretType:     models.SecretSlackToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}`),
		Keywords:       []string{"slack", "user", "oauth", "xoxp"},
		BaseConfidence: 0.95,
		Verifiable:     true,
	})
	rs.addRule(Rule{
		ID:             "slack-app-token",
		Description:    "Slack App-Level Token",
		SecretType:     models.SecretSlackToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`xapp-[0-9]+-[A-Za-z0-9]+-[0-9]+-[A-Za-z0-9]+`),
		Keywords:       []string{"slack", "app"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "slack-webhook",
		Description:    "Slack Incoming Webhook URL",
		SecretType:     models.SecretSlackWebhook,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+`),
		Keywords:       []string{"slack", "webhook", "hooks"},
		BaseConfidence: 0.95,
	})

	// ═══════════════════════════════════════
	// Jira / Confluence / Atlassian
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "atlassian-api-token",
		Description:    "Atlassian (Jira/Confluence) API Token",
		SecretType:     models.SecretJiraToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:jira|atlassian|confluence)[_\-\s]*(?:api[_\-\s]*)?(?:token|key)\s*[=:]\s*['"]?([A-Za-z0-9]{24,})['"]?`),
		Keywords:       []string{"jira", "atlassian", "confluence", "api", "token"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "atlassian-oauth-secret",
		Description:    "Atlassian OAuth 2.0 Client Secret",
		SecretType:     models.SecretAtlassianOAuth,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:atlassian|jira|confluence)[_\-\s]*(?:oauth|client)[_\-\s]*secret\s*[=:]\s*['"]?([A-Za-z0-9_-]{24,})['"]?`),
		Keywords:       []string{"atlassian", "oauth", "client_secret"},
		BaseConfidence: 0.85,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "confluence-api-token",
		Description:    "Confluence Space or API Token",
		SecretType:     models.SecretConfluenceToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)confluence[_\-\s]*(?:space[_\-\s]*)?(?:token|secret|key)\s*[=:]\s*['"]?([A-Za-z0-9]{24,})['"]?`),
		Keywords:       []string{"confluence", "space", "wiki"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "atlassian-webhook-secret",
		Description:    "Atlassian Webhook Secret",
		SecretType:     models.SecretJiraToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:atlassian|jira|confluence)[_\-\s]*webhook[_\-\s]*secret\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"atlassian", "webhook", "secret"},
		BaseConfidence: 0.85,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════
	// Stack Overflow / Stack Enterprise
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "stackoverflow-pat",
		Description:    "Stack Overflow for Teams PAT",
		SecretType:     models.SecretStackOverflowKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:stackoverflow|stack_overflow|stack[_\-]?exchange)[_\-\s]*(?:api[_\-\s]*)?(?:key|token|pat)\s*[=:]\s*['"]?([A-Za-z0-9()]{20,})['"]?`),
		Keywords:       []string{"stackoverflow", "stack_overflow", "stackexchange"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "stack-enterprise-token",
		Description:    "Stack Overflow Enterprise API Token",
		SecretType:     models.SecretStackEnterpriseKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:stack[_\-]?enterprise|soe)[_\-\s]*(?:api[_\-\s]*)?(?:key|token|secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{24,})['"]?`),
		Keywords:       []string{"stack", "enterprise", "soe"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════
	// Microsoft Teams / SharePoint
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "teams-webhook",
		Description:    "Microsoft Teams Webhook URL",
		SecretType:     models.SecretTeamsWebhook,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9-]+@[A-Za-z0-9-]+/IncomingWebhook/[A-Za-z0-9]+/[A-Za-z0-9-]+`),
		Keywords:       []string{"teams", "webhook", "office"},
		BaseConfidence: 0.95,
	})

	// ═══════════════════════════════════════
	// Private Keys (Multi-line)
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "private-key-rsa",
		Description:    "RSA Private Key",
		SecretType:     models.SecretPrivateKeyRSA,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----`),
		MultiLine:      true,
		BaseConfidence: 0.99,
	})
	rs.addRule(Rule{
		ID:             "private-key-ec",
		Description:    "EC Private Key",
		SecretType:     models.SecretPrivateKeyEC,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----`),
		MultiLine:      true,
		BaseConfidence: 0.99,
	})
	rs.addRule(Rule{
		ID:             "private-key-generic",
		Description:    "Generic Private Key",
		SecretType:     models.SecretPrivateKeyGeneric,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----`),
		MultiLine:      true,
		BaseConfidence: 0.99,
	})
	rs.addRule(Rule{
		ID:             "private-key-pkcs8-encrypted",
		Description:    "PKCS#8 Encrypted Private Key",
		SecretType:     models.SecretPrivateKeyPKCS8,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`-----BEGIN ENCRYPTED PRIVATE KEY-----[\s\S]*?-----END ENCRYPTED PRIVATE KEY-----`),
		MultiLine:      true,
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "openssh-private-key",
		Description:    "OpenSSH Private Key",
		SecretType:     models.SecretSSHPrivateKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----`),
		MultiLine:      true,
		BaseConfidence: 0.99,
	})
	rs.addRule(Rule{
		ID:             "pgp-private-key",
		Description:    "PGP Private Key Block",
		SecretType:     models.SecretPGPPrivateKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----`),
		MultiLine:      true,
		BaseConfidence: 0.99,
	})

	// ═══════════════════════════════════════
	// Database Connection Strings
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "postgres-uri",
		Description:    "PostgreSQL Connection URI with Password",
		SecretType:     models.SecretPostgresURI,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`postgres(?:ql)?://[^:]+:([^@]{3,})@[^/\s]+`),
		Keywords:       []string{"postgres", "psql", "database"},
		BaseConfidence: 0.90,
		MinEntropy:     2.0,
	})
	rs.addRule(Rule{
		ID:             "mysql-uri",
		Description:    "MySQL Connection URI with Password",
		SecretType:     models.SecretMySQLURI,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`mysql://[^:]+:(.+)@[\w.-]+`),
		Keywords:       []string{"mysql", "database"},
		BaseConfidence: 0.90,
		MinEntropy:     2.0,
	})
	rs.addRule(Rule{
		ID:             "mongodb-uri",
		Description:    "MongoDB Connection URI with Password",
		SecretType:     models.SecretMongoDBURI,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`mongodb(?:\+srv)?://[^:]+:(.+)@[\w.-]+`),
		Keywords:       []string{"mongodb", "mongo", "database"},
		BaseConfidence: 0.90,
		MinEntropy:     2.0,
	})
	rs.addRule(Rule{
		ID:             "redis-uri",
		Description:    "Redis Connection URI with Password",
		SecretType:     models.SecretRedisURI,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`redis://[^:]*:([^@]{3,})@[^/\s]+`),
		Keywords:       []string{"redis", "cache"},
		BaseConfidence: 0.85,
		MinEntropy:     2.0,
	})
	rs.addRule(Rule{
		ID:             "generic-db-password",
		Description:    "Database Password in Configuration",
		SecretType:     models.SecretDBPassword,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:db|database|sql|mysql|postgres|mongo|redis)[_\-]?(?:pass(?:word)?)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?`),
		Keywords:       []string{"database", "password", "db_pass"},
		BaseConfidence: 0.70,
		MinEntropy:     2.5,
	})

	// ═══════════════════════════════════════
	// JWT
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "json-web-token",
		Description:    "JSON Web Token",
		SecretType:     models.SecretJWT,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		Keywords:       []string{"jwt", "bearer", "authorization"},
		BaseConfidence: 0.90,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════
	// Bearer / Basic Auth
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "bearer-token",
		Description:    "Bearer Token in Authorization Header",
		SecretType:     models.SecretBearerToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:authorization|bearer)\s*[=:]\s*['"]?Bearer\s+([A-Za-z0-9_\-.~+/]+=*)['"]?`),
		Keywords:       []string{"bearer", "authorization", "token"},
		BaseConfidence: 0.75,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "basic-auth",
		Description:    "Basic Auth Credentials in URL",
		SecretType:     models.SecretBasicAuth,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`https?://([^:]+):([^@]{3,})@[a-zA-Z0-9]`),
		Keywords:       []string{"http", "basic", "auth"},
		BaseConfidence: 0.80,
		MinEntropy:     2.0,
	})

	// ═══════════════════════════════════════
	// Stripe
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "stripe-secret-key",
		Description:    "Stripe Secret API Key",
		SecretType:     models.SecretStripeKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`),
		Keywords:       []string{"stripe", "secret", "payment"},
		BaseConfidence: 0.98,
		Verifiable:     true,
	})
	rs.addRule(Rule{
		ID:             "stripe-restricted-key",
		Description:    "Stripe Restricted API Key",
		SecretType:     models.SecretStripeKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`rk_live_[A-Za-z0-9]{24,}`),
		Keywords:       []string{"stripe", "restricted"},
		BaseConfidence: 0.95,
		Verifiable:     true,
	})

	// ═══════════════════════════════════════
	// Twilio
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "twilio-api-key",
		Description:    "Twilio API Key",
		SecretType:     models.SecretTwilioKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		Keywords:       []string{"twilio"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════
	// SendGrid
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "sendgrid-api-key",
		Description:    "SendGrid API Key",
		SecretType:     models.SecretSendgridKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`),
		Keywords:       []string{"sendgrid", "email"},
		BaseConfidence: 0.98,
		Verifiable:     true,
	})

	// ═══════════════════════════════════════
	// Mailgun
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "mailgun-api-key",
		Description:    "Mailgun API Key",
		SecretType:     models.SecretMailgunKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`key-[A-Za-z0-9]{32}`),
		Keywords:       []string{"mailgun", "email"},
		BaseConfidence: 0.85,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════
	// Telegram
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "telegram-bot-token",
		Description:    "Telegram Bot Token",
		SecretType:     models.SecretTelegramBot,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9_-]{35}`),
		Keywords:       []string{"telegram", "bot"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════
	// Discord
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "discord-bot-token",
		Description:    "Discord Bot Token",
		SecretType:     models.SecretDiscordToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:discord|bot)\s*(?:token)?\s*[=:]\s*['"]?([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})['"]?`),
		Keywords:       []string{"discord", "bot", "token"},
		BaseConfidence: 0.85,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════
	// NPM
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "npm-token",
		Description:    "NPM Access Token",
		SecretType:     models.SecretNpmToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		Keywords:       []string{"npm", "token", "registry"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "npm-token-npmrc",
		Description:    "NPM Token in .npmrc",
		SecretType:     models.SecretNpmToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`//registry\.npmjs\.org/:_authToken=([A-Za-z0-9_-]+)`),
		Keywords:       []string{"npm", "registry", "authToken"},
		BaseConfidence: 0.90,
	})

	// ═══════════════════════════════════════
	// PyPI
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "pypi-token",
		Description:    "PyPI API Token",
		SecretType:     models.SecretPyPIToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`pypi-[A-Za-z0-9_-]{16,}`),
		Keywords:       []string{"pypi", "pip", "python"},
		BaseConfidence: 0.95,
	})

	// ═══════════════════════════════════════
	// Docker
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "docker-auth",
		Description:    "Docker Registry Auth Config",
		SecretType:     models.SecretDockerAuth,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)"auth"\s*:\s*"([A-Za-z0-9+/=]{20,})"`),
		Keywords:       []string{"docker", "registry", "auth"},
		BaseConfidence: 0.75,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════
	// HashiCorp Vault
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "vault-token",
		Description:    "HashiCorp Vault Token",
		SecretType:     models.SecretVaultToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?:hvs|s)\.[A-Za-z0-9]{24,}`),
		Keywords:       []string{"vault", "token", "hashicorp"},
		BaseConfidence: 0.90,
		Verifiable:     true,
	})

	// ═══════════════════════════════════════
	// Terraform Cloud
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "terraform-cloud-token",
		Description:    "Terraform Cloud API Token",
		SecretType:     models.SecretTerraformToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}`),
		Keywords:       []string{"terraform", "atlas", "cloud"},
		BaseConfidence: 0.95,
	})

	// ═══════════════════════════════════════
	// Heroku
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "heroku-api-key",
		Description:    "Heroku API Key",
		SecretType:     models.SecretHerokuKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:heroku[_\-\s]*(?:api[_\-\s]*)?(?:key|token))\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?`),
		Keywords:       []string{"heroku", "api", "key"},
		BaseConfidence: 0.85,
	})

	// ═══════════════════════════════════════
	// Datadog
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "datadog-api-key",
		Description:    "Datadog API Key",
		SecretType:     models.SecretDatadogKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:datadog|dd)[_\-\s]*(?:api[_\-\s]*)?key\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Keywords:       []string{"datadog", "dd", "monitoring"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════
	// Firebase
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "firebase-api-key",
		Description:    "Firebase API Key",
		SecretType:     models.SecretFirebaseKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		Keywords:       []string{"firebase", "google", "api"},
		BaseConfidence: 0.85,
	})

	// ═══════════════════════════════════════
	// OpenAI
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "openai-api-key",
		Description:    "OpenAI API Key",
		SecretType:     models.SecretOpenAIKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`),
		Keywords:       []string{"openai", "api", "key"},
		BaseConfidence: 0.98,
		Verifiable:     true,
	})
	rs.addRule(Rule{
		ID:             "openai-api-key-v2",
		Description:    "OpenAI API Key (new format)",
		SecretType:     models.SecretOpenAIKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{40,}`),
		Keywords:       []string{"openai", "api", "key"},
		BaseConfidence: 0.95,
		Verifiable:     true,
	})

	// ═══════════════════════════════════════
	// Anthropic
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "anthropic-api-key",
		Description:    "Anthropic API Key",
		SecretType:     models.SecretAnthropicKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{40,}`),
		Keywords:       []string{"anthropic", "claude", "api"},
		BaseConfidence: 0.95,
		Verifiable:     true,
	})

	// ═══════════════════════════════════════
	// Generic Patterns (lower confidence)
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "generic-api-key",
		Description:    "Generic API Key Assignment",
		SecretType:     models.SecretAPIKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:api[_\-\s]*key|apikey|api[_\-\s]*secret|api[_\-\s]*token)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`),
		Keywords:       []string{"api", "key", "secret", "token"},
		BaseConfidence: 0.55,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "generic-secret",
		Description:    "Generic Secret/Password Assignment",
		SecretType:     models.SecretGeneric,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:secret|password|passwd|pwd|token|credential|auth_key|private_key|access_key)\s*[=:]\s*['"]?([^\s'"]{8,80})['"]?`),
		Keywords:       []string{"secret", "password", "token", "credential"},
		BaseConfidence: 0.45,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "password-in-url",
		Description:    "Password Embedded in URL",
		SecretType:     models.SecretPasswordHash,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`[a-zA-Z]+://[^:]+:([^@\s]{3,})@[a-zA-Z0-9]`),
		Keywords:       []string{"://", "password", "url"},
		BaseConfidence: 0.80,
		MinEntropy:     2.0,
	})

	// ═══════════════════════════════════════
	// Shopify
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "shopify-access-token",
		Description:    "Shopify Access Token",
		SecretType:     models.SecretShopifyToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`),
		Keywords:       []string{"shopify", "token"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "shopify-shared-secret",
		Description:    "Shopify Shared Secret",
		SecretType:     models.SecretShopifyToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`),
		Keywords:       []string{"shopify", "secret"},
		BaseConfidence: 0.95,
	})

	// ═══════════════════════════════════════
	// Algolia
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "algolia-api-key",
		Description:    "Algolia API Key",
		SecretType:     models.SecretAlgoliaKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:algolia[_\-\s]*(?:api[_\-\s]*)?(?:key|secret))\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Keywords:       []string{"algolia", "search"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════
	// Square
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "square-access-token",
		Description:    "Square Access Token",
		SecretType:     models.SecretSquareToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`sq0atp-[A-Za-z0-9_-]{22}`),
		Keywords:       []string{"square", "payment"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "square-oauth-secret",
		Description:    "Square OAuth Secret",
		SecretType:     models.SecretSquareToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`sq0csp-[A-Za-z0-9_-]{43}`),
		Keywords:       []string{"square", "oauth"},
		BaseConfidence: 0.95,
	})

	// ═══════════════════════════════════════
	// CI/CD Tokens
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "circleci-token",
		Description:    "CircleCI Personal API Token",
		SecretType:     models.SecretCircleCIToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:circle[_\-\s]*(?:ci[_\-\s]*)?(?:token|key))\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`),
		Keywords:       []string{"circleci", "ci", "token"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "codecov-token",
		Description:    "Codecov Upload Token",
		SecretType:     models.SecretCodecovToken,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:codecov[_\-\s]*token)\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?`),
		Keywords:       []string{"codecov", "coverage"},
		BaseConfidence: 0.80,
	})

	// ═══════════════════════════════════════
	// Mailchimp
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "mailchimp-api-key",
		Description:    "Mailchimp API Key",
		SecretType:     models.SecretMailchimpKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`[a-f0-9]{32}-us[0-9]{1,2}`),
		Keywords:       []string{"mailchimp", "email"},
		BaseConfidence: 0.90,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════
	// New Relic
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "newrelic-api-key",
		Description:    "New Relic API Key",
		SecretType:     models.SecretNewRelicKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`NRAK-[A-Z0-9]{27}`),
		Keywords:       []string{"newrelic", "monitoring"},
		BaseConfidence: 0.95,
	})

	// ═══════════════════════════════════════
	// NuGet
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "nuget-api-key",
		Description:    "NuGet API Key",
		SecretType:     models.SecretNuGetKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`oy2[A-Za-z0-9]{43}`),
		Keywords:       []string{"nuget", "dotnet"},
		BaseConfidence: 0.90,
	})

	// ═══════════════════════════════════════
	// Bitbucket
	// ═══════════════════════════════════════
	rs.addRule(Rule{
		ID:             "bitbucket-app-password",
		Description:    "Bitbucket App Password/Token",
		SecretType:     models.SecretBitbucketToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:bitbucket[_\-\s]*(?:app[_\-\s]*)?(?:password|token|secret))\s*[=:]\s*['"]?([A-Za-z0-9]{18,})['"]?`),
		Keywords:       []string{"bitbucket", "app", "password"},
		BaseConfidence: 0.70,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// AI / ML SERVICES (the biggest growth category)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "google-gemini-key",
		Description:    "Google Gemini / AI Studio API Key",
		SecretType:     models.SecretGeminiKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`AIzaSy[A-Za-z0-9_-]{33}`),
		Keywords:       []string{"gemini", "google", "ai", "studio"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "huggingface-token",
		Description:    "Hugging Face Access Token",
		SecretType:     models.SecretHuggingFace,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`hf_[A-Za-z0-9]{34,}`),
		Keywords:       []string{"huggingface", "hf", "transformers"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "cohere-api-key",
		Description:    "Cohere API Key",
		SecretType:     models.SecretCohereKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:cohere[_\-]?(?:api)?[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9]{40})['"]?`),
		Keywords:       []string{"cohere", "co:here"},
		BaseConfidence: 0.80,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "mistral-api-key",
		Description:    "Mistral AI API Key",
		SecretType:     models.SecretMistralKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:mistral[_\-]?(?:api)?[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9]{32,})['"]?`),
		Keywords:       []string{"mistral", "mistralai"},
		BaseConfidence: 0.80,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "replicate-api-token",
		Description:    "Replicate API Token",
		SecretType:     models.SecretReplicateKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`r8_[A-Za-z0-9]{36,}`),
		Keywords:       []string{"replicate"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "groq-api-key",
		Description:    "Groq API Key",
		SecretType:     models.SecretGroqKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`gsk_[A-Za-z0-9]{48,}`),
		Keywords:       []string{"groq"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "deepseek-api-key",
		Description:    "DeepSeek API Key",
		SecretType:     models.SecretDeepseekKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:deepseek[_\-]?(?:api)?[_\-]?key)\s*[=:]\s*['"]?(sk-[A-Za-z0-9]{32,})['"]?`),
		Keywords:       []string{"deepseek"},
		BaseConfidence: 0.85,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "perplexity-api-key",
		Description:    "Perplexity API Key",
		SecretType:     models.SecretPerplexityKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`pplx-[A-Za-z0-9]{48,}`),
		Keywords:       []string{"perplexity", "pplx"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "stability-ai-key",
		Description:    "Stability AI API Key",
		SecretType:     models.SecretStabilityKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`sk-[A-Za-z0-9]{48,}`),
		Keywords:       []string{"stability", "stable-diffusion", "sdxl"},
		BaseConfidence: 0.70,
		MinEntropy:     4.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// CLOUD / HOSTING (what small businesses actually use)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "digitalocean-pat",
		Description:    "DigitalOcean Personal Access Token",
		SecretType:     models.SecretDigitalOceanToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
		Keywords:       []string{"digitalocean", "do_"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "digitalocean-oauth",
		Description:    "DigitalOcean OAuth Token",
		SecretType:     models.SecretDigitalOceanToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`doo_v1_[a-f0-9]{64}`),
		Keywords:       []string{"digitalocean"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "digitalocean-refresh",
		Description:    "DigitalOcean Refresh Token",
		SecretType:     models.SecretDigitalOceanToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`dor_v1_[a-f0-9]{64}`),
		Keywords:       []string{"digitalocean"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "digitalocean-spaces-key",
		Description:    "DigitalOcean Spaces Access Key",
		SecretType:     models.SecretDigitalOceanSpaces,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:do_spaces|digitalocean_spaces)[_\-]?(?:access)?[_\-]?key\s*[=:]\s*['"]?([A-Z0-9]{20})['"]?`),
		Keywords:       []string{"digitalocean", "spaces", "s3"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "cloudflare-api-token",
		Description:    "Cloudflare API Token",
		SecretType:     models.SecretCloudflareToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:cloudflare|cf)[_\-]?(?:api)?[_\-]?token\s*[=:]\s*['"]?([A-Za-z0-9_-]{40})['"]?`),
		Keywords:       []string{"cloudflare", "cf_"},
		BaseConfidence: 0.85,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "cloudflare-global-key",
		Description:    "Cloudflare Global API Key",
		SecretType:     models.SecretCloudflareKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:cloudflare|cf)[_\-]?(?:global)?[_\-]?(?:api)?[_\-]?key\s*[=:]\s*['"]?([a-f0-9]{37})['"]?`),
		Keywords:       []string{"cloudflare", "global", "api_key"},
		BaseConfidence: 0.85,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "vercel-token",
		Description:    "Vercel Access Token",
		SecretType:     models.SecretVercelToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:vercel[_\-]?(?:access)?[_\-]?token)\s*[=:]\s*['"]?([A-Za-z0-9]{24,})['"]?`),
		Keywords:       []string{"vercel"},
		BaseConfidence: 0.80,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "netlify-token",
		Description:    "Netlify Personal Access Token",
		SecretType:     models.SecretNetlifyToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:netlify[_\-]?(?:auth)?[_\-]?token)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?`),
		Keywords:       []string{"netlify"},
		BaseConfidence: 0.80,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "supabase-anon-key",
		Description:    "Supabase Anonymous/Public Key",
		SecretType:     models.SecretSupabaseKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}`),
		Keywords:       []string{"supabase", "anon", "public"},
		BaseConfidence: 0.70,
	})
	rs.addRule(Rule{
		ID:             "supabase-service-key",
		Description:    "Supabase Service Role Key",
		SecretType:     models.SecretSupabaseKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:supabase[_\-]?service[_\-]?(?:role)?[_\-]?key)\s*[=:]\s*['"]?(eyJ[A-Za-z0-9_-]{100,})['"]?`),
		Keywords:       []string{"supabase", "service_role", "service"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "railway-token",
		Description:    "Railway API Token",
		SecretType:     models.SecretRailwayToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:railway[_\-]?token)\s*[=:]\s*['"]?([a-f0-9-]{36,})['"]?`),
		Keywords:       []string{"railway"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "render-api-key",
		Description:    "Render API Key",
		SecretType:     models.SecretRenderKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`rnd_[A-Za-z0-9]{32,}`),
		Keywords:       []string{"render"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "fly-io-token",
		Description:    "Fly.io Access Token",
		SecretType:     models.SecretFlyToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`FlyV1\s+fm2_[A-Za-z0-9_-]{40,}`),
		Keywords:       []string{"fly", "flyio", "fly.io"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "linode-token",
		Description:    "Linode/Akamai Personal Access Token",
		SecretType:     models.SecretLinodeToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:linode[_\-]?(?:api)?[_\-]?token)\s*[=:]\s*['"]?([a-f0-9]{64})['"]?`),
		Keywords:       []string{"linode", "akamai"},
		BaseConfidence: 0.85,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// PAYMENT / FINTECH (expanded for global market)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "razorpay-key-id",
		Description:    "Razorpay Key ID",
		SecretType:     models.SecretRazorpayKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`rzp_(?:live|test)_[A-Za-z0-9]{14,}`),
		Keywords:       []string{"razorpay"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "razorpay-secret",
		Description:    "Razorpay Key Secret",
		SecretType:     models.SecretRazorpayKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:razorpay[_\-]?(?:key)?[_\-]?secret)\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`),
		Keywords:       []string{"razorpay", "secret"},
		BaseConfidence: 0.85,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "plaid-client-id",
		Description:    "Plaid Client ID",
		SecretType:     models.SecretPlaidKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:plaid[_\-]?client[_\-]?id)\s*[=:]\s*['"]?([a-f0-9]{24})['"]?`),
		Keywords:       []string{"plaid"},
		BaseConfidence: 0.80,
	})
	rs.addRule(Rule{
		ID:             "plaid-secret",
		Description:    "Plaid API Secret",
		SecretType:     models.SecretPlaidKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:plaid[_\-]?secret)\s*[=:]\s*['"]?([a-f0-9]{30})['"]?`),
		Keywords:       []string{"plaid", "secret"},
		BaseConfidence: 0.85,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "coinbase-api-key",
		Description:    "Coinbase API Key",
		SecretType:     models.SecretCoinbaseKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:coinbase[_\-]?(?:api)?[_\-]?(?:key|secret))\s*[=:]\s*['"]?([A-Za-z0-9]{16,})['"]?`),
		Keywords:       []string{"coinbase"},
		BaseConfidence: 0.80,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "paypal-client-secret",
		Description:    "PayPal Client Secret",
		SecretType:     models.SecretPayPalSecret,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:paypal[_\-]?(?:client)?[_\-]?secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?`),
		Keywords:       []string{"paypal", "secret"},
		BaseConfidence: 0.85,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "adyen-api-key",
		Description:    "Adyen API Key",
		SecretType:     models.SecretAdyenKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:adyen[_\-]?(?:api)?[_\-]?key)\s*[=:]\s*['"]?(AQE[a-z0-9]{5,}\\.[A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"adyen"},
		BaseConfidence: 0.90,
	})

	// ═══════════════════════════════════════════════════════════════
	// E-COMMERCE
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "amazon-mws-key",
		Description:    "Amazon MWS / SP-API Secret Key",
		SecretType:     models.SecretAmazonMWSKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:(?:mws|sp_api|amazon_sp)\s*[_\-]?\s*(?:secret|auth)\s*[_\-]?\s*(?:key|token))\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
		Keywords:       []string{"mws", "amazon", "sp-api", "seller"},
		BaseConfidence: 0.85,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "etsy-api-key",
		Description:    "Etsy API Key / Keystring",
		SecretType:     models.SecretEtsyKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:etsy[_\-]?(?:api)?[_\-]?(?:key|secret))\s*[=:]\s*['"]?([A-Za-z0-9]{24,})['"]?`),
		Keywords:       []string{"etsy"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// MARKETING / ANALYTICS / CRM
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "hubspot-api-key",
		Description:    "HubSpot API Key",
		SecretType:     models.SecretHubSpotKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:hubspot|hapi)[_\-]?(?:api)?[_\-]?key\s*[=:]\s*['"]?([a-f0-9-]{36,})['"]?`),
		Keywords:       []string{"hubspot", "hapi"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "hubspot-private-app",
		Description:    "HubSpot Private App Access Token",
		SecretType:     models.SecretHubSpotKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`pat-(?:na|eu)1-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`),
		Keywords:       []string{"hubspot", "private"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "mixpanel-token",
		Description:    "Mixpanel Project Token / API Secret",
		SecretType:     models.SecretMixpanelToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:mixpanel[_\-]?(?:token|secret|api[_\-]?secret))\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Keywords:       []string{"mixpanel"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "segment-write-key",
		Description:    "Segment Write Key",
		SecretType:     models.SecretSegmentKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:segment[_\-]?write[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`),
		Keywords:       []string{"segment", "analytics"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "intercom-token",
		Description:    "Intercom Access Token",
		SecretType:     models.SecretIntercomToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:intercom[_\-]?(?:access)?[_\-]?token)\s*[=:]\s*['"]?([A-Za-z0-9=_-]{40,})['"]?`),
		Keywords:       []string{"intercom"},
		BaseConfidence: 0.80,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "amplitude-api-key",
		Description:    "Amplitude API Key",
		SecretType:     models.SecretAmplitudeKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:amplitude[_\-]?(?:api)?[_\-]?key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Keywords:       []string{"amplitude"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "posthog-api-key",
		Description:    "PostHog API Key",
		SecretType:     models.SecretPostHogKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`phc_[A-Za-z0-9]{30,}`),
		Keywords:       []string{"posthog"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "zendesk-token",
		Description:    "Zendesk API Token",
		SecretType:     models.SecretZendeskToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:zendesk[_\-]?(?:api)?[_\-]?token)\s*[=:]\s*['"]?([A-Za-z0-9]{40,})['"]?`),
		Keywords:       []string{"zendesk"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "freshdesk-api-key",
		Description:    "Freshdesk API Key",
		SecretType:     models.SecretFreshdeskKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:freshdesk[_\-]?(?:api)?[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`),
		Keywords:       []string{"freshdesk"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "salesforce-oauth-secret",
		Description:    "Salesforce OAuth Client Secret",
		SecretType:     models.SecretSalesforceOAuth,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:salesforce|sfdc)[_\-]?(?:client)?[_\-]?secret\s*[=:]\s*['"]?([A-F0-9]{64})['"]?`),
		Keywords:       []string{"salesforce", "sfdc"},
		BaseConfidence: 0.85,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "zoho-token",
		Description:    "Zoho OAuth / API Token",
		SecretType:     models.SecretZohoToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:zoho[_\-]?(?:oauth|api|auth)[_\-]?(?:token|key|secret))\s*[=:]\s*['"]?([A-Za-z0-9.]{30,})['"]?`),
		Keywords:       []string{"zoho"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// AUTH / IDENTITY
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "auth0-client-secret",
		Description:    "Auth0 Client Secret",
		SecretType:     models.SecretAuth0Secret,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:auth0[_\-]?client[_\-]?secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{32,})['"]?`),
		Keywords:       []string{"auth0"},
		BaseConfidence: 0.85,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "okta-token",
		Description:    "Okta API Token",
		SecretType:     models.SecretOktaToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`00[A-Za-z0-9_-]{40}\.[A-Za-z0-9_-]+`),
		Keywords:       []string{"okta", "ssws"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "clerk-secret-key",
		Description:    "Clerk Secret Key",
		SecretType:     models.SecretClerkKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`sk_(?:live|test)_[A-Za-z0-9]{20,}`),
		Keywords:       []string{"clerk"},
		BaseConfidence: 0.85,
	})

	// ═══════════════════════════════════════════════════════════════
	// OBSERVABILITY / LOGGING
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "sentry-dsn",
		Description:    "Sentry DSN (includes auth token)",
		SecretType:     models.SecretSentryDSN,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io/[0-9]+`),
		Keywords:       []string{"sentry", "dsn"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "grafana-api-key",
		Description:    "Grafana API Key / Service Account Token",
		SecretType:     models.SecretGrafanaKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?:glsa_|eyJr)[A-Za-z0-9_-]{20,}`),
		Keywords:       []string{"grafana"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "grafana-cloud-token",
		Description:    "Grafana Cloud API Token",
		SecretType:     models.SecretGrafanaKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`glc_[A-Za-z0-9_-]{30,}`),
		Keywords:       []string{"grafana", "cloud"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "splunk-hec-token",
		Description:    "Splunk HEC Token",
		SecretType:     models.SecretSplunkToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:splunk[_\-]?(?:hec)?[_\-]?token)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`),
		Keywords:       []string{"splunk", "hec"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "pagerduty-api-key",
		Description:    "PagerDuty API Key / Integration Key",
		SecretType:     models.SecretPagerDutyKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:pagerduty|pd)[_\-]?(?:api|integration|routing)?[_\-]?key\s*[=:]\s*['"]?([A-Za-z0-9+/]{20,})['"]?`),
		Keywords:       []string{"pagerduty"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "elastic-api-key",
		Description:    "Elasticsearch / Elastic Cloud API Key",
		SecretType:     models.SecretElasticKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:elastic(?:search)?[_\-]?(?:api)?[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9_-]{30,})['"]?`),
		Keywords:       []string{"elastic", "elasticsearch", "kibana"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "loggly-token",
		Description:    "Loggly Customer Token",
		SecretType:     models.SecretLogglyToken,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:loggly[_\-]?(?:customer)?[_\-]?token)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`),
		Keywords:       []string{"loggly"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "otel-exporter-otlp-headers",
		Description:    "OpenTelemetry OTLP Exporter Auth Header",
		SecretType:     models.SecretOTelToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:otel[_\-]?exporter[_\-]?otlp[_\-]?headers)\s*[=:]\s*['"]?(?:.*(?:api[_\-]?key|authorization|token)\s*=\s*)([A-Za-z0-9_\-]{20,})['"]?`),
		Keywords:       []string{"otel", "otlp", "opentelemetry", "exporter"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "otel-exporter-otlp-token",
		Description:    "OpenTelemetry OTLP Exporter Token",
		SecretType:     models.SecretOTelToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:otel[_\-]?(?:access)?[_\-]?token|opentelemetry[_\-]?token)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`),
		Keywords:       []string{"otel", "opentelemetry", "tracing"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// EMAIL (expanded)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "postmark-server-token",
		Description:    "Postmark Server API Token",
		SecretType:     models.SecretPostmarkKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:postmark[_\-]?(?:server)?[_\-]?(?:api)?[_\-]?token)\s*[=:]\s*['"]?([a-f0-9-]{36})['"]?`),
		Keywords:       []string{"postmark"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "resend-api-key",
		Description:    "Resend API Key",
		SecretType:     models.SecretResendKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`re_[A-Za-z0-9]{20,}`),
		Keywords:       []string{"resend"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "amazon-ses-smtp",
		Description:    "Amazon SES SMTP Password",
		SecretType:     models.SecretAmazonSESKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:ses[_\-]?smtp[_\-]?(?:password|secret))\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40,})['"]?`),
		Keywords:       []string{"ses", "smtp", "amazon"},
		BaseConfidence: 0.80,
		MinEntropy:     4.0,
	})

	// ═══════════════════════════════════════════════════════════════
	// MAPS / LOCATION
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "google-maps-api-key",
		Description:    "Google Maps / Cloud API Key",
		SecretType:     models.SecretGoogleMapsKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`AIzaSy[A-Za-z0-9_-]{33}`),
		Keywords:       []string{"google", "maps", "places", "geocode"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "mapbox-token",
		Description:    "Mapbox Access Token",
		SecretType:     models.SecretMapboxToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?:pk|sk|tk)\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}`),
		Keywords:       []string{"mapbox"},
		BaseConfidence: 0.95,
	})

	// ═══════════════════════════════════════════════════════════════
	// SOCIAL MEDIA APIs
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "twitter-api-key",
		Description:    "Twitter/X API Key",
		SecretType:     models.SecretTwitterKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:twitter|x_?(?:api))[_\-]?(?:api)?[_\-]?(?:key|secret|consumer)\s*[=:]\s*['"]?([A-Za-z0-9]{25,})['"]?`),
		Keywords:       []string{"twitter", "x_api", "consumer"},
		BaseConfidence: 0.75,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "twitter-bearer",
		Description:    "Twitter/X Bearer Token",
		SecretType:     models.SecretTwitterKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,}`),
		Keywords:       []string{"twitter", "bearer"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "facebook-access-token",
		Description:    "Facebook / Meta Access Token",
		SecretType:     models.SecretFacebookToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`EAA[A-Za-z0-9]{100,}`),
		Keywords:       []string{"facebook", "meta", "fb"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "linkedin-token",
		Description:    "LinkedIn OAuth Token",
		SecretType:     models.SecretLinkedInToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:linkedin[_\-]?(?:access)?[_\-]?token)\s*[=:]\s*['"]?(AQV[A-Za-z0-9_-]{50,})['"]?`),
		Keywords:       []string{"linkedin"},
		BaseConfidence: 0.85,
	})

	// ═══════════════════════════════════════════════════════════════
	// STORAGE / CDN
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "cloudinary-url",
		Description:    "Cloudinary API URL (contains secret)",
		SecretType:     models.SecretCloudinaryKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`cloudinary://[0-9]+:([A-Za-z0-9_-]{20,})@[A-Za-z0-9_-]+`),
		Keywords:       []string{"cloudinary"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "backblaze-b2-key",
		Description:    "Backblaze B2 Application Key",
		SecretType:     models.SecretBackblazeKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:b2[_\-]?(?:application|app)?[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9]{31})['"]?`),
		Keywords:       []string{"backblaze", "b2"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// MODERN DATABASES (the new default stack)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "planetscale-token",
		Description:    "PlanetScale Service Token or Password",
		SecretType:     models.SecretPlanetScaleToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`pscale_tkn_[A-Za-z0-9_-]{30,}`),
		Keywords:       []string{"planetscale", "pscale"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "planetscale-password",
		Description:    "PlanetScale Database Password",
		SecretType:     models.SecretPlanetScaleToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`pscale_pw_[A-Za-z0-9_-]{30,}`),
		Keywords:       []string{"planetscale"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "neon-api-key",
		Description:    "Neon (Serverless Postgres) API Key",
		SecretType:     models.SecretNeonKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:neon[_\-]?(?:api)?[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9]{32,})['"]?`),
		Keywords:       []string{"neon", "postgres", "serverless"},
		BaseConfidence: 0.80,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "neon-connection-string",
		Description:    "Neon Postgres Connection String",
		SecretType:     models.SecretNeonKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`postgres(?:ql)?://[^:]+:([^@]{3,})@[A-Za-z0-9.-]*neon\.tech`),
		Keywords:       []string{"neon", "neon.tech"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "turso-auth-token",
		Description:    "Turso Database Auth Token",
		SecretType:     models.SecretTursoToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:turso[_\-]?(?:auth)?[_\-]?token)\s*[=:]\s*['"]?(eyJ[A-Za-z0-9_-]{50,})['"]?`),
		Keywords:       []string{"turso", "libsql"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "upstash-redis-token",
		Description:    "Upstash Redis REST Token",
		SecretType:     models.SecretUpstashToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:upstash[_\-]?redis[_\-]?(?:rest)?[_\-]?token)\s*[=:]\s*['"]?(AX[A-Za-z0-9_-]{30,})['"]?`),
		Keywords:       []string{"upstash", "redis"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "cockroachdb-uri",
		Description:    "CockroachDB Connection URI",
		SecretType:     models.SecretCockroachDBURI,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`cockroachdb://[^:]+:([^@]{3,})@[A-Za-z0-9.-]+\.cockroachlabs\.cloud`),
		Keywords:       []string{"cockroach", "crdb"},
		BaseConfidence: 0.95,
	})

	// ═══════════════════════════════════════════════════════════════
	// CRYPTO / WEB3
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "alchemy-api-key",
		Description:    "Alchemy API Key",
		SecretType:     models.SecretAlchemyKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:alchemy[_\-]?(?:api)?[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9_-]{32})['"]?`),
		Keywords:       []string{"alchemy", "web3"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "infura-api-key",
		Description:    "Infura Project ID / API Key",
		SecretType:     models.SecretInfuraKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:infura[_\-]?(?:project)?[_\-]?(?:id|key|secret))\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Keywords:       []string{"infura", "ethereum", "web3"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "etherscan-api-key",
		Description:    "Etherscan API Key",
		SecretType:     models.SecretEtherscanKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:etherscan[_\-]?(?:api)?[_\-]?key)\s*[=:]\s*['"]?([A-Z0-9]{34})['"]?`),
		Keywords:       []string{"etherscan"},
		BaseConfidence: 0.80,
	})
	rs.addRule(Rule{
		ID:             "moralis-api-key",
		Description:    "Moralis API Key",
		SecretType:     models.SecretMoralisKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:moralis[_\-]?(?:api)?[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9]{40,})['"]?`),
		Keywords:       []string{"moralis", "web3"},
		BaseConfidence: 0.80,
		MinEntropy:     4.0,
	})

	// ═══════════════════════════════════════════════════════════════
	// CI/CD (expanded)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "buildkite-agent-token",
		Description:    "Buildkite Agent Token",
		SecretType:     models.SecretBuildkiteToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:buildkite[_\-]?(?:agent)?[_\-]?token)\s*[=:]\s*['"]?([a-f0-9]{40,})['"]?`),
		Keywords:       []string{"buildkite"},
		BaseConfidence: 0.85,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "buildkite-api-token",
		Description:    "Buildkite API Access Token",
		SecretType:     models.SecretBuildkiteToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`bkua_[A-Za-z0-9]{40}`),
		Keywords:       []string{"buildkite"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "drone-ci-token",
		Description:    "Drone CI Token",
		SecretType:     models.SecretDroneToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:drone[_\-]?token)\s*[=:]\s*['"]?([A-Za-z0-9]{32,})['"]?`),
		Keywords:       []string{"drone"},
		BaseConfidence: 0.80,
		MinEntropy:     4.0,
	})
	rs.addRule(Rule{
		ID:             "pulumi-token",
		Description:    "Pulumi Access Token",
		SecretType:     models.SecretPulumiToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`pul-[A-Za-z0-9]{40}`),
		Keywords:       []string{"pulumi"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "travis-ci-token",
		Description:    "Travis CI Access Token",
		SecretType:     models.SecretTravisCIToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:travis[_\-]?(?:ci)?[_\-]?token)\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`),
		Keywords:       []string{"travis"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "jenkins-api-token",
		Description:    "Jenkins API Token / Crumb",
		SecretType:     models.SecretJenkinsToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:jenkins[_\-]?(?:api)?[_\-]?token)\s*[=:]\s*['"]?([a-f0-9]{32,})['"]?`),
		Keywords:       []string{"jenkins"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// SEARCH
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "meilisearch-key",
		Description:    "Meilisearch API Key",
		SecretType:     models.SecretMeilisearchKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:meili(?:search)?[_\-]?(?:master|admin|api)?[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"meilisearch", "meili"},
		BaseConfidence: 0.75,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "typesense-key",
		Description:    "Typesense API Key",
		SecretType:     models.SecretTypesenseKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:typesense[_\-]?(?:api)?[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`),
		Keywords:       []string{"typesense"},
		BaseConfidence: 0.75,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// COMMUNICATION (expanded)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "vonage-api-secret",
		Description:    "Vonage / Nexmo API Secret",
		SecretType:     models.SecretVonageKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:vonage|nexmo)[_\-]?(?:api)?[_\-]?secret\s*[=:]\s*['"]?([A-Za-z0-9]{16})['"]?`),
		Keywords:       []string{"vonage", "nexmo"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "pushover-token",
		Description:    "Pushover Application/User Token",
		SecretType:     models.SecretPushoverToken,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:pushover[_\-]?(?:app|user)?[_\-]?(?:token|key))\s*[=:]\s*['"]?([a-z0-9]{30})['"]?`),
		Keywords:       []string{"pushover"},
		BaseConfidence: 0.80,
	})
	rs.addRule(Rule{
		ID:             "onesignal-api-key",
		Description:    "OneSignal REST API Key",
		SecretType:     models.SecretOneSignalKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:onesignal[_\-]?(?:api|rest)?[_\-]?key)\s*[=:]\s*['"]?([a-f0-9-]{36})['"]?`),
		Keywords:       []string{"onesignal"},
		BaseConfidence: 0.80,
	})

	// ═══════════════════════════════════════════════════════════════
	// CODE QUALITY / DEVOPS PLATFORMS
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "sonarqube-token",
		Description:    "SonarQube / SonarCloud User Token",
		SecretType:     models.SecretSonarQubeToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?:squ_[a-f0-9]{40}|sqp_[a-f0-9]{40})`),
		Keywords:       []string{"sonar", "sonarqube", "sonarcloud"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "sonarqube-token-legacy",
		Description:    "SonarQube Token (Legacy / Generic)",
		SecretType:     models.SecretSonarQubeToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:sonar[_\-]?(?:token|login))\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`),
		Keywords:       []string{"sonar", "sonarqube"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "sonarqube-webhook-secret",
		Description:    "SonarQube Webhook Secret",
		SecretType:     models.SecretSonarQubeWebhook,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:sonar[_\-]?webhook[_\-]?secret)\s*[=:]\s*['"]?([A-Za-z0-9+/=_-]{16,})['"]?`),
		Keywords:       []string{"sonar", "webhook"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "artifactory-api-key",
		Description:    "JFrog Artifactory API Key",
		SecretType:     models.SecretArtifactoryToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?:AKC[a-zA-Z0-9]{10,})`),
		Keywords:       []string{"artifactory", "jfrog", "AKC"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "artifactory-token",
		Description:    "JFrog Artifactory Identity/Access Token",
		SecretType:     models.SecretArtifactoryToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:artifactory[_\-]?(?:api[_\-]?key|token|password))\s*[=:]\s*['"]?([A-Za-z0-9+/=_-]{20,})['"]?`),
		Keywords:       []string{"artifactory", "jfrog"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "artifactory-encrypted-pass",
		Description:    "JFrog Artifactory Encrypted Password",
		SecretType:     models.SecretArtifactoryEncPass,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?:AP[A-Za-z0-9]{8,})`),
		Keywords:       []string{"artifactory", "jfrog", "password"},
		BaseConfidence: 0.75,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "gerrit-http-password",
		Description:    "Gerrit HTTP Password / API Token",
		SecretType:     models.SecretGerritHTTPPass,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:gerrit[_\-]?(?:http[_\-]?)?(?:password|token|secret))\s*[=:]\s*['"]?([A-Za-z0-9/+=_-]{16,})['"]?`),
		Keywords:       []string{"gerrit"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════════════════════════════
	// IDENTITY & ACCESS MANAGEMENT (IAM/PAM/KERBEROS)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "ldap-bind-password",
		Description:    "LDAP Bind Password",
		SecretType:     models.SecretLDAPBindPassword,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:ldap[_\-]?(?:bind[_\-]?)?(?:password|passwd|pwd|credential|secret))\s*[=:]\s*['"]?([^\s'"]{8,})['"]?`),
		Keywords:       []string{"ldap", "bind", "password", "directory"},
		BaseConfidence: 0.80,
		MinEntropy:     2.5,
	})
	rs.addRule(Rule{
		ID:             "ldap-connection-uri",
		Description:    "LDAP Connection URI with Credentials",
		SecretType:     models.SecretLDAPBindPassword,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`ldaps?://[^:]+:([^@\s]{4,})@[^\s]+`),
		Keywords:       []string{"ldap", "ldaps", "directory"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "active-directory-password",
		Description:    "Active Directory / Domain Controller Password",
		SecretType:     models.SecretActiveDirectoryPass,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:ad[_\-]?(?:admin)?[_\-]?password|domain[_\-]?(?:admin)?[_\-]?(?:password|passwd)|dc[_\-]?password|active[_\-]?directory[_\-]?(?:password|secret))\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`),
		Keywords:       []string{"active directory", "domain", "AD", "dc"},
		BaseConfidence: 0.80,
		MinEntropy:     2.5,
	})
	rs.addRule(Rule{
		ID:             "kerberos-keytab",
		Description:    "Kerberos Keytab File Reference",
		SecretType:     models.SecretKerberosKeytab,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:kt_default|keytab|KRB5_KTNAME|KRB5_CLIENT_KTNAME)\s*[=:]\s*['"]?([^\s'"]+\.keytab)['"]?`),
		Keywords:       []string{"kerberos", "keytab", "krb5", "kinit"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "kerberos-password",
		Description:    "Kerberos Principal Password",
		SecretType:     models.SecretKerberosPassword,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:krb5?[_\-]?password|kerberos[_\-]?password|kinit[_\-]?password|principal[_\-]?password)\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`),
		Keywords:       []string{"kerberos", "krb5", "kinit", "principal"},
		BaseConfidence: 0.85,
		MinEntropy:     2.5,
	})
	rs.addRule(Rule{
		ID:             "kerberos-krb5-conf",
		Description:    "Kerberos KDC / Realm Configuration with Password",
		SecretType:     models.SecretKerberosPassword,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:default_keytab_name|kdc_master_key|master_key_name)\s*=\s*([^\s]+)`),
		Keywords:       []string{"kerberos", "kdc", "realm", "krb5.conf"},
		BaseConfidence: 0.75,
	})
	rs.addRule(Rule{
		ID:             "cyberark-api-token",
		Description:    "CyberArk PAM / Conjur API Token",
		SecretType:     models.SecretCyberArkToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:cyberark|conjur)[_\-]?(?:api[_\-]?)?(?:token|key|secret|password)\s*[=:]\s*['"]?([A-Za-z0-9+/=_-]{20,})['"]?`),
		Keywords:       []string{"cyberark", "conjur", "pam", "privileged"},
		BaseConfidence: 0.85,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "radius-shared-secret",
		Description:    "RADIUS Shared Secret",
		SecretType:     models.SecretRADIUSSecret,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:radius[_\-]?(?:shared)?[_\-]?secret|radius[_\-]?password)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?`),
		Keywords:       []string{"radius", "shared secret", "NAS", "authenticator"},
		BaseConfidence: 0.80,
		MinEntropy:     2.5,
	})
	rs.addRule(Rule{
		ID:             "saml-private-key",
		Description:    "SAML / SSO Private Key or Certificate Secret",
		SecretType:     models.SecretSAMLKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:saml[_\-]?(?:private[_\-]?key|cert[_\-]?key|signing[_\-]?key|x509[_\-]?key))\s*[=:]\s*['"]?([^\s'"]{20,})['"]?`),
		Keywords:       []string{"saml", "sso", "x509", "signing"},
		BaseConfidence: 0.85,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "freeipa-password",
		Description:    "FreeIPA / IdM Admin Password",
		SecretType:     models.SecretFreeIPAPassword,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:freeipa|ipa)[_\-]?(?:admin)?[_\-]?(?:password|passwd|secret)\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`),
		Keywords:       []string{"freeipa", "ipa", "idm", "identity"},
		BaseConfidence: 0.80,
		MinEntropy:     2.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// REMOTE ACCESS / NAS
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "rdp-password",
		Description:    "RDP / Remote Desktop Password",
		SecretType:     models.SecretRDPPassword,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:rdp[_\-]?password|remote[_\-]?desktop[_\-]?password|mstsc[_\-]?password)\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`),
		Keywords:       []string{"rdp", "remote desktop", "mstsc"},
		BaseConfidence: 0.80,
		MinEntropy:     2.5,
	})
	rs.addRule(Rule{
		ID:             "vnc-password",
		Description:    "VNC Password",
		SecretType:     models.SecretVNCPassword,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:vnc[_\-]?password|vnc[_\-]?passwd)\s*[=:]\s*['"]?([^\s'"]{4,})['"]?`),
		Keywords:       []string{"vnc", "vncserver", "tigervnc"},
		BaseConfidence: 0.80,
		MinEntropy:     2.0,
	})
	rs.addRule(Rule{
		ID:             "synology-api-token",
		Description:    "Synology NAS API Token / Session ID",
		SecretType:     models.SecretSynologyToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:synology[_\-]?(?:api[_\-]?)?(?:token|key|sid|session))\s*[=:]\s*['"]?([A-Za-z0-9+/=_-]{16,})['"]?`),
		Keywords:       []string{"synology", "dsm", "nas"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "qnap-api-token",
		Description:    "QNAP NAS API Token / Session ID",
		SecretType:     models.SecretQNAPToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:qnap[_\-]?(?:api[_\-]?)?(?:token|key|sid|session))\s*[=:]\s*['"]?([A-Za-z0-9+/=_-]{16,})['"]?`),
		Keywords:       []string{"qnap", "qts", "nas"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "nas-admin-credential",
		Description:    "NAS Admin Password / Credential",
		SecretType:     models.SecretNASCredential,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:nas[_\-]?(?:admin)?[_\-]?(?:password|passwd|credential|secret))\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`),
		Keywords:       []string{"nas", "storage", "admin"},
		BaseConfidence: 0.75,
		MinEntropy:     2.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// CLOUD PROVIDERS (ADDITIONAL)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "oracle-cloud-ocid",
		Description:    "Oracle Cloud (OCI) Key Fingerprint / OCID",
		SecretType:     models.SecretOracleCloudKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:oci[_\-]?(?:api[_\-]?)?(?:key|fingerprint|secret))\s*[=:]\s*['"]?([A-Fa-f0-9:]{47,})['"]?`),
		Keywords:       []string{"oci", "oracle", "cloud"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "ibm-cloud-api-key",
		Description:    "IBM Cloud API Key",
		SecretType:     models.SecretIBMCloudKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:ibm[_\-]?cloud[_\-]?(?:api[_\-]?)?key|iam[_\-]?api[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?`),
		Keywords:       []string{"ibm", "cloud", "iam"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "alibaba-cloud-access-key",
		Description:    "Alibaba Cloud AccessKey ID",
		SecretType:     models.SecretAlibabaCloudKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?:LTAI[A-Za-z0-9]{12,20})`),
		Keywords:       []string{"alibaba", "aliyun", "LTAI"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "hetzner-api-token",
		Description:    "Hetzner Cloud API Token",
		SecretType:     models.SecretHetznerToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:hetzner[_\-]?(?:api[_\-]?)?(?:token|key))\s*[=:]\s*['"]?([A-Za-z0-9]{64})['"]?`),
		Keywords:       []string{"hetzner", "hcloud"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// CONTAINER & ORCHESTRATION
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "kubernetes-service-token",
		Description:    "Kubernetes Service Account / Bearer Token",
		SecretType:     models.SecretKubernetesToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:kubernetes[_\-]?(?:service[_\-]?account)?[_\-]?token|k8s[_\-]?token|KUBECONFIG_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9._-]{50,})['"]?`),
		Keywords:       []string{"kubernetes", "k8s", "kubeconfig"},
		BaseConfidence: 0.85,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "docker-hub-pat",
		Description:    "Docker Hub Personal Access Token",
		SecretType:     models.SecretDockerHubPAT,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`dckr_pat_[A-Za-z0-9_-]{20,}`),
		Keywords:       []string{"docker", "dckr_pat"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "harbor-credential",
		Description:    "Harbor Registry Password / Robot Token",
		SecretType:     models.SecretHarborCredential,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:harbor[_\-]?(?:robot[_\-]?)?(?:password|token|secret))\s*[=:]\s*['"]?([^\s'"]{12,})['"]?`),
		Keywords:       []string{"harbor", "registry", "robot"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "quay-robot-token",
		Description:    "Quay.io Robot Account Token",
		SecretType:     models.SecretQuayRobotToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:quay[_\-]?(?:robot[_\-]?)?(?:token|password|secret))\s*[=:]\s*['"]?([A-Za-z0-9+/=_-]{20,})['"]?`),
		Keywords:       []string{"quay", "robot", "registry"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════════════════════════════
	// CI/CD (EXPANDED)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "azure-devops-pat",
		Description:    "Azure DevOps Personal Access Token",
		SecretType:     models.SecretAzureDevOpsPAT,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:azure[_\-]?devops[_\-]?pat|vsts[_\-]?(?:pat|token)|ado[_\-]?(?:pat|token))\s*[=:]\s*['"]?([a-z0-9]{52})['"]?`),
		Keywords:       []string{"azure", "devops", "vsts", "ado"},
		BaseConfidence: 0.85,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "teamcity-token",
		Description:    "JetBrains TeamCity API Token",
		SecretType:     models.SecretTeamCityToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:teamcity[_\-]?(?:api[_\-]?)?(?:token|key|password))\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"teamcity", "jetbrains"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "bamboo-token",
		Description:    "Atlassian Bamboo API Token",
		SecretType:     models.SecretBambooToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:bamboo[_\-]?(?:api[_\-]?)?(?:token|key|password))\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"bamboo", "atlassian"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "harness-api-key",
		Description:    "Harness.io API Key",
		SecretType:     models.SecretHarnessKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:harness[_\-]?(?:api[_\-]?)?(?:key|token|secret))\s*[=:]\s*['"]?([A-Za-z0-9._-]{20,})['"]?`),
		Keywords:       []string{"harness"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "argocd-auth-token",
		Description:    "Argo CD Authentication Token",
		SecretType:     models.SecretArgoCDToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:argocd[_\-]?(?:auth[_\-]?)?token|argo[_\-]?cd[_\-]?token)\s*[=:]\s*['"]?([A-Za-z0-9._-]{30,})['"]?`),
		Keywords:       []string{"argocd", "argo"},
		BaseConfidence: 0.85,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// MONITORING & OBSERVABILITY (EXPANDED)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "dynatrace-api-token",
		Description:    "Dynatrace API Token",
		SecretType:     models.SecretDynatraceToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`dt0c01\.[A-Z0-9]{24}\.[A-Za-z0-9]{64}`),
		Keywords:       []string{"dynatrace", "dt0c01"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "sumologic-access-key",
		Description:    "Sumo Logic Access ID / Key",
		SecretType:     models.SecretSumoLogicKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:sumo[_\-]?logic[_\-]?(?:access[_\-]?)?(?:key|id|token))\s*[=:]\s*['"]?([A-Za-z0-9]{14,64})['"]?`),
		Keywords:       []string{"sumo", "sumologic"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "honeycomb-api-key",
		Description:    "Honeycomb API Key",
		SecretType:     models.SecretHoneycombKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:honeycomb[_\-]?(?:api[_\-]?)?(?:key|token))\s*[=:]\s*['"]?([A-Za-z0-9]{22,})['"]?`),
		Keywords:       []string{"honeycomb"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "bugsnag-api-key",
		Description:    "Bugsnag API Key / Notifier Key",
		SecretType:     models.SecretBugsnagKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:bugsnag[_\-]?(?:api[_\-]?)?key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Keywords:       []string{"bugsnag"},
		BaseConfidence: 0.80,
	})
	rs.addRule(Rule{
		ID:             "rollbar-access-token",
		Description:    "Rollbar Access Token",
		SecretType:     models.SecretRollbarToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:rollbar[_\-]?(?:access[_\-]?)?token)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Keywords:       []string{"rollbar"},
		BaseConfidence: 0.80,
	})
	rs.addRule(Rule{
		ID:             "airbrake-api-key",
		Description:    "Airbrake API Key / Project Key",
		SecretType:     models.SecretAirbrakeKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:airbrake[_\-]?(?:api[_\-]?)?(?:key|project[_\-]?key))\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Keywords:       []string{"airbrake"},
		BaseConfidence: 0.80,
	})
	rs.addRule(Rule{
		ID:             "logzio-token",
		Description:    "Logz.io Shipping / API Token",
		SecretType:     models.SecretLogzioToken,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:logz[_\-]?io[_\-]?(?:api[_\-]?)?(?:token|key))\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`),
		Keywords:       []string{"logzio", "logz"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "instana-api-token",
		Description:    "Instana (IBM) API Token",
		SecretType:     models.SecretInstanaToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:instana[_\-]?(?:api[_\-]?)?(?:token|key))\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"instana"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "zabbix-api-token",
		Description:    "Zabbix API Token",
		SecretType:     models.SecretZabbixToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:zabbix[_\-]?(?:api[_\-]?)?(?:token|key))\s*[=:]\s*['"]?([a-f0-9]{64})['"]?`),
		Keywords:       []string{"zabbix"},
		BaseConfidence: 0.80,
	})

	// ═══════════════════════════════════════════════════════════════
	// CONFIG MANAGEMENT & INFRASTRUCTURE
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "ansible-vault-password",
		Description:    "Ansible Vault Password",
		SecretType:     models.SecretAnsibleVaultPass,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:ansible[_\-]?vault[_\-]?password|ANSIBLE_VAULT_PASSWORD_FILE)\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`),
		Keywords:       []string{"ansible", "vault"},
		BaseConfidence: 0.80,
		MinEntropy:     2.5,
	})
	rs.addRule(Rule{
		ID:             "consul-acl-token",
		Description:    "HashiCorp Consul ACL Token",
		SecretType:     models.SecretConsulToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:consul[_\-]?(?:http[_\-]?)?(?:token|acl[_\-]?token))\s*[=:]\s*['"]?([a-f0-9-]{36})['"]?`),
		Keywords:       []string{"consul", "acl"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "nomad-token",
		Description:    "HashiCorp Nomad ACL Token",
		SecretType:     models.SecretNomadToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:nomad[_\-]?(?:acl[_\-]?)?token)\s*[=:]\s*['"]?([a-f0-9-]{36})['"]?`),
		Keywords:       []string{"nomad", "hashicorp"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "chef-client-key",
		Description:    "Chef Client / Validation Key",
		SecretType:     models.SecretChefKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:chef[_\-]?(?:client[_\-]?)?(?:key|secret|validation[_\-]?key))\s*[=:]\s*['"]?([^\s'"]{16,})['"]?`),
		Keywords:       []string{"chef", "knife", "validation"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "puppet-access-token",
		Description:    "Puppet Enterprise Access Token",
		SecretType:     models.SecretPuppetToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:puppet[_\-]?(?:enterprise[_\-]?)?(?:token|api[_\-]?key))\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"puppet"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════════════════════════════
	// SECURITY TOOLS
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "snyk-api-token",
		Description:    "Snyk API Token",
		SecretType:     models.SecretSnykToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:snyk[_\-]?(?:api[_\-]?)?token)\s*[=:]\s*['"]?([a-f0-9-]{36,})['"]?`),
		Keywords:       []string{"snyk"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:                    "1password-connect-token",
		Description:           "1Password Connect / Service Account Token",
		SecretType:            models.SecretOnePasswordToken,
		Severity:              models.SeverityCritical,
		Pattern:               regexp.MustCompile(`(?:ops_[A-Za-z0-9]{43,}|eyJhbGciOi[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.)`),
		Keywords:              []string{"1password", "op", "connect"},
		BaseConfidence:        0.80,
		MinEntropy:            4.0,
		FalsePositivePatterns: []*regexp.Regexp{regexp.MustCompile(`example`), regexp.MustCompile(`test`)},
	})
	rs.addRule(Rule{
		ID:             "crowdstrike-api-key",
		Description:    "CrowdStrike Falcon API Key",
		SecretType:     models.SecretCrowdStrikeKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:crowdstrike[_\-]?(?:api[_\-]?)?(?:key|secret|client[_\-]?id))\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Keywords:       []string{"crowdstrike", "falcon"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "tenable-api-key",
		Description:    "Tenable / Nessus API Key",
		SecretType:     models.SecretTenableKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:tenable[_\-]?(?:api[_\-]?)?(?:key|access[_\-]?key|secret[_\-]?key)|nessus[_\-]?(?:api[_\-]?)?key)\s*[=:]\s*['"]?([a-f0-9]{64})['"]?`),
		Keywords:       []string{"tenable", "nessus"},
		BaseConfidence: 0.85,
	})

	// ═══════════════════════════════════════════════════════════════
	// API GATEWAY & CDN
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "fastly-api-token",
		Description:    "Fastly API Token",
		SecretType:     models.SecretFastlyToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:fastly[_\-]?(?:api[_\-]?)?(?:token|key))\s*[=:]\s*['"]?([A-Za-z0-9_-]{32,})['"]?`),
		Keywords:       []string{"fastly"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "akamai-client-token",
		Description:    "Akamai EdgeGrid Client Token / Secret",
		SecretType:     models.SecretAkamaiToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:akamai[_\-]?(?:client[_\-]?)?(?:token|secret|access[_\-]?token))\s*[=:]\s*['"]?([A-Za-z0-9+/=]{20,})['"]?`),
		Keywords:       []string{"akamai", "edgegrid"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "kong-admin-token",
		Description:    "Kong API Gateway Admin Token",
		SecretType:     models.SecretKongToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:kong[_\-]?(?:admin[_\-]?)?(?:token|key|api[_\-]?key))\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"kong", "gateway"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "bunnycdn-api-key",
		Description:    "Bunny CDN API Key",
		SecretType:     models.SecretBunnyCDNKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:bunny[_\-]?cdn[_\-]?(?:api[_\-]?)?key)\s*[=:]\s*['"]?([a-f0-9-]{36,})['"]?`),
		Keywords:       []string{"bunny", "bunnycdn"},
		BaseConfidence: 0.75,
	})

	// ═══════════════════════════════════════════════════════════════
	// DATA PLATFORMS
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "snowflake-credentials",
		Description:    "Snowflake Account Password / Connection String",
		SecretType:     models.SecretSnowflakePass,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:snowflake[_\-]?(?:account[_\-]?)?(?:password|passwd|pwd)|sf[_\-]?password)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?`),
		Keywords:       []string{"snowflake"},
		BaseConfidence: 0.80,
		MinEntropy:     2.5,
	})
	rs.addRule(Rule{
		ID:             "snowflake-connection-string",
		Description:    "Snowflake JDBC/ODBC Connection String with Password",
		SecretType:     models.SecretSnowflakePass,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:jdbc:snowflake|snowflake)://[^:]+:([^@\s]{4,})@[^\s]+\.snowflakecomputing\.com`),
		Keywords:       []string{"snowflake", "snowflakecomputing"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "databricks-token",
		Description:    "Databricks Personal Access Token",
		SecretType:     models.SecretDatabricksToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`dapi[a-f0-9]{32}`),
		Keywords:       []string{"databricks", "dapi"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "dbt-cloud-token",
		Description:    "dbt Cloud API Token",
		SecretType:     models.SecretDBTCloudToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:dbt[_\-]?(?:cloud[_\-]?)?(?:api[_\-]?)?(?:token|key))\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"dbt", "cloud"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "fivetran-api-key",
		Description:    "Fivetran API Key / Secret",
		SecretType:     models.SecretFivetranKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:fivetran[_\-]?(?:api[_\-]?)?(?:key|secret))\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"fivetran"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "looker-client-secret",
		Description:    "Looker / Google Looker Client Secret",
		SecretType:     models.SecretLookerSecret,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:looker[_\-]?(?:client[_\-]?)?secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"looker"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════════════════════════════
	// DATABASES (ADDITIONAL)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "influxdb-token",
		Description:    "InfluxDB API Token",
		SecretType:     models.SecretInfluxDBToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:influx[_\-]?db[_\-]?(?:api[_\-]?)?token|INFLUX_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_=-]{40,})['"]?`),
		Keywords:       []string{"influxdb", "influx"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "clickhouse-credentials",
		Description:    "ClickHouse Password / Connection String",
		SecretType:     models.SecretClickHousePass,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:clickhouse[_\-]?(?:password|passwd))\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`),
		Keywords:       []string{"clickhouse"},
		BaseConfidence: 0.80,
		MinEntropy:     2.5,
	})
	rs.addRule(Rule{
		ID:             "neo4j-credentials",
		Description:    "Neo4j Password / Connection URI",
		SecretType:     models.SecretNeo4jPass,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?:neo4j(?:\+s?s?c?)?://[^:]+:([^@\s]{4,})@|(?i)(?:neo4j[_\-]?password)\s*[=:]\s*['"]?([^\s'"]{6,})['"]?)`),
		Keywords:       []string{"neo4j", "bolt"},
		BaseConfidence: 0.80,
		MinEntropy:     2.5,
	})
	rs.addRule(Rule{
		ID:                    "airtable-api-key",
		Description:           "Airtable API Key / PAT",
		SecretType:            models.SecretAirtableKey,
		Severity:              models.SeverityHigh,
		Pattern:               regexp.MustCompile(`(?:pat[A-Za-z0-9]{14}\.[a-f0-9]{64}|key[A-Za-z0-9]{14})`),
		Keywords:              []string{"airtable"},
		BaseConfidence:        0.85,
		MinEntropy:            3.5,
		FalsePositivePatterns: []*regexp.Regexp{regexp.MustCompile(`example`), regexp.MustCompile(`test`)},
	})
	rs.addRule(Rule{
		ID:             "fauna-secret",
		Description:    "FaunaDB Secret Key",
		SecretType:     models.SecretFaunaSecret,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`fnA[A-Za-z0-9_-]{40,}`),
		Keywords:       []string{"fauna", "faunadb", "fnA"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "oracle-db-connection",
		Description:    "Oracle Database Connection String with Password",
		SecretType:     models.SecretOracleDBURI,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:jdbc:oracle:thin|oracle)://[^:/]+:([^@\s]{4,})@`),
		Keywords:       []string{"oracle", "jdbc"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "mssql-connection-string",
		Description:    "SQL Server / MSSQL Connection String with Password",
		SecretType:     models.SecretMSSQLString,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:Server|Data Source)=[^;]+;.*(?:Password|Pwd)\s*=\s*([^;'"]{4,})`),
		Keywords:       []string{"mssql", "sqlserver", "Server", "Password"},
		BaseConfidence: 0.85,
	})

	// ═══════════════════════════════════════════════════════════════
	// PROJECT MANAGEMENT
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:                    "notion-integration-token",
		Description:           "Notion Integration / API Token",
		SecretType:            models.SecretNotionToken,
		Severity:              models.SeverityHigh,
		Pattern:               regexp.MustCompile(`(?:ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{40,})`),
		Keywords:              []string{"notion", "ntn_"},
		BaseConfidence:        0.90,
		FalsePositivePatterns: []*regexp.Regexp{regexp.MustCompile(`example`)},
	})
	rs.addRule(Rule{
		ID:             "linear-api-key",
		Description:    "Linear API Key",
		SecretType:     models.SecretLinearKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`lin_api_[A-Za-z0-9]{40,}`),
		Keywords:       []string{"linear", "lin_api"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "asana-pat",
		Description:    "Asana Personal Access Token",
		SecretType:     models.SecretAsanaPAT,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:asana[_\-]?(?:personal[_\-]?)?(?:access[_\-]?)?token)\s*[=:]\s*['"]?([0-9]/[0-9]{16}:[a-f0-9]{32})['"]?`),
		Keywords:       []string{"asana"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "trello-api-key",
		Description:    "Trello API Key / Token",
		SecretType:     models.SecretTrelloKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:trello[_\-]?(?:api[_\-]?)?(?:key|token))\s*[=:]\s*['"]?([a-f0-9]{32,64})['"]?`),
		Keywords:       []string{"trello"},
		BaseConfidence: 0.80,
	})
	rs.addRule(Rule{
		ID:             "clickup-api-key",
		Description:    "ClickUp API Key / Token",
		SecretType:     models.SecretClickUpKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:clickup[_\-]?(?:api[_\-]?)?(?:key|token))\s*[=:]\s*['"]?(?:pk_[0-9]+_[A-Za-z0-9]{20,})['"]?`),
		Keywords:       []string{"clickup"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "shortcut-api-token",
		Description:    "Shortcut (ex-Clubhouse) API Token",
		SecretType:     models.SecretShortcutToken,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:shortcut[_\-]?(?:api[_\-]?)?token|clubhouse[_\-]?(?:api[_\-]?)?token)\s*[=:]\s*['"]?([a-f0-9-]{36})['"]?`),
		Keywords:       []string{"shortcut", "clubhouse"},
		BaseConfidence: 0.80,
	})

	// ═══════════════════════════════════════════════════════════════
	// CMS & CONTENT PLATFORMS
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "contentful-api-key",
		Description:    "Contentful Delivery / Management API Key",
		SecretType:     models.SecretContentfulKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:contentful[_\-]?(?:delivery|management|preview)?[_\-]?(?:api[_\-]?)?(?:key|token))\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?`),
		Keywords:       []string{"contentful"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "sanity-api-token",
		Description:    "Sanity.io API Token",
		SecretType:     models.SecretSanityToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:sanity[_\-]?(?:api[_\-]?)?(?:token|key))\s*[=:]\s*['"]?(?:sk[A-Za-z0-9]{40,})['"]?`),
		Keywords:       []string{"sanity"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "strapi-api-token",
		Description:    "Strapi API Token",
		SecretType:     models.SecretStrapiToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:strapi[_\-]?(?:api[_\-]?)?(?:token|key))\s*[=:]\s*['"]?([A-Za-z0-9_-]{30,})['"]?`),
		Keywords:       []string{"strapi"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "ghost-admin-key",
		Description:    "Ghost CMS Admin API Key",
		SecretType:     models.SecretGhostKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:ghost[_\-]?(?:admin[_\-]?)?(?:api[_\-]?)?key)\s*[=:]\s*['"]?([a-f0-9]{24}:[a-f0-9]{64})['"]?`),
		Keywords:       []string{"ghost"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "wordpress-app-password",
		Description:    "WordPress Application Password",
		SecretType:     models.SecretWordPressPass,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:wordpress|wp)[_\-]?(?:app(?:lication)?[_\-]?)?password\s*[=:]\s*['"]?([A-Za-z0-9 ]{24,})['"]?`),
		Keywords:       []string{"wordpress", "wp"},
		BaseConfidence: 0.75,
		MinEntropy:     2.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// FEATURE FLAGS
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "launchdarkly-sdk-key",
		Description:    "LaunchDarkly SDK / API Key",
		SecretType:     models.SecretLaunchDarklyKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:launchdarkly[_\-]?(?:sdk[_\-]?)?key|ld[_\-]?sdk[_\-]?key)\s*[=:]\s*['"]?(?:sdk-[a-f0-9-]{36})['"]?`),
		Keywords:       []string{"launchdarkly", "sdk"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "split-api-key",
		Description:    "Split.io API Key / SDK Key",
		SecretType:     models.SecretSplitKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:split[_\-]?(?:io[_\-]?)?(?:api[_\-]?)?key)\s*[=:]\s*['"]?([A-Za-z0-9]{40,})['"]?`),
		Keywords:       []string{"split"},
		BaseConfidence: 0.75,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "flagsmith-api-key",
		Description:    "Flagsmith Server / Environment Key",
		SecretType:     models.SecretFlagsmithKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:flagsmith[_\-]?(?:environment[_\-]?)?key)\s*[=:]\s*['"]?(?:ser\.[A-Za-z0-9_-]{30,})['"]?`),
		Keywords:       []string{"flagsmith"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "configcat-sdk-key",
		Description:    "ConfigCat SDK Key",
		SecretType:     models.SecretConfigCatKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:configcat[_\-]?(?:sdk[_\-]?)?key)\s*[=:]\s*['"]?([A-Za-z0-9/_-]{20,})['"]?`),
		Keywords:       []string{"configcat"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════════════════════════════
	// AUTH / IDENTITY (EXPANDED)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "keycloak-client-secret",
		Description:    "Keycloak Client Secret",
		SecretType:     models.SecretKeycloakSecret,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:keycloak[_\-]?(?:client[_\-]?)?secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"keycloak"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "onelogin-client-secret",
		Description:    "OneLogin Client Secret / API Credential",
		SecretType:     models.SecretOneLoginSecret,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:onelogin[_\-]?(?:client[_\-]?)?secret)\s*[=:]\s*['"]?([a-f0-9]{64})['"]?`),
		Keywords:       []string{"onelogin"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "duo-integration-key",
		Description:    "Duo Security Integration / Secret Key",
		SecretType:     models.SecretDuoKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:duo[_\-]?(?:integration[_\-]?|secret[_\-]?)?key)\s*[=:]\s*['"]?([A-Za-z0-9]{20,40})['"]?`),
		Keywords:       []string{"duo", "duosecurity"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "ping-identity-token",
		Description:    "Ping Identity / PingOne Client Secret",
		SecretType:     models.SecretPingIdentityToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:ping[_\-]?(?:identity|one|federate)[_\-]?(?:client[_\-]?)?secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"ping", "pingone", "pingfederate"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════════════════════════════
	// SECRETS MANAGEMENT
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "doppler-token",
		Description:    "Doppler Service Token / CLI Token",
		SecretType:     models.SecretDopplerToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`dp\.st\.[A-Za-z0-9_-]{40,}|dp\.ct\.[A-Za-z0-9_-]{40,}`),
		Keywords:       []string{"doppler", "dp.st", "dp.ct"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "infisical-token",
		Description:    "Infisical Service Token",
		SecretType:     models.SecretInfisicalToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?:st\.[a-f0-9]{8,}\.[a-f0-9]{16,}\.[a-f0-9]{16,})`),
		Keywords:       []string{"infisical"},
		BaseConfidence: 0.90,
	})

	// ═══════════════════════════════════════════════════════════════
	// NETWORKING
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "ngrok-auth-token",
		Description:    "ngrok Authentication Token",
		SecretType:     models.SecretNgrokToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:ngrok[_\-]?(?:auth[_\-]?)?token)\s*[=:]\s*['"]?([A-Za-z0-9_-]{30,})['"]?`),
		Keywords:       []string{"ngrok"},
		BaseConfidence: 0.85,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "tailscale-api-key",
		Description:    "Tailscale API Key",
		SecretType:     models.SecretTailscaleKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`tskey-[A-Za-z0-9]+-[A-Za-z0-9]+`),
		Keywords:       []string{"tailscale", "tskey"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "wireguard-private-key",
		Description:    "WireGuard Private Key",
		SecretType:     models.SecretWireGuardKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:PrivateKey|wg[_\-]?private[_\-]?key)\s*=\s*([A-Za-z0-9+/]{43}=)`),
		Keywords:       []string{"wireguard", "PrivateKey", "wg"},
		BaseConfidence: 0.90,
	})

	// ═══════════════════════════════════════════════════════════════
	// TESTING & QA
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "browserstack-access-key",
		Description:    "BrowserStack Access Key",
		SecretType:     models.SecretBrowserStackKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:browserstack[_\-]?access[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9]{20})['"]?`),
		Keywords:       []string{"browserstack"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "saucelabs-access-key",
		Description:    "Sauce Labs Access Key",
		SecretType:     models.SecretSauceLabsKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:sauce[_\-]?(?:labs[_\-]?)?access[_\-]?key)\s*[=:]\s*['"]?([a-f0-9-]{36})['"]?`),
		Keywords:       []string{"sauce", "saucelabs"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "cypress-record-key",
		Description:    "Cypress Cloud Record Key",
		SecretType:     models.SecretCypressKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:cypress[_\-]?record[_\-]?key)\s*[=:]\s*['"]?([a-f0-9-]{36})['"]?`),
		Keywords:       []string{"cypress"},
		BaseConfidence: 0.85,
	})

	// ═══════════════════════════════════════════════════════════════
	// DESIGN
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "figma-pat",
		Description:    "Figma Personal Access Token",
		SecretType:     models.SecretFigmaPAT,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`figd_[A-Za-z0-9_-]{40,}`),
		Keywords:       []string{"figma", "figd"},
		BaseConfidence: 0.95,
	})

	// ═══════════════════════════════════════════════════════════════
	// COMMUNICATION (EXPANDED)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "zoom-client-secret",
		Description:    "Zoom OAuth Client Secret",
		SecretType:     models.SecretZoomSecret,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:zoom[_\-]?(?:client[_\-]?)?secret)\s*[=:]\s*['"]?([A-Za-z0-9]{32})['"]?`),
		Keywords:       []string{"zoom"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "webex-bot-token",
		Description:    "Cisco Webex Bot / Integration Token",
		SecretType:     models.SecretWebexToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:webex[_\-]?(?:bot[_\-]?)?(?:token|access[_\-]?token))\s*[=:]\s*['"]?([A-Za-z0-9_-]{60,})['"]?`),
		Keywords:       []string{"webex", "cisco"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})

	// ═══════════════════════════════════════════════════════════════
	// PAYMENTS (EXPANDED)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "braintree-access-token",
		Description:    "Braintree (PayPal) Access Token",
		SecretType:     models.SecretBraintreeToken,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}`),
		Keywords:       []string{"braintree"},
		BaseConfidence: 0.95,
	})
	rs.addRule(Rule{
		ID:             "paddle-api-key",
		Description:    "Paddle API Key",
		SecretType:     models.SecretPaddleKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:paddle[_\-]?(?:api[_\-]?)?(?:key|secret))\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`),
		Keywords:       []string{"paddle"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "klarna-api-key",
		Description:    "Klarna API Key / Credentials",
		SecretType:     models.SecretKlarnaKey,
		Severity:       models.SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)(?:klarna[_\-]?(?:api[_\-]?)?(?:key|secret|password))\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"klarna"},
		BaseConfidence: 0.80,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════════════════════════════
	// MEDIA & VIDEO
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "mux-token-secret",
		Description:    "Mux Video API Token Secret",
		SecretType:     models.SecretMuxSecret,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:mux[_\-]?(?:token[_\-]?)?secret)\s*[=:]\s*['"]?([A-Za-z0-9+/=]{40,})['"]?`),
		Keywords:       []string{"mux"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "twitch-client-secret",
		Description:    "Twitch API Client Secret",
		SecretType:     models.SecretTwitchSecret,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:twitch[_\-]?(?:client[_\-]?)?secret)\s*[=:]\s*['"]?([a-z0-9]{30})['"]?`),
		Keywords:       []string{"twitch"},
		BaseConfidence: 0.85,
	})

	// ═══════════════════════════════════════════════════════════════
	// SMS / VOICE (EXPANDED)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "plivo-auth-token",
		Description:    "Plivo Auth Token",
		SecretType:     models.SecretPlivoToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:plivo[_\-]?(?:auth[_\-]?)?token)\s*[=:]\s*['"]?([A-Za-z0-9]{40,})['"]?`),
		Keywords:       []string{"plivo"},
		BaseConfidence: 0.80,
		MinEntropy:     3.5,
	})
	rs.addRule(Rule{
		ID:             "bandwidth-api-token",
		Description:    "Bandwidth API Token / Password",
		SecretType:     models.SecretBandwidthToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:bandwidth[_\-]?(?:api[_\-]?)?(?:token|password|secret))\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"bandwidth"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:                    "telnyx-api-key",
		Description:           "Telnyx API Key",
		SecretType:            models.SecretTelnyxKey,
		Severity:              models.SeverityHigh,
		Pattern:               regexp.MustCompile(`KEY[A-Za-z0-9_-]{40,}`),
		Keywords:              []string{"telnyx", "KEY"},
		BaseConfidence:        0.70,
		MinEntropy:            4.0,
		FalsePositivePatterns: []*regexp.Regexp{regexp.MustCompile(`example`), regexp.MustCompile(`test`)},
	})

	// ═══════════════════════════════════════════════════════════════
	// EMAIL (EXPANDED)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "sparkpost-api-key",
		Description:    "SparkPost API Key",
		SecretType:     models.SecretSparkPostKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:sparkpost[_\-]?(?:api[_\-]?)?key)\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`),
		Keywords:       []string{"sparkpost"},
		BaseConfidence: 0.85,
	})
	rs.addRule(Rule{
		ID:             "customerio-api-key",
		Description:    "Customer.io API Key / Site ID",
		SecretType:     models.SecretCustomerIOKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:customer[_\-]?io[_\-]?(?:api[_\-]?)?(?:key|token))\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`),
		Keywords:       []string{"customerio", "customer.io"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})
	rs.addRule(Rule{
		ID:             "mandrill-api-key",
		Description:    "Mandrill (Mailchimp Transactional) API Key",
		SecretType:     models.SecretMandrillKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:mandrill[_\-]?(?:api[_\-]?)?key)\s*[=:]\s*['"]?([A-Za-z0-9_-]{22})['"]?`),
		Keywords:       []string{"mandrill", "mailchimp"},
		BaseConfidence: 0.85,
	})

	// ═══════════════════════════════════════════════════════════════
	// VERSION CONTROL (ADDITIONAL)
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "gitea-token",
		Description:    "Gitea Access Token",
		SecretType:     models.SecretGiteaToken,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)(?:gitea[_\-]?(?:access[_\-]?)?token)\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`),
		Keywords:       []string{"gitea"},
		BaseConfidence: 0.80,
	})

	// ═══════════════════════════════════════════════════════════════
	// WORKFLOW AUTOMATION
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "zapier-webhook",
		Description:    "Zapier Webhook URL (contains secret path)",
		SecretType:     models.SecretZapierWebhook,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`https://hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+/?`),
		Keywords:       []string{"zapier", "hooks.zapier.com"},
		BaseConfidence: 0.90,
	})
	rs.addRule(Rule{
		ID:             "n8n-api-key",
		Description:    "n8n API Key / Webhook Secret",
		SecretType:     models.SecretN8NKey,
		Severity:       models.SeverityMedium,
		Pattern:        regexp.MustCompile(`(?i)(?:n8n[_\-]?(?:api[_\-]?)?(?:key|token|secret))\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		Keywords:       []string{"n8n"},
		BaseConfidence: 0.75,
		MinEntropy:     3.0,
	})

	// ═══════════════════════════════════════════════════════════════
	// LOW-CODE
	// ═══════════════════════════════════════════════════════════════
	rs.addRule(Rule{
		ID:             "retool-api-key",
		Description:    "Retool API Key",
		SecretType:     models.SecretRetoolKey,
		Severity:       models.SeverityHigh,
		Pattern:        regexp.MustCompile(`retool_[A-Za-z0-9]{30,}`),
		Keywords:       []string{"retool"},
		BaseConfidence: 0.90,
	})
}
