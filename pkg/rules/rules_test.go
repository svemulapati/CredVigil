package rules

import (
	"testing"
)

func TestNewRuleSet(t *testing.T) {
	rs := NewRuleSet()

	if rs.Count() == 0 {
		t.Fatal("Expected rules to be loaded, got 0")
	}

	t.Logf("Loaded %d rules", rs.Count())

	if rs.Count() < 140 {
		t.Errorf("Expected at least 140 built-in rules, got %d", rs.Count())
	}
}

func TestRuleRetrieval(t *testing.T) {
	rs := NewRuleSet()

	tests := []string{
		// Original rules
		"aws-access-key-id",
		"aws-secret-access-key",
		"github-pat-classic",
		"gitlab-pat",
		"slack-bot-token",
		"stripe-secret-key",
		"sendgrid-api-key",
		"json-web-token",
		"private-key-rsa",
		"postgres-uri",
		"generic-api-key",
		"openai-api-key",
		"anthropic-api-key",
		"teams-webhook",
		"vault-token",
		// AI/ML
		"huggingface-token",
		"replicate-api-token",
		"groq-api-key",
		"perplexity-api-key",
		// Cloud/Hosting
		"digitalocean-pat",
		"cloudflare-api-token",
		"render-api-key",
		"supabase-service-key",
		// Payment
		"razorpay-key-id",
		"plaid-secret",
		"paypal-client-secret",
		// Marketing/CRM
		"hubspot-private-app",
		"posthog-api-key",
		"zendesk-token",
		// Auth
		"auth0-client-secret",
		"clerk-secret-key",
		// Observability
		"sentry-dsn",
		"grafana-cloud-token",
		"splunk-hec-token",
		// Email
		"resend-api-key",
		// Maps
		"mapbox-token",
		// Modern DBs
		"planetscale-token",
		"planetscale-password",
		"turso-auth-token",
		"upstash-redis-token",
		// CI/CD
		"pulumi-token",
		"buildkite-api-token",
	}

	for _, id := range tests {
		t.Run(id, func(t *testing.T) {
			rule, ok := rs.GetRule(id)
			if !ok {
				t.Fatalf("Rule %q not found", id)
			}
			if rule.ID != id {
				t.Errorf("Rule ID mismatch: got %q, want %q", rule.ID, id)
			}
			if rule.Pattern == nil {
				t.Errorf("Rule %q has nil pattern", id)
			}
			if rule.Description == "" {
				t.Errorf("Rule %q has empty description", id)
			}
			if rule.BaseConfidence <= 0 || rule.BaseConfidence > 1.0 {
				t.Errorf("Rule %q has invalid base confidence: %f", id, rule.BaseConfidence)
			}
		})
	}
}

func TestRulePatternMatching(t *testing.T) {
	rs := NewRuleSet()

	tests := []struct {
		ruleID      string
		input       string
		shouldMatch bool
	}{
		// AWS
		{"aws-access-key-id", "AKIAIOSFODNN7EXAMPLE", true},
		{"aws-access-key-id", "not-an-aws-key-here", false},
		{"aws-secret-access-key", `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, true},
		// GitHub
		{"github-pat-classic", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234", true},
		{"github-pat-classic", "ghp_short", false},
		{"github-fine-grained-pat", "github_pat_11AAAAAAA0000000000000_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456", true},
		// GitLab
		{"gitlab-pat", "glpat-ABCDEFGHIJKLMNOPQRSTUVWXYz", true},
		{"gitlab-runner-token", "glrt-ABCDEFGHIJKLMNOPQRSTUVWXYz", true},
		// Slack
		{"slack-bot-token", "xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWXyz", true},
		{"slack-user-token", "xoxp-1234567890-1234567890123-1234567890123-abcdefabcdefabcdefabcdefabcdefab", true},
		{"slack-webhook", "https://hooks.slack.com/services/T01234567/B01234567/ABCDEFGHIJKLMNOPQRSTUVWX", true},
		// Private Keys
		{"private-key-rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----", true},
		{"private-key-generic", "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----", true},
		{"openssh-private-key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb...\n-----END OPENSSH PRIVATE KEY-----", true},
		// Database
		{"postgres-uri", "postgresql://user:secretPassword123@db.example.com:5432/mydb", true},
		{"mysql-uri", "mysql://admin:p@ssw0rd@mysql.example.com/app", true},
		{"mongodb-uri", "mongodb+srv://admin:p@ssw0rd@cluster.example.com/app", true},
		{"redis-uri", "redis://:myRedisPassword@redis.example.com:6379/0", true},
		// JWT
		{"json-web-token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", true},
		// Stripe
		{"stripe-secret-key", "sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz", true},
		// SendGrid
		{"sendgrid-api-key", "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq", true},
		// NPM
		{"npm-token", "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12", true},
		// Vault
		{"vault-token", "hvs.CAESIDhMOEXAMPLETOKENVAL", true},
		// OpenAI
		{"openai-api-key-v2", "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn", true},
		// Anthropic
		{"anthropic-api-key", "sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop", true},
		// Firebase
		{"firebase-api-key", "AIzaSyD-EXAMPLE-FIREBASE-API-KEY-here1234", true},
		// Shopify
		{"shopify-access-token", "shpat_abcdef0123456789abcdef0123456789ab", true},
		// Teams
		{"teams-webhook", "https://myorg.webhook.office.com/webhookb2/abc123-def-456@ghi789-jkl-012/IncomingWebhook/mno345pqr678/stu901-vwx-234", true},
		// New Relic
		{"newrelic-api-key", "NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ0", true},
		// Generic
		{"generic-api-key", `api_key = "kJ9mN2pR5tW8xY1zA3bC6dE"`, true},

		// ===== NEW RULES =====
		// AI/ML
		{"huggingface-token", "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh", true},
		{"replicate-api-token", "r8_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", true},
		{"groq-api-key", "gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv", true},
		{"perplexity-api-key", "pplx-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv", true},
		// Cloud/Hosting
		{"digitalocean-pat", "dop_v1_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", true},
		{"digitalocean-oauth", "doo_v1_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", true},
		{"render-api-key", "rnd_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", true},
		// Payment
		{"razorpay-key-id", "rzp_live_ABCDEFghij1234", true},
		{"razorpay-key-id", "rzp_test_ABCDEFghij1234", true},
		// Auth
		{"clerk-secret-key", "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXyz", true},
		// Observability
		{"sentry-dsn", "https://abcdef0123456789abcdef0123456789@o123456.ingest.sentry.io/1234567", true},
		{"grafana-cloud-token", "glc_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", true},
		// Email
		{"resend-api-key", "re_ABCDEFGHIJKLMNOPQRSTUVWXyz", true},
		// Maps
		{"mapbox-token", "pk.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9ABCDEFGHIJKLMNOPqa.ABCDEFGHIJKLMNOPQRSTUVWXyz", true},
		// Social
		{"facebook-access-token", "EAA" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr", true},
		// Modern DBs
		{"planetscale-token", "pscale_tkn_ABCDEFGHIJKLMNOPQRSTUVWXYZabcde", true},
		{"planetscale-password", "pscale_pw_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", true},
		// Crypto/Web3
		// CI/CD
		{"pulumi-token", "pul-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop", true},
		{"buildkite-api-token", "bkua_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn", true},
		// PostHog
		{"posthog-api-key", "phc_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", true},
		// HubSpot
		{"hubspot-private-app", "pat-na1-abcdef01-2345-6789-abcd-ef0123456789", true},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID+"/"+truncate(tt.input, 40), func(t *testing.T) {
			rule, ok := rs.GetRule(tt.ruleID)
			if !ok {
				t.Fatalf("Rule %q not found", tt.ruleID)
			}
			matched := rule.Pattern.MatchString(tt.input)
			if matched != tt.shouldMatch {
				t.Errorf("Rule %q match on %q: got %v, want %v",
					tt.ruleID, truncate(tt.input, 60), matched, tt.shouldMatch)
			}
		})
	}
}

func TestAllRulesHaveValidPatterns(t *testing.T) {
	rs := NewRuleSet()
	for _, rule := range rs.Rules() {
		if rule.ID == "" {
			t.Error("Found rule with empty ID")
		}
		if rule.Pattern == nil {
			t.Errorf("Rule %q has nil pattern", rule.ID)
		}
		if rule.Description == "" {
			t.Errorf("Rule %q has empty description", rule.ID)
		}
	}
}

func TestAddCustomRule(t *testing.T) {
	rs := NewRuleSet()
	initialCount := rs.Count()
	err := rs.AddRule(Rule{
		ID:          "custom-test-rule",
		Description: "Test custom rule",
	})
	if err != nil {
		t.Fatalf("Failed to add custom rule: %v", err)
	}
	if rs.Count() != initialCount+1 {
		t.Errorf("Expected %d rules, got %d", initialCount+1, rs.Count())
	}

	// Adding duplicate should fail
	err = rs.AddRule(Rule{
		ID: "custom-test-rule",
	})
	if err == nil {
		t.Error("Expected error when adding duplicate rule ID")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
