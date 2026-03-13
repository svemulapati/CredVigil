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

	if rs.Count() < 260 {
		t.Errorf("Expected at least 260 built-in rules, got %d", rs.Count())
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
		// Code Quality / DevOps
		"sonarqube-token",
		"artifactory-api-key",
		"gerrit-http-password",
		// IAM / PAM / Kerberos
		"ldap-bind-password",
		"active-directory-password",
		"kerberos-keytab",
		"kerberos-password",
		"cyberark-api-token",
		"radius-shared-secret",
		"saml-private-key",
		"freeipa-password",
		// Remote Access / NAS
		"rdp-password",
		"vnc-password",
		"synology-api-token",
		"qnap-api-token",
		"nas-admin-credential",
		// Cloud (Additional)
		"oracle-cloud-ocid",
		"ibm-cloud-api-key",
		"alibaba-cloud-access-key",
		"hetzner-api-token",
		// Container & Orchestration
		"kubernetes-service-token",
		"docker-hub-pat",
		"harbor-credential",
		"quay-robot-token",
		// CI/CD (Expanded)
		"azure-devops-pat",
		"teamcity-token",
		"bamboo-token",
		"harness-api-key",
		"argocd-auth-token",
		// Monitoring (Expanded)
		"dynatrace-api-token",
		"sumologic-access-key",
		"honeycomb-api-key",
		"bugsnag-api-key",
		"rollbar-access-token",
		"airbrake-api-key",
		"logzio-token",
		"instana-api-token",
		"zabbix-api-token",
		// Config Management
		"ansible-vault-password",
		"consul-acl-token",
		"nomad-token",
		"chef-client-key",
		"puppet-access-token",
		// Security Tools
		"snyk-api-token",
		"1password-connect-token",
		"crowdstrike-api-key",
		"tenable-api-key",
		// CDN / Edge
		"fastly-api-token",
		"akamai-client-token",
		"kong-admin-token",
		"bunnycdn-api-key",
		// Data Platforms
		"snowflake-credentials",
		"databricks-token",
		"dbt-cloud-token",
		"fivetran-api-key",
		"looker-client-secret",
		// Databases (Additional)
		"influxdb-token",
		"clickhouse-credentials",
		"neo4j-credentials",
		"airtable-api-key",
		"fauna-secret",
		"oracle-db-connection",
		"mssql-connection-string",
		// Project Management
		"notion-integration-token",
		"linear-api-key",
		"asana-pat",
		"trello-api-key",
		"clickup-api-key",
		"shortcut-api-token",
		// CMS
		"contentful-api-key",
		"sanity-api-token",
		"strapi-api-token",
		"ghost-admin-key",
		"wordpress-app-password",
		// Feature Flags
		"launchdarkly-sdk-key",
		"split-api-key",
		"flagsmith-api-key",
		"configcat-sdk-key",
		// Auth (Expanded)
		"keycloak-client-secret",
		"onelogin-client-secret",
		"duo-integration-key",
		"ping-identity-token",
		// Secrets Management
		"doppler-token",
		"infisical-token",
		// Networking
		"ngrok-auth-token",
		"tailscale-api-key",
		"wireguard-private-key",
		// Testing
		"browserstack-access-key",
		"saucelabs-access-key",
		"cypress-record-key",
		// Design
		"figma-pat",
		// Communication (Expanded)
		"zoom-client-secret",
		"webex-bot-token",
		// Payments (Expanded)
		"braintree-access-token",
		"paddle-api-key",
		"klarna-api-key",
		// Media
		"mux-token-secret",
		"twitch-client-secret",
		// SMS (Expanded)
		"plivo-auth-token",
		"bandwidth-api-token",
		"telnyx-api-key",
		// Email (Expanded)
		"sparkpost-api-key",
		"customerio-api-key",
		"mandrill-api-key",
		// Version Control
		"gitea-token",
		// Automation
		"zapier-webhook",
		"n8n-api-key",
		// Low-Code
		"retool-api-key",
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

		// ===== ENTERPRISE / INFRASTRUCTURE =====
		// SonarQube
		{"sonarqube-token", "squ_abcdef0123456789abcdef0123456789abcdef01", true},
		{"sonarqube-token", "sqp_abcdef0123456789abcdef0123456789abcdef01", true},
		{"sonarqube-token", "not-a-sonar-token", false},
		{"sonarqube-token-legacy", "sonar_token=abcdef0123456789abcdef0123456789abcdef01", true},
		{"sonarqube-webhook-secret", "sonar_webhook_secret=MyWebh00kSecretValue", true},
		// JFrog Artifactory
		{"artifactory-api-key", "AKCabcdefghij1234567890ABCDEFGHIJklmnopq", true},
		{"artifactory-api-key", "notakey", false},
		{"artifactory-token", `artifactory_token=ABCDEFghijklmnopqrstuvwx`, true},
		{"artifactory-encrypted-pass", "APabcdefghijklmnopqrstuvwxyz1234567890ABC", true},
		// Gerrit
		{"gerrit-http-password", `gerrit_http_password=ABCDEFghijklmnop`, true},
		// LDAP
		{"ldap-bind-password", `ldap_bind_password=MyS3cur3Pw0rd!`, true},
		{"ldap-connection-uri", `ldaps://admin:secretPass@ldap.example.com:636`, true},
		// Active Directory
		{"active-directory-password", `domain_admin_password=Sup3rS3cur3!`, true},
		// Kerberos
		{"kerberos-keytab", `KRB5_KTNAME=/etc/krb5/service.keytab`, true},
		{"kerberos-password", `kerberos_password=MyKrbPwd123`, true},
		{"kerberos-krb5-conf", `default_keytab_name = /etc/krb5.keytab`, true},
		// CyberArk PAM
		{"cyberark-api-token", `cyberark_api_token=ABCDEFghijklmnopqrstuvwxyz1234`, true},
		// RADIUS
		{"radius-shared-secret", `radius_shared_secret=MyR4d1usSh4r3d!`, true},
		// SAML
		{"saml-private-key", `saml_private_key=MIIEvgIBADANBgkqhkiG9w`, true},
		// FreeIPA
		{"freeipa-password", `freeipa_admin_password=Sup3rIPApass`, true},
		// RDP / VNC
		{"rdp-password", `rdp_password=MyRdpP@ss123`, true},
		{"vnc-password", `vnc_password=vncP@ss`, true},
		// NAS
		{"synology-api-token", `synology_api_token=ABCDEFghijklmnop`, true},
		{"qnap-api-token", `qnap_api_token=ABCDEFghijklmnop`, true},
		{"nas-admin-credential", `nas_admin_password=MyN4sP@ss!`, true},

		// ===== EXPANDED COVERAGE (v2) =====
		// Cloud (Additional)
		{"alibaba-cloud-access-key", "LTAI5tBcc1234567890abc", true},
		{"docker-hub-pat", "dckr_pat_ABCDEFGHIJKLMNOPQRSTUVz", true},
		// CI/CD (Expanded)
		{"azure-devops-pat", `azure_devops_pat=abcdef0123456789abcdef0123456789abcdef0123456789abcd`, true},
		// Monitoring (Expanded)
		{"dynatrace-api-token", "dt0c01.ABCDEFGHIJKLMNOPQRSTUVWX.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB", true},
		{"bugsnag-api-key", `bugsnag_api_key=abcdef0123456789abcdef0123456789`, true},
		{"rollbar-access-token", `rollbar_access_token=abcdef0123456789abcdef0123456789`, true},
		// Security
		{"snyk-api-token", `snyk_api_token=abcdef01-2345-6789-abcd-ef0123456789`, true},
		// Data Platforms
		{"databricks-token", "dapi0123456789abcdef0123456789abcdef", true},
		{"fauna-secret", "fnABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop", true},
		// Project Management
		{"linear-api-key", "lin_api_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv", true},
		{"notion-integration-token", "ntn_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop", true},
		// Feature Flags
		{"launchdarkly-sdk-key", `launchdarkly_sdk_key=sdk-abcdef01-2345-6789-abcd-ef0123456789`, true},
		// Secrets Management
		{"doppler-token", "dp.st.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop", true},
		// Networking
		{"tailscale-api-key", "tskey-abc123-ABCDEFghijklmnop", true},
		{"wireguard-private-key", "PrivateKey = YEZbx6EkrNAhXz0SPM8e4ESKIvL7nBKYJ2W+e4Lp8Xk=", true},
		// Design
		{"figma-pat", "figd_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv", true},
		// Payments (Expanded)
		{"braintree-access-token", "access_token$production$abc123def456ghij$abcdef0123456789abcdef0123456789", true},
		// Database (Additional)
		{"mssql-connection-string", "Server=myserver.database.windows.net;Database=mydb;User Id=admin;Password=MyS3cur3P@ss!", true},
		// Automation
		{"zapier-webhook", "https://hooks.zapier.com/hooks/catch/123456/abcdef/", true},
		// Low-Code
		{"retool-api-key", "retool_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh", true},
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
