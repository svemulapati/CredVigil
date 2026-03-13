// Package models defines the core data structures used throughout CredVigil.
package models

import (
	"fmt"
	"time"
)

// Severity levels for detected secrets.
type Severity int

const (
	SeverityInfo     Severity = iota // Informational / low-confidence
	SeverityLow                      // Low-risk (e.g., test/example keys)
	SeverityMedium                   // Medium-risk (e.g., internal tokens)
	SeverityHigh                     // High-risk (e.g., production API keys)
	SeverityCritical                 // Critical (e.g., private keys, DB passwords in prod)
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// SecretType categorizes the kind of detected credential.
type SecretType string

const (
	// Cloud Providers
	SecretAWSAccessKey      SecretType = "aws-access-key-id"
	SecretAWSSecretKey      SecretType = "aws-secret-access-key"
	SecretAWSSessionToken   SecretType = "aws-session-token"
	SecretGCPServiceAccount SecretType = "gcp-service-account-key"
	SecretGCPOAuth          SecretType = "gcp-oauth-token"
	SecretAzureClientSecret SecretType = "azure-client-secret"
	SecretAzureSubscription SecretType = "azure-subscription-key"
	SecretAzureStorageKey   SecretType = "azure-storage-account-key"

	// Source Control
	SecretGitHubToken       SecretType = "github-token"
	SecretGitHubOAuth       SecretType = "github-oauth"
	SecretGitHubApp         SecretType = "github-app-token"
	SecretGitHubFinegrained SecretType = "github-fine-grained-pat"
	SecretGitLabToken       SecretType = "gitlab-token"
	SecretGitLabRunner      SecretType = "gitlab-runner-token"
	SecretBitbucketToken    SecretType = "bitbucket-token"

	// Collaboration
	SecretSlackToken      SecretType = "slack-token"
	SecretSlackWebhook    SecretType = "slack-webhook"
	SecretJiraToken       SecretType = "jira-api-token"
	SecretConfluenceToken SecretType = "confluence-token"
	SecretTeamsWebhook    SecretType = "teams-webhook"

	// Private Keys & Certificates
	SecretPrivateKeyRSA     SecretType = "private-key-rsa"
	SecretPrivateKeyEC      SecretType = "private-key-ec"
	SecretPrivateKeyGeneric SecretType = "private-key-generic"
	SecretPrivateKeyPKCS8   SecretType = "private-key-pkcs8"
	SecretSSHPrivateKey     SecretType = "ssh-private-key"
	SecretPGPPrivateKey     SecretType = "pgp-private-key"

	// Database
	SecretDBConnectionString SecretType = "database-connection-string"
	SecretDBPassword         SecretType = "database-password"
	SecretMongoDBURI         SecretType = "mongodb-uri"
	SecretPostgresURI        SecretType = "postgresql-uri"
	SecretMySQLURI           SecretType = "mysql-uri"
	SecretRedisURI           SecretType = "redis-uri"

	// Authentication
	SecretJWT          SecretType = "json-web-token"
	SecretBasicAuth    SecretType = "basic-auth-credentials"
	SecretBearerToken  SecretType = "bearer-token"
	SecretOAuthSecret  SecretType = "oauth-client-secret"
	SecretAPIKey       SecretType = "generic-api-key"
	SecretPasswordHash SecretType = "password-in-url"

	// Payment / Finance
	SecretStripeKey   SecretType = "stripe-api-key"
	SecretSquareToken SecretType = "square-access-token"
	SecretPayPalToken SecretType = "paypal-braintree-token"
	SecretTwilioKey   SecretType = "twilio-api-key"

	// Messaging & Communication
	SecretSendgridKey  SecretType = "sendgrid-api-key"
	SecretMailgunKey   SecretType = "mailgun-api-key"
	SecretMailchimpKey SecretType = "mailchimp-api-key"
	SecretTelegramBot  SecretType = "telegram-bot-token"
	SecretDiscordToken SecretType = "discord-bot-token"

	// Infrastructure
	SecretDockerAuth     SecretType = "docker-auth-config"
	SecretNpmToken       SecretType = "npm-token"
	SecretPyPIToken      SecretType = "pypi-token"
	SecretNuGetKey       SecretType = "nuget-api-key"
	SecretHerokuKey      SecretType = "heroku-api-key"
	SecretVaultToken     SecretType = "hashicorp-vault-token"
	SecretTerraformToken SecretType = "terraform-cloud-token"
	SecretDatadogKey     SecretType = "datadog-api-key"
	SecretNewRelicKey    SecretType = "newrelic-api-key"

	// CI/CD
	SecretTravisCIToken SecretType = "travis-ci-token"
	SecretCircleCIToken SecretType = "circleci-token"
	SecretJenkinsToken  SecretType = "jenkins-api-token"
	SecretCodecovToken  SecretType = "codecov-token"

	// SaaS / Other
	SecretFirebaseKey     SecretType = "firebase-api-key"
	SecretAlgoliaKey      SecretType = "algolia-api-key"
	SecretSalesforceToken SecretType = "salesforce-token"
	SecretShopifyToken    SecretType = "shopify-token"
	SecretOpenAIKey       SecretType = "openai-api-key"
	SecretAnthropicKey    SecretType = "anthropic-api-key"

	// AI / ML Services
	SecretGeminiKey     SecretType = "google-gemini-api-key"
	SecretHuggingFace   SecretType = "huggingface-token"
	SecretCohereKey     SecretType = "cohere-api-key"
	SecretMistralKey    SecretType = "mistral-api-key"
	SecretReplicateKey  SecretType = "replicate-api-token"
	SecretGroqKey       SecretType = "groq-api-key"
	SecretDeepseekKey   SecretType = "deepseek-api-key"
	SecretPerplexityKey SecretType = "perplexity-api-key"
	SecretStabilityKey  SecretType = "stability-ai-key"

	// Cloud / Hosting (Small Biz)
	SecretDigitalOceanToken  SecretType = "digitalocean-token"
	SecretDigitalOceanSpaces SecretType = "digitalocean-spaces-key"
	SecretCloudflareToken    SecretType = "cloudflare-api-token"
	SecretCloudflareKey      SecretType = "cloudflare-api-key"
	SecretVercelToken        SecretType = "vercel-token"
	SecretNetlifyToken       SecretType = "netlify-token"
	SecretSupabaseKey        SecretType = "supabase-key"
	SecretRailwayToken       SecretType = "railway-token"
	SecretRenderKey          SecretType = "render-api-key"
	SecretFlyToken           SecretType = "fly-io-token"
	SecretLinodeToken        SecretType = "linode-token"

	// Payment / Fintech (expanded)
	SecretRazorpayKey  SecretType = "razorpay-key"
	SecretPlaidKey     SecretType = "plaid-api-key"
	SecretCoinbaseKey  SecretType = "coinbase-api-key"
	SecretBraintreeKey SecretType = "braintree-key"
	SecretAdyenKey     SecretType = "adyen-api-key"
	SecretPayPalSecret SecretType = "paypal-client-secret"

	// E-commerce
	SecretAmazonMWSKey SecretType = "amazon-mws-key"
	SecretEtsyKey      SecretType = "etsy-api-key"

	// Marketing / Analytics / CRM
	SecretHubSpotKey      SecretType = "hubspot-api-key"
	SecretMixpanelToken   SecretType = "mixpanel-token"
	SecretSegmentKey      SecretType = "segment-write-key"
	SecretIntercomToken   SecretType = "intercom-token"
	SecretAmplitudeKey    SecretType = "amplitude-api-key"
	SecretPostHogKey      SecretType = "posthog-api-key"
	SecretZendeskToken    SecretType = "zendesk-token"
	SecretFreshdeskKey    SecretType = "freshdesk-api-key"
	SecretSalesforceOAuth SecretType = "salesforce-oauth"
	SecretZohoToken       SecretType = "zoho-token"

	// Auth / Identity
	SecretAuth0Secret SecretType = "auth0-client-secret"
	SecretOktaToken   SecretType = "okta-token"
	SecretClerkKey    SecretType = "clerk-secret-key"

	// Observability / Logging
	SecretSentryDSN    SecretType = "sentry-dsn"
	SecretGrafanaKey   SecretType = "grafana-api-key"
	SecretSplunkToken  SecretType = "splunk-token"
	SecretPagerDutyKey SecretType = "pagerduty-key"
	SecretLogglyToken  SecretType = "loggly-token"
	SecretElasticKey   SecretType = "elasticsearch-key"
	SecretOTelToken    SecretType = "opentelemetry-token"

	// Email (expanded)
	SecretPostmarkKey  SecretType = "postmark-server-token"
	SecretResendKey    SecretType = "resend-api-key"
	SecretAmazonSESKey SecretType = "amazon-ses-smtp"

	// Maps / Location
	SecretGoogleMapsKey SecretType = "google-maps-api-key"
	SecretMapboxToken   SecretType = "mapbox-token"

	// Social Media APIs
	SecretTwitterKey    SecretType = "twitter-api-key"
	SecretFacebookToken SecretType = "facebook-access-token"
	SecretLinkedInToken SecretType = "linkedin-token"
	SecretTikTokKey     SecretType = "tiktok-api-key"

	// Storage / CDN
	SecretCloudinaryKey SecretType = "cloudinary-key"
	SecretBackblazeKey  SecretType = "backblaze-b2-key"

	// Modern Databases
	SecretPlanetScaleToken SecretType = "planetscale-token"
	SecretNeonKey          SecretType = "neon-api-key"
	SecretTursoToken       SecretType = "turso-token"
	SecretUpstashToken     SecretType = "upstash-token"
	SecretCockroachDBURI   SecretType = "cockroachdb-uri"

	// Crypto / Web3
	SecretAlchemyKey   SecretType = "alchemy-api-key"
	SecretInfuraKey    SecretType = "infura-api-key"
	SecretEtherscanKey SecretType = "etherscan-api-key"
	SecretMoralisKey   SecretType = "moralis-api-key"

	// CI/CD (expanded)
	SecretBuildkiteToken SecretType = "buildkite-token"
	SecretDroneToken     SecretType = "drone-ci-token"
	SecretPulumiToken    SecretType = "pulumi-token"
	SecretGitHubActions  SecretType = "github-actions-secret"

	// Search
	SecretMeilisearchKey SecretType = "meilisearch-key"
	SecretTypesenseKey   SecretType = "typesense-key"

	// Communication (expanded)
	SecretVonageKey     SecretType = "vonage-api-key"
	SecretPushoverToken SecretType = "pushover-token"
	SecretOneSignalKey  SecretType = "onesignal-key"

	// Entropy-based / Unknown
	SecretHighEntropy SecretType = "high-entropy-string"
	SecretGeneric     SecretType = "generic-secret"
)

// Finding represents a single detected secret occurrence.
type Finding struct {
	// Unique ID for this finding (generated at detection time)
	ID string `json:"id"`

	// What type of secret was found
	SecretType SecretType `json:"secret_type"`

	// Human-readable description
	Description string `json:"description"`

	// Severity assessment
	Severity Severity `json:"severity"`

	// The rule that triggered this finding
	RuleID string `json:"rule_id"`

	// Source location
	Source Source `json:"source"`

	// The matched text (ONLY used locally, NEVER transmitted)
	// Will be redacted before any network operation
	RawMatch string `json:"raw_match,omitempty"`

	// Redacted/masked version safe for display
	RedactedMatch string `json:"redacted_match"`

	// Shannon entropy of the matched secret
	Entropy float64 `json:"entropy"`

	// Confidence score 0.0 - 1.0
	Confidence float64 `json:"confidence"`

	// Whether the secret was verified as active (if validation was attempted)
	Verified *bool `json:"verified,omitempty"`

	// When the finding was detected
	DetectedAt time.Time `json:"detected_at"`

	// Additional contextual metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Source describes where a finding was located.
type Source struct {
	// The type of source (file, git-commit, slack-message, jira-issue, etc.)
	Type string `json:"type"`

	// File path, URL, or resource identifier
	Location string `json:"location"`

	// Line number (1-based) if applicable
	Line int `json:"line,omitempty"`

	// Column (1-based) if applicable
	Column int `json:"column,omitempty"`

	// End line for multi-line matches
	EndLine int `json:"end_line,omitempty"`

	// The line(s) of context around the match (redacted)
	Context string `json:"context,omitempty"`

	// Git-specific fields
	CommitHash string `json:"commit_hash,omitempty"`
	Author     string `json:"author,omitempty"`
	Branch     string `json:"branch,omitempty"`

	// Machine/runtime fields (populated by agent)
	MachineID   string `json:"machine_id,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
}

// Redact masks the raw secret for safe display/transmission.
// Shows first 4 and last 4 characters for secrets > 12 chars,
// otherwise shows first 2 and masks the rest.
func (f *Finding) Redact() {
	if f.RawMatch == "" {
		return
	}
	raw := f.RawMatch
	if len(raw) > 12 {
		f.RedactedMatch = fmt.Sprintf("%s****%s", raw[:4], raw[len(raw)-4:])
	} else if len(raw) > 4 {
		f.RedactedMatch = fmt.Sprintf("%s****", raw[:2])
	} else {
		f.RedactedMatch = "****"
	}
}

// ClearRawMatch removes the plaintext secret from the finding.
// Must be called before any network transmission.
func (f *Finding) ClearRawMatch() {
	f.Redact()
	f.RawMatch = ""
}

// ScanRequest represents a request to scan content.
type ScanRequest struct {
	// Content to scan (text)
	Content string `json:"content"`

	// Source metadata
	Source Source `json:"source"`

	// Optional: only scan for these specific types
	FilterTypes []SecretType `json:"filter_types,omitempty"`

	// Optional: minimum severity to report
	MinSeverity Severity `json:"min_severity,omitempty"`

	// Optional: minimum confidence to report
	MinConfidence float64 `json:"min_confidence,omitempty"`
}

// ScanResult contains the aggregated results of a scan.
type ScanResult struct {
	// All findings from the scan
	Findings []Finding `json:"findings"`

	// Total number of findings
	TotalFindings int `json:"total_findings"`

	// Counts by severity
	CountBySeverity map[Severity]int `json:"count_by_severity"`

	// How long the scan took
	Duration time.Duration `json:"duration"`

	// Source that was scanned
	Source Source `json:"source"`

	// Any non-fatal errors encountered
	Errors []string `json:"errors,omitempty"`
}
