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
	SecretSlackToken         SecretType = "slack-token"
	SecretSlackWebhook       SecretType = "slack-webhook"
	SecretJiraToken          SecretType = "jira-api-token"
	SecretConfluenceToken    SecretType = "confluence-token"
	SecretAtlassianOAuth     SecretType = "atlassian-oauth-secret"
	SecretTeamsWebhook       SecretType = "teams-webhook"
	SecretStackOverflowKey   SecretType = "stackoverflow-key"
	SecretStackEnterpriseKey SecretType = "stack-enterprise-key"

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

	// Code Quality / DevOps Platforms
	SecretSonarQubeToken     SecretType = "sonarqube-token"
	SecretSonarQubeWebhook   SecretType = "sonarqube-webhook-secret"
	SecretArtifactoryToken   SecretType = "artifactory-token"
	SecretArtifactoryEncPass SecretType = "artifactory-encrypted-password"
	SecretGerritHTTPPass     SecretType = "gerrit-http-password"

	// Identity & Access Management (IAM/PAM)
	SecretLDAPBindPassword    SecretType = "ldap-bind-password"
	SecretActiveDirectoryPass SecretType = "active-directory-password"
	SecretKerberosKeytab      SecretType = "kerberos-keytab"
	SecretKerberosPassword    SecretType = "kerberos-password"
	SecretCyberArkToken       SecretType = "cyberark-token"
	SecretRADIUSSecret        SecretType = "radius-shared-secret"
	SecretSAMLKey             SecretType = "saml-private-key"
	SecretFreeIPAPassword     SecretType = "freeipa-password"

	// Remote Access / NAS
	SecretRDPPassword   SecretType = "rdp-password"
	SecretVNCPassword   SecretType = "vnc-password"
	SecretSynologyToken SecretType = "synology-api-token"
	SecretQNAPToken     SecretType = "qnap-api-token"
	SecretNASCredential SecretType = "nas-credential"

	// Cloud Providers (Additional)
	SecretOracleCloudKey  SecretType = "oracle-cloud-key"
	SecretIBMCloudKey     SecretType = "ibm-cloud-api-key"
	SecretAlibabaCloudKey SecretType = "alibaba-cloud-access-key"
	SecretHetznerToken    SecretType = "hetzner-api-token"

	// Container & Orchestration
	SecretKubernetesToken  SecretType = "kubernetes-service-token"
	SecretDockerHubPAT     SecretType = "docker-hub-pat"
	SecretHarborCredential SecretType = "harbor-credential"
	SecretQuayRobotToken   SecretType = "quay-robot-token"

	// CI/CD (Expanded)
	SecretAzureDevOpsPAT SecretType = "azure-devops-pat"
	SecretTeamCityToken  SecretType = "teamcity-token"
	SecretBambooToken    SecretType = "bamboo-token"
	SecretHarnessKey     SecretType = "harness-api-key"
	SecretArgoCDToken    SecretType = "argocd-auth-token"

	// Monitoring & Observability (Expanded)
	SecretDynatraceToken SecretType = "dynatrace-api-token"
	SecretSumoLogicKey   SecretType = "sumologic-access-key"
	SecretHoneycombKey   SecretType = "honeycomb-api-key"
	SecretBugsnagKey     SecretType = "bugsnag-api-key"
	SecretRollbarToken   SecretType = "rollbar-access-token"
	SecretAirbrakeKey    SecretType = "airbrake-api-key"
	SecretLogzioToken    SecretType = "logzio-token"
	SecretInstanaToken   SecretType = "instana-api-token"
	SecretZabbixToken    SecretType = "zabbix-api-token"

	// Config Management & Infrastructure
	SecretAnsibleVaultPass SecretType = "ansible-vault-password"
	SecretConsulToken      SecretType = "consul-acl-token"
	SecretNomadToken       SecretType = "nomad-token"
	SecretChefKey          SecretType = "chef-client-key"
	SecretPuppetToken      SecretType = "puppet-access-token"

	// Security Tools
	SecretSnykToken        SecretType = "snyk-api-token"
	SecretOnePasswordToken SecretType = "1password-connect-token"
	SecretCrowdStrikeKey   SecretType = "crowdstrike-api-key"
	SecretTenableKey       SecretType = "tenable-api-key"

	// API Gateway & CDN
	SecretFastlyToken SecretType = "fastly-api-token"
	SecretAkamaiToken SecretType = "akamai-client-token"
	SecretKongToken   SecretType = "kong-admin-token"
	SecretBunnyCDNKey SecretType = "bunnycdn-api-key"

	// Data Platforms
	SecretSnowflakePass   SecretType = "snowflake-credential"
	SecretDatabricksToken SecretType = "databricks-token"
	SecretDBTCloudToken   SecretType = "dbt-cloud-token"
	SecretFivetranKey     SecretType = "fivetran-api-key"
	SecretLookerSecret    SecretType = "looker-client-secret"

	// Databases (Additional)
	SecretInfluxDBToken  SecretType = "influxdb-token"
	SecretClickHousePass SecretType = "clickhouse-credential"
	SecretNeo4jPass      SecretType = "neo4j-credential"
	SecretAirtableKey    SecretType = "airtable-api-key"
	SecretFaunaSecret    SecretType = "fauna-secret"
	SecretOracleDBURI    SecretType = "oracle-db-uri"
	SecretMSSQLString    SecretType = "mssql-connection-string"

	// Project Management
	SecretNotionToken   SecretType = "notion-integration-token"
	SecretLinearKey     SecretType = "linear-api-key"
	SecretAsanaPAT      SecretType = "asana-pat"
	SecretTrelloKey     SecretType = "trello-api-key"
	SecretClickUpKey    SecretType = "clickup-api-key"
	SecretShortcutToken SecretType = "shortcut-api-token"

	// CMS & Content
	SecretContentfulKey SecretType = "contentful-api-key"
	SecretSanityToken   SecretType = "sanity-api-token"
	SecretStrapiToken   SecretType = "strapi-api-token"
	SecretGhostKey      SecretType = "ghost-admin-key"
	SecretWordPressPass SecretType = "wordpress-app-password"

	// Feature Flags
	SecretLaunchDarklyKey SecretType = "launchdarkly-sdk-key"
	SecretSplitKey        SecretType = "split-api-key"
	SecretFlagsmithKey    SecretType = "flagsmith-api-key"
	SecretConfigCatKey    SecretType = "configcat-sdk-key"

	// Auth/Identity (Expanded)
	SecretKeycloakSecret    SecretType = "keycloak-client-secret"
	SecretOneLoginSecret    SecretType = "onelogin-client-secret"
	SecretDuoKey            SecretType = "duo-integration-key"
	SecretPingIdentityToken SecretType = "ping-identity-token"

	// Secrets Management
	SecretDopplerToken   SecretType = "doppler-token"
	SecretInfisicalToken SecretType = "infisical-token"

	// Networking
	SecretNgrokToken   SecretType = "ngrok-auth-token"
	SecretTailscaleKey SecretType = "tailscale-api-key"
	SecretWireGuardKey SecretType = "wireguard-private-key"

	// Testing & QA
	SecretBrowserStackKey SecretType = "browserstack-access-key"
	SecretSauceLabsKey    SecretType = "saucelabs-access-key"
	SecretCypressKey      SecretType = "cypress-record-key"

	// Design
	SecretFigmaPAT SecretType = "figma-pat"

	// Communication (Expanded)
	SecretZoomSecret SecretType = "zoom-client-secret"
	SecretWebexToken SecretType = "webex-bot-token"

	// Payments (Expanded)
	SecretBraintreeToken SecretType = "braintree-access-token"
	SecretPaddleKey      SecretType = "paddle-api-key"
	SecretKlarnaKey      SecretType = "klarna-api-key"

	// Media & Video
	SecretMuxSecret    SecretType = "mux-token-secret"
	SecretTwitchSecret SecretType = "twitch-client-secret"

	// SMS/Voice (Expanded)
	SecretPlivoToken     SecretType = "plivo-auth-token"
	SecretBandwidthToken SecretType = "bandwidth-api-token"
	SecretTelnyxKey      SecretType = "telnyx-api-key"

	// Email (Expanded)
	SecretSparkPostKey  SecretType = "sparkpost-api-key"
	SecretCustomerIOKey SecretType = "customerio-api-key"
	SecretMandrillKey   SecretType = "mandrill-api-key"

	// Version Control (Additional)
	SecretGiteaToken SecretType = "gitea-token"

	// Workflow Automation
	SecretZapierWebhook SecretType = "zapier-webhook"
	SecretN8NKey        SecretType = "n8n-api-key"

	// Low-Code
	SecretRetoolKey SecretType = "retool-api-key"

	// AI/ML Inference Providers (Next Generation)
	SecretTogetherAIKey  SecretType = "together-ai-api-key"
	SecretFireworksAIKey SecretType = "fireworks-ai-api-key"
	SecretCerebrasKey    SecretType = "cerebras-api-key"
	SecretSambaNovaKey   SecretType = "sambanova-api-key"
	SecretModalKey       SecretType = "modal-api-key"
	SecretBasetenKey     SecretType = "baseten-api-key"
	SecretRunPodKey      SecretType = "runpod-api-key"
	SecretLambdaLabsKey  SecretType = "lambda-labs-api-key"

	// AI/ML Tooling & Orchestration
	SecretWandBKey     SecretType = "wandb-api-key"
	SecretLangSmithKey SecretType = "langsmith-api-key"
	SecretCometMLKey   SecretType = "comet-ml-api-key"
	SecretNeptuneKey   SecretType = "neptune-api-key"
	SecretVoyageAIKey  SecretType = "voyage-ai-api-key"

	// Vector Databases
	SecretPineconeKey SecretType = "pinecone-api-key"
	SecretWeaviateKey SecretType = "weaviate-api-key"
	SecretQdrantKey   SecretType = "qdrant-api-key"
	SecretChromaKey   SecretType = "chroma-api-key"
	SecretZillizKey   SecretType = "zilliz-api-key"

	// Modern Developer Infrastructure
	SecretConvexKey       SecretType = "convex-deploy-key"
	SecretXataKey         SecretType = "xata-api-key"
	SecretDenoDeployToken SecretType = "deno-deploy-token"
	SecretTriggerDevKey   SecretType = "trigger-dev-api-key"
	SecretInngestKey      SecretType = "inngest-signing-key"
	SecretTemporalKey     SecretType = "temporal-api-key"
	SecretTinybirdToken   SecretType = "tinybird-api-token"

	// Modern Auth & Payments
	SecretWorkOSKey       SecretType = "workos-api-key"
	SecretStytchSecret    SecretType = "stytch-secret"
	SecretDescopeKey      SecretType = "descope-project-key"
	SecretLemonSqueezyKey SecretType = "lemonsqueezy-api-key"

	// Modern Communication & Observability
	SecretNovuKey      SecretType = "novu-api-key"
	SecretLoopsKey     SecretType = "loops-api-key"
	SecretAxiomToken   SecretType = "axiom-api-token"
	SecretHighlightKey SecretType = "highlight-api-key"

	// GitLeaks-Parity Additions
	SecretAdobeClientSecret     SecretType = "adobe-client-secret"
	SecretAgeSecretKey          SecretType = "age-secret-key"
	SecretAnthropicAdminKey     SecretType = "anthropic-admin-api-key"
	SecretAWSBedrockKey         SecretType = "aws-bedrock-api-key"
	SecretCloudflareOriginCAKey SecretType = "cloudflare-origin-ca-key"
	SecretConfluentToken        SecretType = "confluent-access-token"
	SecretConfluentSecret       SecretType = "confluent-secret-key"
	SecretDiscordClientSecret   SecretType = "discord-client-secret"
	SecretDropboxToken          SecretType = "dropbox-api-token"
	SecretFacebookAppSecret     SecretType = "facebook-app-secret"
	SecretFacebookPageToken     SecretType = "facebook-page-access-token"
	SecretFlutterwaveKey        SecretType = "flutterwave-secret-key"
	SecretGrafanaSAToken        SecretType = "grafana-service-account-token"
	SecretMattermostToken       SecretType = "mattermost-access-token"
	SecretOpenShiftToken        SecretType = "openshift-user-token"
	SecretPostmanToken          SecretType = "postman-api-token"
	SecretRapidAPIToken         SecretType = "rapidapi-access-token"
	SecretRubyGemsToken         SecretType = "rubygems-api-token"
	SecretSentryAuthToken       SecretType = "sentry-auth-token"
	SecretSourcegraphToken      SecretType = "sourcegraph-access-token"
	SecretSquarespaceToken      SecretType = "squarespace-access-token"
	SecretTypeformToken         SecretType = "typeform-api-token"

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

	// SHA-256 hash of the raw secret (zero-trust fingerprint)
	SecretHash string `json:"secret_hash"`

	// Stable cross-scan fingerprint for deduplication and tracking
	// Derived from rule_id + source_location + secret_hash
	Fingerprint string `json:"fingerprint"`

	// Shannon entropy of the matched secret
	Entropy float64 `json:"entropy"`

	// Confidence score 0.0 - 1.0
	Confidence float64 `json:"confidence"`

	// Whether the secret was verified as active (if validation was attempted)
	Verified *bool `json:"verified,omitempty"`

	// When the finding was detected
	DetectedAt time.Time `json:"detected_at"`

	// Detected file type / programming language
	FileType string `json:"file_type,omitempty"`

	// Detected environment (production, staging, development, ci, unknown)
	Environment string `json:"environment,omitempty"`

	// Secret category for grouping (cloud, auth, database, etc.)
	Category string `json:"category,omitempty"`

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

// ScanMetadata holds scan-level context attached to every finding
// during pipeline processing. Provides audit trail and reproducibility.
type ScanMetadata struct {
	// Unique identifier for this scan run
	ScanID string `json:"scan_id"`

	// CredVigil version that performed the scan
	ScannerVersion string `json:"scanner_version"`

	// SHA-256 hash of the effective scan configuration
	ConfigHash string `json:"config_hash"`

	// When the scan started
	StartedAt time.Time `json:"started_at"`

	// What type of source was scanned (file, directory, stdin, git)
	SourceType string `json:"source_type"`

	// The root path or identifier being scanned
	SourcePath string `json:"source_path"`

	// Hostname of the machine running the scan
	MachineName string `json:"machine_name,omitempty"`

	// Total number of rules loaded
	RuleCount int `json:"rule_count"`
}
