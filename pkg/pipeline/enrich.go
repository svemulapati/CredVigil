package pipeline

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/svemulapati/CredVigil/pkg/models"
)

// EnrichProcessor adds derived metadata to each finding:
//   - FileType: detected from the source file extension
//   - Environment: inferred from path/filename patterns
//   - Category: high-level grouping derived from SecretType
//   - Scan-level metadata (scanner version, scan ID) written to Metadata map
type EnrichProcessor struct{}

// NewEnrichProcessor creates a new EnrichProcessor.
func NewEnrichProcessor() *EnrichProcessor {
	return &EnrichProcessor{}
}

func (e *EnrichProcessor) Name() string { return "enrich" }

func (e *EnrichProcessor) Process(_ context.Context, f *models.Finding, meta *models.ScanMetadata) error {
	// ── File type classification ──
	if f.Source.Location != "" && f.FileType == "" {
		f.FileType = classifyFileType(f.Source.Location)
	}

	// ── Environment detection ──
	if f.Environment == "" {
		f.Environment = detectEnvironment(f.Source.Location)
	}

	// ── Secret category ──
	if f.Category == "" {
		f.Category = categorizeSecret(f.SecretType)
	}

	// ── Scan-level audit metadata ──
	if meta != nil {
		if f.Metadata == nil {
			f.Metadata = make(map[string]string)
		}
		if meta.ScanID != "" {
			f.Metadata["scan_id"] = meta.ScanID
		}
		if meta.ScannerVersion != "" {
			f.Metadata["scanner_version"] = meta.ScannerVersion
		}
		if meta.ConfigHash != "" {
			f.Metadata["config_hash"] = meta.ConfigHash
		}
	}

	return nil
}

// ──────────────────────────────────────────────────────────────────────
// File type classification
// ──────────────────────────────────────────────────────────────────────

// extToFileType maps file extensions to human-readable file type labels.
var extToFileType = map[string]string{
	// Programming languages
	".go":    "go",
	".py":    "python",
	".js":    "javascript",
	".ts":    "typescript",
	".jsx":   "javascript",
	".tsx":   "typescript",
	".java":  "java",
	".kt":    "kotlin",
	".swift": "swift",
	".rs":    "rust",
	".rb":    "ruby",
	".php":   "php",
	".cs":    "csharp",
	".cpp":   "cpp",
	".c":     "c",
	".h":     "c-header",
	".scala": "scala",
	".r":     "r",
	".dart":  "dart",
	".lua":   "lua",
	".pl":    "perl",
	".ex":    "elixir",
	".exs":   "elixir",
	".erl":   "erlang",
	".hs":    "haskell",
	".clj":   "clojure",

	// Config / Data
	".json":       "json",
	".yaml":       "yaml",
	".yml":        "yaml",
	".toml":       "toml",
	".xml":        "xml",
	".ini":        "ini",
	".cfg":        "config",
	".conf":       "config",
	".properties": "properties",
	".env":        "env",
	".plist":      "plist",
	".hcl":        "hcl",
	".tf":         "terraform",
	".tfvars":     "terraform",

	// Shell
	".sh":   "shell",
	".bash": "shell",
	".zsh":  "shell",
	".fish": "shell",
	".ps1":  "powershell",
	".psm1": "powershell",
	".bat":  "batch",
	".cmd":  "batch",

	// Markup / Docs
	".html": "html",
	".htm":  "html",
	".md":   "markdown",
	".rst":  "restructuredtext",
	".txt":  "text",
	".csv":  "csv",
	".sql":  "sql",

	// Build / Package
	".dockerfile": "dockerfile",
	".gradle":     "gradle",
	".maven":      "maven",
	".sbt":        "sbt",

	// Certificates & Keys
	".pem": "pem",
	".key": "key",
	".crt": "certificate",
	".p12": "pkcs12",
	".jks": "java-keystore",
}

// specialFilenames maps exact filenames to types.
var specialFilenames = map[string]string{
	"dockerfile":       "dockerfile",
	"docker-compose":   "docker-compose",
	"makefile":         "makefile",
	"gemfile":          "ruby",
	"rakefile":         "ruby",
	"pipfile":          "python",
	"cargo.toml":       "rust",
	"go.mod":           "go",
	"go.sum":           "go",
	"package.json":     "javascript",
	"tsconfig.json":    "typescript",
	"requirements.txt": "python",
	"build.gradle":     "gradle",
	"pom.xml":          "maven",
	".gitignore":       "git",
	".dockerignore":    "docker",
	".npmrc":           "npm",
	".pypirc":          "pypi",
	".netrc":           "netrc",
	".htpasswd":        "htpasswd",
	"id_rsa":           "ssh-key",
	"id_ed25519":       "ssh-key",
	"known_hosts":      "ssh",
	"authorized_keys":  "ssh",
}

func classifyFileType(location string) string {
	base := strings.ToLower(filepath.Base(location))

	// Check special filenames first
	if ft, ok := specialFilenames[base]; ok {
		return ft
	}

	ext := strings.ToLower(filepath.Ext(location))
	if ft, ok := extToFileType[ext]; ok {
		return ft
	}

	// Heuristics for extensionless files
	if strings.Contains(base, "env") {
		return "env"
	}
	if strings.Contains(base, "secret") || strings.Contains(base, "credential") {
		return "secrets"
	}

	return "unknown"
}

// ──────────────────────────────────────────────────────────────────────
// Environment detection
// ──────────────────────────────────────────────────────────────────────

// envPatterns maps path substrings to environment labels.
// Checked in priority order.
var envPatterns = []struct {
	pattern string
	env     string
}{
	// Production indicators
	{"production", "production"},
	{"/prod/", "production"},
	{".prod.", "production"},
	{"-prod-", "production"},
	{"_prod_", "production"},
	{"prod.env", "production"},
	{".production.", "production"},

	// Staging indicators
	{"staging", "staging"},
	{"/stage/", "staging"},
	{".staging.", "staging"},
	{"-staging-", "staging"},
	{"-stage-", "staging"},
	{"stage.env", "staging"},

	// Development indicators
	{"development", "development"},
	{"/dev/", "development"},
	{".dev.", "development"},
	{"-dev-", "development"},
	{"_dev_", "development"},
	{"dev.env", "development"},
	{".local", "development"},
	{"localhost", "development"},

	// CI/CD indicators
	{".github/", "ci"},
	{".gitlab-ci", "ci"},
	{".circleci", "ci"},
	{"jenkinsfile", "ci"},
	{".travis", "ci"},
	{"buildkite", "ci"},
	{".drone", "ci"},
	{"azure-pipelines", "ci"},

	// Test indicators
	{"/test/", "test"},
	{"/tests/", "test"},
	{"_test.", "test"},
	{".test.", "test"},
	{"testdata", "test"},
	{"/spec/", "test"},
	{"/fixtures/", "test"},
}

func detectEnvironment(location string) string {
	if location == "" {
		return "unknown"
	}
	lower := strings.ToLower(location)
	for _, ep := range envPatterns {
		if strings.Contains(lower, ep.pattern) {
			return ep.env
		}
	}
	return "unknown"
}

// ──────────────────────────────────────────────────────────────────────
// Secret category classification
// ──────────────────────────────────────────────────────────────────────

// categorizeSecret maps SecretType to a broad category string.
func categorizeSecret(st models.SecretType) string {
	s := string(st)
	switch {
	// Cloud providers
	case strings.HasPrefix(s, "aws-") || strings.HasPrefix(s, "gcp-") ||
		strings.HasPrefix(s, "azure-") || strings.Contains(s, "cloud") ||
		strings.HasPrefix(s, "digitalocean") || strings.HasPrefix(s, "cloudflare") ||
		strings.HasPrefix(s, "oracle") || strings.HasPrefix(s, "ibm") ||
		strings.HasPrefix(s, "alibaba") || strings.HasPrefix(s, "hetzner") ||
		strings.HasPrefix(s, "vercel") || strings.HasPrefix(s, "netlify") ||
		strings.HasPrefix(s, "heroku") || strings.HasPrefix(s, "render") ||
		strings.HasPrefix(s, "fly-") || strings.HasPrefix(s, "railway") ||
		strings.HasPrefix(s, "linode"):
		return "cloud"

	// Databases
	case strings.Contains(s, "postgres") || strings.Contains(s, "mysql") ||
		strings.Contains(s, "mongo") || strings.Contains(s, "redis") ||
		strings.Contains(s, "database") || strings.Contains(s, "db-") ||
		strings.Contains(s, "influx") || strings.Contains(s, "clickhouse") ||
		strings.Contains(s, "neo4j") || strings.Contains(s, "airtable") ||
		strings.Contains(s, "fauna") || strings.Contains(s, "mssql") ||
		strings.Contains(s, "snowflake") || strings.Contains(s, "supabase") ||
		strings.Contains(s, "planetscale") || strings.Contains(s, "neon") ||
		strings.Contains(s, "turso") || strings.Contains(s, "upstash") ||
		strings.Contains(s, "cockroach"):
		return "database"

	// Auth & Identity
	case strings.Contains(s, "jwt") || strings.Contains(s, "oauth") ||
		strings.Contains(s, "bearer") || strings.Contains(s, "auth") ||
		strings.Contains(s, "okta") || strings.Contains(s, "clerk") ||
		strings.Contains(s, "keycloak") || strings.Contains(s, "onelogin") ||
		strings.Contains(s, "duo") || strings.Contains(s, "ping-identity") ||
		strings.Contains(s, "saml") || strings.Contains(s, "ldap") ||
		strings.Contains(s, "active-directory") || strings.Contains(s, "kerberos") ||
		strings.Contains(s, "freeipa") || strings.Contains(s, "radius"):
		return "auth"

	// CI/CD
	case strings.Contains(s, "circle") || strings.Contains(s, "jenkins") ||
		strings.Contains(s, "travis") || strings.Contains(s, "buildkite") ||
		strings.Contains(s, "drone") || strings.Contains(s, "pulumi") ||
		strings.Contains(s, "codecov") || strings.Contains(s, "teamcity") ||
		strings.Contains(s, "bamboo") || strings.Contains(s, "harness") ||
		strings.Contains(s, "argocd") || strings.Contains(s, "azure-devops"):
		return "ci-cd"

	// SCM / Version Control
	case strings.Contains(s, "github") || strings.Contains(s, "gitlab") ||
		strings.Contains(s, "bitbucket") || strings.Contains(s, "gitea"):
		return "scm"

	// Private Keys
	case strings.Contains(s, "private-key") || strings.Contains(s, "ssh") ||
		strings.Contains(s, "pgp") || strings.Contains(s, "wireguard"):
		return "private-key"

	// Payment
	case strings.Contains(s, "stripe") || strings.Contains(s, "square") ||
		strings.Contains(s, "paypal") || strings.Contains(s, "razorpay") ||
		strings.Contains(s, "plaid") || strings.Contains(s, "coinbase") ||
		strings.Contains(s, "adyen") || strings.Contains(s, "braintree") ||
		strings.Contains(s, "paddle") || strings.Contains(s, "klarna"):
		return "payment"

	// AI/ML
	case strings.Contains(s, "openai") || strings.Contains(s, "anthropic") ||
		strings.Contains(s, "gemini") || strings.Contains(s, "hugging") ||
		strings.Contains(s, "cohere") || strings.Contains(s, "mistral") ||
		strings.Contains(s, "replicate") || strings.Contains(s, "groq") ||
		strings.Contains(s, "deepseek") || strings.Contains(s, "perplexity") ||
		strings.Contains(s, "stability"):
		return "ai-ml"

	// Messaging & Email
	case strings.Contains(s, "sendgrid") || strings.Contains(s, "mailgun") ||
		strings.Contains(s, "mailchimp") || strings.Contains(s, "telegram") ||
		strings.Contains(s, "discord") || strings.Contains(s, "vonage") ||
		strings.Contains(s, "postmark") || strings.Contains(s, "resend") ||
		strings.Contains(s, "ses-") || strings.Contains(s, "pushover") ||
		strings.Contains(s, "onesignal") || strings.Contains(s, "sparkpost") ||
		strings.Contains(s, "customer-io") || strings.Contains(s, "mandrill") ||
		strings.Contains(s, "slack") || strings.Contains(s, "teams") ||
		strings.Contains(s, "zoom") || strings.Contains(s, "webex") ||
		strings.Contains(s, "plivo") || strings.Contains(s, "bandwidth") ||
		strings.Contains(s, "telnyx") || strings.Contains(s, "twilio"):
		return "messaging"

	// Observability
	case strings.Contains(s, "datadog") || strings.Contains(s, "newrelic") ||
		strings.Contains(s, "sentry") || strings.Contains(s, "grafana") ||
		strings.Contains(s, "splunk") || strings.Contains(s, "pagerduty") ||
		strings.Contains(s, "elastic") || strings.Contains(s, "otel") ||
		strings.Contains(s, "dynatrace") || strings.Contains(s, "sumologic") ||
		strings.Contains(s, "honeycomb") || strings.Contains(s, "bugsnag") ||
		strings.Contains(s, "rollbar") || strings.Contains(s, "airbrake") ||
		strings.Contains(s, "logzio") || strings.Contains(s, "instana") ||
		strings.Contains(s, "zabbix"):
		return "observability"

	// Infrastructure & Containers
	case strings.Contains(s, "docker") || strings.Contains(s, "npm") ||
		strings.Contains(s, "pypi") || strings.Contains(s, "nuget") ||
		strings.Contains(s, "vault") || strings.Contains(s, "terraform") ||
		strings.Contains(s, "kubernetes") || strings.Contains(s, "harbor") ||
		strings.Contains(s, "quay") || strings.Contains(s, "consul") ||
		strings.Contains(s, "nomad") || strings.Contains(s, "ansible") ||
		strings.Contains(s, "chef") || strings.Contains(s, "puppet"):
		return "infrastructure"

	// Security
	case strings.Contains(s, "snyk") || strings.Contains(s, "1password") ||
		strings.Contains(s, "crowdstrike") || strings.Contains(s, "tenable") ||
		strings.Contains(s, "cyberark") || strings.Contains(s, "sonar") ||
		strings.Contains(s, "artifactory"):
		return "security"

	// Data platforms
	case strings.Contains(s, "databricks") || strings.Contains(s, "dbt") ||
		strings.Contains(s, "fivetran") || strings.Contains(s, "looker"):
		return "data-platform"

	// Feature flags
	case strings.Contains(s, "launchdarkly") || strings.Contains(s, "split") ||
		strings.Contains(s, "flagsmith") || strings.Contains(s, "configcat"):
		return "feature-flags"

	// Secrets management
	case strings.Contains(s, "doppler") || strings.Contains(s, "infisical"):
		return "secrets-management"

	// CDN / Edge
	case strings.Contains(s, "fastly") || strings.Contains(s, "akamai") ||
		strings.Contains(s, "kong") || strings.Contains(s, "bunny") ||
		strings.Contains(s, "cloudinary") || strings.Contains(s, "backblaze"):
		return "cdn"

	// CMS
	case strings.Contains(s, "contentful") || strings.Contains(s, "sanity") ||
		strings.Contains(s, "strapi") || strings.Contains(s, "ghost") ||
		strings.Contains(s, "wordpress"):
		return "cms"

	// Project management
	case strings.Contains(s, "notion") || strings.Contains(s, "linear") ||
		strings.Contains(s, "asana") || strings.Contains(s, "trello") ||
		strings.Contains(s, "clickup") || strings.Contains(s, "shortcut") ||
		strings.Contains(s, "jira") || strings.Contains(s, "confluence"):
		return "project-management"

	// CRM / Marketing
	case strings.Contains(s, "hubspot") || strings.Contains(s, "mixpanel") ||
		strings.Contains(s, "segment") || strings.Contains(s, "intercom") ||
		strings.Contains(s, "amplitude") || strings.Contains(s, "posthog") ||
		strings.Contains(s, "zendesk") || strings.Contains(s, "freshdesk") ||
		strings.Contains(s, "salesforce") || strings.Contains(s, "zoho"):
		return "marketing-crm"

	// Networking
	case strings.Contains(s, "ngrok") || strings.Contains(s, "tailscale"):
		return "networking"

	// Remote access / NAS
	case strings.Contains(s, "rdp") || strings.Contains(s, "vnc") ||
		strings.Contains(s, "synology") || strings.Contains(s, "qnap") ||
		strings.Contains(s, "nas"):
		return "remote-access"

	// Crypto / Web3
	case strings.Contains(s, "alchemy") || strings.Contains(s, "infura") ||
		strings.Contains(s, "etherscan") || strings.Contains(s, "moralis"):
		return "crypto"

	// Entropy-based
	case s == "high-entropy-string":
		return "entropy"

	default:
		return "generic"
	}
}
