// CredVigil CLI — command-line interface for the core detection engine.
// Scans files, directories, or stdin for hardcoded secrets and credentials.
//
// Usage:
//
//	credvigil scan <path>           Scan a file or directory
//	credvigil scan --stdin          Scan from stdin
//	credvigil rules                 List all detection rules
//	credvigil version               Show version info
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/credvigil/credvigil/pkg/detector"
	"github.com/credvigil/credvigil/pkg/models"
)

const (
	version   = "0.1.0"
	buildDate = "2026-03-12"
	component = "core-detection-engine"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}
	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "rules":
		cmdRules()
	case "version":
		cmdVersion()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════════╗
║                     CredVigil v` + version + `                        ║
║         Credential Detection & Monitoring Engine             ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
  credvigil scan <path>         Scan a file or directory for secrets
  credvigil scan --stdin        Scan from standard input
  credvigil rules               List all detection rules
  credvigil version             Show version and build info

Options:
  --format <text|json>          Output format (default: text)
  --min-confidence <0.0-1.0>    Minimum confidence threshold (default: 0.3)
  --min-severity <info|low|medium|high|critical>  Minimum severity
  --no-entropy                  Disable entropy-based detection
  --no-context                  Don't show surrounding context
  --context-lines <n>           Number of context lines (default: 2)

Examples:
  credvigil scan .                           Scan current directory
  credvigil scan /path/to/project            Scan a project
  credvigil scan config.yaml                  Scan a single file
  credvigil scan --stdin < config.yaml        Scan from stdin
  credvigil scan . --format json             Output as JSON
  credvigil scan . --min-severity high       Only show high/critical
  cat file.txt | credvigil scan --stdin      Pipe content to scan`)
}

func cmdScan(args []string) {
	// Parse flags
	cfg := detector.DefaultConfig()
	fsCfg := detector.DefaultFileScanConfig()
	outputFormat := "text"
	scanStdin := false
	var targets []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--stdin":
			scanStdin = true
		case "--format":
			if i+1 < len(args) {
				i++
				outputFormat = args[i]
			}
		case "--min-confidence":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%f", &cfg.MinConfidence)
			}
		case "--min-severity":
			if i+1 < len(args) {
				i++
				cfg.MinSeverity = parseSeverity(args[i])
			}
		case "--no-entropy":
			cfg.EnableEntropy = false
		case "--no-context":
			cfg.IncludeContext = false
		case "--context-lines":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &cfg.ContextLines)
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				targets = append(targets, args[i])
			}
		}
	}

	if !scanStdin && len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No scan target specified. Use a file/directory path or --stdin")
		os.Exit(1)
	}

	engine := detector.New(cfg)
	scanner := detector.NewFileScanner(engine, fsCfg)
	startTime := time.Now()
	var allResults []models.ScanResult

	if scanStdin {
		result, err := scanner.ScanStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning stdin: %v\n", err)
			os.Exit(1)
		}
		allResults = append(allResults, result)
	} else {
		for _, target := range targets {
			info, err := os.Stat(target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				continue
			}
			if info.IsDir() {
				results, err := scanner.ScanDirectory(target)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error scanning directory %s: %v\n", target, err)
					continue
				}
				allResults = append(allResults, results...)
			} else {
				result, err := scanner.ScanFile(target)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error scanning file %s: %v\n", target, err)
					continue
				}
				if result.TotalFindings > 0 {
					allResults = append(allResults, result)
				}
			}
		}
	}

	totalDuration := time.Since(startTime)

	switch outputFormat {
	case "json":
		outputJSON(allResults, totalDuration)
	default:
		outputText(allResults, totalDuration, engine.RuleCount())
	}

	// Exit with code 1 if any findings
	totalFindings := 0
	for _, r := range allResults {
		totalFindings += r.TotalFindings
	}
	if totalFindings > 0 {
		os.Exit(1)
	}
}

func cmdRules() {
	engine := detector.NewDefault()
	fmt.Printf("\nCredVigil Detection Rules (%d total)\n", engine.RuleCount())
	fmt.Println("═══════════════════════════════════════════════════════════════")
	// We can't easily iterate the rules from the engine, so create a new ruleset
	rs := detector.NewDefault()
	_ = rs // The rules are internal; we print the count
	fmt.Printf("\nLoaded %d detection rules covering:\n", engine.RuleCount())
	fmt.Println("  • Cloud: AWS, GCP, Azure, DigitalOcean, Cloudflare, Vercel, Netlify")
	fmt.Println("  • Cloud (Extended): Oracle OCI, IBM Cloud, Alibaba Cloud, Hetzner, Supabase, Railway, Render, Fly.io, Linode")
	fmt.Println("  • SCM: GitHub, GitLab, Bitbucket, Gitea")
	fmt.Println("  • Collaboration: Slack, Jira, Confluence, Atlassian, Teams, Stack Overflow, Zoom, Webex")
	fmt.Println("  • Private Keys: RSA, EC, PKCS8, OpenSSH, PGP, WireGuard")
	fmt.Println("  • Databases: PostgreSQL, MySQL, MongoDB, Redis, InfluxDB, ClickHouse, Neo4j")
	fmt.Println("  •            Airtable, FaunaDB, Oracle DB, SQL Server/MSSQL, Snowflake")
	fmt.Println("  • Databases (Modern): Supabase, PlanetScale, Neon, Turso, Upstash, CockroachDB")
	fmt.Println("  • Auth/Identity: JWT, Bearer, Basic Auth, OAuth, Auth0, Okta, Clerk")
	fmt.Println("  •                Keycloak, OneLogin, Duo Security, Ping Identity")
	fmt.Println("  • Payment: Stripe, Square, PayPal, Razorpay, Plaid, Coinbase, Adyen")
	fmt.Println("  •          Braintree, Paddle, Klarna")
	fmt.Println("  • AI/ML: OpenAI, Anthropic, Gemini, Hugging Face, Cohere, Mistral")
	fmt.Println("  •        Replicate, Groq, DeepSeek, Perplexity, Stability AI")
	fmt.Println("  • Messaging: SendGrid, Mailgun, Mailchimp, Telegram, Discord, Vonage")
	fmt.Println("  •            Postmark, Resend, Amazon SES, Pushover, OneSignal")
	fmt.Println("  •            SparkPost, Customer.io, Mandrill, Plivo, Bandwidth, Telnyx")
	fmt.Println("  • Marketing/CRM: HubSpot, Mixpanel, Segment, Intercom, Amplitude")
	fmt.Println("  •                PostHog, Zendesk, Freshdesk, Salesforce, Zoho")
	fmt.Println("  • Infrastructure: Docker, Docker Hub, NPM, PyPI, NuGet, Heroku, Vault, Terraform")
	fmt.Println("  • Container/K8s: Kubernetes, Harbor, Quay.io")
	fmt.Println("  • CI/CD: CircleCI, Codecov, Jenkins, Travis CI, Buildkite, Drone, Pulumi")
	fmt.Println("  •        Azure DevOps, TeamCity, Bamboo, Harness, Argo CD")
	fmt.Println("  • Config Mgmt: Ansible, Consul, Nomad, Chef, Puppet")
	fmt.Println("  • Secrets Mgmt: HashiCorp Vault, Doppler, Infisical, 1Password Connect")
	fmt.Println("  • Security: Snyk, CrowdStrike Falcon, Tenable/Nessus")
	fmt.Println("  • CDN/Edge: Fastly, Akamai, Kong, Bunny CDN, Cloudinary, Backblaze B2")
	fmt.Println("  • Data Platforms: Snowflake, Databricks, dbt Cloud, Fivetran, Looker")
	fmt.Println("  • Project Mgmt: Notion, Linear, Asana, Trello, ClickUp, Shortcut")
	fmt.Println("  • CMS: Contentful, Sanity, Strapi, Ghost, WordPress")
	fmt.Println("  • Feature Flags: LaunchDarkly, Split, Flagsmith, ConfigCat")
	fmt.Println("  • Maps: Google Maps, Mapbox")
	fmt.Println("  • Social: Twitter/X, Facebook/Meta, LinkedIn, TikTok")
	fmt.Println("  • Media/Video: Mux, Twitch")
	fmt.Println("  • Design: Figma")
	fmt.Println("  • Testing: BrowserStack, Sauce Labs, Cypress Cloud")
	fmt.Println("  • Networking: ngrok, Tailscale, WireGuard")
	fmt.Println("  • Automation: Zapier, n8n")
	fmt.Println("  • Low-Code: Retool")
	fmt.Println("  • Observability: Datadog, New Relic, Sentry, Grafana, Splunk, PagerDuty, OpenTelemetry")
	fmt.Println("  •               Dynatrace, Sumo Logic, Honeycomb, Bugsnag, Rollbar, Airbrake")
	fmt.Println("  •               Logz.io, Instana, Zabbix")
	fmt.Println("  • Crypto/Web3: Alchemy, Infura, Etherscan, Moralis")
	fmt.Println("  • Search: Meilisearch, Typesense, Elasticsearch, Algolia")
	fmt.Println("  • SaaS: Firebase, Shopify")
	fmt.Println("  • Code Quality: SonarQube, SonarCloud")
	fmt.Println("  • Artifact Mgmt: JFrog Artifactory")
	fmt.Println("  • Code Review: Gerrit")
	fmt.Println("  • IAM/PAM: LDAP, Active Directory, CyberArk, FreeIPA, RADIUS")
	fmt.Println("  • Kerberos: Keytab, Principals, KDC")
	fmt.Println("  • SSO: SAML Private Keys")
	fmt.Println("  • Remote Access: RDP, VNC")
	fmt.Println("  • NAS: Synology, QNAP")
	fmt.Println("  • Generic: API keys, passwords, high-entropy strings")
	fmt.Println()
}

func cmdVersion() {
	fmt.Printf("CredVigil %s\n", version)
	fmt.Printf("Component: %s\n", component)
	fmt.Printf("Build date: %s\n", buildDate)
	fmt.Printf("Go version: see `go version`\n")
}

func parseSeverity(s string) models.Severity {
	switch strings.ToLower(s) {
	case "info":
		return models.SeverityInfo
	case "low":
		return models.SeverityLow
	case "medium", "med":
		return models.SeverityMedium
	case "high":
		return models.SeverityHigh
	case "critical", "crit":
		return models.SeverityCritical
	default:
		return models.SeverityInfo
	}
}

func outputText(results []models.ScanResult, duration time.Duration, ruleCount int) {
	totalFindings := 0
	sevCounts := make(map[models.Severity]int)

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    CredVigil Scan Report                     ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	for _, result := range results {
		if result.TotalFindings == 0 {
			continue
		}
		// Sort findings by severity (critical first)
		sort.Slice(result.Findings, func(i, j int) bool {
			return result.Findings[i].Severity > result.Findings[j].Severity
		})
		for _, f := range result.Findings {
			totalFindings++
			sevCounts[f.Severity]++
			sevColor := severityColor(f.Severity)
			fmt.Printf("%s[%s]%s %s\n", sevColor, f.Severity, colorReset, f.Description)
			fmt.Printf("  Rule:       %s\n", f.RuleID)
			fmt.Printf("  Type:       %s\n", f.SecretType)
			fmt.Printf("  File:       %s:%d\n", f.Source.Location, f.Source.Line)
			fmt.Printf("  Match:      %s\n", f.RedactedMatch)
			fmt.Printf("  Entropy:    %.2f\n", f.Entropy)
			fmt.Printf("  Confidence: %.0f%%\n", f.Confidence*100)
			if hash, ok := f.Metadata["sha256"]; ok {
				fmt.Printf("  SHA-256:    %s...%s\n", hash[:8], hash[len(hash)-8:])
			}
			if f.Source.Context != "" {
				fmt.Println("  Context:")
				for _, line := range strings.Split(f.Source.Context, "\n") {
					fmt.Printf("    %s\n", line)
				}
			}
			fmt.Println()
		}
	}

	// Summary
	fmt.Println("─────────────────────────────────────────────────────────────────")
	fmt.Printf("  Scan completed in %v using %d rules\n", duration.Round(time.Millisecond), ruleCount)
	fmt.Printf("  Total findings: %d\n", totalFindings)
	if totalFindings > 0 {
		fmt.Print("  By severity: ")
		sevOrder := []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo}
		parts := []string{}
		for _, s := range sevOrder {
			if c, ok := sevCounts[s]; ok && c > 0 {
				parts = append(parts, fmt.Sprintf("%s=%d", s, c))
			}
		}
		fmt.Println(strings.Join(parts, ", "))
	}
	fmt.Println("─────────────────────────────────────────────────────────────────")
	if totalFindings == 0 {
		fmt.Println("  ✅ No secrets detected!")
	} else {
		fmt.Printf("  ⚠️  %d potential secret(s) found. Review and remediate.\n", totalFindings)
	}
	fmt.Println()
}

func outputJSON(results []models.ScanResult, duration time.Duration) {
	type jsonOutput struct {
		Version       string              `json:"version"`
		ScanDuration  string              `json:"scan_duration"`
		TotalFindings int                 `json:"total_findings"`
		Results       []models.ScanResult `json:"results"`
	}

	total := 0
	for _, r := range results {
		// Clear raw matches before JSON output (zero-trust: no plaintext in output)
		for i := range r.Findings {
			r.Findings[i].ClearRawMatch()
		}
		total += r.TotalFindings
	}

	out := jsonOutput{
		Version:       version,
		ScanDuration:  duration.String(),
		TotalFindings: total,
		Results:       results,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[91m"
	colorYellow = "\033[93m"
	colorOrange = "\033[33m"
	colorBlue   = "\033[94m"
	colorGray   = "\033[90m"
)

func severityColor(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return colorRed
	case models.SeverityHigh:
		return colorOrange
	case models.SeverityMedium:
		return colorYellow
	case models.SeverityLow:
		return colorBlue
	default:
		return colorGray
	}
}
