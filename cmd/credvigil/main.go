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
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	appconfig "github.com/svemulapati/CredVigil/internal/config"
	"github.com/svemulapati/CredVigil/internal/storage"
	"github.com/svemulapati/CredVigil/pkg/baseline"
	"github.com/svemulapati/CredVigil/pkg/detector"
	gitpkg "github.com/svemulapati/CredVigil/pkg/git"
	"github.com/svemulapati/CredVigil/pkg/models"
	"github.com/svemulapati/CredVigil/pkg/pipeline"
	"github.com/svemulapati/CredVigil/pkg/report"
)

// version is overridable at build time via -ldflags "-X main.version=...".
// GoReleaser injects the git tag; this default is used for `go build`/dev.
var version = "0.2.0"

const (
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
  credvigil scan --git <path|url>  Scan git repository history
  credvigil rules               List all detection rules
  credvigil version             Show version and build info

Options:
  --format <text|json|sarif>    Output format (default: text)
  --config <path>               Config file (default: auto-discover .credvigil.yml)
  --min-confidence <0.0-1.0>    Minimum confidence threshold (default: 0.3)
  --min-severity <info|low|medium|high|critical>  Minimum severity
  --no-entropy                  Disable entropy-based detection
  --no-bpe                      Disable BPE token efficiency detection
  --no-ignore                   Ignore the .credvigilignore baseline file
  --no-context                  Don't show surrounding context
  --context-lines <n>           Number of context lines (default: 2)
  --store                       Persist findings to PostgreSQL/TimescaleDB
  --db <connection-string>      PostgreSQL DSN (or set CREDVIGIL_DB env var)

Suppression:
  Baseline findings in a .credvigilignore file at the scan root — one finding
  fingerprint or path glob per line. Or add an inline "# credvigil:allow"
  comment on a line to accept any secret on it. See CONTRIBUTING.md.

Git Options:
  --git <path|url>              Scan a git repository's commit history
  --git-branch <branch>         Scan a specific branch (default: current)
  --git-since <commit>          Only scan commits after this hash
  --git-depth <n>               Clone depth for remote repos (0 = full)
  --git-max-commits <n>         Maximum commits to scan (0 = all)
  --git-all-branches            Scan all branches
  --git-include-merges          Include merge commits

Examples:
  credvigil scan .                           Scan current directory
  credvigil scan /path/to/project            Scan a project
  credvigil scan config.yaml                  Scan a single file
  credvigil scan --stdin < config.yaml        Scan from stdin
  credvigil scan . --format json             Output as JSON
  credvigil scan . --min-severity high       Only show high/critical
  cat file.txt | credvigil scan --stdin      Pipe content to scan
  credvigil scan --git .                     Scan current repo history
  credvigil scan --git /path/to/repo         Scan local repo history
  credvigil scan --git https://github.com/org/repo.git  Clone and scan
  credvigil scan --git . --git-since abc123  Incremental scan`)
}

func cmdScan(args []string) {
	// Parse flags
	cfg := detector.DefaultConfig()
	fsCfg := detector.DefaultFileScanConfig()
	gitOpts := gitpkg.DefaultScanOptions()
	outputFormat := "text"
	scanStdin := false
	gitTarget := ""
	storeEnabled := false
	useIgnore := true
	configPath := ""
	dbConnString := os.Getenv("CREDVIGIL_DB")
	var targets []string

	// First pass: resolve --config and the primary target so a config file can
	// be discovered and layered under the defaults before CLI flags override it.
	configPath, preTarget := prescanConfig(args)
	if ac, path, ok := loadScanConfig(configPath, preTarget); ok {
		applyAppConfig(ac, &cfg, &fsCfg, &outputFormat)
		fmt.Fprintf(os.Stderr, "Loaded config: %s\n", path)
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			if i+1 < len(args) {
				i++
			}
		case "--no-ignore":
			useIgnore = false
		case "--stdin":
			scanStdin = true
		case "--git":
			if i+1 < len(args) {
				i++
				gitTarget = args[i]
			}
		case "--git-branch":
			if i+1 < len(args) {
				i++
				gitOpts.Branch = args[i]
			}
		case "--git-since":
			if i+1 < len(args) {
				i++
				gitOpts.SinceCommit = args[i]
			}
		case "--git-depth":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &gitOpts.Depth)
			}
		case "--git-max-commits":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &gitOpts.MaxCommits)
			}
		case "--git-all-branches":
			gitOpts.AllBranches = true
		case "--git-include-merges":
			gitOpts.IncludeMerges = true
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
		case "--no-bpe":
			cfg.EnableBPE = false
		case "--no-context":
			cfg.IncludeContext = false
		case "--context-lines":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &cfg.ContextLines)
			}
		case "--store":
			storeEnabled = true
		case "--db":
			if i+1 < len(args) {
				i++
				dbConnString = args[i]
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				targets = append(targets, args[i])
			}
		}
	}

	if !scanStdin && len(targets) == 0 && gitTarget == "" {
		fmt.Fprintln(os.Stderr, "Error: No scan target specified. Use a file/directory path, --stdin, or --git")
		os.Exit(1)
	}

	engine := detector.New(cfg)
	startTime := time.Now()

	// Git history scanning mode
	if gitTarget != "" {
		cmdScanGit(engine, gitTarget, gitOpts, outputFormat, startTime)
		return
	}

	scanner := detector.NewFileScanner(engine, fsCfg)
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

	// Run the zero-trust post-processing pipeline on all results.
	// This hashes, redacts, enriches, fingerprints, and sanitizes every finding.
	pipe := pipeline.NewDefault()
	meta := &models.ScanMetadata{
		ScannerVersion: version,
		StartedAt:      startTime,
		RuleCount:      engine.RuleCount(),
	}
	for i := range allResults {
		if errs := pipe.ProcessResult(context.Background(), &allResults[i], meta); len(errs) > 0 {
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "pipeline: %v\n", e)
			}
		}
	}

	// Apply the .credvigilignore baseline (fingerprints + path globs) so
	// accepted / pre-existing findings are suppressed. Runs after the pipeline
	// because suppression keys on the stable fingerprint it computes.
	if useIgnore && !scanStdin {
		root := "."
		if len(targets) > 0 {
			root = targets[0]
		}
		if bl, err := baseline.Discover(root); err != nil {
			fmt.Fprintf(os.Stderr, "baseline: %v\n", err)
		} else if n := bl.Apply(allResults); n > 0 {
			fmt.Fprintf(os.Stderr, "Suppressed %d finding(s) via %s\n", n, baseline.DefaultFileName)
		}
	}

	switch outputFormat {
	case "json":
		outputJSON(allResults, totalDuration)
	case "sarif":
		if err := report.WriteSARIF(os.Stdout, flattenFindings(allResults), version); err != nil {
			fmt.Fprintf(os.Stderr, "sarif: %v\n", err)
			os.Exit(2)
		}
	default:
		outputText(allResults, totalDuration, engine.RuleCount())
	}

	// Count total findings for exit code and storage
	totalFindings := 0
	for _, r := range allResults {
		totalFindings += r.TotalFindings
	}

	// Persist findings to PostgreSQL if --store is enabled
	if storeEnabled {
		if dbConnString == "" {
			fmt.Fprintln(os.Stderr, "Error: --store requires a database connection string.")
			fmt.Fprintln(os.Stderr, "  Use --db <connection-string> or set CREDVIGIL_DB env var.")
			fmt.Fprintln(os.Stderr, "  Example: --db postgres://user:pass@localhost:5432/credvigil?sslmode=disable")
			os.Exit(2)
		}
		persistResults(allResults, dbConnString, startTime, totalDuration, engine.RuleCount(), totalFindings, targets)
	}

	if totalFindings > 0 {
		os.Exit(1)
	}
}

// persistResults saves scan results and findings to PostgreSQL.
func persistResults(results []models.ScanResult, connString string, startTime time.Time, duration time.Duration, ruleCount, totalFindings int, targets []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	repo, err := storage.NewPostgresRepository(ctx, connString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "storage: failed to connect: %v\n", err)
		fmt.Fprintln(os.Stderr, "  Scan results were NOT persisted. Continuing...")
		return
	}
	defer repo.Close()

	scanID := generateID()
	finishedAt := startTime.Add(duration)

	// Build severity counts
	sevCounts := make(models.JSONMap)
	for _, r := range results {
		for sev, count := range r.CountBySeverity {
			key := sev.String()
			if existing, ok := sevCounts[key]; ok {
				sevCounts[key] = existing.(int) + count
			} else {
				sevCounts[key] = count
			}
		}
	}

	// Determine scan target
	scanTarget := "."
	if len(targets) > 0 {
		scanTarget = strings.Join(targets, ", ")
	}

	// Determine exit code
	exitCode := 0
	if totalFindings > 0 {
		exitCode = 1
	}

	// Check if running in CI
	isCI := os.Getenv("CI") == "true" || os.Getenv("GITHUB_ACTIONS") == "true"
	ciJobRef := os.Getenv("GITHUB_SERVER_URL") + "/" + os.Getenv("GITHUB_REPOSITORY") + "/actions/runs/" + os.Getenv("GITHUB_RUN_ID")
	if !isCI {
		ciJobRef = ""
	}

	hostname, _ := os.Hostname()

	scan := &models.StoredScanResult{
		ID:             scanID,
		ScannerVersion: version,
		ScanType:       "file",
		ScanTarget:     scanTarget,
		StartedAt:      startTime,
		FinishedAt:     finishedAt,
		DurationMs:     duration.Milliseconds(),
		TotalFindings:  totalFindings,
		SeverityCounts: sevCounts,
		FilesScanned:   len(results),
		RuleCount:      ruleCount,
		MachineName:    hostname,
		ExitCode:       exitCode,
		IsCI:           isCI,
		CIJobRef:       ciJobRef,
	}

	// Convert findings to StoredFinding
	var storedFindings []models.StoredFinding
	for _, r := range results {
		for i := range r.Findings {
			sf := models.ToStoredFinding(&r.Findings[i], scanID, finishedAt)
			storedFindings = append(storedFindings, sf)
		}
	}

	if err := repo.SaveScanResult(ctx, scan, storedFindings); err != nil {
		fmt.Fprintf(os.Stderr, "storage: failed to persist: %v\n", err)
		fmt.Fprintln(os.Stderr, "  Scan results were NOT persisted. Continuing...")
		return
	}

	// Log audit event
	auditLog := &models.AuditLog{
		Timestamp: finishedAt,
		EventType: "scan.completed",
		Actor:     "credvigil-cli",
		ScanID:    &scanID,
		Details: models.JSONMap{
			"scan_target":    scanTarget,
			"total_findings": totalFindings,
			"duration_ms":    duration.Milliseconds(),
			"rule_count":     ruleCount,
		},
		Severity: "info",
	}
	if err := repo.LogEvent(ctx, auditLog); err != nil {
		fmt.Fprintf(os.Stderr, "storage: failed to log audit event: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "  💾 Persisted %d finding(s) to database (scan: %s)\n", totalFindings, scanID[:8])
}

// generateID creates a random hex string suitable for use as a UUID-like ID.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// cmdScanGit handles git repository history scanning.
func cmdScanGit(engine *detector.Engine, target string, opts gitpkg.ScanOptions, outputFormat string, startTime time.Time) {
	ctx := context.Background()

	scanner := gitpkg.NewGitScanner(engine, opts)

	// Determine if this is a URL (remote) or local path
	isRemote := strings.HasPrefix(target, "http://") ||
		strings.HasPrefix(target, "https://") ||
		strings.HasPrefix(target, "git@") ||
		strings.HasPrefix(target, "ssh://")

	var result *gitpkg.GitScanResult
	var err error

	if isRemote {
		fmt.Fprintf(os.Stderr, "Cloning %s...\n", target)
		result, err = scanner.ScanRemoteRepo(ctx, target)
	} else {
		result, err = scanner.ScanLocalRepo(ctx, target)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning git repository: %v\n", err)
		os.Exit(1)
	}

	totalDuration := time.Since(startTime)

	switch outputFormat {
	case "json":
		outputGitJSON(result, totalDuration)
	case "sarif":
		var findings []models.Finding
		for _, cr := range result.CommitResults {
			findings = append(findings, cr.Findings...)
		}
		if err := report.WriteSARIF(os.Stdout, findings, version); err != nil {
			fmt.Fprintf(os.Stderr, "sarif: %v\n", err)
			os.Exit(2)
		}
	default:
		outputGitText(result, totalDuration, engine.RuleCount())
	}

	if result.TotalFindings > 0 {
		os.Exit(1)
	}
}

func outputGitText(result *gitpkg.GitScanResult, duration time.Duration, ruleCount int) {
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║               CredVigil Git History Scan Report              ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Repository: %s\n", result.Repository)
	if result.RemoteURL != "" {
		fmt.Printf("  Remote:     %s\n", result.RemoteURL)
	}
	fmt.Printf("  Commits:    %d scanned / %d total\n", result.ScannedCommits, result.TotalCommits)
	fmt.Println()

	if result.TotalFindings == 0 {
		fmt.Println("  ✅ No secrets found in git history!")
		fmt.Println()
		fmt.Println("─────────────────────────────────────────────────────────────────")
		fmt.Printf("  Scan completed in %v using %d rules\n", duration.Round(time.Millisecond), ruleCount)
		fmt.Println("─────────────────────────────────────────────────────────────────")
		fmt.Println()
		return
	}

	sevCounts := make(map[models.Severity]int)
	totalFindings := 0

	for _, cr := range result.CommitResults {
		fmt.Printf("  Commit: %s by %s\n", cr.Commit.ShortHash, cr.Commit.AuthorName)
		fmt.Printf("  Date:   %s\n", cr.Commit.AuthorDate.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Message: %s\n", cr.Commit.Subject)
		fmt.Println()

		// Sort findings by severity
		sort.Slice(cr.Findings, func(i, j int) bool {
			return cr.Findings[i].Severity > cr.Findings[j].Severity
		})

		for _, f := range cr.Findings {
			totalFindings++
			sevCounts[f.Severity]++
			sevColor := severityColor(f.Severity)
			fmt.Printf("  %s[%s]%s %s\n", sevColor, f.Severity, colorReset, f.Description)
			fmt.Printf("    Rule:       %s\n", f.RuleID)
			fmt.Printf("    File:       %s:%d\n", f.Source.Location, f.Source.Line)
			fmt.Printf("    Match:      %s\n", f.RedactedMatch)
			fmt.Printf("    Confidence: %.0f%%\n", f.Confidence*100)
			if f.Metadata != nil {
				if bpeEff, ok := f.Metadata["bpe_efficiency"]; ok {
					fmt.Printf("    BPE Eff:    %s", bpeEff)
					if bpeTok, ok2 := f.Metadata["bpe_tokens"]; ok2 {
						fmt.Printf(" (%s tokens)", bpeTok)
					}
					fmt.Println()
				}
			}
			if f.SecretHash != "" {
				fmt.Printf("    SHA-256:    %s...%s\n", f.SecretHash[:8], f.SecretHash[len(f.SecretHash)-8:])
			}
			if f.Fingerprint != "" {
				fmt.Printf("    Fingerprint:%s\n", f.Fingerprint[:16])
			}
			fmt.Printf("    Commit:     %s\n", f.Source.CommitHash[:8])
			fmt.Printf("    Author:     %s\n", f.Source.Author)
			fmt.Println()
		}
		fmt.Println("  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
		fmt.Println()
	}

	fmt.Println("─────────────────────────────────────────────────────────────────")
	fmt.Printf("  Scan completed in %v using %d rules\n", duration.Round(time.Millisecond), ruleCount)
	fmt.Printf("  Commits scanned: %d / %d\n", result.ScannedCommits, result.TotalCommits)
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
	fmt.Printf("  ⚠️  %d potential secret(s) found in git history. Review and remediate.\n", totalFindings)
	fmt.Println()
}

func outputGitJSON(result *gitpkg.GitScanResult, duration time.Duration) {
	type jsonOutput struct {
		Version        string                `json:"version"`
		ScanType       string                `json:"scan_type"`
		Repository     string                `json:"repository"`
		RemoteURL      string                `json:"remote_url,omitempty"`
		ScanDuration   string                `json:"scan_duration"`
		TotalCommits   int                   `json:"total_commits"`
		ScannedCommits int                   `json:"scanned_commits"`
		TotalFindings  int                   `json:"total_findings"`
		Result         *gitpkg.GitScanResult `json:"result"`
	}

	out := jsonOutput{
		Version:        version,
		ScanType:       "git-history",
		Repository:     result.Repository,
		RemoteURL:      result.RemoteURL,
		ScanDuration:   duration.String(),
		TotalCommits:   result.TotalCommits,
		ScannedCommits: result.ScannedCommits,
		TotalFindings:  result.TotalFindings,
		Result:         result,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
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
		fmt.Fprintf(os.Stderr, "Warning: unknown severity %q, valid values are: info, low, medium, high, critical\n", s)
		fmt.Fprintf(os.Stderr, "         Defaulting to 'info' (show all findings)\n")
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
			if f.Metadata != nil {
				if bpeEff, ok := f.Metadata["bpe_efficiency"]; ok {
					fmt.Printf("  BPE Eff:    %s", bpeEff)
					if bpeTok, ok2 := f.Metadata["bpe_tokens"]; ok2 {
						fmt.Printf(" (%s tokens)", bpeTok)
					}
					fmt.Println()
				}
			}
			fmt.Printf("  Confidence: %.0f%%\n", f.Confidence*100)
			if f.SecretHash != "" {
				fmt.Printf("  SHA-256:    %s...%s\n", f.SecretHash[:8], f.SecretHash[len(f.SecretHash)-8:])
			}
			if f.Fingerprint != "" {
				fmt.Printf("  Fingerprint:%s\n", f.Fingerprint[:16])
			}
			if f.FileType != "" {
				fmt.Printf("  File Type:  %s\n", f.FileType)
			}
			if f.Environment != "" {
				fmt.Printf("  Environment:%s\n", f.Environment)
			}
			if f.Category != "" {
				fmt.Printf("  Category:   %s\n", f.Category)
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
		// Pipeline already sanitized findings (RawMatch cleared by SanitizeProcessor)
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

// flattenFindings collects all findings across scan results into one slice,
// as SARIF expects a flat result list per run.
func flattenFindings(results []models.ScanResult) []models.Finding {
	var out []models.Finding
	for _, r := range results {
		out = append(out, r.Findings...)
	}
	return out
}

// prescanConfig extracts an explicit --config path and the first positional
// target from raw args without mutating parse state. Used to discover a config
// file before the main flag loop runs.
func prescanConfig(args []string) (configPath, target string) {
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--config" && i+1 < len(args):
			configPath = args[i+1]
			i++
		case args[i] == "--git" && i+1 < len(args):
			if target == "" {
				target = args[i+1]
			}
			i++
		case !strings.HasPrefix(args[i], "-") && target == "":
			target = args[i]
		}
	}
	return configPath, target
}

// loadScanConfig resolves a config file: an explicit path takes precedence,
// otherwise one is auto-discovered next to the scan target. ok is false when no
// config applies.
func loadScanConfig(explicit, target string) (appconfig.AppConfig, string, bool) {
	if explicit != "" {
		ac, err := appconfig.Load(explicit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config: %v\n", err)
			return appconfig.DefaultAppConfig(), "", false
		}
		return ac, explicit, true
	}
	root := target
	if root == "" {
		root = "."
	}
	ac, path, ok, err := appconfig.Discover(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return appconfig.DefaultAppConfig(), "", false
	}
	return ac, path, ok
}

// applyAppConfig layers a loaded AppConfig onto the engine and file-scan
// configs. CLI flags parsed afterward override these values.
func applyAppConfig(ac appconfig.AppConfig, cfg *detector.Config, fsCfg *detector.FileScanConfig, outputFormat *string) {
	d := ac.Detection
	cfg.MinConfidence = d.MinConfidence
	cfg.EnableEntropy = d.EnableEntropy
	cfg.EnableBPE = d.EnableBPE
	cfg.EntropyMinLength = d.EntropyMinLength
	cfg.ContextLines = d.ContextLines
	if d.MaxFileSize > 0 {
		cfg.MaxFileSize = d.MaxFileSize
	}
	if d.MinSeverity != "" {
		cfg.MinSeverity = parseSeverity(d.MinSeverity)
	}
	cfg.ExcludeRuleIDs = d.ExcludeRuleIDs
	cfg.AllowListPatterns = d.AllowListPatterns

	fs := ac.FileScanning
	if len(fs.IncludeExtensions) > 0 {
		fsCfg.IncludeExtensions = fs.IncludeExtensions
	}
	if len(fs.ExcludeExtensions) > 0 {
		fsCfg.ExcludeExtensions = append(fsCfg.ExcludeExtensions, fs.ExcludeExtensions...)
	}
	if len(fs.ExcludeDirs) > 0 {
		fsCfg.ExcludeDirs = append(fsCfg.ExcludeDirs, fs.ExcludeDirs...)
	}
	if len(fs.ExcludeFiles) > 0 {
		fsCfg.ExcludeFiles = append(fsCfg.ExcludeFiles, fs.ExcludeFiles...)
	}
	if fs.Workers > 0 {
		fsCfg.Workers = fs.Workers
	}
	fsCfg.FollowSymlinks = fs.FollowSymlinks

	if ac.OutputFormat != "" {
		*outputFormat = ac.OutputFormat
	}
}

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
