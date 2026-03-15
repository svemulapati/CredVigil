<p align="center">
  <h1 align="center">CredVigil</h1>
  <p align="center">
    <strong>Intelligent credential detection for modern engineering teams.</strong>
  </p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> · <a href="#detection-coverage">Detection Coverage</a> · <a href="#architecture">Architecture</a> · <a href="#documentation">Documentation</a>
  </p>
</p>

---

## Overview

CredVigil scans codebases, configuration files, and data streams for exposed credentials — API keys, tokens, passwords, private keys, and connection strings. It combines **331 regex detection rules** with **Shannon entropy analysis**, producing findings with confidence scores, severity ratings, and SHA-256 fingerprints. It can scan git history, and monitor files in real-time for instant secret detection.

### Key Principles

| Principle | How It Works |
|-----------|-------------|
| **Zero-Trust** | Raw secrets are never stored or transmitted. Findings include only SHA-256 hashes and redacted previews. |
| **Confidence Scoring** | Every finding gets a 0–100% confidence score — not a binary yes/no — so teams can set thresholds and eliminate noise. |
| **Dual Detection** | Regex catches known credential formats. Shannon entropy catches novel secrets no rule covers. |
| **False-Positive Reduction** | Placeholders, test fixtures, and documentation patterns are detected and penalized automatically. |

---

## Quick Start

### Prerequisites

- Go 1.21+

### Install

```bash
git clone https://github.com/credvigil/credvigil.git
cd credvigil
go build -o credvigil ./cmd/credvigil
```

### Usage

```bash
# Scan a file
./credvigil scan path/to/file.env

# Scan a directory (recursive, auto-skips binaries/.git/node_modules)
./credvigil scan ./my-project/

# Scan from stdin (pipe from git diff, clipboard, etc.)
echo 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' | ./credvigil scan --stdin

# Filter by severity or confidence
./credvigil scan --min-severity high ./src/
./credvigil scan --min-confidence 0.7 ./src/

# Machine-readable JSON output
./credvigil scan --format json ./src/

# Regex-only mode (disable entropy detection)
./credvigil scan --no-entropy ./src/

# Scan a git repository's commit history for secrets
./credvigil scan --git https://github.com/org/repo.git

# Scan a local repo's git history
./credvigil scan --git ./my-project/

# Scan only a specific branch, limit commits
./credvigil scan --git ./my-project/ --git-branch develop --git-max-commits 100

# Incremental scan (only commits after a known point)
./credvigil scan --git ./my-project/ --git-since abc1234

# List all detection rules
./credvigil rules
```

### Sample Output

```
╔═══════════════════════════════════════════════════════════════╗
║                    CredVigil Scan Report                     ║
╚═══════════════════════════════════════════════════════════════╝

[CRITICAL] AWS Secret Access Key
  Rule:       aws-secret-access-key
  File:       config.env:7
  Match:      wJal****EKEY
  Entropy:    4.66
  Confidence: 50%
  SHA-256:    78314b11...080e0598

[HIGH] JSON Web Token
  Rule:       json-web-token
  File:       auth.js:28
  Match:      eyJh****sw5c
  Entropy:    5.44
  Confidence: 83%
  SHA-256:    7f75367e...4a830606

─────────────────────────────────────────────────────────────────
  Scan completed in 7ms using 331 rules
  Total findings: 55
  By severity: CRITICAL=17, HIGH=14, MEDIUM=20, LOW=4
─────────────────────────────────────────────────────────────────
```

---

## Detection Coverage

**331 built-in rules** across 60+ categories.

<details>
<summary><strong>View full coverage matrix</strong></summary>

| Category | Services & Formats |
|----------|-------------------|
| **Cloud Providers** | AWS, GCP, Azure, DigitalOcean, Cloudflare, Vercel, Netlify, Supabase, Railway, Render, Fly.io, Linode |
| **Cloud (Extended)** | Oracle OCI, IBM Cloud, Alibaba Cloud, Hetzner |
| **Source Control** | GitHub (PAT, Fine-Grained, OAuth), GitLab (PAT, Runner, Pipeline), Bitbucket, Gitea |
| **Collaboration** | Slack, Jira, Confluence, Atlassian OAuth, Microsoft Teams, Stack Overflow, Zoom, Webex |
| **Private Keys** | RSA, EC, PKCS8, OpenSSH, PGP, WireGuard |
| **Databases** | PostgreSQL, MySQL, MongoDB, Redis, PlanetScale, Neon, Turso, Upstash, CockroachDB |
| **Databases (Extended)** | InfluxDB, ClickHouse, Neo4j, Airtable, FaunaDB, Oracle DB, SQL Server/MSSQL, Snowflake |
| **Auth & Identity** | JWT, Bearer, Basic Auth, OAuth, Auth0, Okta, Clerk, Keycloak, OneLogin, Duo Security, Ping Identity |
| **Payment** | Stripe, Square, PayPal, Razorpay, Plaid, Coinbase, Adyen, Braintree, Paddle, Klarna |
| **AI & ML** | OpenAI, Anthropic, Gemini, Hugging Face, Cohere, Mistral, Replicate, Groq, DeepSeek, Perplexity, Stability AI |
| **AI Inference (Next Gen)** | Together AI, Fireworks AI, Cerebras, SambaNova, Modal, Baseten, RunPod, Lambda Labs |
| **AI/ML Tooling** | Weights & Biases, LangSmith/LangChain, Comet ML, Neptune.ai, Voyage AI |
| **Vector Databases** | Pinecone, Weaviate, Qdrant, Chroma, Zilliz/Milvus |
| **Email & Messaging** | SendGrid, Mailgun, Mailchimp, Postmark, Resend, Amazon SES, Telegram, Discord, Vonage, Pushover, OneSignal, SparkPost, Mandrill, Customer.io |
| **SMS & Voice** | Twilio, Plivo, Bandwidth, Telnyx |
| **Marketing & CRM** | HubSpot, Mixpanel, Segment, Intercom, Amplitude, PostHog, Zendesk, Freshdesk, Salesforce, Zoho |
| **CI/CD** | CircleCI, Codecov, Jenkins, Travis CI, Buildkite, Drone, Pulumi, Azure DevOps, TeamCity, Bamboo, Harness, Argo CD |
| **Container & K8s** | Kubernetes, Docker Hub, Harbor, Quay.io |
| **Config Management** | Ansible, HashiCorp Consul, HashiCorp Nomad, Chef, Puppet |
| **Secrets Management** | HashiCorp Vault, Doppler, Infisical, 1Password Connect |
| **Security Tools** | Snyk, CrowdStrike Falcon, Tenable/Nessus |
| **Observability** | Datadog, New Relic, Sentry, Grafana, Splunk, PagerDuty, OpenTelemetry, Dynatrace, Sumo Logic, Honeycomb, Bugsnag, Rollbar, Airbrake, Logz.io, Instana, Zabbix |
| **Data Platforms** | Snowflake, Databricks, dbt Cloud, Fivetran, Looker |
| **Project Management** | Notion, Linear, Asana, Trello, ClickUp, Shortcut |
| **CMS & Content** | Contentful, Sanity, Strapi, Ghost, WordPress |
| **Feature Flags** | LaunchDarkly, Split, Flagsmith, ConfigCat |
| **CDN & Edge** | Fastly, Akamai, Kong, Bunny CDN, Cloudinary, Backblaze B2 |
| **Media & Video** | Mux, Twitch |
| **Design** | Figma |
| **Testing & QA** | BrowserStack, Sauce Labs, Cypress Cloud |
| **Networking** | ngrok, Tailscale, WireGuard |
| **Workflow Automation** | Zapier, n8n |
| **Low-Code** | Retool |
| **Modern Dev Infra** | Convex, Xata, Deno Deploy, Trigger.dev, Inngest, Temporal, Tinybird |
| **Modern Auth** | WorkOS, Stytch, Descope |
| **Modern Payments** | LemonSqueezy |
| **Modern Observability** | Axiom, Highlight.io |
| **Modern Email/Comms** | Novu, Loops |
| **Encryption** | Age Secret Key |
| **Data Streaming** | Confluent (Kafka) |
| **Cloud Storage** | Dropbox |
| **Enterprise Comms** | Mattermost |
| **Enterprise K8s** | OpenShift |
| **API Dev Tools** | Postman, RapidAPI |
| **Package Registries** | RubyGems |
| **Code Search** | Sourcegraph |
| **Website Builders** | Squarespace |
| **Forms & Surveys** | Typeform |
| **African Payments** | Flutterwave |
| **Code Quality** | SonarQube, SonarCloud |
| **Artifact Management** | JFrog Artifactory |
| **Code Review** | Gerrit |
| **IAM & PAM** | LDAP, Active Directory, CyberArk/Conjur, FreeIPA, RADIUS |
| **Kerberos & SSO** | Kerberos Keytab, KDC, SAML |
| **Remote Access** | RDP, VNC |
| **NAS** | Synology, QNAP |
| **Infrastructure** | Docker, NPM, PyPI, NuGet, Heroku, Terraform |
| **Maps** | Google Maps, Mapbox |
| **Social** | Twitter/X, Facebook/Meta, LinkedIn, TikTok |
| **Crypto & Web3** | Alchemy, Infura, Etherscan, Moralis |
| **Search** | Algolia, Meilisearch, Typesense |
| **E-commerce** | Shopify, Amazon MWS/SP-API, Etsy |
| **Generic** | API keys, passwords, connection strings, high-entropy strings |

</details>

---

## How It Works

```
Input (file / directory / stdin)
    │
    ├── Regex Pattern Matching ──────── 331 compiled rules
    │     Known formats: ghp_*, AKIA*, sk_live_*, squ_*, AKC*, etc.
    │
    ├── Shannon Entropy Analysis ────── Catches novel/unknown secrets
    │     Flags high-randomness strings that look like credentials
    │
    ├── Confidence Scoring ──────────── 0–100% per finding
    │     ├── Base confidence from matched rule
    │     ├── + Entropy boost (high entropy → likely real)
    │     ├── + Keyword proximity ("password", "secret", "key")
    │     ├── − Placeholder penalty (EXAMPLE, TODO, changeme)
    │     └── − Length/pattern penalties
    │
    └── Output ──────────────────────── Zero-trust findings
          Severity · Confidence · SHA-256 hash · Redacted preview
```

---

## Architecture

CredVigil is designed as a modular, component-based system. Each component is developed, tested, and validated independently.

| # | Component | Status | Description |
|---|-----------|:------:|-------------|
| 1 | **Core Detection Engine** | ✅ | Regex + entropy scanning, confidence scoring, false-positive reduction |
| 2 | **Secure Hashing & Metadata Pipeline** | ✅ | Zero-trust pipeline — hash, redact, enrich, fingerprint, and sanitize findings |
| 3 | **Git Integration Layer** | ✅ | Clone repos, walk commit history, diff branches, detect secrets in git history |
| 4 | **File System Watcher** | ✅ | Real-time monitoring via fsnotify — debounced events, recursive watching, configurable exclusions |
| 5 | **Event Bus** | ✅ | Internal pub/sub for decoupled component communication — topic-based, async delivery, wildcard subscriptions, stats |
| 6 | API Server | — | REST/gRPC API for integrations |
| 7 | Storage Layer | — | Persistent storage for findings, trends, and audit trail |
| 8 | Web Dashboard | — | Visual overview of credential risk across repositories |
| 9 | Notification Engine | — | Slack, email, and webhook alerts on new findings |
| 10 | Policy Engine | — | Define and enforce credential security policies |
| 11 | CI/CD Integration | — | GitHub Actions, pre-commit hooks, pipeline gates |
| 12 | Compliance Reporter | — | SOC 2, ISO 27001, PCI-DSS compliance reports |
| 13 | Secret Rotation Tracker | — | Track whether leaked secrets have been rotated |
| 14 | ML Anomaly Detection | — | Catch novel secret patterns no regex would find |
| 15 | Plugin System | — | Extensible architecture for custom rules and integrations |

---

## Project Structure

```
credvigil/
├── cmd/credvigil/          # CLI entry point (scan, rules, version)
│   └── main.go
├── pkg/
│   ├── models/             # Core types: Finding, Source, ScanRequest, Severity
│   │   └── finding.go
│   ├── entropy/            # Shannon entropy calculation
│   │   ├── entropy.go
│   │   └── entropy_test.go
│   ├── rules/              # 331 compiled regex detection rules
│   │   ├── rules.go
│   │   └── rules_test.go
│   ├── detector/           # Detection engine + concurrent file scanner
│   │   ├── engine.go
│   │   ├── engine_test.go
│   │   └── scanner.go
│   ├── pipeline/           # Post-processing pipeline (Component 2)
│   │   ├── pipeline.go     # Orchestrator & Processor interface
│   │   ├── hash.go         # SHA-256 hashing
│   │   ├── redact.go       # Secret masking
│   │   ├── enrich.go       # File type, environment, category classification
│   │   ├── fingerprint.go  # Stable cross-scan identifier
│   │   ├── sanitize.go     # Zero-trust RawMatch clearing
│   │   ├── verify.go       # Verification hook interface (placeholder)
│   │   └── pipeline_test.go
│   ├── git/                # Git integration layer (Component 3)
│   │   ├── git.go          # Core types: Repository, Commit, DiffEntry, ScanOptions
│   │   ├── clone.go        # Open, clone, and manage git repositories
│   │   ├── diff.go         # Unified diff parser — extract added lines
│   │   ├── walker.go       # Walk commit history, yield diffs per commit
│   │   ├── scanner.go      # Orchestrate detection engine over git history
│   │   └── git_test.go     # 45+ tests + 2 benchmarks
│   ├── watcher/            # File system watcher (Component 4)
│   │   ├── watcher.go      # Real-time fsnotify watcher with debounce + filtering
│   │   └── watcher_test.go # 22 tests: events, debounce, exclusions, recursive watching
│   └── eventbus/           # Event bus (Component 5)
│       ├── eventbus.go     # Topic-based pub/sub with async delivery + wildcard support
│       └── eventbus_test.go # 42 tests + 5 benchmarks: pub/sub, concurrency, integration
├── internal/
│   └── config/             # Application configuration
│       └── config.go
├── testdata/
│   └── fake_secrets.env    # Test fixtures with synthetic credentials
├── docs/
│   └── training/           # Training guides
├── go.mod
├── LICENSE                 # Apache License 2.0
├── SECURITY.md             # Security policy & responsible disclosure
└── README.md
```

---

## Testing

```bash
# Run all tests
go test ./...

# Verbose output
go test ./... -v

# With race detector
go test ./... -race

# Individual packages
go test ./pkg/rules -v        # Rule loading + pattern matching
go test ./pkg/entropy -v      # Entropy calculation
go test ./pkg/detector -v     # Engine + scanner integration
go test ./pkg/pipeline -v     # Post-processing pipeline
go test ./pkg/git -v          # Git integration layer
go test ./pkg/watcher -v      # File system watcher
go test ./pkg/eventbus -v     # Event bus
```

An interactive test suite is also available:

```bash
bash run_all_tests.sh
```

This runs 14 end-to-end tests covering version checks, full scans, severity/confidence filtering, JSON output, stdin piping, enterprise rule detection (SonarQube, Kerberos, LDAP, Artifactory), clean-input validation, and the full Go test suite.

---

## Documentation

| Resource | Description |
|----------|-------------|
| [Module 1: Core Detection Engine](docs/training/01-core-detection-engine.md) | Concepts, CLI usage, hands-on exercises, and full code walkthrough |
| [Module 2: Secure Hashing & Metadata Pipeline](docs/training/02-secure-hashing-metadata-pipeline.md) | Pipeline architecture, processors, zero-trust guarantee, custom processors |
| [Module 3: Git Integration Layer](docs/training/03-git-integration-layer.md) | Clone, walk history, parse diffs, scan commits for leaked secrets |
| [Module 4: File System Watcher](docs/training/04-file-system-watcher.md) | Real-time file monitoring, fsnotify, debounce, recursive watching, event filtering |
| [Module 5: Event Bus](docs/training/05-event-bus.md) | Internal pub/sub, topic-based routing, wildcard subscriptions, async delivery, backpressure |
| [SECURITY.md](SECURITY.md) | Security policy, responsible disclosure, zero-trust design, and liability |
| [LICENSE](LICENSE) | Apache License 2.0 |

Additional training modules will accompany each new component as it is released.

---

## Contributing

CredVigil is under active development. Components are built and validated incrementally — see the [Architecture](#architecture) table for current progress.

---

## License

Licensed under the [Apache License 2.0](LICENSE).

Copyright 2026 CredVigil Contributors.
