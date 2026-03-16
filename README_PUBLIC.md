<p align="center">
  <h1 align="center">🔐 CredVigil Secrets Scanner</h1>
  <p align="center">
    <strong>Intelligent credential detection for modern engineering teams.</strong>
  </p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> · <a href="#detection-coverage">Detection Coverage</a> · <a href="#how-it-works">How It Works</a> · <a href="#architecture">Architecture</a>
  </p>
</p>

---

## Created by

**Sudeep Nag Vemulapati** (Performance Test Engineer → DevSecOps builder)  
Personal project built while learning credential security, zero-trust design, and real-time detection.

- GitHub: [@svemulapati](https://github.com/svemulapati)
- Email: svemulapati@gmx.com (for security reports or collaboration)

CredVigil started as a side project to solve real pain I faced in performance testing environments — credentials leaking into config files, .env files committed to repos, API keys scattered across test scripts. I wanted something that catches every format, gives confidence scores (not just binary yes/no), and never stores raw secrets.

---

## Overview

CredVigil scans codebases, configuration files, and data streams for exposed credentials — API keys, tokens, passwords, private keys, and connection strings. It combines **369 regex detection rules** with **Shannon entropy analysis** and **BPE token efficiency scoring**, producing findings with confidence scores, severity ratings, and SHA-256 fingerprints. It can scan git history and monitor files in real-time for instant secret detection.

### Key Principles

| Principle | How It Works |
|-----------|-------------|
| **Zero-Trust** | Raw secrets are never stored or transmitted. Findings include only SHA-256 hashes and redacted previews. |
| **Confidence Scoring** | Every finding gets a 0–100% confidence score — not a binary yes/no — so teams can set thresholds and eliminate noise. |
| **Triple Detection** | Regex catches known credential formats. Shannon entropy catches novel secrets no rule covers. BPE token efficiency provides a second statistical lens independent of character-frequency analysis. |
| **False-Positive Reduction** | Placeholders, test fixtures, and documentation patterns are detected and penalized automatically. |

---

## Quick Start

### Prerequisites

- Go 1.21+

### Install

```bash
git clone https://github.com/svemulapati/CredVigil_Secrets_Scanner.git
cd CredVigil_Secrets_Scanner
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
  BPE Eff:    1.08 (37 tokens)
  Confidence: 58%
  SHA-256:    78314b11...080e0598
  Fingerprint:a1b2c3d4e5f67890
  File Type:  env
  Environment:production
  Category:   cloud

[HIGH] JSON Web Token
  Rule:       json-web-token
  File:       auth.js:28
  Match:      eyJh****sw5c
  Entropy:    5.44
  Confidence: 91%
  SHA-256:    7f75367e...4a830606

─────────────────────────────────────────────────────────────────
  Scan completed in 7ms using 369 rules
  Total findings: 55
  By severity: CRITICAL=17, HIGH=14, MEDIUM=20, LOW=4
─────────────────────────────────────────────────────────────────
```

---

## Detection Coverage

**369 built-in rules** across 75+ categories covering every major platform.

<details>
<summary><strong>🔍 View full coverage matrix (75+ categories)</strong></summary>

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
| **Performance Testing** | LoadRunner Cloud, BlazeMeter, k6 Cloud (Grafana), Gatling Enterprise, NeoLoad, Flood.io |
| **Functional Automation** | Selenium Grid, Appium Cloud, Playwright, Katalon, TestComplete, Ranorex, Mabl, Testim, Ghost Inspector, Reflect |
| **API & Integration Testing** | ReadyAPI, SoapUI Pro, Pact Broker/PactFlow, Insomnia, Hoppscotch, Stoplight, Karate |
| **Test Management** | TestRail, Allure TestOps, Xray, Zephyr, qTest, PractiTest, TestMonitor |
| **CI/CD Quality** | Coveralls, Parasoft, Tricentis Tosca, Micro Focus UFT, SmartBear, Robot Framework/Robocorp |
| **Testing & QA** | BrowserStack, Sauce Labs, Cypress Cloud, LambdaTest, Perfecto |
| **Networking** | ngrok, Tailscale, WireGuard |
| **Workflow Automation** | Zapier, n8n |
| **Low-Code** | Retool |
| **Modern Dev Infra** | Convex, Xata, Deno Deploy, Trigger.dev, Inngest, Temporal, Tinybird |
| **Modern Auth** | WorkOS, Stytch, Descope |
| **Modern Payments** | LemonSqueezy |
| **Modern Observability** | Axiom, Highlight.io |
| **Encryption** | Age Secret Key |
| **Data Streaming** | Confluent (Kafka) |
| **Cloud Storage** | Dropbox |
| **Enterprise Comms** | Mattermost |
| **Enterprise K8s** | OpenShift |
| **API Dev Tools** | Postman, RapidAPI |
| **Package Registries** | RubyGems |
| **Code Search** | Sourcegraph |
| **Code Quality** | SonarQube, SonarCloud |
| **Artifact Management** | JFrog Artifactory |
| **Code Review** | Gerrit |
| **IAM & PAM** | LDAP, Active Directory, CyberArk/Conjur, FreeIPA, RADIUS |
| **Kerberos & SSO** | Kerberos Keytab, KDC, SAML |
| **Remote Access** | RDP, VNC |
| **NAS** | Synology, QNAP |
| **Crypto & Web3** | Alchemy, Infura, Etherscan, Moralis |
| **Search** | Algolia, Meilisearch, Typesense |
| **E-commerce** | Shopify, Amazon MWS/SP-API, Etsy |
| **Social** | Twitter/X, Facebook/Meta, LinkedIn, TikTok |
| **Maps** | Google Maps, Mapbox |
| **Infrastructure** | Docker, NPM, PyPI, NuGet, Heroku, Terraform |
| **Generic** | API keys, passwords, connection strings, high-entropy strings |

</details>

---

## How It Works

```
Input (file / directory / stdin / git history)
    │
    ├── Regex Pattern Matching ──────── 369 compiled rules
    │     Known formats: ghp_*, AKIA*, sk_live_*, squ_*, AKC*, etc.
    │
    ├── Shannon Entropy Analysis ────── Catches novel/unknown secrets
    │     Flags high-randomness strings that look like credentials
    │
    ├── BPE Token Efficiency ────────── Independent statistical check
    │     Measures how well a string compresses under Byte Pair Encoding
    │     Normal text compresses well; random secrets don't
    │
    ├── Confidence Scoring ──────────── 0–100% per finding
    │     ├── Base confidence from matched rule
    │     ├── + Entropy boost (high entropy → likely real)
    │     ├── + BPE boost (low token efficiency → likely real)
    │     ├── + Keyword proximity ("password", "secret", "key")
    │     ├── − Placeholder penalty (EXAMPLE, TODO, changeme)
    │     └── − Length/pattern penalties
    │
    └── Output ──────────────────────── Zero-trust findings
          Severity · Confidence · SHA-256 hash · Redacted preview
          Fingerprint · File type · Environment · Category
```

---

## Architecture

CredVigil is designed as a modular, component-based system. Each component is developed, tested, and validated independently.

| # | Component | Status | Description |
|---|-----------|:------:|-------------|
| 1 | **Core Detection Engine** | ✅ | Regex + entropy + BPE token efficiency scanning, confidence scoring, false-positive reduction |
| 2 | **Secure Hashing & Metadata Pipeline** | ✅ | Zero-trust pipeline — hash, redact, enrich, fingerprint, and sanitize findings |
| 3 | **Git Integration Layer** | ✅ | Clone repos, walk commit history, diff branches, detect secrets in git history |
| 4 | **File System Watcher** | ✅ | Real-time monitoring via fsnotify — debounced events, recursive watching, configurable exclusions |
| 5 | **Event Bus** | ✅ | Internal pub/sub for decoupled component communication — topic-based, async delivery, wildcard subscriptions |
| 6 | API Server | 🔜 | REST/gRPC API for integrations |
| 7 | Storage Layer | 🔜 | Persistent storage for findings, trends, and audit trail |
| 8 | Web Dashboard | 🔜 | Visual overview of credential risk across repositories |
| 9 | Notification Engine | 🔜 | Slack, email, and webhook alerts on new findings |
| 10 | Policy Engine | 🔜 | Define and enforce credential security policies |
| 11 | CI/CD Integration | 🔜 | GitHub Actions, pre-commit hooks, pipeline gates |
| 12 | Compliance Reporter | 🔜 | SOC 2, ISO 27001, PCI-DSS compliance reports |
| 13 | Secret Rotation Tracker | 🔜 | Track whether leaked secrets have been rotated |
| 14 | ML Anomaly Detection | 🔜 | Catch novel secret patterns no regex would find |
| 15 | Plugin System | 🔜 | Extensible architecture for custom rules and integrations |

---

## Project Structure

```
credvigil/
├── cmd/credvigil/          # CLI entry point (scan, rules, version)
│   └── main.go
├── pkg/
│   ├── models/             # Core types: Finding, Source, ScanRequest, Severity
│   ├── entropy/            # Shannon entropy + BPE token efficiency analysis
│   ├── rules/              # 369 compiled regex detection rules
│   ├── detector/           # Detection engine + concurrent file scanner
│   ├── pipeline/           # Post-processing pipeline (hash, redact, enrich, fingerprint, sanitize)
│   ├── git/                # Git integration layer (clone, walk, diff, scan history)
│   ├── watcher/            # File system watcher (fsnotify, debounce, recursive)
│   └── eventbus/           # Event bus (pub/sub, topics, wildcard, async delivery)
├── internal/config/        # Application configuration
├── testdata/               # Test fixtures with synthetic credentials
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

# With race detector (recommended)
go test ./... -race

# Verbose output
go test ./... -v

# Individual packages
go test ./pkg/rules -v        # Rule loading + pattern matching
go test ./pkg/entropy -v      # Entropy + BPE token efficiency
go test ./pkg/detector -v     # Engine + scanner integration
go test ./pkg/pipeline -v     # Post-processing pipeline
go test ./pkg/git -v          # Git integration layer
go test ./pkg/watcher -v      # File system watcher
go test ./pkg/eventbus -v     # Event bus
```

An interactive end-to-end test suite is also available:

```bash
bash run_all_tests.sh   # Runs 14 E2E tests
```

---

## Why CredVigil?

| Feature | CredVigil | Most alternatives |
|---------|-----------|-------------------|
| Detection rules | **369** across 75+ categories | ~100–200 |
| Detection method | Regex + Shannon entropy + BPE token efficiency (**triple detection**) | Usually regex only |
| Confidence scoring | 0–100% per finding | Binary yes/no |
| Zero-trust output | SHA-256 hashes, redacted previews, no raw secrets ever stored | Often stores raw match |
| Git history scanning | Full commit history, incremental, branch-specific | Varies |
| Real-time monitoring | fsnotify-based file watcher with debounce | Usually CLI-only |
| False-positive reduction | Placeholder detection, length/pattern penalties | Basic allowlists |

---

## Roadmap

- [ ] REST API server for integrations
- [ ] Persistent storage layer (SQLite/PostgreSQL)
- [ ] Web dashboard for visual risk overview
- [ ] Slack/email/webhook notifications
- [ ] GitHub Actions pre-commit hook
- [ ] Policy engine for custom enforcement rules
- [ ] ML-based anomaly detection
- [ ] Plugin system for custom rules

---

## Contributing

Contributions are welcome! CredVigil is under active development — see the [Architecture](#architecture) table for current progress.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

Licensed under the [Apache License 2.0](LICENSE).

Copyright 2026 Sudeep Nag Vemulapati.

---

<p align="center">
  <strong>If CredVigil helps you catch a leaked secret, consider giving it a ⭐</strong>
</p>
