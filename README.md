# CredVigil

**Continuous credential monitoring and detection for modern engineering teams.**

CredVigil is a layered, event-driven, zero-trust credential detection tool that scans codebases, files, and streams for leaked secrets. It combines regex pattern matching with Shannon entropy analysis, confidence scoring, and intelligent false-positive reduction — so your team only sees findings that matter.

---

## Why CredVigil?

Every year, millions of API keys, passwords, and tokens are accidentally committed to repositories or left in configuration files. Most secret detection tools give you a binary "found" or "not found" — flooding teams with alerts, including false positives, and offering no way to prioritize. CredVigil is different:

- **Confidence scoring (0–100%)** — every finding has a confidence score, so teams can set thresholds and eliminate alert fatigue
- **Zero-trust architecture** — raw secrets are never stored or transmitted; only SHA-256 hashes and redacted previews leave the scanner
- **False-positive intelligence** — detects placeholders, test fixtures, and documentation patterns and penalizes their scores
- **Dual detection** — regex patterns catch known formats; Shannon entropy catches novel secrets no rule covers
- **154 detection rules** covering the full modern stack (AI/ML, cloud, payment, databases, CI/CD, and more)
- **Continuous monitoring** (planned) — not just one-shot scans, but real-time watching across repos and infrastructure

---

## Quick Start

### Prerequisites

- Go 1.21+ installed

### Build

```bash
git clone https://github.com/credvigil/credvigil.git
cd credvigil
go build ./cmd/credvigil
```

### Scan a file or directory

```bash
# Scan a single file
./credvigil scan path/to/file.env

# Scan an entire directory (recursive, auto-skips binaries/.git/node_modules)
./credvigil scan ./my-project/

# Scan from stdin
echo 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' | ./credvigil scan --source stdin
```

### Filter and format

```bash
# Only show HIGH and CRITICAL severity findings
./credvigil scan --min-severity high ./src/

# JSON output (for CI/CD pipelines or other tools)
./credvigil scan --format json ./src/

# Set minimum confidence threshold
./credvigil scan --min-confidence 0.7 ./src/

# Disable entropy-based detection (regex only)
./credvigil scan --no-entropy ./src/
```

### List detection rules

```bash
./credvigil rules
```

---

## What It Detects (154 Rules)

CredVigil detects credentials across the entire modern stack:

| Category | Services |
|----------|----------|
| **Cloud** | AWS, GCP, Azure, DigitalOcean, Cloudflare, Vercel, Netlify, Supabase, Railway, Render, Fly.io, Linode |
| **Source Control** | GitHub, GitLab, Bitbucket |
| **Collaboration** | Slack, Jira, Confluence, Microsoft Teams |
| **Private Keys** | RSA, EC, PKCS8, OpenSSH, PGP |
| **Databases** | PostgreSQL, MySQL, MongoDB, Redis, PlanetScale, Neon, Turso, Upstash, CockroachDB |
| **Auth/Identity** | JWT, Bearer, Basic Auth, OAuth, Auth0, Okta, Clerk |
| **Payment** | Stripe, Square, PayPal, Razorpay, Plaid, Coinbase, Adyen |
| **AI/ML** | OpenAI, Anthropic, Gemini, Hugging Face, Cohere, Mistral, Replicate, Groq, DeepSeek, Perplexity, Stability AI |
| **Email** | SendGrid, Mailgun, Mailchimp, Postmark, Resend, Amazon SES |
| **Marketing/CRM** | HubSpot, Mixpanel, Segment, Intercom, Amplitude, PostHog, Zendesk, Freshdesk, Salesforce, Zoho |
| **CI/CD** | CircleCI, Codecov, Jenkins, Travis CI, Buildkite, Drone, Pulumi |
| **Messaging** | Telegram, Discord, Vonage/Nexmo, Pushover, OneSignal |
| **Maps** | Google Maps, Mapbox |
| **Social** | Twitter/X, Facebook/Meta, LinkedIn |
| **Storage/CDN** | Cloudinary, Backblaze B2 |
| **Observability** | Datadog, New Relic, Sentry, Grafana, Splunk, PagerDuty, Elasticsearch |
| **Crypto/Web3** | Alchemy, Infura, Etherscan, Moralis |
| **Search** | Algolia, Meilisearch, Typesense |
| **Infrastructure** | Docker, NPM, PyPI, NuGet, Heroku, Vault, Terraform |
| **E-commerce** | Shopify, Amazon MWS/SP-API, Etsy |
| **Generic** | API keys, passwords, high-entropy strings |

---

## Architecture

CredVigil is built as a modular, component-based system. Each component is developed, tested, and validated independently before integration.

### Component Roadmap

| # | Component | Status | Description |
|---|-----------|--------|-------------|
| 1 | **Core Detection Engine** | ✅ Done | Regex + entropy scanning, confidence scoring, false-positive reduction |
| 2 | Secure Hashing & Metadata Pipeline | 🔜 Next | Zero-trust pipeline — hash, redact, enrich findings before storage |
| 3 | Git Integration Layer | ⬜ | Scan git history, blame, branches, PR diffs |
| 4 | File System Watcher | ⬜ | Real-time monitoring via fsnotify |
| 5 | Event Bus | ⬜ | Internal pub/sub for decoupled component communication |
| 6 | API Server | ⬜ | REST/gRPC API for integrations |
| 7 | Storage Layer | ⬜ | Persistent storage for findings, trends, audit trail |
| 8 | Web Dashboard | ⬜ | Visual overview of credential risk across repos |
| 9 | Notification Engine | ⬜ | Slack, email, webhook alerts on new findings |
| 10 | Policy Engine | ⬜ | Define and enforce credential security policies |
| 11 | CI/CD Integration | ⬜ | GitHub Actions, pre-commit hooks, pipeline gates |
| 12 | Compliance Reporter | ⬜ | SOC2, ISO 27001, PCI-DSS compliance reports |
| 13 | Secret Rotation Tracker | ⬜ | Track whether leaked secrets were actually rotated |
| 14 | ML Anomaly Detection | ⬜ | Catch novel secret patterns no regex would find |
| 15 | Plugin System | ⬜ | Extensible architecture for custom rules and integrations |

---

## Component 1: Core Detection Engine (Completed)

The foundation of CredVigil — a dual-strategy secret detection engine.

### How It Works

```
Input (file/stdin/stream)
    │
    ├── Regex Pattern Matching (154 rules)
    │     └── Known formats: ghp_*, AKIA*, sk_live_*, etc.
    │
    ├── Shannon Entropy Analysis
    │     └── Detects high-randomness strings that look like secrets
    │
    ├── Confidence Scoring (0.0 – 1.0)
    │     ├── Base confidence from rule
    │     ├── + Entropy boost (high entropy → more likely a real secret)
    │     ├── + Keyword proximity (nearby "password", "secret", "key")
    │     ├── − False positive penalty (placeholder, test data, docs)
    │     └── − Length/pattern penalties
    │
    └── Output: Findings with severity, confidence, SHA-256 hash, redacted preview
```

### Key Design Decisions

- **Zero-trust by default**: Raw secrets are never stored or transmitted. Every finding includes a SHA-256 hash for tracking and a redacted preview for display.
- **Confidence > binary**: Instead of "found" / "not found", every finding has a confidence score. This lets teams set thresholds and reduce alert fatigue.
- **Dual detection**: Regex catches known patterns; entropy catches novel/unknown secrets that no rule covers.
- **False-positive intelligence**: Detects placeholders (`EXAMPLE`, `TODO`, `changeme`, `your-key-here`), test fixtures, and documentation patterns — and penalizes their confidence scores.

### Project Structure

```
credvigil/
├── cmd/credvigil/         # CLI entry point
│   └── main.go            # scan, rules, version commands
├── pkg/
│   ├── models/            # Core data structures (Finding, Source, ScanRequest)
│   │   └── finding.go
│   ├── entropy/           # Shannon entropy analysis
│   │   ├── entropy.go
│   │   └── entropy_test.go
│   ├── rules/             # 154 compiled regex detection rules
│   │   ├── rules.go
│   │   └── rules_test.go
│   └── detector/          # Detection engine + file scanner
│       ├── engine.go
│       ├── engine_test.go
│       └── scanner.go
├── internal/
│   └── config/            # Application configuration
│       └── config.go
├── testdata/              # Test fixtures
│   └── fake_secrets.env
├── go.mod
└── README.md
```

### Running Tests

```bash
# Run all tests
go test ./... -v

# Run with race detector
go test ./... -race

# Run specific package tests
go test ./pkg/detector -v
go test ./pkg/entropy -v
go test ./pkg/rules -v
```

---

## Sample Output

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
  Scan completed in 3ms using 154 rules
  Total findings: 37
  By severity: CRITICAL=10, HIGH=10, MEDIUM=13, LOW=4
─────────────────────────────────────────────────────────────────
```

---

## Contributing

This project is under active development. Components are being built and validated one at a time.

## License

TBD
