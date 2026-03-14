# CredVigil — Complete Commands & Practice Guide

> **Master every command, flag, and option across all 4 components.**
> This guide is designed so you can open a terminal and practice each command live on your machine.
> Every section includes: the command, what it does, expected output, and why it matters.

---

## Table of Contents

1. [Prerequisites & Setup](#1-prerequisites--setup)
2. [Component 1: Core Detection Engine (CLI)](#2-component-1-core-detection-engine-cli)
   - [2.1 Build the Binary](#21-build-the-binary)
   - [2.2 Version & Help](#22-version--help)
   - [2.3 List Detection Rules](#23-list-detection-rules)
   - [2.4 Scan a Single File](#24-scan-a-single-file)
   - [2.5 Scan a Directory](#25-scan-a-directory)
   - [2.6 Scan from Stdin (Piping)](#26-scan-from-stdin-piping)
   - [2.7 Output Formats (Text vs JSON)](#27-output-formats-text-vs-json)
   - [2.8 Severity Filtering](#28-severity-filtering)
   - [2.9 Confidence Filtering](#29-confidence-filtering)
   - [2.10 Entropy Toggle](#210-entropy-toggle)
   - [2.11 Context Lines](#211-context-lines)
   - [2.12 Combining Multiple Flags](#212-combining-multiple-flags)
   - [2.13 Exit Codes](#213-exit-codes)
3. [Component 2: Secure Hashing & Metadata Pipeline](#3-component-2-secure-hashing--metadata-pipeline)
   - [3.1 Observing the Pipeline in Action](#31-observing-the-pipeline-in-action)
   - [3.2 Pipeline Stages Explained](#32-pipeline-stages-explained)
   - [3.3 Zero-Trust Verification](#33-zero-trust-verification)
4. [Component 3: Git Integration Layer](#4-component-3-git-integration-layer)
   - [4.1 Scan Local Repository History](#41-scan-local-repository-history)
   - [4.2 Git Branch Scanning](#42-git-branch-scanning)
   - [4.3 Incremental Scanning (Since Commit)](#43-incremental-scanning-since-commit)
   - [4.4 Limit Number of Commits](#44-limit-number-of-commits)
   - [4.5 Scan All Branches](#45-scan-all-branches)
   - [4.6 Include Merge Commits](#46-include-merge-commits)
   - [4.7 Clone and Scan Remote Repository](#47-clone-and-scan-remote-repository)
   - [4.8 Remote with Shallow Clone](#48-remote-with-shallow-clone)
   - [4.9 Git + Output Format](#49-git--output-format)
5. [Component 4: File System Watcher (Debouncing & Real-Time)](#5-component-4-file-system-watcher-debouncing--real-time)
   - [5.1 Understanding Debouncing](#51-understanding-debouncing)
   - [5.2 Watching the Watcher with Tests](#52-watching-the-watcher-with-tests)
   - [5.3 Live Debounce Experiment](#53-live-debounce-experiment)
   - [5.4 Watcher Configuration Options](#54-watcher-configuration-options)
   - [5.5 Event Types Explained](#55-event-types-explained)
   - [5.6 Stats & Monitoring](#56-stats--monitoring)
6. [Unit Testing Commands](#6-unit-testing-commands)
   - [6.1 Run All Tests](#61-run-all-tests)
   - [6.2 Run Tests for a Single Package](#62-run-tests-for-a-single-package)
   - [6.3 Run a Specific Test Function](#63-run-a-specific-test-function)
   - [6.4 Verbose Test Output](#64-verbose-test-output)
   - [6.5 Test with Race Detector](#65-test-with-race-detector)
   - [6.6 Test Coverage](#66-test-coverage)
   - [6.7 Test Count (Disable Caching)](#67-test-count-disable-caching)
   - [6.8 Test Timeout](#68-test-timeout)
   - [6.9 Benchmark Tests](#69-benchmark-tests)
7. [Interactive Test Suite Script](#7-interactive-test-suite-script)
8. [Creating Test Files for Practice](#8-creating-test-files-for-practice)
   - [8.1 Create a Fake Secrets File](#81-create-a-fake-secrets-file)
   - [8.2 Create a Clean File (No Secrets)](#82-create-a-clean-file-no-secrets)
   - [8.3 Create a Multi-Language Project for Scanning](#83-create-a-multi-language-project-for-scanning)
   - [8.4 Create Files for Watcher Practice](#84-create-files-for-watcher-practice)
9. [Advanced Piping & Automation](#9-advanced-piping--automation)
10. [Quick Reference Card](#10-quick-reference-card)

---

## 1. Prerequisites & Setup

### Check Go Installation

```bash
go version
```

**Expected output:** `go version go1.21+` (or higher)

If Go is not installed:
```bash
# macOS
brew install go

# Linux (Ubuntu/Debian)
sudo apt install golang-go
```

### Check Git Installation (needed for Component 3)

```bash
git --version
```

**Expected output:** `git version 2.x.x`

### Navigate to the Project

```bash
cd ~/Github_Projects/CredVigil
```

### Verify Project Structure

```bash
ls -la
```

**Expected output:** You should see `cmd/`, `pkg/`, `testdata/`, `go.mod`, `README.md`, etc.

### Install Dependencies

```bash
go mod download
```

**What it does:** Downloads the `fsnotify` dependency and any transitive dependencies.

### Verify Dependencies

```bash
go mod tidy
cat go.mod
```

**Expected output:**
```
module github.com/credvigil/credvigil

go 1.26.1

require (
    github.com/fsnotify/fsnotify v1.9.0
    golang.org/x/sys v0.13.0
)
```

---

## 2. Component 1: Core Detection Engine (CLI)

This is the main user-facing component. It scans files, directories, and stdin for hardcoded secrets using 183+ regex rules and Shannon entropy analysis.

---

### 2.1 Build the Binary

```bash
cd ~/Github_Projects/CredVigil
go build -o credvigil ./cmd/credvigil
```

**What it does:** Compiles the CLI binary from `cmd/credvigil/main.go` and all imported packages.

**Verify it built:**
```bash
ls -lh credvigil
```

**Expected output:** A binary file (~10-15 MB) named `credvigil`.

**Alternative — build and install to `$GOPATH/bin`:**
```bash
go install ./cmd/credvigil
```

---

### 2.2 Version & Help

#### Show Version
```bash
./credvigil version
```

**Expected output:**
```
CredVigil 0.1.0
Component: core-detection-engine
Build date: 2026-03-12
Go version: see `go version`
```

**Why it matters:** Confirms the binary is working. In production, this helps debug which version is deployed.

#### Show Help / Usage
```bash
./credvigil help
```

Or equivalently:
```bash
./credvigil --help
./credvigil -h
./credvigil        # (no arguments also shows help)
```

**Expected output:** A full usage banner with all flags, options, and examples.

---

### 2.3 List Detection Rules

```bash
./credvigil rules
```

**What it does:** Lists all 183+ detection rule categories grouped by provider/service.

**Expected output (partial):**
```
CredVigil Detection Rules (183 total)
═══════════════════════════════════════════════════════════════

Loaded 183 detection rules covering:
  • Cloud: AWS, GCP, Azure, DigitalOcean, Cloudflare, Vercel, Netlify
  • SCM: GitHub, GitLab, Bitbucket, Gitea
  • Databases: PostgreSQL, MySQL, MongoDB, Redis, InfluxDB...
  ...
```

**Why it matters:** Shows you exactly what the engine can detect. Each rule is a compiled regex with metadata (severity, confidence, entropy threshold). Understanding rule coverage is key to knowing what CredVigil can and cannot catch.

#### Count the rules programmatically
```bash
./credvigil rules 2>&1 | grep "total"
```

---

### 2.4 Scan a Single File

#### Basic file scan
```bash
./credvigil scan testdata/fake_secrets.env
```

**What it does:** Reads `testdata/fake_secrets.env`, runs all 183 regex rules + Shannon entropy analysis, then processes every finding through the zero-trust pipeline (Hash → Redact → Enrich → Fingerprint → Sanitize).

**Expected output:** A formatted report showing each finding with:
- **Severity** (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- **Rule ID** (e.g., `aws-access-key-id`)
- **Type** (e.g., `aws-access-key-id`)
- **File:Line** (e.g., `testdata/fake_secrets.env:6`)
- **Match** (redacted, e.g., `AKIA****MPLE`)
- **Entropy** (Shannon entropy score)
- **Confidence** (e.g., `95%`)
- **SHA-256** (first 8 + last 8 chars of the hash)
- **Fingerprint** (first 16 chars of stable fingerprint)
- **Context** (surrounding lines)

#### Scan without context lines
```bash
./credvigil scan testdata/fake_secrets.env --no-context
```

**What it does:** Same scan, but suppresses the 2-line context around each finding. Cleaner output for quick review.

#### Scan your own file
```bash
./credvigil scan ~/.aws/credentials        # CAREFUL — real credentials!
./credvigil scan .env                       # Scan a .env file
./credvigil scan config/database.yml        # Scan config files
```

**Warning:** Scanning real credential files will detect secrets. The scan output uses redaction (no raw secrets in output), but still — don't accidentally commit scan logs.

---

### 2.5 Scan a Directory

#### Scan current directory
```bash
./credvigil scan .
```

**What it does:** Recursively walks the current directory, skipping excluded directories (`.git`, `node_modules`, `vendor`, etc.) and binary files. Scans all remaining text files in parallel (4 workers by default).

#### Scan a specific project
```bash
./credvigil scan /path/to/any/project
```

#### Scan the CredVigil project itself
```bash
./credvigil scan ~/Github_Projects/CredVigil
```

**What it does:** Scans its own source code! Will find the fake secrets in `testdata/`. This is a great way to see the engine working on a real project tree.

**Directories automatically excluded:**
```
.git, node_modules, vendor, .venv, __pycache__, .idea, .vscode,
.vs, dist, build, target, .terraform, .next, .nuxt, coverage, bin, obj
```

**File extensions automatically excluded:**
```
.exe, .dll, .so, .dylib, .bin, .o, .a, .png, .jpg, .jpeg, .gif,
.bmp, .ico, .svg, .webp, .mp3, .mp4, .avi, .mov, .wav, .flac,
.zip, .tar, .gz, .bz2, .xz, .7z, .rar, .pdf, .doc, .docx,
.xls, .xlsx, .ppt, .pptx, .woff, .woff2, .ttf, .eot, .otf,
.lock, .sum
```

**Files automatically excluded:**
```
package-lock.json, yarn.lock, go.sum, Cargo.lock,
poetry.lock, Gemfile.lock, composer.lock
```

---

### 2.6 Scan from Stdin (Piping)

This is one of CredVigil's most powerful features. You can pipe ANY text into the scanner.

#### Basic stdin scan
```bash
echo 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' | ./credvigil scan --stdin
```

#### Pipe a file via cat
```bash
cat testdata/fake_secrets.env | ./credvigil scan --stdin
```

#### Pipe a git diff (check staged changes for secrets)
```bash
git diff --staged | ./credvigil scan --stdin --no-context
```

**Why it matters:** This is how you integrate CredVigil into git pre-commit hooks!

#### Pipe clipboard contents (macOS)
```bash
pbpaste | ./credvigil scan --stdin --no-context
```

#### Pipe a remote file
```bash
curl -s https://raw.githubusercontent.com/some/repo/main/.env | ./credvigil scan --stdin
```

#### Pipe multiple lines
```bash
echo -e 'GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234\nSTRIPE_KEY=sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz' | ./credvigil scan --stdin --no-context
```

#### Test with clean input (no secrets)
```bash
echo -e 'APP_NAME=my-app\nDEBUG=true\nPORT=3000\nLOG_LEVEL=info' | ./credvigil scan --stdin --no-context
```

**Expected output:** "No secrets detected!" and exit code 0.

#### Test specific secret types one by one

```bash
# AWS Access Key
echo 'AKIAIOSFODNN7EXAMPLE' | ./credvigil scan --stdin --no-context

# GitHub Personal Access Token
echo 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234' | ./credvigil scan --stdin --no-context

# GitLab Personal Access Token
echo 'glpat-ABCDEFGHIJKLMNOPQRSTUVWXYz' | ./credvigil scan --stdin --no-context

# Slack Bot Token
echo 'xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWXyz' | ./credvigil scan --stdin --no-context

# Database URI with password
echo 'postgresql://admin:SuperSecret123@db.prod.example.com:5432/myapp' | ./credvigil scan --stdin --no-context

# JWT
echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U' | ./credvigil scan --stdin --no-context

# Stripe Secret Key
echo 'sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz' | ./credvigil scan --stdin --no-context

# SendGrid API Key
echo 'SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq' | ./credvigil scan --stdin --no-context

# OpenAI API Key
echo 'sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn' | ./credvigil scan --stdin --no-context

# NPM Token
echo 'npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12' | ./credvigil scan --stdin --no-context

# Private Key
echo '-----BEGIN RSA PRIVATE KEY-----' | ./credvigil scan --stdin --no-context

# SonarQube Token
echo 'squ_abcdef0123456789abcdef0123456789abcdef01' | ./credvigil scan --stdin --no-context

# JFrog Artifactory API Key
echo 'AKCabcdefghij1234567890ABCDEFGHIJklmnopq' | ./credvigil scan --stdin --no-context

# Kerberos Keytab
echo 'KRB5_KTNAME=/etc/krb5/service.keytab' | ./credvigil scan --stdin --no-context

# LDAP URI with password
echo 'ldaps://admin:secretPass@ldap.example.com:636' | ./credvigil scan --stdin --no-context

# Teams Webhook
echo 'https://myorg.webhook.office.com/webhookb2/abc123-def-456@ghi789-jkl-012/IncomingWebhook/mno345pqr678/stu901-vwx-234' | ./credvigil scan --stdin --no-context

# Vault Token
echo 'hvs.CAESIDhMOEXAMPLETOKENVAL' | ./credvigil scan --stdin --no-context
```

**Practice tip:** Try each one and note the severity, confidence, and rule ID in the output.

---

### 2.7 Output Formats (Text vs JSON)

#### Text output (default)
```bash
./credvigil scan testdata/fake_secrets.env --no-context
```

#### JSON output
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json
```

**What it does:** Outputs machine-readable JSON. Perfect for piping to `jq`, dashboards, or APIs.

#### JSON + jq: count findings
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | jq '.total_findings'
```

#### JSON + jq: list all rule IDs found
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | jq '[.results[].Findings[].rule_id] | unique'
```

#### JSON + jq: show only critical findings
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | jq '[.results[].Findings[] | select(.severity == "CRITICAL")]'
```

#### JSON + jq: group by severity
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | jq '[.results[].Findings[]] | group_by(.severity) | map({severity: .[0].severity, count: length})'
```

#### JSON + python: validate structure
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f'Valid JSON: YES')
print(f'Version: {data.get(\"version\")}')
print(f'Total findings: {data.get(\"total_findings\")}')
print(f'Scan duration: {data.get(\"scan_duration\")}')
"
```

#### JSON + python: verify zero-trust (raw_match is always empty)
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
findings = [f for r in data.get('results', []) for f in r.get('Findings', [])]
raw_leaked = [f for f in findings if f.get('raw_match', '') != '']
print(f'Total findings: {len(findings)}')
print(f'Raw secrets leaked: {len(raw_leaked)}')
print(f'Zero-trust enforced: {len(raw_leaked) == 0}')
"
```

---

### 2.8 Severity Filtering

Filter findings by minimum severity level. Severity levels (lowest to highest):
`info` < `low` < `medium` < `high` < `critical`

#### Show only CRITICAL findings
```bash
./credvigil scan testdata/fake_secrets.env --no-context --min-severity critical
```

#### Show HIGH and above
```bash
./credvigil scan testdata/fake_secrets.env --no-context --min-severity high
```

#### Show MEDIUM and above
```bash
./credvigil scan testdata/fake_secrets.env --no-context --min-severity medium
```

#### Show LOW and above
```bash
./credvigil scan testdata/fake_secrets.env --no-context --min-severity low
```

#### Show everything (default)
```bash
./credvigil scan testdata/fake_secrets.env --no-context --min-severity info
```

#### Compare finding counts at each level
```bash
echo "=== ALL ==="
./credvigil scan testdata/fake_secrets.env --no-context 2>&1 | tail -5
echo ""
echo "=== MEDIUM+ ==="
./credvigil scan testdata/fake_secrets.env --no-context --min-severity medium 2>&1 | tail -5
echo ""
echo "=== HIGH+ ==="
./credvigil scan testdata/fake_secrets.env --no-context --min-severity high 2>&1 | tail -5
echo ""
echo "=== CRITICAL ==="
./credvigil scan testdata/fake_secrets.env --no-context --min-severity critical 2>&1 | tail -5
```

**Practice tip:** Run this comparison and note how the finding count decreases as you raise the severity threshold.

---

### 2.9 Confidence Filtering

Confidence is a 0.0-1.0 score representing how sure the engine is that a match is a real secret (not a false positive).

#### Show only high-confidence findings (70%+)
```bash
./credvigil scan testdata/fake_secrets.env --no-context --min-confidence 0.7
```

#### Show very high confidence (90%+)
```bash
./credvigil scan testdata/fake_secrets.env --no-context --min-confidence 0.9
```

#### Show essentially-certain findings (95%+)
```bash
./credvigil scan testdata/fake_secrets.env --no-context --min-confidence 0.95
```

#### Lowest threshold (30%, the default)
```bash
./credvigil scan testdata/fake_secrets.env --no-context --min-confidence 0.3
```

#### Compare confidence thresholds
```bash
for conf in 0.3 0.5 0.7 0.8 0.9 0.95; do
  count=$(./credvigil scan testdata/fake_secrets.env --no-context --min-confidence $conf 2>&1 | grep "Total findings" | awk '{print $NF}')
  echo "Confidence >= $conf → $count findings"
done
```

---

### 2.10 Entropy Toggle

Shannon entropy measures the randomness of a string. High-entropy strings are statistically likely to be secrets.

#### Normal scan (entropy enabled — default)
```bash
./credvigil scan testdata/fake_secrets.env --no-context
```

#### Regex-only mode (entropy disabled)
```bash
./credvigil scan testdata/fake_secrets.env --no-context --no-entropy
```

**What changes:** Without entropy, the engine only uses regex pattern matching. It will miss:
- Generic high-entropy secrets that don't match any known pattern
- Additional confidence boosting from entropy analysis

#### Compare with and without entropy
```bash
echo "=== WITH ENTROPY ==="
./credvigil scan testdata/fake_secrets.env --no-context 2>&1 | grep "Total findings"
echo "=== WITHOUT ENTROPY ==="
./credvigil scan testdata/fake_secrets.env --no-context --no-entropy 2>&1 | grep "Total findings"
```

**Practice tip:** Notice the finding count difference. The entropy detector catches secrets that regex misses.

---

### 2.11 Context Lines

Context lines show the surrounding code/text around each finding. Helps you understand WHERE the secret is and if it's really a problem.

#### Default (2 context lines)
```bash
./credvigil scan testdata/fake_secrets.env
```

#### No context
```bash
./credvigil scan testdata/fake_secrets.env --no-context
```

#### 5 context lines
```bash
./credvigil scan testdata/fake_secrets.env --context-lines 5
```

#### 0 context lines (same as --no-context)
```bash
./credvigil scan testdata/fake_secrets.env --context-lines 0
```

#### 10 context lines (maximum useful context)
```bash
./credvigil scan testdata/fake_secrets.env --context-lines 10
```

---

### 2.12 Combining Multiple Flags

You can combine any flags together. Here are the most useful combinations:

#### CI/CD gate: only critical, high confidence, JSON output
```bash
./credvigil scan . --no-context --min-severity critical --min-confidence 0.9 --format json
```

#### Quick security audit: high+, minimal output
```bash
./credvigil scan . --no-context --min-severity high
```

#### Thorough audit: everything, lots of context
```bash
./credvigil scan . --context-lines 5 --min-confidence 0.3
```

#### Regex-only, critical, JSON (fastest scan)
```bash
./credvigil scan . --no-context --no-entropy --min-severity critical --format json
```

#### Git pre-commit hook style
```bash
git diff --staged | ./credvigil scan --stdin --no-context --min-severity medium
```

---

### 2.13 Exit Codes

CredVigil uses exit codes to signal results. This is critical for CI/CD integration.

| Exit Code | Meaning |
|-----------|---------|
| `0`       | No secrets found (clean scan) |
| `1`       | Secrets found OR errors occurred |

#### Test exit code on clean input
```bash
echo 'APP_NAME=my-app' | ./credvigil scan --stdin --no-context
echo "Exit code: $?"
```
**Expected:** Exit code `0`

#### Test exit code on secrets
```bash
echo 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234' | ./credvigil scan --stdin --no-context
echo "Exit code: $?"
```
**Expected:** Exit code `1`

#### Use in a script
```bash
if ./credvigil scan testdata/fake_secrets.env --no-context --min-severity critical 2>&1 > /dev/null; then
  echo "PASS: No critical secrets found"
else
  echo "FAIL: Critical secrets detected!"
fi
```

---

## 3. Component 2: Secure Hashing & Metadata Pipeline

The pipeline is the security boundary between raw detection output and any consumer. It's not a separate CLI command — it runs automatically on every scan. But you can observe its effects.

---

### 3.1 Observing the Pipeline in Action

The pipeline runs automatically. To see its effects, compare text and JSON outputs:

#### See redacted matches in text output
```bash
echo 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' | ./credvigil scan --stdin --no-context
```

Look for the `Match:` line — it will show something like `wJal****EKEY` (first 4 + `****` + last 4).

#### See SHA-256 hash in output
```bash
echo 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234' | ./credvigil scan --stdin --no-context
```

Look for the `SHA-256:` line — shows first 8 + `...` + last 8 characters of the full SHA-256 hash.

#### See fingerprint in output
Look for the `Fingerprint:` line — first 16 characters of a stable, reproducible fingerprint.

#### See enrichment fields: FileType, Environment, Category
```bash
./credvigil scan testdata/fake_secrets.env --no-context
```

Look for `File Type:`, `Environment:`, and `Category:` fields in each finding.

---

### 3.2 Pipeline Stages Explained

The pipeline runs these 5 stages in order on every finding:

| Stage | What It Does | Observable In |
|-------|-------------|---------------|
| **Hash** | SHA-256 hash of raw secret → `SecretHash` field | `SHA-256:` in text, `secret_hash` in JSON |
| **Redact** | Creates masked preview → `RedactedMatch` field | `Match:` in text, `redacted_match` in JSON |
| **Enrich** | Adds FileType, Environment, Category metadata | `File Type:`, `Environment:`, `Category:` lines |
| **Fingerprint** | Generates stable cross-scan fingerprint | `Fingerprint:` in text, `fingerprint` in JSON |
| **Sanitize** | Clears `RawMatch` (zero-trust enforcement) | `raw_match` is always `""` in JSON |

---

### 3.3 Zero-Trust Verification

This is the most important thing to understand about the pipeline. After sanitization, no raw secret ever leaves the system.

#### Prove zero-trust works
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
findings = []
for r in data.get('results', []):
    findings.extend(r.get('Findings', []))
for f in findings:
    raw = f.get('raw_match', '')
    if raw != '':
        print(f'LEAK! raw_match is not empty: {raw[:20]}...')
        sys.exit(1)
print(f'✅ Zero-trust verified: {len(findings)} findings, 0 raw secrets leaked')
"
```

#### See the full pipeline in JSON
```bash
echo 'STRIPE_SECRET_KEY=sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz' | ./credvigil scan --stdin --no-context --format json 2>/dev/null | python3 -m json.tool
```

Look for these fields in each finding:
- `"raw_match": ""` ← sanitized (empty)
- `"redacted_match": "sk_l****WXyz"` ← redacted preview
- `"secret_hash": "abc123..."` ← SHA-256 hash
- `"fingerprint": "def456..."` ← stable fingerprint
- `"file_type": "..."` ← enriched file type
- `"environment": "..."` ← enriched environment
- `"category": "..."` ← enriched category

---

## 4. Component 3: Git Integration Layer

Scan the commit history of git repositories to find secrets that were ever committed — even if they were later deleted or overwritten.

---

### 4.1 Scan Local Repository History

#### Scan the CredVigil repo itself
```bash
./credvigil scan --git .
```

**What it does:**
1. Verifies git is available on PATH
2. Opens the local repository at `.`
3. Gets the commit log for the current branch
4. For each commit, parses the diff to find added lines
5. Runs the detection engine on each added line
6. Processes all findings through the zero-trust pipeline

#### Scan any local repo
```bash
./credvigil scan --git /path/to/any/repo
```

---

### 4.2 Git Branch Scanning

#### Scan a specific branch
```bash
./credvigil scan --git . --git-branch main
```

#### Scan a feature branch
```bash
./credvigil scan --git . --git-branch feature/my-feature
```

#### Scan develop branch
```bash
./credvigil scan --git . --git-branch develop
```

---

### 4.3 Incremental Scanning (Since Commit)

Only scan commits after a specific hash. Essential for CI/CD to avoid re-scanning everything.

#### Get a commit hash to use
```bash
git log --oneline -5
```

Pick a hash from the output, then:

#### Scan only commits after that hash
```bash
./credvigil scan --git . --git-since <commit-hash>
```

**Example:**
```bash
HASH=$(git rev-parse HEAD~3)   # 3 commits ago
./credvigil scan --git . --git-since $HASH
```

---

### 4.4 Limit Number of Commits

#### Scan only the last 5 commits
```bash
./credvigil scan --git . --git-max-commits 5
```

#### Scan only the last commit
```bash
./credvigil scan --git . --git-max-commits 1
```

#### Scan last 20 commits
```bash
./credvigil scan --git . --git-max-commits 20
```

---

### 4.5 Scan All Branches

```bash
./credvigil scan --git . --git-all-branches
```

**What it does:** Scans every branch in the repository, not just the current one. Useful for finding secrets that were committed on branches that haven't been merged yet.

---

### 4.6 Include Merge Commits

By default, merge commits are skipped (they duplicate content from feature branches).

```bash
./credvigil scan --git . --git-include-merges
```

---

### 4.7 Clone and Scan Remote Repository

#### Scan a public GitHub repo
```bash
./credvigil scan --git https://github.com/some-org/some-repo.git
```

**What it does:**
1. Clones the repository to a temporary directory
2. Scans the entire commit history
3. Cleans up the temporary directory
4. Reports findings with commit hashes, authors, and dates

**Note:** This can take a long time for large repos. Use `--git-depth` for faster scans.

---

### 4.8 Remote with Shallow Clone

#### Clone only last 10 commits
```bash
./credvigil scan --git https://github.com/some-org/some-repo.git --git-depth 10
```

#### Clone only last commit
```bash
./credvigil scan --git https://github.com/some-org/some-repo.git --git-depth 1
```

---

### 4.9 Git + Output Format

#### Git scan with JSON output
```bash
./credvigil scan --git . --format json
```

#### Git scan with JSON + jq
```bash
./credvigil scan --git . --format json 2>/dev/null | jq '.total_findings'
```

#### Combine all git options
```bash
./credvigil scan --git . --git-branch main --git-max-commits 50 --git-include-merges --format json
```

---

## 5. Component 4: File System Watcher (Debouncing & Real-Time)

The watcher monitors directories for file changes in real-time and triggers scanning. It uses **debouncing** to avoid scanning the same file multiple times within a short window.

---

### 5.1 Understanding Debouncing

**What is debouncing?**

When you save a file, the OS may emit multiple events rapidly:
1. `WRITE` event (content changed)
2. `CHMOD` event (permissions updated)
3. `WRITE` event (editor writes temp then renames)

Without debouncing, the scanner would run 3 times for 1 save. Debouncing collapses these into a single scan after a configurable interval (default: 500ms).

**How CredVigil implements it:**

```
File saved → fsnotify emits events → Watcher receives event
  → Check debounce map: was this file seen in the last 500ms?
    → YES: Drop event (increment EventsDropped counter)
    → NO:  Record timestamp, emit event to handler (increment EventsEmitted)
```

---

### 5.2 Watching the Watcher with Tests

The best way to see debouncing live is through the test suite.

#### Run all watcher tests (verbose)
```bash
go test ./pkg/watcher -v
```

**Expected output:** 22 test functions, each showing PASS/FAIL with details.

Key tests to watch for:

| Test Name | What It Proves |
|-----------|---------------|
| `TestDebounce_SameFile` | Rapid writes to same file → only 1 handler call |
| `TestDebounce_DifferentFiles` | Writes to different files → separate handler calls |
| `TestDebounce_AfterInterval` | After debounce window passes, new events fire |
| `TestRecursiveWatch` | Subdirectory changes are caught |
| `TestExcludeDirs` | Events in `.git`, `node_modules` etc. are filtered |
| `TestExcludeExtensions` | `.png`, `.exe` etc. are skipped |
| `TestNewDirAutoWatch` | Creating a new subdirectory auto-registers it |
| `TestHandler` | Handler receives correct event type and path |

#### Run a specific debounce test
```bash
go test ./pkg/watcher -v -run TestDebounce_SameFile
```

#### Run all debounce-related tests
```bash
go test ./pkg/watcher -v -run "TestDebounce"
```

#### Run all exclusion-related tests
```bash
go test ./pkg/watcher -v -run "TestExclude"
```

#### Run the recursive watching test
```bash
go test ./pkg/watcher -v -run "TestRecursive"
```

---

### 5.3 Live Debounce Experiment

You can write a small Go program to see debouncing live. Create this file:

**File to create: `testdata/watcher_demo.go`** (see Section 8.4)

Then run:
```bash
go run testdata/watcher_demo.go
```

In another terminal, rapidly create/modify files in the watched directory and observe how events are collapsed.

---

### 5.4 Watcher Configuration Options

These are the configuration knobs available in `watcher.Config`:

| Option | Type | Default | What It Controls |
|--------|------|---------|-----------------|
| `Paths` | `[]string` | (required) | Directories/files to watch |
| `Recursive` | `bool` | `true` | Watch subdirectories automatically |
| `DebounceInterval` | `time.Duration` | `500ms` | Minimum time between events for same file |
| `ExcludeDirs` | `[]string` | `.git`, `node_modules`, etc. | Directory names to skip |
| `ExcludeExtensions` | `[]string` | `.exe`, `.png`, etc. | File extensions to ignore |
| `ExcludeFiles` | `[]string` | `package-lock.json`, etc. | Exact filenames to ignore |
| `IncludeExtensions` | `[]string` | (empty = all) | Only watch these extensions |

#### Print default config in a test
```bash
go test ./pkg/watcher -v -run "TestDefaultConfig"
```

---

### 5.5 Event Types Explained

The watcher emits 4 event types:

| EventType | Constant | Meaning | When It Fires |
|-----------|----------|---------|---------------|
| `CREATED` | `EventCreated` | New file/directory appeared | `touch`, `cp`, `mv` (to new name), IDE create |
| `MODIFIED` | `EventModified` | File content changed | `echo >> file`, save in editor, `sed -i` |
| `DELETED` | `EventDeleted` | File/directory removed | `rm`, `mv` (from old name) |
| `RENAMED` | `EventRenamed` | File/directory renamed | `mv old new` |

#### Test event types
```bash
go test ./pkg/watcher -v -run "TestEvent"
```

---

### 5.6 Stats & Monitoring

The watcher tracks runtime statistics:

| Stat | Meaning |
|------|---------|
| `EventsReceived` | Total raw events from fsnotify |
| `EventsEmitted` | Events that passed debouncing and filtering |
| `EventsDropped` | Events suppressed by debouncing or filtering |
| `DirsWatched` | Number of directories currently being monitored |
| `StartedAt` | When the watcher was started |

**Key metrics to observe:**
- `EventsReceived - EventsEmitted = EventsDropped` (they should add up)
- `EventsDropped / EventsReceived` = debounce efficiency (higher = more efficient)

#### Test stats with the test suite
```bash
go test ./pkg/watcher -v -run "TestStats"
```

---

## 6. Unit Testing Commands

Go's testing framework is central to CredVigil's development.

---

### 6.1 Run All Tests

```bash
go test ./...
```

**What it does:** Runs all tests in every package recursively.

**Expected output:**
```
ok      github.com/credvigil/credvigil/pkg/detector   0.XXXs
ok      github.com/credvigil/credvigil/pkg/entropy     0.XXXs
ok      github.com/credvigil/credvigil/pkg/git          0.XXXs
ok      github.com/credvigil/credvigil/pkg/pipeline     0.XXXs
ok      github.com/credvigil/credvigil/pkg/rules        0.XXXs
ok      github.com/credvigil/credvigil/pkg/watcher      0.XXXs
```

---

### 6.2 Run Tests for a Single Package

```bash
# Component 1: Detection Engine
go test ./pkg/detector

# Component 1: Rules
go test ./pkg/rules

# Component 1: Entropy
go test ./pkg/entropy

# Component 2: Pipeline
go test ./pkg/pipeline

# Component 3: Git
go test ./pkg/git

# Component 4: Watcher
go test ./pkg/watcher
```

---

### 6.3 Run a Specific Test Function

```bash
# Syntax: go test ./pkg/<package> -run <TestFunctionName>

# Detection engine tests
go test ./pkg/detector -run TestScanContent_AWSKeys
go test ./pkg/detector -run TestScanContent_GitHubTokens
go test ./pkg/detector -run TestScanContent_SlackTokens
go test ./pkg/detector -run TestScanContent_PrivateKeys
go test ./pkg/detector -run TestScanContent_DatabaseURIs
go test ./pkg/detector -run TestScanContent_JWT
go test ./pkg/detector -run TestScanContent_Stripe
go test ./pkg/detector -run TestScanContent_SendGrid
go test ./pkg/detector -run TestScanContent_GenericSecrets
go test ./pkg/detector -run TestScanContent_FalsePositiveReduction
go test ./pkg/detector -run TestScanContent_EmptyContent
go test ./pkg/detector -run TestScanContent_NoSecrets
go test ./pkg/detector -run TestScanContent_MultiSecret
go test ./pkg/detector -run TestScanContent_Deduplication
go test ./pkg/detector -run TestScanContent_FilterTypes
go test ./pkg/detector -run TestScanContent_MinSeverity
go test ./pkg/detector -run TestScanContent_ContextIncluded
go test ./pkg/detector -run TestScanContent_RedactionWorks
go test ./pkg/detector -run TestScanContent_ScanDuration
go test ./pkg/detector -run TestScanContent_HashMetadata
go test ./pkg/detector -run TestScanContent_TeamsWebhook

# Git tests
go test ./pkg/git -run TestGitAvailable
go test ./pkg/git -run TestOpenRepository
go test ./pkg/git -run TestHeadCommit
go test ./pkg/git -run TestDefaultBranch
go test ./pkg/git -run TestBranches
go test ./pkg/git -run TestParseDiff_AddedFile
go test ./pkg/git -run TestParseDiff_ModifiedFile
go test ./pkg/git -run TestParseDiff_MultipleFiles
go test ./pkg/git -run TestParseDiff_DeletedFile
go test ./pkg/git -run TestParseDiff_RenamedFile
go test ./pkg/git -run TestParseDiff_EmptyInput
go test ./pkg/git -run TestParseDiff_MultipleHunks
go test ./pkg/git -run TestParseHunkNewStart
go test ./pkg/git -run TestFilterDiffEntries_NoFilters
go test ./pkg/git -run TestFilterDiffEntries_IncludeOnly
go test ./pkg/git -run TestFilterDiffEntries_ExcludeOnly
go test ./pkg/git -run TestFilterDiffEntries_IncludeAndExclude
go test ./pkg/git -run TestMatchPattern

# Run multiple test functions using regex
go test ./pkg/detector -run "TestScanContent_AWS|TestScanContent_GitHub"
go test ./pkg/git -run "TestParseDiff"
go test ./pkg/watcher -run "TestDebounce"
```

---

### 6.4 Verbose Test Output

```bash
# All tests verbose
go test ./... -v

# Single package verbose
go test ./pkg/detector -v

# Single test verbose
go test ./pkg/detector -v -run TestScanContent_AWSKeys
```

**What `-v` shows:** Each test function name, PASS/FAIL status, and any `t.Log()` output.

---

### 6.5 Test with Race Detector

Go's race detector finds data races in concurrent code. Critical for the watcher (which uses goroutines).

```bash
# All tests with race detection
go test -race ./...

# Watcher specifically (most concurrent code)
go test -race ./pkg/watcher -v

# Pipeline (uses mutexes)
go test -race ./pkg/pipeline -v

# Detection engine (concurrent scanning)
go test -race ./pkg/detector -v
```

**What it does:** Instruments the binary to detect concurrent access to shared memory without proper synchronization. If a race is found, the test fails with a detailed stack trace.

---

### 6.6 Test Coverage

```bash
# Coverage percentage for all packages
go test ./... -cover

# Coverage for a specific package
go test ./pkg/detector -cover
go test ./pkg/watcher -cover
go test ./pkg/pipeline -cover
go test ./pkg/git -cover
go test ./pkg/entropy -cover
go test ./pkg/rules -cover

# Generate coverage profile
go test ./... -coverprofile=coverage.out

# View coverage in terminal
go tool cover -func=coverage.out

# View coverage in browser (visual — highlights covered/uncovered lines)
go tool cover -html=coverage.out

# Coverage for a single package with HTML report
go test ./pkg/detector -coverprofile=detector_coverage.out
go tool cover -html=detector_coverage.out

# Coverage for watcher with HTML report
go test ./pkg/watcher -coverprofile=watcher_coverage.out
go tool cover -html=watcher_coverage.out
```

---

### 6.7 Test Count (Disable Caching)

Go caches test results. To force a fresh run:

```bash
# Run all tests without cache
go test ./... -count=1

# Same but verbose
go test ./... -count=1 -v
```

---

### 6.8 Test Timeout

```bash
# Default timeout is 10 minutes. Override:
go test ./... -timeout 30s

# Longer timeout for slow machines
go test ./... -timeout 5m

# Watcher tests (may need more time for debounce timers)
go test ./pkg/watcher -timeout 60s -v
```

---

### 6.9 Benchmark Tests

If benchmarks are defined (e.g., `BenchmarkScanContent`):

```bash
# Run all benchmarks in a package
go test ./pkg/detector -bench=.

# Run specific benchmark
go test ./pkg/detector -bench=BenchmarkScanContent

# Benchmarks with memory allocation stats
go test ./pkg/detector -bench=. -benchmem

# Run benchmark N times for stable results
go test ./pkg/detector -bench=. -count=5
```

---

## 7. Interactive Test Suite Script

A comprehensive script that runs all CLI-level tests:

```bash
# Run the interactive test suite
bash run_all_tests.sh
```

**What it does:** Runs 14 tests covering:
1. Version check
2. List rules (183 rules)
3. Full scan of `fake_secrets.env`
4. Severity filter (CRITICAL only)
5. Confidence filter (70%+)
6. JSON output with validation
7. Stdin piping
8. SonarQube token detection
9. Kerberos keytab detection
10. LDAP URI detection
11. JFrog Artifactory detection
12. Clean input (no secrets)
13. Regex-only mode (no entropy)
14. Go unit tests

---

## 8. Creating Test Files for Practice

### 8.1 Create a Fake Secrets File

The project already includes `testdata/fake_secrets.env`. You can also create your own:

```bash
cat > /tmp/my_test_secrets.env << 'EOF'
# My test secrets file
# NONE of these are real credentials

# AWS Keys
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# GitHub Token
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234

# Slack Token
SLACK_BOT_TOKEN=xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWXyz

# Database
DATABASE_URL=postgresql://admin:SuperSecret123@db.prod.example.com:5432/myapp

# Stripe
STRIPE_SECRET_KEY=sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz

# OpenAI
OPENAI_API_KEY=sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn

# Private Key
PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
-----END RSA PRIVATE KEY-----"

# JWT
JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
EOF
```

Now scan it:
```bash
./credvigil scan /tmp/my_test_secrets.env --no-context
```

---

### 8.2 Create a Clean File (No Secrets)

```bash
cat > /tmp/clean_config.env << 'EOF'
# Application configuration (no secrets)
APP_NAME=my-awesome-app
APP_VERSION=1.2.3
DEBUG=false
PORT=8080
LOG_LEVEL=info
MAX_CONNECTIONS=100
CACHE_TTL=3600
FEATURE_FLAG_NEW_UI=true
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=myapp_dev
EOF
```

Scan it:
```bash
./credvigil scan /tmp/clean_config.env --no-context
echo "Exit code: $?"
```

**Expected:** No findings, exit code 0.

---

### 8.3 Create a Multi-Language Project for Scanning

Create a fake project tree with secrets embedded in different file types:

```bash
mkdir -p /tmp/fake_project/{src,config,scripts,docs}

# Python with secrets
cat > /tmp/fake_project/src/app.py << 'PYEOF'
import os
import requests

# Bad: hardcoded API key
API_KEY = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"

def call_api():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get("https://api.example.com/data", headers=headers)

# Good: use environment variable
SAFE_KEY = os.getenv("API_KEY")
PYEOF

# JavaScript with secrets
cat > /tmp/fake_project/src/config.js << 'JSEOF'
// Database configuration
module.exports = {
  db: {
    host: 'db.prod.example.com',
    port: 5432,
    user: 'admin',
    // Bad: hardcoded password in connection string
    connectionString: 'postgresql://admin:SuperSecret123@db.prod.example.com:5432/myapp'
  },
  // Bad: hardcoded Stripe key
  stripe: {
    secretKey: 'sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz'
  }
};
JSEOF

# YAML config with secrets
cat > /tmp/fake_project/config/database.yml << 'YAMLEOF'
production:
  adapter: postgresql
  host: db.prod.example.com
  database: myapp_production
  username: admin
  password: SuperSecret123
  
development:
  adapter: postgresql
  host: localhost
  database: myapp_dev
  username: dev
  password: devpass123
YAMLEOF

# Shell script with secrets
cat > /tmp/fake_project/scripts/deploy.sh << 'SHEOF'
#!/bin/bash
# Deployment script

# Bad: hardcoded AWS keys
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Bad: hardcoded GitHub token
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234

echo "Deploying..."
SHEOF

# Dockerfile with secrets
cat > /tmp/fake_project/Dockerfile << 'DKEOF'
FROM python:3.11-slim

# Bad: hardcoded API key in build arg
ENV OPENAI_API_KEY=sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
ENV STRIPE_KEY=sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz

COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "src/app.py"]
DKEOF
```

Now scan the entire fake project:

```bash
# Full scan
./credvigil scan /tmp/fake_project --no-context

# Only critical findings
./credvigil scan /tmp/fake_project --no-context --min-severity critical

# JSON output
./credvigil scan /tmp/fake_project --no-context --format json 2>/dev/null | jq '.total_findings'

# Scan each file individually
./credvigil scan /tmp/fake_project/src/app.py --no-context
./credvigil scan /tmp/fake_project/src/config.js --no-context
./credvigil scan /tmp/fake_project/config/database.yml --no-context
./credvigil scan /tmp/fake_project/scripts/deploy.sh --no-context
./credvigil scan /tmp/fake_project/Dockerfile --no-context
```

**Cleanup when done:**
```bash
rm -rf /tmp/fake_project
```

---

### 8.4 Create Files for Watcher Practice

Create a small Go program to observe debouncing, event filtering, and real-time watching:

```bash
cat > /tmp/watcher_demo.go << 'GOEOF'
//go:build ignore

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/credvigil/credvigil/pkg/watcher"
)

func main() {
	// Create a temp directory to watch
	watchDir := "/tmp/credvigil_watch_demo"
	os.MkdirAll(watchDir, 0755)

	fmt.Println("╔═════════════════════════════════════════════════════════╗")
	fmt.Println("║         CredVigil Watcher & Debounce Demo              ║")
	fmt.Println("╚═════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Watching directory: %s\n", watchDir)
	fmt.Println("Debounce interval: 500ms")
	fmt.Println()
	fmt.Println("Open another terminal and try these commands:")
	fmt.Println("  touch /tmp/credvigil_watch_demo/test.txt")
	fmt.Println("  echo 'hello' >> /tmp/credvigil_watch_demo/test.txt")
	fmt.Println("  echo 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234' > /tmp/credvigil_watch_demo/secret.env")
	fmt.Println("  mkdir /tmp/credvigil_watch_demo/subdir")
	fmt.Println("  touch /tmp/credvigil_watch_demo/subdir/file.go")
	fmt.Println("  rm /tmp/credvigil_watch_demo/test.txt")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop.")
	fmt.Println("─────────────────────────────────────────────────────────")
	fmt.Println()

	cfg := watcher.DefaultConfig()
	cfg.Paths = []string{watchDir}
	cfg.DebounceInterval = 500 * time.Millisecond

	eventCount := 0
	w, err := watcher.New(cfg, func(event watcher.Event) {
		eventCount++
		fmt.Printf("[%s] #%d  %s  %s\n",
			event.Timestamp.Format("15:04:05.000"),
			eventCount,
			event.Type,
			event.Path,
		)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Graceful shutdown on Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nShutting down watcher...")
		cancel()
	}()

	if err := w.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Watcher error: %v\n", err)
	}

	stats := w.GetStats()
	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────")
	fmt.Printf("Events received: %d\n", stats.EventsReceived)
	fmt.Printf("Events emitted:  %d\n", stats.EventsEmitted)
	fmt.Printf("Events dropped:  %d (debounced/filtered)\n", stats.EventsDropped)
	fmt.Printf("Dirs watched:    %d\n", stats.DirsWatched)
	fmt.Printf("Uptime:          %v\n", time.Since(stats.StartedAt).Round(time.Second))
}
GOEOF
```

#### Run the watcher demo

**Terminal 1 — Start the watcher:**
```bash
cd ~/Github_Projects/CredVigil
go run /tmp/watcher_demo.go
```

**Terminal 2 — Create and modify files:**
```bash
# Create a file (should trigger CREATED event)
touch /tmp/credvigil_watch_demo/test.txt

# Modify a file (should trigger MODIFIED event)
echo "hello world" >> /tmp/credvigil_watch_demo/test.txt

# Rapid-fire modifications (test debouncing!)
for i in {1..10}; do echo "line $i" >> /tmp/credvigil_watch_demo/test.txt; done
# ↑ Even though 10 writes happen, debouncing should collapse them!

# Create a file with a secret
echo 'GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234' > /tmp/credvigil_watch_demo/secret.env

# Create a subdirectory (should auto-watch)
mkdir /tmp/credvigil_watch_demo/subdir

# Create file in subdirectory
echo 'hello' > /tmp/credvigil_watch_demo/subdir/deep_file.txt

# Create a binary file (should be ignored due to extension exclusion)
touch /tmp/credvigil_watch_demo/image.png

# Delete a file
rm /tmp/credvigil_watch_demo/test.txt

# Rename a file
mv /tmp/credvigil_watch_demo/secret.env /tmp/credvigil_watch_demo/secret_renamed.env

# Done — press Ctrl+C in Terminal 1 to see stats
```

**What to observe:**
1. **Debouncing:** The `for i in {1..10}` rapid-fire test should NOT produce 10 events. It should produce 1-2 events.
2. **Event types:** `CREATED`, `MODIFIED`, `DELETED`, `RENAMED` — each appears correctly.
3. **Auto-watch:** Creating `subdir/` should automatically start watching it.
4. **Extension filtering:** `image.png` should NOT trigger an event (`.png` is excluded).
5. **Stats:** At the end, `EventsDropped` shows how many events were suppressed by debouncing.

**Cleanup:**
```bash
rm -rf /tmp/credvigil_watch_demo
rm /tmp/watcher_demo.go
```

---

## 9. Advanced Piping & Automation

### Scan git diff before committing (pre-commit hook)
```bash
git diff --staged | ./credvigil scan --stdin --no-context --min-severity medium
```

### Scan a specific git commit's changes
```bash
git show HEAD --format="" | ./credvigil scan --stdin --no-context
```

### Scan all .env files in a project
```bash
find /path/to/project -name "*.env" -exec cat {} + | ./credvigil scan --stdin --no-context
```

### Scan Kubernetes secrets (base64 decoded)
```bash
kubectl get secret my-secret -o jsonpath='{.data}' | base64 -d | ./credvigil scan --stdin --no-context
```

### Scan Terraform state file
```bash
./credvigil scan terraform.tfstate --no-context --min-severity high
```

### Scan entire project, output JSON, filter with jq
```bash
./credvigil scan . --no-context --format json 2>/dev/null | jq '
  [.results[].Findings[] | {
    severity: .severity,
    rule: .rule_id,
    file: .source.location,
    line: .source.line_number,
    confidence: (.confidence * 100 | tostring) + "%"
  }]
'
```

### Generate a CSV report
```bash
./credvigil scan . --no-context --format json 2>/dev/null | python3 -c "
import json, sys, csv
data = json.load(sys.stdin)
writer = csv.writer(sys.stdout)
writer.writerow(['Severity', 'Rule', 'File', 'Line', 'Confidence', 'SHA-256'])
for r in data.get('results', []):
    for f in r.get('Findings', []):
        writer.writerow([
            f.get('severity', ''),
            f.get('rule_id', ''),
            f.get('source', {}).get('location', ''),
            f.get('source', {}).get('line_number', ''),
            f'{f.get(\"confidence\", 0)*100:.0f}%',
            f.get('secret_hash', '')[:16]
        ])
" > scan_report.csv
```

### Count findings by rule
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | jq '[.results[].Findings[].rule_id] | group_by(.) | map({rule: .[0], count: length}) | sort_by(-.count)'
```

### Scan and fail CI if any critical finding
```bash
#!/bin/bash
RESULT=$(./credvigil scan . --no-context --min-severity critical --format json 2>/dev/null)
COUNT=$(echo "$RESULT" | jq '.total_findings')
if [ "$COUNT" -gt "0" ]; then
  echo "❌ FAILED: $COUNT critical secret(s) found"
  echo "$RESULT" | jq '.results[].Findings[] | {rule: .rule_id, file: .source.location, line: .source.line_number}'
  exit 1
fi
echo "✅ PASSED: No critical secrets found"
```

---

## 10. Quick Reference Card

### CLI Commands

| Command | Description |
|---------|-------------|
| `./credvigil version` | Show version info |
| `./credvigil help` | Show usage and options |
| `./credvigil rules` | List all 183+ detection rules |
| `./credvigil scan <path>` | Scan file or directory |
| `./credvigil scan --stdin` | Scan from piped input |
| `./credvigil scan --git <path\|url>` | Scan git repository history |

### Scan Flags

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--format` | `text`, `json` | `text` | Output format |
| `--min-confidence` | `0.0` - `1.0` | `0.3` | Minimum confidence threshold |
| `--min-severity` | `info`, `low`, `medium`, `high`, `critical` | `info` | Minimum severity level |
| `--no-entropy` | (flag) | off | Disable entropy detection |
| `--no-context` | (flag) | off | Hide context lines |
| `--context-lines` | `0` - `N` | `2` | Number of context lines |

### Git Flags

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--git` | path or URL | (none) | Enable git history scanning |
| `--git-branch` | branch name | current | Scan specific branch |
| `--git-since` | commit hash | (none) | Only commits after this hash |
| `--git-depth` | integer | `0` (full) | Clone depth for remote repos |
| `--git-max-commits` | integer | `0` (all) | Maximum commits to scan |
| `--git-all-branches` | (flag) | off | Scan all branches |
| `--git-include-merges` | (flag) | off | Include merge commits |

### Test Commands

| Command | Description |
|---------|-------------|
| `go test ./...` | Run all tests |
| `go test ./pkg/<name>` | Test single package |
| `go test ./pkg/<name> -run <test>` | Run specific test |
| `go test ./... -v` | Verbose output |
| `go test -race ./...` | Race condition detection |
| `go test ./... -cover` | Coverage percentage |
| `go test ./... -coverprofile=c.out` | Coverage profile |
| `go tool cover -html=c.out` | Visual coverage in browser |
| `go test ./... -count=1` | Disable test caching |
| `go test ./... -timeout 30s` | Set timeout |
| `go test ./pkg/<name> -bench=.` | Run benchmarks |

### Build Commands

| Command | Description |
|---------|-------------|
| `go build -o credvigil ./cmd/credvigil` | Build CLI binary |
| `go install ./cmd/credvigil` | Install to `$GOPATH/bin` |
| `go mod download` | Download dependencies |
| `go mod tidy` | Clean up go.mod/go.sum |
| `go vet ./...` | Static analysis |
| `bash run_all_tests.sh` | Interactive test suite |

### Package-to-Component Map

| Package | Component | Tests |
|---------|-----------|-------|
| `pkg/detector` | 1 — Core Detection Engine | `engine_test.go` |
| `pkg/rules` | 1 — Detection Rules | `rules_test.go` |
| `pkg/entropy` | 1 — Entropy Analysis | `entropy_test.go` |
| `pkg/pipeline` | 2 — Secure Hash/Metadata Pipeline | `pipeline_test.go` |
| `pkg/git` | 3 — Git Integration Layer | `git_test.go` |
| `pkg/watcher` | 4 — File System Watcher | `watcher_test.go` |
| `cmd/credvigil` | CLI (uses all components) | `run_all_tests.sh` |
| `pkg/models` | Shared data structures | (no tests, pure types) |

---

## Files You Need for Practice

| File | Already Exists? | Purpose |
|------|----------------|---------|
| `testdata/fake_secrets.env` | ✅ Yes | Pre-built test data with 20+ fake secrets |
| `/tmp/my_test_secrets.env` | ❌ Create (Section 8.1) | Your own test secrets file |
| `/tmp/clean_config.env` | ❌ Create (Section 8.2) | Clean file for zero-findings test |
| `/tmp/fake_project/` | ❌ Create (Section 8.3) | Multi-language project with embedded secrets |
| `/tmp/watcher_demo.go` | ❌ Create (Section 8.4) | Live watcher/debounce demo program |
| `/tmp/credvigil_watch_demo/` | ❌ Created by demo | Directory the watcher monitors |

**Important:** All test files in `/tmp/` use fake/example credentials. None of them are real. They are safe to create and delete.

---

*Last updated: March 14, 2026*
*Covers Components 1-4 of the CredVigil build order*
