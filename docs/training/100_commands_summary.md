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
11. [CredVigil vs TruffleHog — Command Comparison](#11-credvigil-vs-trufflehog--command-comparison)
    - [11.1 Installation](#111-installation)
    - [11.2 Scanning Files & Directories](#112-scanning-files--directories)
    - [11.3 Git Repository Scanning](#113-git-repository-scanning)
    - [11.4 Filtering & Severity](#114-filtering--severity)
    - [11.5 Output & JSON Processing](#115-output--json-processing)
    - [11.6 Watching (Live Monitoring)](#116-watching-live-monitoring)
    - [11.7 Additional TruffleHog Sources](#117-additional-trufflehog-sources-not-in-credvigil)
    - [11.8 JSON Field Comparison](#118-json-field-comparison)
    - [11.9 Side-by-Side Quick Reference](#119-side-by-side-quick-reference)
    - [11.10 Summary: When to Use Which](#1110-summary-when-to-use-which)

---

## How This Guide Works — The CredVigil Philosophy

CredVigil follows a **Linux-native command style**. If you know `grep`, `find`, or `git`, you already know how to use CredVigil. Every command follows the pattern:

```
credvigil <verb> <target> [--flags]
```

Compare this to other tools:
| Tool | Style | Example |
|------|-------|--------|
| **CredVigil** | `verb target --flags` (Linux-native) | `credvigil scan . --format json` |
| TruffleHog | `verb source-type target --flags` | `trufflehog filesystem . --json` |
| GitLeaks | `verb --source target --flags` | `gitleaks detect --source .` |

CredVigil is the most concise. No unnecessary subcommands.

### Architecture Overview

```mermaid
flowchart LR
    subgraph INPUT["Input Sources"]
        F["File/Directory"]
        S["Stdin (pipe)"]
        G["Git Repository"]
        W["File Watcher"]
    end

    subgraph ENGINE["Component 1: Detection Engine"]
        R["369 Regex Rules"]
        E["Shannon Entropy"]
    end

    subgraph PIPELINE["Component 2: Zero-Trust Pipeline"]
        direction LR
        H["Hash"] --> RD["Redact"] --> EN["Enrich"] --> FP["Fingerprint"] --> SN["Sanitize"]
    end

    subgraph OUTPUT["Output"]
        TXT["Text Report"]
        JSON["JSON"]
    end

    F --> ENGINE
    S --> ENGINE
    G --> ENGINE
    W --> ENGINE
    ENGINE --> PIPELINE
    PIPELINE --> OUTPUT
```

### Real-Life Scenarios This Guide Covers

```mermaid
mindmap
  root((CredVigil\nUse Cases))
    Developer Workflow
      Pre-commit hook
      Scan before push
      IDE integration
    CI/CD Pipeline
      GitHub Actions gate
      Exit code checking
      JSON report generation
    Security Audit
      Full repo history scan
      Cross-branch analysis
      Severity triage
    Real-Time Monitoring
      Watch project directory
      Debounce rapid saves
      Auto-scan on change
```

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

### Check jq Installation (used for JSON processing)

```bash
jq --version
```

If jq is not installed:
```bash
# macOS
brew install jq

# Linux (Ubuntu/Debian)
sudo apt install jq
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

**Step-by-step breakdown:**
1. Go reads `go.mod` to find required modules
2. Downloads `github.com/fsnotify/fsnotify v1.9.0` (file system notifications)
3. Downloads transitive dependency `golang.org/x/sys` (OS-level syscalls for fsnotify)
4. Stores packages in `$GOPATH/pkg/mod/` (shared cache across all Go projects)
5. Updates `go.sum` with cryptographic checksums for supply-chain integrity

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

This is the main user-facing component. It scans files, directories, and stdin for hardcoded secrets using 369 regex rules and Shannon entropy analysis.

### How a Scan Works (Step-by-Step)

```mermaid
sequenceDiagram
    participant User
    participant CLI as credvigil CLI
    participant Scanner as FileScanner
    participant Engine as DetectionEngine
    participant Rules as 369 Rules
    participant Entropy as Shannon Entropy
    participant Pipeline as Zero-Trust Pipeline
    participant Output as Formatter

    User->>CLI: ./credvigil scan file.env
    CLI->>Scanner: ScanFile("file.env")
    Scanner->>Scanner: Read file, split into lines
    loop For each line
        Scanner->>Engine: ScanContent(line)
        Engine->>Rules: Match against 369 compiled regexes
        Rules-->>Engine: Matches found
        Engine->>Entropy: Calculate Shannon entropy
        Entropy-->>Engine: Entropy score (0.0 - 8.0)
        Engine->>Engine: Deduplicate, assign severity & confidence
    end
    Scanner-->>CLI: ScanResult{findings[]}
    CLI->>Pipeline: ProcessResult(findings)
    Note over Pipeline: Hash → Redact → Enrich → Fingerprint → Sanitize
    Pipeline-->>CLI: Processed findings (zero-trust)
    CLI->>Output: Format as text or JSON
    Output-->>User: Report with redacted matches
```

---

### 2.1 Build the Binary

```bash
cd ~/Github_Projects/CredVigil
go build -o credvigil ./cmd/credvigil
```

**What it does:** Compiles the CLI binary from `cmd/credvigil/main.go` and all imported packages.

**Step-by-step breakdown:**
1. `go build` invokes the Go compiler on `./cmd/credvigil` (the `main` package)
2. The compiler resolves all `import` statements, pulling in `pkg/detector`, `pkg/rules`, `pkg/pipeline`, `pkg/git`, `pkg/watcher`, etc.
3. All 369 regex patterns are compiled at init time and baked into the binary
4. The `-o credvigil` flag names the output binary (otherwise it defaults to the directory name)
5. Result: a single, statically-linked binary with zero runtime dependencies

**Verify it built:**
```bash
ls -lh credvigil
```

**Expected output:** A binary file (~3-4 MB) named `credvigil`.

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

**Actual output:**
```
CredVigil 0.1.0
Component: core-detection-engine
Build date: 2026-03-12
Go version: see `go version`
```

**Why it matters:** Confirms the binary is working. In production, this helps debug which version is deployed. The version string is also embedded in every JSON scan output under the `version` field.

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

**Actual output:**
```
╔═══════════════════════════════════════════════════════════════╗
║                     CredVigil v0.1.0                        ║
║         Credential Detection & Monitoring Engine             ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
  credvigil scan <path>         Scan a file or directory for secrets
  credvigil scan --stdin        Scan from standard input
  credvigil scan --git <path|url>  Scan git repository history
  credvigil rules               List all detection rules
  credvigil version             Show version and build info

Options:
  --format <text|json>          Output format (default: text)
  --min-confidence <0.0-1.0>    Minimum confidence threshold (default: 0.3)
  --min-severity <info|low|medium|high|critical>  Minimum severity
  --no-entropy                  Disable entropy-based detection
  --no-context                  Don't show surrounding context
  --context-lines <n>           Number of context lines (default: 2)

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
```

**Command anatomy — reading the help output:**

```mermaid
flowchart TD
    A["credvigil"] --> B{"Verb"}
    B -->|scan| C["Scan for secrets"]
    B -->|rules| D["List detection rules"]
    B -->|version| E["Show version"]
    B -->|help| F["Show usage"]
    
    C --> G{"Target"}
    G -->|"path"| H["File or directory"]
    G -->|"--stdin"| I["Piped input"]
    G -->|"--git path"| J["Git repository"]
    
    H --> K["--flags"]
    K --> L["--format json"]
    K --> M["--min-severity high"]
    K --> N["--no-context"]
    K --> O["--min-confidence 0.7"]
```

---

### 2.3 List Detection Rules

```bash
./credvigil rules
```

**What it does:** Lists all 369 detection rules grouped by provider/service.

**Expected output (partial):**
```
CredVigil Detection Rules (369 total)
═══════════════════════════════════════════════════════════════

Loaded 369 detection rules covering:
  • Cloud: AWS, GCP, Azure, DigitalOcean, Cloudflare, Vercel, Netlify
  • SCM: GitHub, GitLab, Bitbucket, Gitea
  • Databases: PostgreSQL, MySQL, MongoDB, Redis, InfluxDB...
  ...
```

**Why it matters:** Shows you exactly what the engine can detect. Each rule is a compiled regex with metadata (severity, confidence, entropy threshold). Understanding rule coverage is key to knowing what CredVigil can and cannot catch.

**How rules work internally:**

```mermaid
flowchart LR
    subgraph Rule["Example: aws-access-key-id"]
        Pattern["Regex: AKIA[0-9A-Z]'{16}'"]
        Sev["Severity: CRITICAL"]
        Conf["Base Confidence: 0.9"]
        Ent["Min Entropy: 3.0"]
        Cat["Category: cloud"]
    end

    Input["Line from file"] --> Compile["Compiled Regex"]
    Compile -->|Match| Score["Calculate:\nconfidence + entropy bonus"]
    Compile -->|No match| Skip["Next rule"]
    Score --> Finding["Finding object"]
```

Each rule has:
- **Compiled regex** — pre-compiled at startup for speed (not interpreted at scan time)
- **Severity** — CRITICAL/HIGH/MEDIUM/LOW/INFO based on the damage potential
- **Base confidence** — starting confidence score, boosted by entropy analysis
- **Entropy threshold** — minimum randomness to consider a match real
- **Category** — cloud, scm, database, messaging, etc.

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

**What it does:** Reads `testdata/fake_secrets.env`, runs all 369 regex rules + Shannon entropy analysis, then processes every finding through the zero-trust pipeline (Hash → Redact → Enrich → Fingerprint → Sanitize).

**Step-by-step — what happens when you run this command:**

```mermaid
flowchart TD
    A["./credvigil scan testdata/fake_secrets.env"] --> B["CLI parses arguments"]
    B --> C["FileScanner.ScanFile()"]
    C --> D["Read file into memory"]
    D --> E["Split into lines"]
    E --> F{"For each line"}
    F --> G["Run 369 regex rules"]
    G --> H{"Any matches?"}
    H -->|Yes| I["Calculate entropy"]
    H -->|No| F
    I --> J["Assign severity + confidence"]
    J --> K["Deduplicate overlapping matches"]
    K --> F
    F -->|All lines done| L["Pipeline: Hash → Redact → Enrich → Fingerprint → Sanitize"]
    L --> M["Format output (text or JSON)"]
    M --> N["Print to stdout"]
    N --> O{"Findings > 0?"}
    O -->|Yes| P["Exit code 1"]
    O -->|No| Q["Exit code 0"]
```

1. CLI parses `scan testdata/fake_secrets.env` — identifies target as a file
2. `FileScanner.ScanFile()` reads the file, checks it's under the size limit
3. Splits content into lines and sends to `Engine.ScanContent()`
4. Engine runs all 369 compiled regexes against each line
5. For each match, calculates Shannon entropy of the matched text
6. Assigns severity (from the rule) and confidence (base + entropy bonus)
7. Deduplicates overlapping matches on the same line
8. Zero-trust pipeline processes all findings (hash, redact, enrich, fingerprint, sanitize)
9. Formatter outputs results as text or JSON

**Actual output (first 3 findings + summary):**
```
╔═══════════════════════════════════════════════════════════════╗
║                    CredVigil Scan Report                     ║
╚═══════════════════════════════════════════════════════════════╝

[CRITICAL] AWS Access Key ID
  Rule:       aws-access-key-id
  Type:       aws-access-key-id
  File:       testdata/fake_secrets.env:6
  Match:      AKIA****MPLE
  Entropy:    3.68
  Confidence: 40%
  SHA-256:    1a5d44a2...d78ddb3
  Fingerprint:98ddf6a49d642146
  File Type:  env
  Environment:test
  Category:   cloud

[CRITICAL] AWS Secret Access Key
  Rule:       aws-secret-access-key
  Type:       aws-secret-access-key
  File:       testdata/fake_secrets.env:7
  Match:      wJal****EKEY
  Entropy:    4.66
  Confidence: 50%
  SHA-256:    78314b11...080e0598
  Fingerprint:a14a113ed62a9f72
  File Type:  env
  Environment:test
  Category:   cloud

[CRITICAL] GitHub Personal Access Token (Classic)
  Rule:       github-pat-classic
  Type:       github-token
  File:       testdata/fake_secrets.env:10
  Match:      ghp_****1234
  Entropy:    5.32
  Confidence: 55%
  SHA-256:    edc43928...4c92e588
  Fingerprint:fd61cc7abb8cfb59
  File Type:  env
  Environment:test
  Category:   scm

... (53 more findings) ...

─────────────────────────────────────────────────────────────────
  Scan completed in 15ms using 369 rules
  Total findings: 56
  By severity: CRITICAL=18, HIGH=14, MEDIUM=20, LOW=4
─────────────────────────────────────────────────────────────────
  ⚠️  56 potential secret(s) found. Review and remediate.
```

**Reading the output — field-by-field guide:**

| Field | Example | What It Means |
|-------|---------|---------------|
| `[CRITICAL]` | `[CRITICAL]` | Severity level — how dangerous this secret is if leaked |
| `Rule:` | `aws-access-key-id` | Which detection rule matched |
| `Type:` | `aws-access-key-id` | Secret type classification |
| `File:` | `testdata/fake_secrets.env:6` | File path and line number |
| `Match:` | `AKIA****MPLE` | Redacted preview (first 4 + `****` + last 4 chars) |
| `Entropy:` | `3.68` | Shannon entropy score (higher = more random = more likely real) |
| `Confidence:` | `40%` | How confident the engine is this is a real secret |
| `SHA-256:` | `1a5d44a2...d78ddb3` | Cryptographic hash of the secret (for tracking without exposing) |
| `Fingerprint:` | `98ddf6a49d642146` | Stable identifier across scans (same secret = same fingerprint) |
| `File Type:` | `env` | Detected file type |
| `Environment:` | `test` | Detected environment (test, dev, staging, prod) |
| `Category:` | `cloud` | Secret category (cloud, scm, database, etc.) |

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

When scanning a directory, CredVigil walks the file tree recursively, skipping binary/media files and common non-source directories.

```mermaid
flowchart TD
    DIR["./credvigil scan ./project/"] --> WALK["Recursive directory walker"]
    WALK --> CHECK_DIR{"Directory in<br/>exclude list?"}
    CHECK_DIR -->|"Yes (.git, node_modules)"| SKIP_DIR["⏭ Skip entire directory"]
    CHECK_DIR -->|No| CHECK_EXT{"File extension<br/>excluded?"}
    CHECK_EXT -->|"Yes (.png, .exe, .zip)"| SKIP_FILE["⏭ Skip file"]
    CHECK_EXT -->|No| CHECK_NAME{"Filename<br/>excluded?"}
    CHECK_NAME -->|"Yes (package-lock.json)"| SKIP_FILE2["⏭ Skip file"]
    CHECK_NAME -->|No| SCAN["🔍 Scan file content<br/>(parallel, 4 workers)"]
    SCAN --> RESULTS["Aggregate all findings"]
    
    style SKIP_DIR fill:#e74c3c,color:#fff
    style SKIP_FILE fill:#e74c3c,color:#fff
    style SKIP_FILE2 fill:#e74c3c,color:#fff
    style SCAN fill:#27ae60,color:#fff
```

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

> **Real-life scenario: New developer onboarding audit**
> 
> You've just cloned repo. Before writing any code, audit it for existing secrets:
> ```bash
> git clone https://github.com/your-org/legacy-app.git
> cd legacy-app
> ./credvigil scan . --no-context --min-severity high
> ```
> This immediately tells you if the repo has leaked credentials in any file.

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

This is one of CredVigil's most powerful features. You can pipe ANY text into the scanner. This follows the Unix philosophy: **programs should be filters that read stdin and write stdout**.

```mermaid
flowchart LR
    subgraph Sources["Anything that outputs text"]
        echo["echo 'secret'"] 
        cat["cat file.env"]
        git["git diff --staged"]
        curl["curl -s URL"]
        pb["pbpaste"]
        kubectl["kubectl get secret"]
    end
    
    pipe["|"]
    cv["./credvigil scan --stdin"]
    
    Sources --> pipe --> cv
    cv --> report["Scan Report"]
```

#### Real-life scenario: Developer checks code before committing

```bash
# Step 1: Stage your changes
git add -A

# Step 2: Pipe only staged diff to CredVigil
git diff --staged | ./credvigil scan --stdin --no-context

# Step 3: If exit code is 0, safe to commit
if git diff --staged | ./credvigil scan --stdin --no-context --min-severity medium 2>&1 > /dev/null; then
  git commit -m "Safe commit - no secrets"
else
  echo "BLOCKED: Secrets detected in staged changes!"
fi
```

**What happens step-by-step:**
1. `git diff --staged` outputs the unified diff of all staged changes
2. The `|` pipe sends that text to CredVigil's stdin
3. CredVigil treats each line of the diff as content to scan
4. Any added lines containing secrets are flagged
5. Exit code determines if the commit proceeds

#### Basic stdin scan
```bash
echo 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' | ./credvigil scan --stdin
```

**Actual output:**
```
[CRITICAL] AWS Secret Access Key
  Rule:       aws-secret-access-key
  Type:       aws-secret-access-key
  File:       stdin:1
  Match:      wJal****EKEY
  Entropy:    4.66
  Confidence: 50%
  SHA-256:    78314b11...080e0598
  Fingerprint:a14a113ed62a9f72
  File Type:  unknown
  Environment:unknown
  Category:   cloud

[MEDIUM] High-entropy base64 string (entropy: 4.66)
  Rule:       entropy-detection
  Type:       high-entropy-string
  File:       stdin:1
  Match:      wJal****EKEY
  Entropy:    4.66
  Confidence: 80%
  SHA-256:    78314b11...080e0598
  Fingerprint:4dc95cb124ca821a
  File Type:  unknown
  Environment:unknown
  Category:   entropy

─────────────────────────────────────────────────────────────────
  Scan completed in 1ms using 369 rules
  Total findings: 2
  By severity: CRITICAL=1, MEDIUM=1
─────────────────────────────────────────────────────────────────
  ⚠️  2 potential secret(s) found. Review and remediate.
```

**Notice:** Two findings for one secret! The regex rule catches it as `aws-secret-access-key`, and the entropy detector independently flags the high-entropy string. This is **defense in depth** — even if a regex rule is missing, entropy catches suspicious strings.

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

**JSON structure overview:**

```mermaid
classDiagram
    class JSONOutput {
        version: "0.1.0"
        scan_duration: "15ms"
        total_findings: 56
        results: ScanResult[]
    }
    class ScanResult {
        findings: Finding[]
        total_findings: int
        count_by_severity: map
        duration: string
        source: Source
    }
    class Finding {
        id: "CVF-1773527227549-1"
        secret_type: "aws-secret-access-key"
        description: "AWS Secret Access Key"
        severity: "CRITICAL"
        rule_id: "aws-secret-access-key"
        source: Source
        redacted_match: "wJal****EKEY"
        secret_hash: "78314b11..."
        fingerprint: "a14a113e..."
        entropy: 4.66
        confidence: 0.5
        file_type: "env"
        environment: "test"
        category: "cloud"
        raw_match: "" ← always empty
    }
    class Source {
        type: "file"
        location: "testdata/fake_secrets.env"
        line: 7
        end_line: 7
    }
    JSONOutput --> ScanResult
    ScanResult --> Finding
    Finding --> Source
```

**Actual JSON output (single secret piped via stdin):**

```json
{
  "version": "0.1.0",
  "scan_duration": "745µs",
  "total_findings": 2,
  "results": [
    {
      "findings": [
        {
          "id": "CVF-1773527227549-1",
          "secret_type": "aws-secret-access-key",
          "description": "AWS Secret Access Key",
          "severity": "CRITICAL",
          "rule_id": "aws-secret-access-key",
          "source": {
            "type": "stdin",
            "location": "stdin",
            "line": 1,
            "end_line": 1
          },
          "redacted_match": "wJal****EKEY",
          "secret_hash": "78314b11be2e581549ac1c4f616563fad3fdf0c3...",
          "fingerprint": "a14a113ed62a9f7212255a232c2c53cfee4b1830...",
          "entropy": 4.662814895472355,
          "confidence": 0.5,
          "detected_at": "2026-03-14T18:27:07.549414-04:00",
          "file_type": "unknown",
          "environment": "unknown",
          "category": "cloud",
          "metadata": {
            "scanner_version": "0.1.0",
            "sha256": "78314b11be2e581549ac1c4f616563fad3fdf0c3..."
          }
        }
      ]
    }
  ]
}
```

**Key observations:**
- `raw_match` is always `""` (zero-trust — raw secret is never in the output)
- `severity` is a string (`"CRITICAL"`) not an integer
- `results` is an array — one entry per file scanned
- Each result has a `findings` array — one entry per detected secret
- `source.line` gives you the exact line number in the file

#### How to navigate the JSON with jq

```mermaid
flowchart LR
    root["."] --> total[".total_findings → 56"]
    root --> results[".results[]"]
    results --> findings[".findings[]"]
    findings --> severity[".severity → 'CRITICAL'"]
    findings --> rule[".rule_id → 'aws-access-key-id'"]
    findings --> source[".source"]
    source --> loc[".location → 'file.env'"]
    source --> line[".line → 7"]
    findings --> hash[".secret_hash → '78314b...'"]
```

#### JSON + jq: count findings
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | jq '.total_findings'
```

**Actual output:** `56`

#### JSON + jq: list all rule IDs found
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | jq '[.results[].findings[].rule_id] | unique'
```

**Actual output:** `["1password-connect-token", "artifactory-api-key", "aws-access-key-id", ...]` (34 unique rules)

#### JSON + jq: show only critical findings
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | jq '[.results[].findings[] | select(.severity == "CRITICAL")]'
```

#### JSON + jq: group by severity
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | jq '[.results[].findings[]] | group_by(.severity) | map({severity: .[0].severity, count: length})'
```

**Actual output:**
```json
[
  { "severity": "CRITICAL", "count": 18 },
  { "severity": "HIGH",     "count": 14 },
  { "severity": "LOW",      "count": 4  },
  { "severity": "MEDIUM",   "count": 20 }
]
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
findings = [f for r in data.get('results', []) for f in r.get('findings', [])]
raw_leaked = [f for f in findings if f.get('raw_match', '') != '']
print(f'Total findings: {len(findings)}')
print(f'Raw secrets leaked: {len(raw_leaked)}')
print(f'Zero-trust enforced: {len(raw_leaked) == 0}')
"
```

---

### 2.8 Severity Filtering

Filter findings by minimum severity level. Severity levels (lowest to highest):

```mermaid
flowchart LR
    INFO["INFO<br/>(informational)"] --> LOW["LOW<br/>(minor risk)"] --> MEDIUM["MEDIUM<br/>(should fix)"] --> HIGH["HIGH<br/>(must fix soon)"] --> CRITICAL["CRITICAL<br/>(fix immediately!)"]
    
    style INFO fill:#95a5a6,color:#fff
    style LOW fill:#3498db,color:#fff
    style MEDIUM fill:#f39c12,color:#fff
    style HIGH fill:#e67e22,color:#fff
    style CRITICAL fill:#e74c3c,color:#fff
```

`--min-severity` sets the floor — anything below it is filtered out.

#### Show only CRITICAL findings
```bash
./credvigil scan testdata/fake_secrets.env --no-context --min-severity critical
```

> **Real-life use:** In CI/CD, you might only block on CRITICAL (AWS keys, private keys) and let MEDIUM pass with a warning.

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

```mermaid
flowchart TD
    MATCH["Regex matches a string"] --> SCORE["Calculate confidence score"]
    SCORE --> FACTORS["Factors that increase confidence:"]
    FACTORS --> F1["✅ High entropy (4.0+)"]
    FACTORS --> F2["✅ Known key prefix (AKIA, ghp_, sk_live)"]
    FACTORS --> F3["✅ Near keyword (password=, token=)"]
    FACTORS --> F4["✅ Correct length/format for type"]
    
    SCORE --> CHECK{"confidence >= min-confidence?"}
    CHECK -->|Yes| REPORT["Include in report"]
    CHECK -->|No| DROP["Filter out (likely false positive)"]
    
    style REPORT fill:#27ae60,color:#fff
    style DROP fill:#e74c3c,color:#fff
```

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

Shannon entropy measures the randomness of a string. High-entropy strings are statistically likely to be secrets because random passwords/keys have much higher entropy than normal English text or variable names.

```mermaid
flowchart LR
    subgraph "Low Entropy (< 3.0)"
        L1["'password' → 2.75"]
        L2["'admin123' → 2.91"]
        L3["'localhost' → 2.95"]
    end
    
    subgraph "Medium Entropy (3.0-4.0)"
        M1["'MyApp_Config_2024' → 3.67"]
    end
    
    subgraph "High Entropy (> 4.0) 🔴"
        H1["'wJalrXUtnFEMI/K7M...' → 4.66"]
        H2["'ghp_ABCDEF...' → 4.32"]
    end
    
    style H1 fill:#e74c3c,color:#fff
    style H2 fill:#e74c3c,color:#fff
```

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

CredVigil uses exit codes to signal results. This is critical for CI/CD integration — scripts can check `$?` to decide whether to proceed or abort.

```mermaid
flowchart TD
    SCAN["./credvigil scan ..."] --> RESULT{"Any findings?"}
    RESULT -->|No findings| EXIT0["Exit code 0<br/>✅ Clean"]
    RESULT -->|Findings found| EXIT1["Exit code 1<br/>❌ Secrets detected"]
    RESULT -->|Error occurred| EXIT1_ERR["Exit code 1<br/>⚠️ Error"]
    
    EXIT0 --> CI_PASS["CI/CD: continue pipeline"]
    EXIT1 --> CI_FAIL["CI/CD: block deployment"]
    
    style EXIT0 fill:#27ae60,color:#fff
    style EXIT1 fill:#e74c3c,color:#fff
    style EXIT1_ERR fill:#e67e22,color:#fff
    style CI_PASS fill:#27ae60,color:#fff
    style CI_FAIL fill:#e74c3c,color:#fff
```

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

### Why the Pipeline Exists

```mermaid
flowchart TD
    subgraph PROBLEM["The Problem"]
        A["Detection engine finds:\\n'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"] 
        B["If we log/store this raw secret,\\nwe just leaked it AGAIN"]
    end
    
    subgraph SOLUTION["The Zero-Trust Solution"]
        C["Pipeline transforms every finding\\nBEFORE it reaches any output"]
        D["Raw secret is DESTROYED\\nafter processing"]
    end
    
    A --> B
    B --> C
    C --> D
```

**Real-life scenario:** Your CI/CD pipeline runs CredVigil and stores scan reports in a dashboard. Without the zero-trust pipeline, those reports would contain the actual secrets — creating a new attack surface. With the pipeline, reports contain hashes, fingerprints, and redacted previews — useful for tracking but not exploitable.

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

Look for `File Type:`, `Environment:`, `Category:` fields — these are added by the Enrich stage.

---

### 3.2 Pipeline Stages Explained

The pipeline runs these 5 stages in order on every finding:

```mermaid
flowchart LR
    RAW["Raw Finding\\n(has raw_match)"] --> HASH
    
    subgraph Pipeline["Zero-Trust Pipeline (5 stages)"]
        direction LR
        HASH["1️⃣ Hash\\nSHA-256(raw_match)\\n→ secret_hash"] --> REDACT["2️⃣ Redact\\nwJal****EKEY\\n→ redacted_match"]
        REDACT --> ENRICH["3️⃣ Enrich\\nfile_type, env,\\ncategory"]
        ENRICH --> FP["4️⃣ Fingerprint\\nStable ID across\\nscans"]
        FP --> SANITIZE["5️⃣ Sanitize\\nraw_match = ''\\n⛔ DESTROYED"]
    end
    
    SANITIZE --> SAFE["Safe Finding\\n(raw_match = '')"]
```

| Stage | Input → Output | Real Example | Observable In |
|-------|---------------|-------------|---------------|
| **1. Hash** | Raw secret → SHA-256 hash | `wJalrXUt...EKEY` → `78314b11be2e5815...` | `SHA-256:` in text, `secret_hash` in JSON |
| **2. Redact** | Raw secret → Masked preview | `wJalrXUt...EKEY` → `wJal****EKEY` | `Match:` in text, `redacted_match` in JSON |
| **3. Enrich** | File path → Metadata | `testdata/fake_secrets.env` → `{env, test, cloud}` | `File Type:`, `Environment:`, `Category:` |
| **4. Fingerprint** | (rule_id + file + line + hash) → Stable ID | → `a14a113ed62a9f72` | `Fingerprint:` in text, `fingerprint` in JSON |
| **5. Sanitize** | Raw secret → Empty string | `wJalrXUt...EKEY` → `""` | `raw_match` is always `""` in JSON |

**Key design principle:** Each stage can run independently. If the hash stage fails, redaction still works. If enrichment fails, sanitization still clears the raw secret. The pipeline **never** fails open — if anything goes wrong, the raw secret is still destroyed.

#### Verify all 5 stages with a single command
```bash
echo 'STRIPE_SECRET_KEY=sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz' | \
  ./credvigil scan --stdin --no-context --format json 2>/dev/null | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
f = data['results'][0]['findings'][0]
print('Stage 1 - Hash:       ', f.get('secret_hash', 'MISSING')[:20] + '...')
print('Stage 2 - Redact:     ', f.get('redacted_match', 'MISSING'))
print('Stage 3 - Enrich:      file_type=' + f.get('file_type', '?') + ', env=' + f.get('environment', '?') + ', cat=' + f.get('category', '?'))
print('Stage 4 - Fingerprint:', f.get('fingerprint', 'MISSING')[:16])
print('Stage 5 - Sanitize:    raw_match=' + repr(f.get('raw_match', 'NOT_EMPTY')))
"
```

**Expected output:**
```
Stage 1 - Hash:        d4f1a8b3e9c2... (SHA-256 of the Stripe key)
Stage 2 - Redact:      sk_l****WXyz
Stage 3 - Enrich:      file_type=unknown, env=unknown, cat=payment
Stage 4 - Fingerprint: a3b7c9d1e5f2...
Stage 5 - Sanitize:    raw_match=''     ← EMPTY! Zero-trust enforced.
```

---

### 3.3 Zero-Trust Verification

This is the most important thing to understand about the pipeline. After sanitization, no raw secret ever leaves the system.

```mermaid
flowchart TD
    A["56 secrets detected in testdata/fake_secrets.env"]
    A --> B["Pipeline processes all 56 findings"]
    B --> C["All 56 raw_match fields = ''"]
    C --> D{"Any raw secrets leaked?"}
    D -->|"Zero!"| E["✅ Zero-trust verified"]
    D -->|"Any > 0"| F["❌ SECURITY BUG"]
```

#### Prove zero-trust works
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
findings = [f for r in data.get('results', []) for f in r.get('findings', [])]
raw_leaked = [f for f in findings if f.get('raw_match', '') != '']
print(f'Total findings: {len(findings)}')
print(f'Raw secrets leaked: {len(raw_leaked)}')
print(f'Zero-trust enforced: {len(raw_leaked) == 0}')
if raw_leaked:
    print('SECURITY BUG: raw secrets found in output!')
    sys.exit(1)
print('✅ All raw_match fields are empty. Zero-trust pipeline verified.')
"
```

**Actual output:**
```
Total findings: 56
Raw secrets leaked: 0
Zero-trust enforced: True
✅ All raw_match fields are empty. Zero-trust pipeline verified.
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

#### Real-life scenario: Tracking a rotated secret across scans

The `fingerprint` field lets you track the same secret across multiple scans — even if the file changes. But if the secret itself is rotated (changed), the `secret_hash` will differ, telling you it's a new credential.

```bash
# First scan — establish baseline
./credvigil scan testdata/fake_secrets.env --format json 2>/dev/null | \
  jq '[.results[].findings[] | select(.rule_id == "aws-access-key-id") | {hash: .secret_hash[:16], fp: .fingerprint[:16]}]'

# After rotation, the hash changes but you can track the same location via fingerprint
```

---

## 4. Component 3: Git Integration Layer

Scan the commit history of git repositories to find secrets that were ever committed — even if they were later deleted or overwritten.

### Why Git History Scanning Matters

```mermaid
gitGraph
    commit id: "Initial commit"
    commit id: "Add config"
    commit id: "Add AWS key ⚠️" type: HIGHLIGHT
    commit id: "Oops, remove key"
    commit id: "Fix tests"
    commit id: "Release v1.0"
```

Even though the AWS key was removed in a later commit, **it still exists in the git history**. Anyone with repo access can run `git log -p` to find it. CredVigil scans every commit's diff to catch these.

**Real-life scenario:** A developer accidentally commits their AWS credentials on Monday, notices on Tuesday, and deletes them. They think the problem is solved. But the credentials are still in the git history, and any attacker who clones the repo can extract them. CredVigil catches this.

### How Git Scanning Works

```mermaid
sequenceDiagram
    participant CLI as credvigil CLI
    participant Git as Git Layer
    participant Repo as Local/Remote Repo
    participant Engine as Detection Engine
    participant Pipeline as Pipeline

    CLI->>Git: scan --git .
    Git->>Repo: git log (list commits)
    Repo-->>Git: [commit1, commit2, ...]
    loop For each commit
        Git->>Repo: git diff (parent → commit)
        Repo-->>Git: Added lines in diff
        Git->>Engine: ScanContent(added lines)
        Engine-->>Git: Findings[]
    end
    Git->>Pipeline: Process all findings
    Pipeline-->>CLI: Safe output (zero-trust)
    CLI-->>CLI: Print report with commit hashes
```

---

### 4.1 Scan Local Repository History

#### Scan the CredVigil repo itself
```bash
./credvigil scan --git .
```

**What it does — step by step:**
1. Verifies `git` is available on PATH (`which git`)
2. Opens the local repository at `.` using Go's `os/exec` to call git
3. Runs `git log --format=...` to get all commits on the current branch
4. For each commit, runs `git diff <parent> <commit>` to get the unified diff
5. Parses the diff to extract only **added lines** (lines starting with `+`)
6. Runs each added line through the 369-rule detection engine
7. Adjusts line numbers to match the original file positions
8. Processes all findings through the zero-trust pipeline
9. Outputs results with commit hash, author, date, and file path

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

**Real-life scenario: Security review before merging a PR**
```bash
# Developer opened a PR from feature/payments to main
# Security reviewer scans only the feature branch:
./credvigil scan --git . --git-branch feature/payments --format json 2>/dev/null | \
  jq '.total_findings'

# If findings > 0, block the PR
```

---

### 4.3 Incremental Scanning (Since Commit)

Only scan commits after a specific hash. Essential for CI/CD to avoid re-scanning everything.

```mermaid
flowchart LR
    subgraph "Full Scan (slow)"
        A1["Commit 1"] --> A2["Commit 2"] --> A3["Commit 3"] --> A4["Commit 4"] --> A5["Commit 5"]
    end
    
    subgraph "Incremental Scan (fast)"
        B3["Commit 3\\n(--git-since)"] --> B4["Commit 4"] --> B5["Commit 5"]
    end
    
    style A1 fill:#ccc
    style A2 fill:#ccc
    style B3 fill:#ffa
```

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

**Real-life CI/CD scenario: Only scan new commits in GitHub Actions**
```yaml
# .github/workflows/secret-scan.yml
- name: Scan new commits for secrets
  run: |
    LAST_SCANNED=$(cat .credvigil-last-scan 2>/dev/null || echo "")
    if [ -n "$LAST_SCANNED" ]; then
      ./credvigil scan --git . --git-since $LAST_SCANNED --format json
    else
      ./credvigil scan --git . --git-max-commits 10 --format json
    fi
    git rev-parse HEAD > .credvigil-last-scan
```

This avoids re-scanning the entire history on every CI run — only new commits since the last scan are checked.

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

### Why Real-Time Watching Matters

```mermaid
flowchart LR
    subgraph WITHOUT["Without Watcher"]
        D1["Developer writes code"] --> D2["Forgets to scan"] --> D3["Commits secret"] --> D4["Push to GitHub"] --> D5["Secret exposed 💀"]
    end
    
    subgraph WITH["With Watcher"]
        W1["Developer writes code"] --> W2["Watcher detects save"] --> W3["Auto-scan in <1s"] --> W4["Alert: secret found!"] --> W5["Developer fixes before commit ✅"]
    end
```

**Real-life scenario:** You're coding and accidentally paste an API key into a config file. Without a watcher, you might not notice until the secret is already committed and pushed. With CredVigil's watcher, you get an alert within 500ms of saving — before you even switch to the terminal.

---

### 5.1 Understanding Debouncing

**What is debouncing?**

When you save a file, the OS may emit multiple events rapidly:
1. `WRITE` event (content changed)
2. `CHMOD` event (permissions updated)
3. `WRITE` event (editor writes temp then renames)

Without debouncing, the scanner would run 3 times for 1 save. Debouncing collapses these into a single scan after a configurable interval (default: 500ms).

**How CredVigil implements it:**

```mermaid
sequenceDiagram
    participant Editor as VS Code
    participant OS as macOS/Linux
    participant FSN as fsnotify
    participant DB as Debouncer
    participant Handler as Scan Handler

    Editor->>OS: Save file (Cmd+S)
    OS->>FSN: WRITE event
    FSN->>DB: Event for "config.env"
    Note over DB: First time seeing this file<br/>Record timestamp, EMIT
    DB->>Handler: ✅ Scan "config.env"
    
    OS->>FSN: CHMOD event (50ms later)
    FSN->>DB: Event for "config.env"
    Note over DB: Seen 50ms ago (<500ms)<br/>DROP event
    DB--xHandler: ❌ Dropped (debounced)
    
    OS->>FSN: WRITE event (80ms later)
    FSN->>DB: Event for "config.env"
    Note over DB: Seen 80ms ago (<500ms)<br/>DROP event  
    DB--xHandler: ❌ Dropped (debounced)
    
    Note over DB: 500ms passes...
    
    Editor->>OS: Save again
    OS->>FSN: WRITE event
    FSN->>DB: Event for "config.env"
    Note over DB: Last seen >500ms ago<br/>Record timestamp, EMIT
    DB->>Handler: ✅ Scan "config.env"
```

**Result:** 4 OS events → 2 handler calls. The scanner runs efficiently instead of wasting CPU.

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

> **Real-life scenario: IDE auto-save storm**
> 
> You're using VS Code with auto-save enabled (every 1 second). You're editing a `.env` file and typing an API key character by character. Without debouncing, the watcher would trigger 20+ scans in 20 seconds. With 500ms debouncing, it triggers maybe 3-4 scans total, saving CPU and keeping your machine responsive.

---

### 5.4 Watcher Configuration Options

These are the configuration knobs available in `watcher.Config`:

```mermaid
flowchart TD
    CONFIG["watcher.Config"] --> WHAT["WHAT to Watch"]
    CONFIG --> HOW["HOW to Watch"]
    CONFIG --> FILTER["WHAT to Ignore"]
    
    WHAT --> P["Paths: []string<br/>(required)"]
    WHAT --> R["Recursive: bool<br/>default: true"]
    
    HOW --> DI["DebounceInterval: Duration<br/>default: 500ms"]
    
    FILTER --> ED["ExcludeDirs<br/>.git, node_modules, vendor"]
    FILTER --> EE["ExcludeExtensions<br/>.exe, .png, .jpg, .zip"]
    FILTER --> EF["ExcludeFiles<br/>package-lock.json, yarn.lock"]
    FILTER --> IE["IncludeExtensions<br/>(empty = watch all)"]
    
    style CONFIG fill:#4a90d9,color:#fff
    style WHAT fill:#27ae60,color:#fff
    style HOW fill:#e67e22,color:#fff
    style FILTER fill:#e74c3c,color:#fff
```

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

**How filtering works — step by step:**

When an event arrives, the watcher checks filters in this order:

```mermaid
flowchart TD
    EVENT["📁 File event received"] --> CHECK_DIR{"Is file in<br/>ExcludeDirs?"}
    CHECK_DIR -->|Yes| DROP1["❌ DROP<br/>(e.g., .git/objects/...)"]
    CHECK_DIR -->|No| CHECK_EXT{"Is extension in<br/>ExcludeExtensions?"}
    CHECK_EXT -->|Yes| DROP2["❌ DROP<br/>(e.g., image.png)"]
    CHECK_EXT -->|No| CHECK_FILE{"Is filename in<br/>ExcludeFiles?"}
    CHECK_FILE -->|Yes| DROP3["❌ DROP<br/>(e.g., package-lock.json)"]
    CHECK_FILE -->|No| CHECK_INCLUDE{"IncludeExtensions<br/>set?"}
    CHECK_INCLUDE -->|Yes| CHECK_MATCH{"Does extension<br/>match?"}
    CHECK_MATCH -->|No| DROP4["❌ DROP"]
    CHECK_MATCH -->|Yes| DEBOUNCE{"Debounce<br/>check"}
    CHECK_INCLUDE -->|No (empty)| DEBOUNCE
    DEBOUNCE -->|"Seen < 500ms ago"| DROP5["❌ DROP (debounced)"]
    DEBOUNCE -->|"First time or > 500ms"| EMIT["✅ EMIT to handler"]
    
    style EVENT fill:#3498db,color:#fff
    style EMIT fill:#27ae60,color:#fff
    style DROP1 fill:#e74c3c,color:#fff
    style DROP2 fill:#e74c3c,color:#fff
    style DROP3 fill:#e74c3c,color:#fff
    style DROP4 fill:#e74c3c,color:#fff
    style DROP5 fill:#e74c3c,color:#fff
```

---

### 5.5 Event Types Explained

The watcher emits 4 event types, each triggered by specific OS-level file operations:

| EventType | Constant | Meaning | When It Fires |
|-----------|----------|---------|---------------|
| `CREATED` | `EventCreated` | New file/directory appeared | `touch`, `cp`, `mv` (to new name), IDE create |
| `MODIFIED` | `EventModified` | File content changed | `echo >> file`, save in editor, `sed -i` |
| `DELETED` | `EventDeleted` | File/directory removed | `rm`, `mv` (from old name) |
| `RENAMED` | `EventRenamed` | File/directory renamed | `mv old new` |

```mermaid
flowchart LR
    subgraph "Linux/macOS Terminal Commands → Event Types"
        T1["touch newfile.env"] -->|CREATED| W["Watcher"]
        T2["echo 'key=val' >> file"] -->|MODIFIED| W
        T3["rm secret.env"] -->|DELETED| W
        T4["mv old.env new.env"] -->|"RENAMED<br/>(old → new)"| W
        T5["cp source.env dest.env"] -->|"CREATED<br/>(dest appears)"| W
        T6["vim file.env → :wq"] -->|"MODIFIED<br/>(or CREATED+DELETED<br/>if editor uses temp file)"| W
    end
```

> **Note:** Some editors (like Vim) don't modify files in-place — they write a temporary file, delete the original, and rename the temp file. This produces `CREATED + DELETED + RENAMED` events instead of a single `MODIFIED`. CredVigil's debouncer handles this gracefully by collapsing the event storm.

#### Test event types
```bash
go test ./pkg/watcher -v -run "TestEvent"
```

---

### 5.6 Stats & Monitoring

The watcher tracks runtime statistics that help you monitor its health and efficiency:

```mermaid
flowchart LR
    RAW["Raw Events<br/>(from fsnotify)"] --> RECEIVED["EventsReceived<br/>counter++"]
    RECEIVED --> FILTER{"Filtering<br/>+ Debounce"}
    FILTER -->|Passed| EMITTED["EventsEmitted<br/>counter++"]
    FILTER -->|Dropped| DROPPED["EventsDropped<br/>counter++"]
    
    EMITTED --> HANDLER["→ Scan Handler"]
    
    subgraph "Invariant"
        INV["EventsReceived = EventsEmitted + EventsDropped"]
    end
    
    style RAW fill:#3498db,color:#fff
    style EMITTED fill:#27ae60,color:#fff
    style DROPPED fill:#e74c3c,color:#fff
```

| Stat | Meaning |
|------|---------|
| `EventsReceived` | Total raw events from fsnotify |
| `EventsEmitted` | Events that passed debouncing and filtering |
| `EventsDropped` | Events suppressed by debouncing or filtering |
| `DirsWatched` | Number of directories currently being monitored |
| `StartedAt` | When the watcher was started |

**Key metrics to observe:**
- `EventsReceived - EventsEmitted = EventsDropped` (they should add up — this is the invariant)
- `EventsDropped / EventsReceived` = debounce efficiency (higher = more efficient filtering)

**Example:** If you see `Received: 150, Emitted: 30, Dropped: 120`, that's 80% efficiency — the watcher saved 120 unnecessary scans.

#### Test stats with the test suite
```bash
go test ./pkg/watcher -v -run "TestStats"
```

---

## 6. Unit Testing Commands

Go's testing framework is central to CredVigil's development. Understanding how to run, filter, and analyze tests is essential for validating that every component works correctly.

```mermaid
flowchart TD
    subgraph "Go Test Pyramid"
        UNIT["Unit Tests<br/>go test ./pkg/..."]
        INTEGRATION["Integration Tests<br/>go test ./pkg/git (uses real git)"]
        CLI["CLI Tests<br/>bash run_all_tests.sh"]
        RACE["Race Detection<br/>go test -race ./..."]
        COVERAGE["Coverage Analysis<br/>go test -cover ./..."]
    end
    
    UNIT --> INTEGRATION
    INTEGRATION --> CLI
    UNIT --> RACE
    UNIT --> COVERAGE
```

---

### 6.1 Run All Tests

```bash
go test ./...
```

**What it does:** Recursively discovers and runs every `_test.go` file in every Go package.

**Step-by-step:**
1. `go test` — invokes Go's test runner
2. `./...` — `./` means current directory, `...` means "and all subdirectories recursively"
3. Each package compiles separately, runs its test functions, reports PASS/FAIL
4. Packages with no test files show `[no test files]`

**Actual output:**
```
?       github.com/credvigil/credvigil/cmd/credvigil         [no test files]
?       github.com/credvigil/credvigil/internal/config       [no test files]
ok      github.com/credvigil/credvigil/pkg/detector     0.707s
ok      github.com/credvigil/credvigil/pkg/entropy      0.277s
ok      github.com/credvigil/credvigil/pkg/git          5.831s
?       github.com/credvigil/credvigil/pkg/models       [no test files]
ok      github.com/credvigil/credvigil/pkg/pipeline     0.643s
ok      github.com/credvigil/credvigil/pkg/rules        0.777s
ok      github.com/credvigil/credvigil/pkg/watcher      1.513s
```

**Reading the output:**
- `?` = no test files (pure types or config, nothing to test)
- `ok` + time = all tests passed in that duration
- `pkg/git` takes longest (5.8s) because it creates actual git repos in temp dirs
- `pkg/detector` takes ~0.7s because it runs 369 regex rules against test content

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

```mermaid
flowchart LR
    subgraph "Package → Component Mapping"
        DET["pkg/detector"] -->|"Component 1"| ENGINE["Core Detection Engine"]
        RULES["pkg/rules"] -->|"Component 1"| ENGINE
        ENT["pkg/entropy"] -->|"Component 1"| ENGINE
        PIPE["pkg/pipeline"] -->|"Component 2"| PIPELINE["Secure Pipeline"]
        GIT["pkg/git"] -->|"Component 3"| GITCOMP["Git Integration"]
        WATCH["pkg/watcher"] -->|"Component 4"| WATCHCOMP["File Watcher"]
    end
```

---

### 6.3 Run a Specific Test Function

```bash
# Syntax: go test ./pkg/<package> -run <TestFunctionName>
```

**How `-run` works:** It takes a regex pattern, not an exact name. So `-run AWS` matches any test with "AWS" in the name.

**Example with actual output:**
```bash
go test ./pkg/detector -v -run TestScanContent_AWSKeys
```

**Actual output:**
```
=== RUN   TestScanContent_AWSKeys
    engine_test.go:27: Found: AWS Access Key ID (type=aws-access-key-id, confidence=0.40, entropy=3.68)
    engine_test.go:27: Found: AWS Secret Access Key (type=aws-secret-access-key, confidence=0.50, entropy=4.66)
    engine_test.go:27: Found: High-entropy base64 string (entropy: 4.66) (type=high-entropy-string, confidence=0.80, entropy=4.66)
--- PASS: TestScanContent_AWSKeys (0.01s)
PASS
ok      github.com/credvigil/credvigil/pkg/detector     0.167s
```

**What this tells you:**
1. The test injected fake AWS credentials into the scanner
2. The scanner found **3 things**: the Access Key ID, the Secret Key, and a high-entropy string (the secret key is also flagged by entropy analysis)
3. Confidence scores differ: the entropy detector has 0.80 confidence (high entropy = likely a secret)
4. The test passed in 10ms, total package compile+run was 167ms

**More specific test examples:**
```bash
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

```mermaid
flowchart TD
    RACE["go test -race ./..."] --> INSTRUMENT["Go compiler instruments<br/>every memory access"]
    INSTRUMENT --> RUN["Tests run with<br/>instrumented binary"]
    RUN --> CHECK{"Concurrent access<br/>without sync?"}
    CHECK -->|Yes| FAIL["❌ FAIL + detailed<br/>stack trace showing<br/>both goroutines"]
    CHECK -->|No| PASS["✅ PASS<br/>(no races detected)"]
    
    style FAIL fill:#e74c3c,color:#fff
    style PASS fill:#27ae60,color:#fff
```

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

**Actual output (watcher with race detection, all 21 tests):**
```
=== RUN   TestNewWatcher_NilHandler
--- PASS: TestNewWatcher_NilHandler (0.00s)
=== RUN   TestNewWatcher_NoPaths
--- PASS: TestNewWatcher_NoPaths (0.00s)
=== RUN   TestNewWatcher_Valid
--- PASS: TestNewWatcher_Valid (0.00s)
=== RUN   TestNewWatcher_DefaultDebounce
--- PASS: TestNewWatcher_DefaultDebounce (0.00s)
=== RUN   TestDefaultConfig
--- PASS: TestDefaultConfig (0.00s)
=== RUN   TestEventTypeString
--- PASS: TestEventTypeString (0.00s)
=== RUN   TestShouldSkip
--- PASS: TestShouldSkip (0.00s)
=== RUN   TestShouldSkip_IncludeExtensions
--- PASS: TestShouldSkip_IncludeExtensions (0.00s)
=== RUN   TestShouldSkipDir
--- PASS: TestShouldSkipDir (0.00s)
=== RUN   TestPath2Components
--- PASS: TestPath2Components (0.00s)
=== RUN   TestMapEventType
--- PASS: TestMapEventType (0.00s)
=== RUN   TestWatcher_StartStop
--- PASS: TestWatcher_StartStop (0.02s)
=== RUN   TestWatcher_DetectsCreate
--- PASS: TestWatcher_DetectsCreate (0.04s)
=== RUN   TestWatcher_DetectsModify
--- PASS: TestWatcher_DetectsModify (0.04s)
=== RUN   TestWatcher_Debounce
--- PASS: TestWatcher_Debounce (0.54s)
=== RUN   TestWatcher_ExcludesFiltered
--- PASS: TestWatcher_ExcludesFiltered (0.05s)
=== RUN   TestWatcher_Recursive
--- PASS: TestWatcher_Recursive (0.04s)
=== RUN   TestWatcher_Stats
--- PASS: TestWatcher_Stats (0.22s)
=== RUN   TestWatcher_DoubleStart
--- PASS: TestWatcher_DoubleStart (0.02s)
=== RUN   TestWatcher_WatchedDirs
--- PASS: TestWatcher_WatchedDirs (0.02s)
=== RUN   TestWatcher_ExcludedDir
--- PASS: TestWatcher_ExcludedDir (0.02s)
=== RUN   TestStats_Snapshot
--- PASS: TestStats_Snapshot (0.00s)
PASS
ok      github.com/credvigil/credvigil/pkg/watcher      2.216s
```

**What it does:** Instruments the binary to detect concurrent access to shared memory without proper synchronization. If a race is found, the test fails with a detailed stack trace showing both goroutines and the exact memory location.

> **Why this matters:** The watcher runs a background goroutine (fsnotify event loop) and accesses shared state (debounce map, stats counters). Without proper locking, concurrent reads/writes would corrupt data. The race detector proves our mutexes work correctly.

---

### 6.6 Test Coverage

```bash
# Coverage percentage for all packages
go test ./... -cover
```

**Actual output:**
```
        github.com/credvigil/credvigil/cmd/credvigil         coverage: 0.0% of statements
        github.com/credvigil/credvigil/internal/config        coverage: 0.0% of statements
ok      github.com/credvigil/credvigil/pkg/detector     0.592s  coverage: 62.8% of statements
ok      github.com/credvigil/credvigil/pkg/entropy      0.277s  coverage: 76.0% of statements
ok      github.com/credvigil/credvigil/pkg/git          6.150s  coverage: 80.3% of statements
        github.com/credvigil/credvigil/pkg/models               coverage: 0.0% of statements
ok      github.com/credvigil/credvigil/pkg/pipeline     0.688s  coverage: 86.7% of statements
ok      github.com/credvigil/credvigil/pkg/rules        0.403s  coverage: 100.0% of statements
ok      github.com/credvigil/credvigil/pkg/watcher      1.852s  coverage: 89.4% of statements
```

**Reading the coverage results:**

| Package | Coverage | Status |
|---------|----------|--------|
| `pkg/rules` | 100.0% | All rule definitions are exercised |
| `pkg/watcher` | 89.4% | Excellent — most watcher code paths tested |
| `pkg/pipeline` | 86.7% | Strong — all 5 pipeline stages tested |
| `pkg/git` | 80.3% | Good — diff parsing, filtering, repo operations |
| `pkg/entropy` | 76.0% | Good — Shannon entropy calculations |
| `pkg/detector` | 62.8% | Room for improvement — many edge cases |
| `cmd/credvigil` | 0.0% | CLI entry point — tested via `run_all_tests.sh` instead |
| `pkg/models` | 0.0% | Pure type definitions — no logic to test |

```bash
# Coverage for a specific package
go test ./pkg/detector -cover
go test ./pkg/watcher -cover
go test ./pkg/pipeline -cover
go test ./pkg/git -cover
go test ./pkg/entropy -cover
go test ./pkg/rules -cover

# Generate coverage profile
go test ./... -coverprofile=coverage.out

# View coverage in terminal (shows per-function coverage)
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

> **Pro tip:** The HTML coverage report (`go tool cover -html=coverage.out`) is incredibly useful — it opens in your browser and highlights each line in green (covered) or red (not covered). This helps you write targeted tests for uncovered code paths.

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

A comprehensive bash script that runs all CLI-level tests end-to-end, validating the binary works correctly:

```mermaid
flowchart TD
    START["bash run_all_tests.sh"] --> T1["1. Version check"]
    T1 --> T2["2. List rules (369 rules)"]
    T2 --> T3["3. Full scan fake_secrets.env"]
    T3 --> T4["4. Severity filter (CRITICAL)"]
    T4 --> T5["5. Confidence filter (70%+)"]
    T5 --> T6["6. JSON output + validation"]
    T6 --> T7["7. Stdin piping"]
    T7 --> T8["8-11. Specific secret types"]
    T8 --> T12["12. Clean input (no secrets)"]
    T12 --> T13["13. Regex-only mode"]
    T13 --> T14["14. Go unit tests"]
    T14 --> SUMMARY["Summary: X/14 passed"]
    
    style START fill:#3498db,color:#fff
    style SUMMARY fill:#27ae60,color:#fff
```

```bash
# Run the interactive test suite
bash run_all_tests.sh
```

**What it does:** Runs 14 tests covering:
1. Version check
2. List rules (369 rules)
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

> **Real-life scenario: Pre-release validation**
> 
> Before tagging a new release, run `bash run_all_tests.sh` to ensure all 14 categories still work. This catches regressions like:
> - A new rule accidentally breaks JSON output format
> - A severity enum change breaks severity filtering
> - A dependency update causes stdin piping to fail

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

CredVigil's Linux-native design shines when combined with standard Unix tools. Every command below follows the Unix philosophy: **each tool does one thing, and they connect via pipes.**

```mermaid
flowchart LR
    subgraph "Data Sources"
        GIT["git diff"]
        FIND["find . -name"]
        KUBECTL["kubectl get secret"]
        CURL["curl API"]
        CAT["cat file"]
    end
    
    subgraph "CredVigil"
        SCAN["credvigil scan --stdin"]
    end
    
    subgraph "Post-Processing"
        JQ["jq (filter JSON)"]
        PYTHON["python3 (reports)"]
        WC["wc -l (count)"]
        SORT["sort | uniq (dedupe)"]
        CSV["csv (export)"]
    end
    
    GIT --> SCAN
    FIND --> SCAN
    KUBECTL --> SCAN
    CURL --> SCAN
    CAT --> SCAN
    SCAN --> JQ
    SCAN --> PYTHON
    SCAN --> WC
    JQ --> SORT
    JQ --> CSV
```

---

### 9.1 Pre-Commit Scanning

> **Real-life scenario:** You've staged changes for a commit. Before running `git commit`, check if you accidentally added any secrets.

#### Scan git diff before committing (pre-commit hook)
```bash
git diff --staged | ./credvigil scan --stdin --no-context --min-severity medium
```

**Step-by-step:**
1. `git diff --staged` — shows only the changes you've `git add`-ed (staged for commit)
2. `|` — pipes the diff text to CredVigil
3. `--stdin` — tells CredVigil to read from stdin instead of a file
4. `--no-context` — hides surrounding code lines (cleaner output for automation)
5. `--min-severity medium` — ignores LOW/INFO findings (reduces noise)

**To make this an actual Git hook:**
```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# CredVigil pre-commit hook — block commits with secrets

RESULT=$(git diff --staged | ./credvigil scan --stdin --no-context --min-severity high --format json 2>/dev/null)
COUNT=$(echo "$RESULT" | jq -r '.total_findings // 0')

if [ "$COUNT" -gt "0" ]; then
    echo "🚫 BLOCKED: $COUNT high/critical secret(s) found in staged changes!"
    echo ""
    echo "$RESULT" | jq -r '.results[].findings[] | "  [\(.severity)] \(.secret_type) at line \(.source.line)"'
    echo ""
    echo "Fix: remove the secrets and re-stage, or use 'git commit --no-verify' to bypass."
    exit 1
fi
echo "✅ No secrets detected in staged changes."
EOF
chmod +x .git/hooks/pre-commit
```

### 9.2 Scanning Specific File Types

#### Scan a specific git commit's changes
```bash
git show HEAD --format="" | ./credvigil scan --stdin --no-context
```

#### Scan all .env files in a project
```bash
find /path/to/project -name "*.env" -exec cat {} + | ./credvigil scan --stdin --no-context
```

**Step-by-step:**
1. `find` recursively searches for all `.env` files
2. `-exec cat {} +` concatenates their contents (more efficient than `xargs`)
3. The combined content is piped to CredVigil for scanning

#### Scan all YAML/YML config files
```bash
find /path/to/project \( -name "*.yml" -o -name "*.yaml" \) -exec cat {} + | ./credvigil scan --stdin --no-context
```

### 9.3 Cloud & DevOps Scanning

#### Scan Kubernetes secrets (base64 decoded)
```bash
kubectl get secret my-secret -o jsonpath='{.data}' | base64 -d | ./credvigil scan --stdin --no-context
```

#### Scan Terraform state file
```bash
./credvigil scan terraform.tfstate --no-context --min-severity high
```

> **Why Terraform state?** Terraform stores the actual values of all resources in `terraform.tfstate`, including database passwords, API keys, and certificates. This file should NEVER be committed to git. CredVigil can audit it for secrets.

### 9.4 JSON Post-Processing with jq

#### Scan entire project, output JSON, filter with jq
```bash
./credvigil scan . --no-context --format json 2>/dev/null | jq '
  [.results[].findings[] | {
    severity: .severity,
    rule: .rule_id,
    file: .source.location,
    line: .source.line,
    confidence: (.confidence * 100 | tostring) + "%"
  }]
'
```

#### Count findings by rule (which rules fire most?)
```bash
./credvigil scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | jq '[.results[].findings[].rule_id] | group_by(.) | map({rule: .[0], count: length}) | sort_by(-.count)'
```

### 9.5 Report Generation

#### Generate a CSV report
```bash
./credvigil scan . --no-context --format json 2>/dev/null | python3 -c "
import json, sys, csv
data = json.load(sys.stdin)
writer = csv.writer(sys.stdout)
writer.writerow(['Severity', 'Rule', 'File', 'Line', 'Confidence', 'SHA-256'])
for r in data.get('results', []):
    for f in r.get('findings', []):
        writer.writerow([
            f.get('severity', ''),
            f.get('rule_id', ''),
            f.get('source', {}).get('location', ''),
            f.get('source', {}).get('line', ''),
            f'{f.get(\"confidence\", 0)*100:.0f}%',
            f.get('secret_hash', '')[:16]
        ])
" > scan_report.csv
```

```mermaid
flowchart LR
    SCAN["credvigil scan<br/>--format json"] --> PYTHON["python3<br/>(parse JSON)"]
    PYTHON --> CSV["scan_report.csv"]
    CSV --> EXCEL["Open in Excel<br/>or Google Sheets"]
    CSV --> JIRA["Import to<br/>Jira/ServiceNow"]
    
    style SCAN fill:#3498db,color:#fff
    style CSV fill:#27ae60,color:#fff
```

### 9.6 CI/CD Gate Script

#### Scan and fail CI if any critical finding
```bash
#!/bin/bash
RESULT=$(./credvigil scan . --no-context --min-severity critical --format json 2>/dev/null)
COUNT=$(echo "$RESULT" | jq '.total_findings')
if [ "$COUNT" -gt "0" ]; then
  echo "❌ FAILED: $COUNT critical secret(s) found"
  echo "$RESULT" | jq '.results[].findings[] | {rule: .rule_id, file: .source.location, line: .source.line}'
  exit 1
fi
echo "✅ PASSED: No critical secrets found"
```

> **Real-life scenario: CI/CD pipeline gate**
> 
> Add this script as a step in your GitHub Actions, GitLab CI, or Jenkins pipeline. If any CRITICAL secret is found, the build fails before deployment — preventing secrets from reaching production.

---

## 10. Quick Reference Card

> **Print this section!** Keep it beside your terminal for fast lookups.

### CLI Commands

| Command | Description | Example |
|---------|-------------|---------|
| `./credvigil version` | Show version info | Version, Go version, OS |
| `./credvigil help` | Show usage and options | All flags documented |
| `./credvigil rules` | List all 369 detection rules | Rule ID, severity, description |
| `./credvigil scan <path>` | Scan file or directory | `./credvigil scan ./src/` |
| `./credvigil scan --stdin` | Scan from piped input | `cat file \| ./credvigil scan --stdin` |
| `./credvigil scan --git <path\|url>` | Scan git repository history | `./credvigil scan --git .` |

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

## 11. CredVigil vs TruffleHog — Command Comparison

> **How do CredVigil commands relate to TruffleHog?**
> Both are secret-scanning tools. TruffleHog (by Truffle Security) is the most popular open-source alternative.
> This section maps CredVigil commands to their TruffleHog equivalents so you can see the similarities and differences.

### 11.1 Installation

| Action | CredVigil | TruffleHog |
|--------|-----------|------------|
| Build from source | `go build -o credvigil ./cmd/credvigil` | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| macOS install | Build from source | `brew install trufflehog` |
| Docker | N/A (local binary) | `docker run --rm -it trufflesecurity/trufflehog:latest` |
| Version check | `./credvigil version` | `trufflehog --version` |
| Help | `./credvigil help` | `trufflehog --help` |

### 11.2 Scanning Files & Directories

| Action | CredVigil | TruffleHog |
|--------|-----------|------------|
| Scan a file | `./credvigil scan myfile.env` | `trufflehog filesystem myfile.env` |
| Scan a directory | `./credvigil scan ./src/` | `trufflehog filesystem ./src/` |
| Scan from stdin | `cat file \| ./credvigil scan -` | `cat file \| trufflehog --stdin` |
| JSON output | `./credvigil scan . --format json` | `trufflehog filesystem . --json` |
| Text output (default) | `./credvigil scan .` | `trufflehog filesystem .` |

**Key difference:** TruffleHog uses `filesystem` subcommand; CredVigil uses `scan` for everything.

### 11.3 Git Repository Scanning

| Action | CredVigil | TruffleHog |
|--------|-----------|------------|
| Scan local repo (all commits) | `./credvigil scan --git .` | `trufflehog git file://./` |
| Scan remote repo | `./credvigil scan --git https://github.com/user/repo` | `trufflehog git https://github.com/user/repo` |
| Limit commit depth | `./credvigil scan --git . --max-depth 10` | `trufflehog git file://./ --max-depth 10` |
| Scan specific branch | `./credvigil scan --git . --branch main` | `trufflehog git file://./ --branch main` |
| Scan since commit | `./credvigil scan --git . --since-commit abc123` | `trufflehog git file://./ --since-commit abc123` |

**Key difference:** TruffleHog uses `git` subcommand with `file://` prefix for local repos; CredVigil uses `--git` flag.

### 11.4 Filtering & Severity

| Action | CredVigil | TruffleHog |
|--------|-----------|------------|
| Filter by severity | `./credvigil scan . --min-severity HIGH` | `trufflehog filesystem . --results=verified` (verification-based) |
| Filter by confidence | `./credvigil scan . --min-confidence 0.7` | N/A (TruffleHog uses verification instead) |
| Only verified secrets | N/A (CredVigil uses confidence scores) | `trufflehog filesystem . --only-verified` |
| Disable entropy detection | `./credvigil scan . --no-entropy` | `trufflehog filesystem . --no-entropy` |
| Exclude paths | `./credvigil scan . --exclude "vendor/*"` | `trufflehog filesystem . --exclude-paths /path/to/excludes.txt` |

**Key difference:** CredVigil uses severity levels (INFO→CRITICAL) and confidence scores (0.0→1.0). TruffleHog focuses on "verified" vs "unverified" — it actually calls APIs to check if secrets are live.

### 11.5 Output & JSON Processing

```bash
# CredVigil JSON output → jq
./credvigil scan . --format json 2>/dev/null | jq '.results[].findings[]'

# TruffleHog JSON output → jq (one JSON object per line, JSONL format)
trufflehog filesystem . --json 2>/dev/null | jq '.'

# CredVigil: count findings
./credvigil scan . --format json 2>/dev/null | jq '.total_findings'

# TruffleHog: count findings (JSONL, so count lines)
trufflehog filesystem . --json 2>/dev/null | wc -l
```

**Key difference:** CredVigil outputs a single JSON object with `results[].findings[]` nested structure. TruffleHog outputs one JSON object per line (JSONL/newline-delimited JSON). This matters for jq processing.

### 11.6 Watching (Live Monitoring)

| Action | CredVigil | TruffleHog |
|--------|-----------|------------|
| Watch for changes | `./credvigil watch ./src/` | N/A (not supported) |
| Watch with debounce | `./credvigil watch ./src/ --debounce 500ms` | N/A |
| Watch with custom cooldown | `./credvigil watch ./src/ --cooldown 5s` | N/A |

**Key difference:** CredVigil has built-in file watching with intelligent debouncing. TruffleHog does not have a watch mode — you'd need to combine it with `fswatch` or `inotifywait`.

### 11.7 Additional TruffleHog Sources (Not in CredVigil)

TruffleHog can scan many cloud/SaaS sources that CredVigil does not:
```bash
# GitHub org (requires token)
trufflehog github --org=mycompany --token=$GITHUB_TOKEN

# GitLab
trufflehog gitlab --group=mygroup --token=$GITLAB_TOKEN

# S3 buckets
trufflehog s3 --bucket=my-bucket

# Docker images
trufflehog docker --image=myimage:latest

# Postman workspaces
trufflehog postman --token=$POSTMAN_TOKEN --workspace=ws-id
```

CredVigil focuses on local files, directories, git repos, and real-time watching.

### 11.8 JSON Field Comparison

| Field | CredVigil | TruffleHog |
|-------|-----------|------------|
| Secret type | `.rule_id` / `.secret_type` | `.DetectorName` |
| Severity | `.severity` ("CRITICAL", "HIGH", etc.) | `.Verified` (boolean) |
| File location | `.source.location` | `.SourceMetadata.Data.Filesystem.file` |
| Line number | `.source.line` | `.SourceMetadata.Data.Filesystem.line` |
| Raw secret | `.raw_match` (always empty — zero-trust) | `.Raw` (base64 encoded) |
| Hash | `.secret_hash` | `.RawV2` (sometimes) |
| Fingerprint | `.fingerprint` | N/A |
| Confidence | `.confidence` (0.0-1.0) | N/A (uses verification) |
| Redacted | `.redacted_match` ("AKIA****MPLE") | `.Redacted` |
| Entropy | `.entropy` (float) | N/A (internal only) |

**Key differences:**
1. **Zero-trust**: CredVigil never outputs raw secrets (`.raw_match` is always empty). TruffleHog outputs raw secrets in `.Raw`.
2. **Severity vs Verification**: CredVigil rates findings by severity & confidence. TruffleHog marks secrets as verified/unverified by actually testing them against APIs.
3. **Field naming**: CredVigil uses `snake_case` JSON. TruffleHog uses `PascalCase` (Go struct names).

### 11.9 Side-by-Side Quick Reference

```bash
# ━━━━━ SCAN A FILE ━━━━━
# CredVigil                                    # TruffleHog
./credvigil scan secrets.env                    trufflehog filesystem secrets.env

# ━━━━━ SCAN A DIRECTORY ━━━━━
./credvigil scan ./project/                     trufflehog filesystem ./project/

# ━━━━━ SCAN GIT REPO ━━━━━
./credvigil scan --git .                        trufflehog git file://./

# ━━━━━ JSON OUTPUT ━━━━━
./credvigil scan . --format json                trufflehog filesystem . --json

# ━━━━━ LIST DETECTORS ━━━━━
./credvigil rules                               trufflehog --list-detectors

# ━━━━━ WATCH MODE ━━━━━
./credvigil watch ./src/                        # TruffleHog: not available

# ━━━━━ COUNT FINDINGS (jq) ━━━━━
./credvigil scan . --format json | \            trufflehog filesystem . --json | \
  jq '.total_findings'                            wc -l

# ━━━━━ CRITICAL/VERIFIED ONLY ━━━━━
./credvigil scan . --min-severity CRITICAL      trufflehog filesystem . --only-verified
```

### 11.10 Summary: When to Use Which

| Scenario | Best Tool | Why |
|----------|-----------|-----|
| Pre-commit local scan | **CredVigil** | Fast, no API calls, zero-trust |
| CI/CD pipeline | **Both** | CredVigil for speed, TruffleHog for verification |
| Real-time editor monitoring | **CredVigil** | Built-in watch + debounce |
| Scan GitHub org | **TruffleHog** | Direct GitHub API integration |
| Scan S3/Docker/Postman | **TruffleHog** | Cloud source connectors |
| Audit git history | **Both** | Both scan full commit history |
| Never expose raw secrets | **CredVigil** | Zero-trust: raw_match always empty |
| Verify if secrets are live | **TruffleHog** | Actually calls provider APIs |

---

*Last updated: March 14, 2026*
*Covers Components 1-4 of the CredVigil build order*
