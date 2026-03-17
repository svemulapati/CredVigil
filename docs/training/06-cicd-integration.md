# CredVigil Training Guide — Module 6: CI/CD Integration

> **Version**: 0.1.0  
> **Component**: CI/CD Integration (Component 11 of 15)  
> **Audience**: Everyone — no programming or CI/CD background required. Written for learners preparing for interviews.  
> **Prerequisites**: Completion of Modules 1–5. Go 1.21+ installed (for hands-on exercises only).

---

## Table of Contents

1. [What Is CI/CD Integration?](#1-what-is-cicd-integration)
2. [Why Do We Need CI/CD Integration?](#2-why-do-we-need-cicd-integration)
3. [Key Concepts Explained](#3-key-concepts-explained)
   - 3.1 [What Is CI/CD?](#31-what-is-cicd)
   - 3.2 [What Are GitHub Actions?](#32-what-are-github-actions)
   - 3.3 [What Is a Reusable Workflow?](#33-what-is-a-reusable-workflow)
   - 3.4 [What Is a Pre-Commit Hook?](#34-what-is-a-pre-commit-hook)
   - 3.5 [What Are Exit Codes?](#35-what-are-exit-codes)
   - 3.6 [What Are Pipeline Gates?](#36-what-are-pipeline-gates)
   - 3.7 [What Is Shift-Left Security?](#37-what-is-shift-left-security)
   - 3.8 [What Are Workflow Artifacts?](#38-what-are-workflow-artifacts)
   - 3.9 [What Is the Staged Area in Git?](#39-what-is-the-staged-area-in-git)
   - 3.10 [What Is Zero-Trust in CI/CD Context?](#310-what-is-zero-trust-in-cicd-context)
4. [Architecture Overview](#4-architecture-overview)
5. [Part 1: GitHub Actions — The Reusable Workflow](#5-part-1-github-actions--the-reusable-workflow)
   - 5.1 [What the Workflow File Does](#51-what-the-workflow-file-does)
   - 5.2 [Step-by-Step Walkthrough](#52-step-by-step-walkthrough)
   - 5.3 [Inputs and Configuration](#53-inputs-and-configuration)
   - 5.4 [Outputs](#54-outputs)
   - 5.5 [How to Use It in Your Repository](#55-how-to-use-it-in-your-repository)
6. [Part 2: Pre-Commit Hook — Local Development](#6-part-2-pre-commit-hook--local-development)
   - 6.1 [What the Pre-Commit Hook Does](#61-what-the-pre-commit-hook-does)
   - 6.2 [Installation Methods](#62-installation-methods)
   - 6.3 [Step-by-Step Walkthrough](#63-step-by-step-walkthrough)
   - 6.4 [Configuration Options](#64-configuration-options)
   - 6.5 [What Happens When Secrets Are Found](#65-what-happens-when-secrets-are-found)
7. [Exit Code Design Philosophy](#7-exit-code-design-philosophy)
8. [Integration with Other Components](#8-integration-with-other-components)
9. [Practical Examples](#9-practical-examples)
   - 9.1 [Example 1: First-Time Setup for a New Project](#91-example-1-first-time-setup-for-a-new-project)
   - 9.2 [Example 2: Adding to an Existing Team Project](#92-example-2-adding-to-an-existing-team-project)
   - 9.3 [Example 3: Audit Mode for Large Codebases](#93-example-3-audit-mode-for-large-codebases)
   - 9.4 [Example 4: JSON Export for Security Dashboard](#94-example-4-json-export-for-security-dashboard)
   - 9.5 [Example 5: Pre-Commit Hook in Daily Workflow](#95-example-5-pre-commit-hook-in-daily-workflow)
10. [Hands-On Exercises](#10-hands-on-exercises)
11. [Deep Dive: Code Walkthrough](#11-deep-dive-code-walkthrough)
    - 11.1 [GitHub Action YAML Structure](#111-github-action-yaml-structure)
    - 11.2 [Pre-Commit Hook Bash Script](#112-pre-commit-hook-bash-script)
12. [Security Considerations](#12-security-considerations)
13. [Troubleshooting](#13-troubleshooting)
14. [Frequently Asked Questions](#14-frequently-asked-questions)
15. [Glossary](#15-glossary)
16. [Interview Tips — CI/CD Integration](#16-interview-tips--cicd-integration)
17. [What's Next?](#17-whats-next)

---

## 1. What Is CI/CD Integration?

In Modules 1–5, we built CredVigil as a powerful command-line tool. You could scan files, directories, git history, and monitor file changes in real-time. But there was a gap: **you had to remember to run the tool manually.**

CI/CD Integration closes that gap. It makes CredVigil run **automatically**:

- **Before every commit** (pre-commit hook) — catches secrets on your machine before they reach git
- **On every push and pull request** (GitHub Actions) — catches secrets in the cloud before they reach main branch

This is the difference between having a fire extinguisher (manual tool) and having a sprinkler system (automatic protection).

### How This Component Connects to the Others

```mermaid
flowchart TB
    subgraph M1["Module 1: Detection Engine"]
        ENGINE["369 Rules +\nEntropy + BPE"]
    end
    subgraph M2["Module 2: Pipeline"]
        PIPE["Hash → Redact → Enrich\n→ Fingerprint → Sanitize"]
    end
    subgraph M3["Module 3: Git Integration"]
        GIT["Clone → Walk History\n→ Parse Diffs"]
    end
    subgraph M6["Module 6: CI/CD Integration"]
        PRECOMMIT["Pre-Commit Hook\n(local)"]
        GHACTION["GitHub Action\n(cloud)"]
    end

    PRECOMMIT -->|"scans staged files via"| ENGINE
    GHACTION -->|"scans repo via"| ENGINE
    ENGINE -->|"findings processed by"| PIPE
    GHACTION -->|"can also scan"| GIT

    style M1 fill:#f3e5f5
    style M2 fill:#e8f5e9
    style M3 fill:#e3f2fd
    style M6 fill:#fff9c4
```

> **Interview Tip**: If asked "How does CI/CD integration fit into CredVigil?", say: "CI/CD integration makes secret scanning automatic. The pre-commit hook runs the detection engine on staged files before they're committed locally. The GitHub Action runs the same engine in the cloud on every push and PR. Both use the same triple-detection approach — regex, entropy, and BPE — and the same zero-trust pipeline to ensure raw secrets never appear in logs or artifacts."

### Real-World Analogy: Airport Security

Think of your code like luggage going through an airport:

- **Pre-commit hook** = the security checkpoint **at your gate**. It catches problems before your bag gets on the plane. Quick, personal, immediate.
- **GitHub Action** = the security checkpoint **at the terminal entrance**. Even if you bypassed your gate check, this one catches it. It's the last line of defense before code reaches the main branch.
- **Exit codes** = the green light / red light at security. Green (code 0) = you're clear. Red (code 1) = stop, something was found.

```mermaid
flowchart LR
    DEV["👨‍💻 Developer\nwrites code"] --> STAGE["📋 git add\n(stage files)"]
    STAGE --> PRECOMMIT{"🔐 Pre-Commit\nHook"}
    PRECOMMIT -->|"✅ clean"| COMMIT["git commit"]
    PRECOMMIT -->|"🚫 secrets found"| BLOCK1["❌ Commit\nBlocked"]
    COMMIT --> PUSH["git push"]
    PUSH --> GHACTION{"🔐 GitHub\nAction"}
    GHACTION -->|"✅ clean"| MERGE["✅ Merge\nAllowed"]
    GHACTION -->|"🚫 secrets found"| BLOCK2["❌ Build\nFailed"]

    style PRECOMMIT fill:#fff9c4
    style GHACTION fill:#fff9c4
    style BLOCK1 fill:#ffcdd2
    style BLOCK2 fill:#ffcdd2
    style MERGE fill:#c8e6c9
```

---

## 2. Why Do We Need CI/CD Integration?

### The Problem: Human Memory Is Unreliable

Consider these real-world scenarios:

| Scenario | Without CI/CD | With CI/CD |
|----------|--------------|------------|
| Developer adds AWS key to test script | Key gets committed and pushed | Pre-commit hook blocks the commit |
| Junior dev copies `.env.example` to `.env` and fills in real values, then accidentally commits it | `.env` with real database passwords reaches GitHub | GitHub Action catches it on the PR, fails the build |
| Late-night hotfix — developer is tired, pastes a Stripe API key into config | Key reaches production branch | Pre-commit hook catches it immediately |
| Team of 15 developers, each with different habits | No consistent scanning | Every commit is scanned automatically |

### The Numbers

According to GitHub's 2024 Secret Scanning Report:
- **12.8 million secrets** were detected in public repositories in one year
- The average time to detect a leaked secret without automated scanning: **5 days**
- With automated scanning: **seconds**

### Defense in Depth

CI/CD integration adds **two additional layers** to CredVigil's defense:

```
Layer 1: Pre-Commit Hook     → Catches secrets BEFORE they enter git
Layer 2: GitHub Action        → Catches secrets BEFORE they reach main branch
Layer 3: Manual CLI scan      → On-demand scanning (already built in Module 1)
Layer 4: File System Watcher  → Real-time monitoring (built in Module 4)
Layer 5: Git History Scan     → Find secrets in past commits (built in Module 3)
```

---

## 3. Key Concepts Explained

### 3.1 What Is CI/CD?

**CI** stands for **Continuous Integration**. It means every time a developer pushes code, it's automatically built, tested, and checked. The key word is *continuous* — it happens on every push, not just when someone remembers to do it.

**CD** stands for **Continuous Delivery** (or Continuous Deployment). It means tested code is automatically prepared for (or deployed to) production.

Together, CI/CD is a system that automatically builds, tests, scans, and deploys code every time a change is made.

```mermaid
flowchart LR
    CODE["Code\nChange"] --> BUILD["Build"] --> TEST["Test"] --> SCAN["Security\nScan"] --> DEPLOY["Deploy"]
    
    style SCAN fill:#fff9c4
```

CredVigil lives in the **SCAN** step. It checks every code change for hardcoded secrets before the code can be deployed.

### 3.2 What Are GitHub Actions?

GitHub Actions is GitHub's built-in CI/CD platform. It lets you define **workflows** — automated sequences of steps that run when something happens in your repository (like a push or a pull request).

A workflow is defined in a YAML file inside `.github/workflows/` in your repository:

```
your-repo/
├── .github/
│   └── workflows/
│       └── secrets-scan.yml    ← This file defines when and how to scan
├── src/
│   └── app.js
└── README.md
```

**Key concepts:**
- **Workflow** = the whole automated process (defined in a YAML file)
- **Job** = a group of steps that run on the same machine
- **Step** = a single task (e.g., "checkout code", "build binary", "run scan")
- **Runner** = the machine (GitHub provides free Linux/macOS/Windows VMs)
- **Trigger** = what starts the workflow (`on: push`, `on: pull_request`, etc.)

```yaml
# This is a complete workflow file — it's just YAML
name: My Workflow          # Human-readable name
on: [push]                 # Trigger: run on every push

jobs:                      # What to do
  my-job:                  # Job name
    runs-on: ubuntu-latest # Which machine to use
    steps:                 # Sequence of tasks
      - name: Say hello
        run: echo "Hello, world!"
```

### 3.3 What Is a Reusable Workflow?

A **reusable workflow** is a workflow that lives in one repository but can be **called from other repositories**. Instead of copying the entire workflow YAML into every repo, you just reference it:

```yaml
# In YOUR repo's workflow — just 5 lines:
jobs:
  scan:
    uses: svemulapati/CredVigil/.github/workflows/credvigil-scan.yml@main
    with:
      scan-path: '.'
```

This is like the difference between:
- **Copy-paste**: Everyone has their own copy of the recipe (gets out of sync)
- **Shared recipe book**: Everyone references the same recipe (always up to date)

When CredVigil updates its scanning rules or workflow, every repo that uses the reusable workflow automatically gets the latest version.

### 3.4 What Is a Pre-Commit Hook?

A **git hook** is a script that git runs automatically at specific points in the git workflow. Git supports many hooks, but we use `pre-commit` — a script that runs **after you type `git commit` but before the commit is actually created**.

```
           You type:          Git runs:           If hook says OK:
          git commit  →  .git/hooks/pre-commit  →  commit created ✅
                                    │
                                    └─ If hook says FAIL:
                                       commit BLOCKED ❌
```

The hook is just a file at `.git/hooks/pre-commit`. If it exists and is executable, git will run it. If the script exits with code 0, the commit proceeds. If it exits with code 1, the commit is blocked.

**Important**: `.git/hooks/` is a local directory. It's NOT tracked by git (it's inside `.git/`). This means:
- Each developer needs to install the hook on their machine
- The hook doesn't automatically appear when you clone a repo
- That's why we provide the `scripts/pre-commit` file in the repo and a simple install command

### 3.5 What Are Exit Codes?

Every program that runs on a computer returns a number when it finishes. This number is called the **exit code** (or return code). It tells the calling program whether things went well or not.

| Exit Code | Meaning |
|-----------|---------|
| **0** | Success — everything went well |
| **1** | Failure — something specific went wrong |
| **2** | Error — the program itself had a problem |

CredVigil uses exit codes consistently across all integration points:

| Exit Code | CredVigil Meaning | CI/CD Effect |
|-----------|-------------------|-------------|
| **0** | No secrets found — clean | Build passes ✅ |
| **1** | Secrets found | Build fails (if `fail-on-secrets` is true) ❌ |
| **2** | Scanner error (e.g., can't read files) | Build fails ❌ |

This is critical because GitHub Actions and git hooks check the exit code to decide what to do. A non-zero exit code means "something went wrong" and will stop the pipeline.

```bash
# You can check any program's exit code with $?
./credvigil scan clean-file.go
echo $?   # Prints: 0

./credvigil scan file-with-secrets.env
echo $?   # Prints: 1
```

### 3.6 What Are Pipeline Gates?

A **pipeline gate** (also called a "quality gate" or "check") is a point in the CI/CD pipeline where the build can be stopped if it doesn't meet certain criteria.

CredVigil acts as a **security gate**: if secrets are detected, the gate closes and the code cannot proceed to the next stage (merge, deploy, etc.).

```mermaid
flowchart LR
    PR["Pull Request\nCreated"] --> LINT["Lint\nCheck ✅"] --> TEST["Unit\nTests ✅"] --> CRED{"CredVigil\nScan"}
    CRED -->|"✅ clean"| REVIEW["Code\nReview"]
    CRED -->|"❌ secrets"| BLOCKED["Build\nFailed"]
    REVIEW --> MERGE["Merge to\nmain"]

    style CRED fill:#fff9c4
    style BLOCKED fill:#ffcdd2
```

### 3.7 What Is Shift-Left Security?

"Shift left" means moving security checks **earlier** in the development process. Instead of finding secrets after deployment (expensive, dangerous), you find them at the earliest possible moment.

```
Traditional (shift right):
  Code → Build → Test → Deploy → [Security finds secret] → Panic! 😱

Shift left with CredVigil:
  Code → [Pre-commit catches secret] → Fix → Commit → Build → Deploy ✅
```

The pre-commit hook is the **ultimate shift-left** — it catches problems before they even enter version control.

### 3.8 What Are Workflow Artifacts?

GitHub Actions lets you **upload files** from a workflow run so you can download them later. These uploaded files are called **artifacts**.

CredVigil can upload its JSON scan results as an artifact. This is useful for:
- Keeping a record of scan results for auditing
- Feeding results into a dashboard or notification system
- Debugging false positives after a build failure

```yaml
upload-artifact: true    # Save scan results as a downloadable file
format: 'json'           # Must be JSON format to upload
```

### 3.9 What Is the Staged Area in Git?

Git has three areas where your files can live:

```
Working Directory  →  Staging Area  →  Repository
(your edits)         (git add)        (git commit)
```

1. **Working Directory**: Your actual files on disk, including unsaved edits
2. **Staging Area** (also called "index"): Files you've marked for the next commit with `git add`
3. **Repository**: Committed history (`.git/` directory)

The pre-commit hook scans **only the staging area** — the exact files that will be committed. This is important because:
- If you edit a file but don't `git add` it, the edit won't be scanned (it's not being committed)
- If you `git add` a file with a secret, the hook will catch it even if you've already started editing the file again

```bash
# Edit a file
echo "API_KEY=sk_live_abc123" >> config.env

# Stage it for commit
git add config.env

# The pre-commit hook scans the STAGED version of config.env
# Even if you edit config.env again right now, the hook sees
# the version you staged with git add
```

### 3.10 What Is Zero-Trust in CI/CD Context?

In Modules 1–2, we established that CredVigil never stores raw secrets. This principle extends to CI/CD:

- **GitHub Action logs** never contain raw secrets — only redacted previews and SHA-256 hashes
- **PR comments** from the action never include raw secrets
- **Uploaded artifacts** never contain raw secrets (the pipeline sanitizes before output)
- **Pre-commit hook output** in your terminal shows only redacted matches

This matters because:
- GitHub Action logs are visible to anyone with repo access
- PR comments are visible to all contributors
- Artifacts can be downloaded by anyone with repo access

If CredVigil printed raw secrets in the log, it would be **leaking the secrets through the scanner itself**.

---

## 4. Architecture Overview

The CI/CD integration consists of two independent entry points that both use the existing CredVigil engine:

```mermaid
flowchart TB
    subgraph LOCAL["🖥️ Developer's Machine"]
        EDIT["Edit Code"] --> ADD["git add"]
        ADD --> HOOK{"scripts/pre-commit"}
        HOOK -->|"exit 0: clean"| COMMIT["git commit ✅"]
        HOOK -->|"exit 1: secrets"| BLOCK1["❌ Blocked"]
        COMMIT --> PUSH["git push"]
    end

    subgraph CLOUD["☁️ GitHub Actions"]
        PUSH --> TRIGGER["Workflow Triggered"]
        TRIGGER --> CHECKOUT["Step 1: Checkout repo"]
        CHECKOUT --> BUILD["Step 2: Build CredVigil"]
        BUILD --> SCAN["Step 3: Run scan"]
        SCAN -->|"exit 0"| PASS["✅ Build passes"]
        SCAN -->|"exit 1"| FAIL["❌ Build fails"]
        FAIL --> COMMENT["Step 4: PR comment"]
        PASS --> ARTIFACT["Step 5: Upload artifact\n(optional)"]
    end

    style LOCAL fill:#e3f2fd
    style CLOUD fill:#f3e5f5
    style HOOK fill:#fff9c4
    style SCAN fill:#fff9c4
```

### File Layout

```
credvigil/
├── .github/
│   └── workflows/
│       ├── credvigil-scan.yml    ← Reusable workflow (THE action)
│       └── example-usage.yml     ← Example: how to call the action
├── scripts/
│   └── pre-commit                ← Git pre-commit hook
└── cmd/credvigil/main.go         ← CLI (used by both)
```

---

## 5. Part 1: GitHub Actions — The Reusable Workflow

### 5.1 What the Workflow File Does

The file `.github/workflows/credvigil-scan.yml` is a **reusable GitHub Action workflow**. When another repository calls it, it:

1. Checks out the repository's code
2. Sets up Go
3. Clones CredVigil and builds the binary
4. Runs the scan with configured options
5. Sets outputs (findings count, result status)
6. Optionally uploads JSON results as an artifact
7. Optionally posts a PR comment with the summary

### 5.2 Step-by-Step Walkthrough

Let's walk through every step of the workflow:

#### Step 1: Checkout Repository

```yaml
- name: Checkout repository
  uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

**What this does**: Downloads (checks out) the code from the repository being scanned onto the GitHub Actions runner (a temporary Linux VM). `fetch-depth: 0` means "download the full git history" — needed if you want to do git-based scanning later.

**Real-world analogy**: It's like photocopying all the documents in an office so the security inspector can review them.

#### Step 2: Set Up Go

```yaml
- name: Set up Go
  uses: actions/setup-go@v5
  with:
    go-version: ${{ inputs.go-version }}
```

**What this does**: Installs the Go programming language on the runner. CredVigil is written in Go, so we need Go to compile it.

**Why not pre-build?**: Building from source ensures you always get the latest detection rules (369 rules are compiled into the binary at build time).

#### Step 3: Build CredVigil

```yaml
- name: Build CredVigil scanner
  run: |
    git clone --depth 1 https://github.com/svemulapati/CredVigil.git /tmp/credvigil-build
    cd /tmp/credvigil-build
    go build -o /tmp/credvigil ./cmd/credvigil
    /tmp/credvigil version
```

**What this does**:
1. Clones the CredVigil repository (shallow clone — `--depth 1` — for speed)
2. Compiles the Go code into a binary at `/tmp/credvigil`
3. Runs `version` to verify the binary works

**How long does this take?**: About 15–30 seconds on a GitHub Actions runner. Go compiles fast.

#### Step 4: Run the Scan

```yaml
- name: Run CredVigil scan
  id: scan
  run: |
    SCAN_CMD="/tmp/credvigil scan"
    SCAN_CMD="$SCAN_CMD --min-severity ${{ inputs.min-severity }}"
    SCAN_CMD="$SCAN_CMD --min-confidence ${{ inputs.min-confidence }}"
    SCAN_CMD="$SCAN_CMD --format ${{ inputs.format }}"
    # ... run the command and check exit code
```

**What this does**: Builds the scan command from the configured inputs and runs it. The exit code determines the result:

| Exit Code | What Happens |
|-----------|-------------|
| 0 | Sets output `scan_result=clean`, prints ✅ |
| 1 | Sets output `scan_result=findings-detected`, optionally fails the build |
| Other | Prints error, exits with code 2 |

**Key detail**: The `set +e` before the scan command tells bash "don't exit the script if the command fails." This lets us capture the exit code and handle it ourselves instead of the entire workflow crashing.

#### Step 5: Upload Artifact (Optional)

```yaml
- name: Upload scan results artifact
  if: ${{ inputs.upload-artifact && inputs.format == 'json' && always() }}
  uses: actions/upload-artifact@v4
  with:
    name: credvigil-scan-results
    path: /tmp/credvigil-results.json
    retention-days: 30
```

**What this does**: If `upload-artifact` is true and format is JSON, uploads the scan results as a downloadable file in the GitHub Actions UI. The `always()` condition means it uploads even if the build failed (you want to see the results especially when secrets were found).

#### Step 6: PR Comment (Automatic)

```yaml
- name: Add PR comment with scan summary
  if: ${{ github.event_name == 'pull_request' && steps.scan.outputs.scan_result == 'findings-detected' }}
  uses: actions/github-script@v7
  with:
    script: |
      // Creates a comment on the PR with scan results
```

**What this does**: If this scan was triggered by a pull request AND secrets were found, it automatically adds a comment on the PR:

```
## 🔐 CredVigil Secrets Scan

⚠️ **3 potential secret(s) detected.**

Please review the scan results in the Actions tab, rotate any
exposed credentials, and remove them from the code.

> Note: CredVigil never logs raw secrets. All findings show only
> SHA-256 hashes and redacted previews.
```

This makes it immediately visible to the developer and reviewers without having to dig into the Actions logs.

### 5.3 Inputs and Configuration

The reusable workflow accepts these inputs (all optional — defaults are sensible):

| Input | Type | Default | What It Controls |
|-------|------|---------|-----------------|
| `scan-path` | string | `.` | Which directory or file to scan |
| `min-severity` | string | `low` | Minimum severity level to report |
| `min-confidence` | string | `0.3` | Minimum confidence score (0.0–1.0) |
| `format` | string | `text` | Output format: `text` or `json` |
| `fail-on-secrets` | boolean | `true` | Whether to fail the build on findings |
| `enable-entropy` | boolean | `true` | Enable Shannon entropy detection |
| `enable-bpe` | boolean | `true` | Enable BPE token efficiency detection |
| `go-version` | string | `1.21` | Go version for building the scanner |
| `upload-artifact` | boolean | `false` | Upload JSON results as artifact |

**Choosing the right settings:**

| Use Case | Recommended Settings |
|----------|---------------------|
| **New project, strict** | Default settings (fail on any finding) |
| **Existing large codebase, first adoption** | `fail-on-secrets: false`, fix gradually |
| **Only care about real secrets** | `min-confidence: 0.7`, `min-severity: high` |
| **Feeding results to a dashboard** | `format: json`, `upload-artifact: true` |
| **Maximum detection** | All defaults (entropy + BPE both enabled) |
| **Fastest scans** | `enable-entropy: false`, `enable-bpe: false` (regex only) |

### 5.4 Outputs

The workflow produces two outputs that can be used by downstream jobs:

| Output | Values | When to Use |
|--------|--------|-------------|
| `findings-count` | `0`, `1`, `5`, etc. | Trend tracking, threshold alerts |
| `scan-result` | `clean`, `findings-detected`, `error` | Conditional logic in downstream jobs |

Example — using outputs in a downstream job:

```yaml
jobs:
  scan:
    uses: svemulapati/CredVigil/.github/workflows/credvigil-scan.yml@main
    with:
      fail-on-secrets: false  # Don't fail — we'll handle it ourselves
  
  notify:
    needs: scan
    if: ${{ needs.scan.outputs.scan-result == 'findings-detected' }}
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Found ${{ needs.scan.outputs.findings-count }} secrets!"
          # Send Slack notification, create Jira ticket, etc.
```

### 5.5 How to Use It in Your Repository

**Minimum setup** — just create one file:

```bash
# In YOUR repository (not CredVigil)
mkdir -p .github/workflows
cat > .github/workflows/secrets-scan.yml << 'EOF'
name: Secrets Scan
on: [push, pull_request]

jobs:
  scan:
    uses: svemulapati/CredVigil/.github/workflows/credvigil-scan.yml@main
    with:
      scan-path: '.'
      fail-on-secrets: true
EOF

git add .github/workflows/secrets-scan.yml
git commit -m "Add CredVigil secrets scanning"
git push
```

That's it. Your repository is now protected.

---

## 6. Part 2: Pre-Commit Hook — Local Development

### 6.1 What the Pre-Commit Hook Does

The pre-commit hook (`scripts/pre-commit`) runs on **your local machine** every time you type `git commit`. It:

1. Finds the CredVigil binary (checks multiple locations)
2. Gets the list of staged files (`git diff --cached`)
3. Extracts the **staged version** of each file (from git's index, not the working tree)
4. Copies them to a temporary directory
5. Runs `credvigil scan` on that temporary directory
6. If secrets are found (exit code 1), blocks the commit
7. If clean (exit code 0), allows the commit to proceed
8. If there's an error (exit code 2+), warns but allows the commit (fail-open)

### 6.2 Installation Methods

**Method A: Copy** (simple, but requires manual updates)

```bash
cp scripts/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

**Method B: Symlink** (recommended — auto-updates when you `git pull`)

```bash
ln -sf ../../scripts/pre-commit .git/hooks/pre-commit
```

**Method C: Global hooks** (applies to ALL your git repos)

```bash
git config --global core.hooksPath /path/to/credvigil/scripts
```

**Method D: Script alias** (install with one command from the Makefile)

```bash
# Future Makefile target:
make install-hooks
```

### 6.3 Step-by-Step Walkthrough

Here's what happens when you run `git commit` with the hook installed:

```
Step 1: You type "git commit -m 'add new feature'"
        │
Step 2: Git sees .git/hooks/pre-commit exists and is executable
        │
Step 3: Git runs the pre-commit script
        │
Step 4: Script checks CREDVIGIL_SKIP — if set to "1", exit 0 (skip)
        │
Step 5: Script finds the credvigil binary (checks multiple paths)
        │
Step 6: Script runs "git diff --cached --name-only --diff-filter=ACMR"
        This lists all staged files that are Added, Copied, Modified, or Renamed
        │
Step 7: For each staged file, extract the staged version:
        "git show :path/to/file" > /tmp/scan/path/to/file
        │
Step 8: Run "credvigil scan /tmp/scan/ --min-severity low"
        │
Step 9: Check exit code:
        0 → Print "✅ No secrets detected" → commit proceeds
        1 → Print "🚫 COMMIT BLOCKED" → commit aborted
        * → Print "⚠️ Error" → commit proceeds (fail-open)
```

**Why extract staged files to a temp directory?**

This is a subtle but important detail. When you `git add` a file, git stores a snapshot of the file at that moment. If you keep editing the file after `git add`, the working copy and the staged copy are different.

The hook must scan the **staged copy** (what will actually be committed), not the working copy (which might have changes you haven't staged yet). That's why it uses `git show :file` to extract each file from the index.

### 6.4 Configuration Options

The hook is configured through environment variables:

| Variable | Default | What It Does |
|----------|---------|-------------|
| `CREDVIGIL_BIN` | auto-detect | Path to the credvigil binary |
| `CREDVIGIL_SEVERITY` | `low` | Minimum severity to block on |
| `CREDVIGIL_CONFIDENCE` | `0.3` | Minimum confidence to block on |
| `CREDVIGIL_SKIP` | `0` | Set to `1` to skip the hook |
| `CREDVIGIL_NO_ENTROPY` | `0` | Set to `1` to disable entropy |
| `CREDVIGIL_NO_BPE` | `0` | Set to `1` to disable BPE |

You can set these permanently in your shell profile:

```bash
# Add to ~/.zshrc or ~/.bashrc
export CREDVIGIL_SEVERITY=medium     # Only block on medium+ severity
export CREDVIGIL_CONFIDENCE=0.5      # Only block on 50%+ confidence
```

Or override for a single commit:

```bash
CREDVIGIL_SEVERITY=critical git commit -m "only block on critical"
```

### 6.5 What Happens When Secrets Are Found

When the hook detects secrets, you see output like this:

```
🔐 CredVigil Pre-Commit Scan
   Scanning 3 staged file(s) for secrets...

🚫 COMMIT BLOCKED — Secrets detected!

╔═══════════════════════════════════════════════════════════════╗
║                    CredVigil Scan Report                     ║
╚═══════════════════════════════════════════════════════════════╝

[CRITICAL] AWS Secret Access Key
  Rule:       aws-secret-access-key
  File:       config.env:7
  Match:      wJal****EKEY
  Entropy:    4.66
  BPE Eff:    1.08 (37 tokens)
  Confidence: 85%
  SHA-256:    78314b11...080e0598
  Category:   cloud

─────────────────────────────────────────────────────────────────
  Scan completed in 3ms using 369 rules
  Total findings: 1
  By severity: CRITICAL=1
─────────────────────────────────────────────────────────────────

─────────────────────────────────────────────────────────────────
  Action Required:
  1. Remove or rotate the detected credentials
  2. Use environment variables or a secrets manager instead
  3. Add the value to .gitignore or .credvigilignore if it's a false positive

  To skip this check once (NOT recommended):
    CREDVIGIL_SKIP=1 git commit -m "your message"

  To bypass with git flag (NOT recommended):
    git commit --no-verify -m "your message"
```

Notice:
- **No raw secret is printed** — only the redacted match (`wJal****EKEY`)
- The SHA-256 hash is shown for reference (if you need to look up the finding later)
- Clear remediation steps are provided
- Two escape hatches are offered for emergencies (both clearly marked as not recommended)

---

## 7. Exit Code Design Philosophy

CredVigil's exit codes follow a deliberate philosophy:

```
Exit 0 = Clean = Pass = "All clear"
Exit 1 = Findings = Fail = "We found something"
Exit 2 = Error = Fail = "Something went wrong with the scanner"
```

**Why this matters:**

Every tool in the Unix ecosystem uses exit codes to communicate. When tools are chained together (as in CI/CD), the exit code is the **only way** one tool tells the next tool whether things went well.

```bash
# In a CI/CD pipeline, each command must succeed for the next to run:
go build ./...           # Exit 0 → continue
go test ./...            # Exit 0 → continue
./credvigil scan .       # Exit 1 → STOP! Build fails.
deploy-to-production     # Never reaches here
```

**Why exit 2 for errors (not exit 1)?**

Because "scanner had a bug" and "secrets were found" are different situations that require different responses:
- Exit 1 (secrets found) → Developer needs to fix the code
- Exit 2 (scanner error) → DevOps team needs to fix the scanner/pipeline

The pre-commit hook uses **fail-open** on error: if the scanner itself crashes, the commit is allowed through (with a warning). This prevents a broken scanner from blocking all development.

---

## 8. Integration with Other Components

The CI/CD integration ties together all previous components:

| Component | How CI/CD Uses It |
|-----------|-------------------|
| **Module 1: Detection Engine** | Both the hook and action invoke `credvigil scan`, which runs 369 regex rules + entropy + BPE |
| **Module 2: Pipeline** | The scan output is always post-processed (hash → redact → enrich → fingerprint → sanitize) before printing |
| **Module 3: Git Integration** | The GitHub Action can also run `credvigil scan --git .` to scan commit history |
| **Module 4: File Watcher** | Not used directly in CI/CD (it's for real-time monitoring), but a developer could run the watcher alongside the hook |
| **Module 5: Event Bus** | Not used directly yet — future: publish `cicd.scan.completed` events for notification integrations |

---

## 9. Practical Examples

### 9.1 Example 1: First-Time Setup for a New Project

You just created a new project and want to protect it from day one:

```bash
# 1. Build CredVigil binary
cd /path/to/credvigil
go build -o credvigil ./cmd/credvigil

# 2. Install the pre-commit hook in your new project
cd /path/to/my-new-project
ln -sf /path/to/credvigil/scripts/pre-commit .git/hooks/pre-commit

# 3. Add the GitHub Action
mkdir -p .github/workflows
cat > .github/workflows/secrets-scan.yml << 'EOF'
name: Secrets Scan
on: [push, pull_request]
jobs:
  scan:
    uses: svemulapati/CredVigil/.github/workflows/credvigil-scan.yml@main
    with:
      scan-path: '.'
      fail-on-secrets: true
EOF

# 4. Commit and push
git add .github/workflows/secrets-scan.yml
git commit -m "Add secrets scanning"  # Pre-commit hook runs here!
git push                              # GitHub Action runs here!
```

### 9.2 Example 2: Adding to an Existing Team Project

Your team has 50,000 lines of code. You want to adopt CredVigil gradually:

```yaml
# .github/workflows/secrets-scan.yml
name: Secrets Scan
on: [push, pull_request]

jobs:
  # Phase 1: Audit mode (first 2 weeks)
  # Don't fail the build — just report what's there
  audit:
    uses: svemulapati/CredVigil/.github/workflows/credvigil-scan.yml@main
    with:
      scan-path: '.'
      fail-on-secrets: false     # Don't block builds yet
      min-severity: 'medium'     # Only report medium+ to avoid noise
      upload-artifact: true      # Save results for review
      format: 'json'
```

After reviewing the audit results and fixing existing secrets:

```yaml
  # Phase 2: Enforcement mode (after cleanup)
  enforce:
    uses: svemulapati/CredVigil/.github/workflows/credvigil-scan.yml@main
    with:
      scan-path: '.'
      fail-on-secrets: true      # Now block builds with secrets
      min-severity: 'low'
      min-confidence: '0.5'
```

### 9.3 Example 3: Audit Mode for Large Codebases

Scan everything, report to a file, don't block anyone:

```yaml
name: Weekly Security Audit
on:
  schedule:
    - cron: '0 9 * * 1'  # Every Monday at 9 AM

jobs:
  audit:
    uses: svemulapati/CredVigil/.github/workflows/credvigil-scan.yml@main
    with:
      scan-path: '.'
      format: 'json'
      upload-artifact: true
      fail-on-secrets: false
      min-severity: 'info'      # Report everything
      min-confidence: '0.1'     # Even low-confidence matches
```

### 9.4 Example 4: JSON Export for Security Dashboard

```yaml
name: Secrets Scan + Dashboard Feed
on: [push]

jobs:
  scan:
    uses: svemulapati/CredVigil/.github/workflows/credvigil-scan.yml@main
    with:
      format: 'json'
      upload-artifact: true
      fail-on-secrets: true
  
  # Download results and send to your security dashboard
  report:
    needs: scan
    if: always()
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: credvigil-scan-results
      
      - name: Send to dashboard
        run: |
          curl -X POST https://your-security-dashboard.com/api/scans \
            -H "Authorization: Bearer ${{ secrets.DASHBOARD_TOKEN }}" \
            -H "Content-Type: application/json" \
            -d @credvigil-results.json
```

### 9.5 Example 5: Pre-Commit Hook in Daily Workflow

```bash
# Morning: Start working on a new feature
git checkout -b feature/payment-integration

# Edit files...
vim src/payments/stripe.js

# Stage your changes
git add src/payments/stripe.js

# Commit — the hook runs automatically
git commit -m "Add Stripe payment integration"

# Output:
# 🔐 CredVigil Pre-Commit Scan
#    Scanning 1 staged file(s) for secrets...
#
# 🚫 COMMIT BLOCKED — Secrets detected!
#
# [CRITICAL] Stripe Secret Key
#   Rule:       stripe-secret-key
#   File:       src/payments/stripe.js:15
#   Match:      sk_l****_abc
#   Confidence: 92%

# Fix: Move the key to environment variable
vim src/payments/stripe.js
# Change: const apiKey = "sk_live_abc123..."
# To:     const apiKey = process.env.STRIPE_SECRET_KEY

# Re-stage and commit
git add src/payments/stripe.js
git commit -m "Add Stripe payment integration"

# Output:
# 🔐 CredVigil Pre-Commit Scan
#    Scanning 1 staged file(s) for secrets...
#
# ✅ No secrets detected — 1 file(s) scanned.
# 
# [main abc1234] Add Stripe payment integration
```

---

## 10. Hands-On Exercises

### Exercise 1: Install and Test the Pre-Commit Hook

```bash
# 1. Create a test project
mkdir /tmp/test-hook-project && cd /tmp/test-hook-project
git init

# 2. Build CredVigil (if not already built)
cd /path/to/credvigil
go build -o credvigil ./cmd/credvigil

# 3. Install the hook
cd /tmp/test-hook-project
cp /path/to/credvigil/scripts/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
export CREDVIGIL_BIN=/path/to/credvigil/credvigil

# 4. Create a clean file and commit
echo "hello = world" > config.txt
git add config.txt
git commit -m "clean commit"
# Expected: ✅ No secrets detected

# 5. Create a file with a secret and try to commit
echo 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' > secrets.env
git add secrets.env
git commit -m "this should be blocked"
# Expected: 🚫 COMMIT BLOCKED — Secrets detected!

# 6. Skip the hook (emergency escape hatch)
CREDVIGIL_SKIP=1 git commit -m "skip the hook"
# Expected: ⚠️ CredVigil pre-commit hook SKIPPED

# 7. Clean up
cd / && rm -rf /tmp/test-hook-project
```

### Exercise 2: Test Exit Codes

```bash
# Build CredVigil
cd /path/to/credvigil
go build -o credvigil ./cmd/credvigil

# Test exit code 0 (clean)
echo "hello world" | ./credvigil scan --stdin
echo "Exit code: $?"
# Expected: 0

# Test exit code 1 (secrets found)
echo "AKIAIOSFODNN7EXAMPLE" | ./credvigil scan --stdin
echo "Exit code: $?"
# Expected: 1
```

### Exercise 3: Test Different Severity Levels

```bash
# Create a test file with mixed-severity secrets
cat > /tmp/test-secrets.env << 'EOF'
# Low severity: generic API key pattern
API_KEY=abcdef123456789012345678901234567890

# Critical severity: AWS secret key
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF

# Scan with different severity thresholds
./credvigil scan --min-severity info /tmp/test-secrets.env
echo "Exit: $?"     # 1 (finds both)

./credvigil scan --min-severity critical /tmp/test-secrets.env
echo "Exit: $?"     # 1 (finds only critical)

rm /tmp/test-secrets.env
```

---

## 11. Deep Dive: Code Walkthrough

### 11.1 GitHub Action YAML Structure

The reusable workflow file has these main sections:

```yaml
# 1. HEADER: Name and trigger
name: CredVigil Secrets Scan
on:
  workflow_call:         # ← This makes it "reusable"
    inputs: { ... }      # ← Configuration options
    outputs: { ... }     # ← Values exposed to calling workflow

# 2. JOBS: What to run
jobs:
  scan:
    runs-on: ubuntu-latest
    outputs: { ... }     # ← Map job outputs to workflow outputs
    steps:
      - name: Checkout   # ← Get the code
      - name: Setup Go   # ← Install Go
      - name: Build      # ← Compile CredVigil
      - name: Scan       # ← Run the scan (the core step)
      - name: Artifact   # ← Upload results (optional)
      - name: Comment    # ← PR comment (on findings)
```

**Key YAML concepts for beginners:**

| Syntax | Meaning |
|--------|---------|
| `${{ inputs.scan-path }}` | Reference an input value |
| `${{ steps.scan.outputs.scan_result }}` | Reference a step's output |
| `${{ github.event_name }}` | Built-in context variable |
| `if: ${{ condition }}` | Only run this step if condition is true |
| `set +e ... set -e` | Temporarily allow commands to fail without stopping the script |
| `>> "$GITHUB_OUTPUT"` | Write to GitHub Actions' output mechanism |

### 11.2 Pre-Commit Hook Bash Script

The pre-commit hook is a bash script with these sections:

```bash
#!/usr/bin/env bash

# 1. SETUP: Colors, strict mode
set -euo pipefail        # Exit on error, undefined vars, pipe failures

# 2. SKIP CHECK: Allow emergency bypass
if [ "${CREDVIGIL_SKIP:-0}" = "1" ]; then exit 0; fi

# 3. BINARY SEARCH: Find the credvigil binary
find_credvigil() { ... }

# 4. STAGED FILES: Get list of files being committed  
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)

# 5. EXTRACT: Copy staged versions to temp directory
git show ":$file" > "$TMPDIR/$file"

# 6. SCAN: Run credvigil on the temp directory
$CREDVIGIL_BIN scan $TMPDIR

# 7. RESULT: Check exit code and print result
case $EXIT_CODE in
    0) echo "✅ clean" ;;
    1) echo "🚫 blocked" ;;
    *) echo "⚠️ error, allowing commit" ;;
esac
```

**Key bash concepts for beginners:**

| Syntax | Meaning |
|--------|---------|
| `set -euo pipefail` | Strict mode: exit on any error |
| `${VAR:-default}` | Use `$VAR` if set, otherwise use `default` |
| `trap "cleanup" EXIT` | Run cleanup function when script exits |
| `$?` | Exit code of the last command |
| `set +e` / `set -e` | Temporarily disable/enable exit-on-error |
| `git diff --cached` | Show changes in the staging area (not working tree) |
| `git show :file` | Show the staged version of a file |
| `mktemp -d` | Create a temporary directory |

---

## 12. Security Considerations

### What CI/CD Integration Does NOT Do

| ❌ Does NOT | ✅ Does |
|------------|---------|
| Store raw secrets in logs | Store only SHA-256 hashes and redacted previews |
| Send secrets to external services | Run entirely within your GitHub Actions runner or local machine |
| Require network access for scanning | Work offline (pre-commit) — only needs network for GitHub Action (to clone CredVigil) |
| Replace proper secrets management | Add a detection layer to catch accidents |

### Who Can See What

| Artifact | Who Can See | Contains Raw Secrets? |
|----------|-------------|----------------------|
| GitHub Action logs | Repo collaborators | ❌ Never — only redacted matches |
| PR comments | Repo collaborators | ❌ Never — only counts |
| Uploaded JSON | Repo collaborators | ❌ Never — pipeline sanitizes |
| Pre-commit terminal output | Only the developer | ❌ Never — only redacted matches |

### Pre-Commit Hook Security

The pre-commit hook runs **on your machine** with **your permissions**. It:
- Only reads files you've staged with `git add`
- Creates a temporary directory that is deleted when the script exits (`trap`)
- Does not send any data anywhere
- Does not store scan results anywhere

---

## 13. Troubleshooting

### Pre-Commit Hook Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| "CredVigil binary not found" | Binary not built or not in PATH | Run `go build -o credvigil ./cmd/credvigil` and set `CREDVIGIL_BIN` |
| Hook doesn't run | File not executable | `chmod +x .git/hooks/pre-commit` |
| Hook runs on wrong files | Scanning working tree, not staged | This shouldn't happen — the hook extracts staged versions. File a bug if it does |
| Hook is too slow | Scanning many large files | Set `CREDVIGIL_SEVERITY=high` to reduce output |
| "permission denied" | Script not executable | `chmod +x .git/hooks/pre-commit` |
| Hook blocks on false positive | Confidence too low, or test fixture detected | Set `CREDVIGIL_CONFIDENCE=0.7` or `CREDVIGIL_SEVERITY=medium` |

### GitHub Action Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| "Build failed" but I don't have secrets | False positive | Set `min-confidence: 0.7` or `min-severity: high` |
| Action takes too long | Building Go + scanning large repo | Normal — typically 1-3 minutes |
| "Not found" when calling reusable workflow | Wrong repo URL or branch | Verify: `svemulapati/CredVigil/.github/workflows/credvigil-scan.yml@main` |
| PR comment not appearing | Workflow doesn't have write permissions | Add `permissions: pull-requests: write` to calling workflow |
| Artifact not uploading | Format not set to JSON | Set `format: 'json'` alongside `upload-artifact: true` |

---

## 14. Frequently Asked Questions

**Q: Can I use the pre-commit hook AND the GitHub Action?**  
A: Yes, and you should! They complement each other. The hook catches secrets before they enter git (fast, personal). The action catches anything the hook missed — maybe a developer bypassed it, or used `--no-verify`. Defense in depth.

**Q: Will the pre-commit hook slow down my commits?**  
A: CredVigil scans at thousands of files per second. Typical scans complete in under 100ms. You won't notice it.

**Q: What if a developer uses `git commit --no-verify` to bypass the hook?**  
A: That's why the GitHub Action exists. It's the second layer. A developer can bypass their local hook, but they can't bypass the GitHub Action running in the cloud.

**Q: Does the GitHub Action work with private repositories?**  
A: Yes. The action checks out your private repo's code (GitHub handles authentication). It clones CredVigil from the public repo to build the scanner.

**Q: Can I use this with GitLab CI, Jenkins, or Bitbucket Pipelines?**  
A: Not directly — the reusable workflow is GitHub-specific. But the pre-commit hook works with any git hosting. And you can adapt the workflow logic to any CI system by running `credvigil scan` in a pipeline step.

**Q: What if I want to allow a specific secret (false positive)?**  
A: Use the `--min-confidence` flag to filter out low-confidence matches. Future versions will support `.credvigilignore` for explicit allow-listing.

**Q: How often is the rule set updated?**  
A: The rules are compiled into the binary. When you update CredVigil (git pull + rebuild), you get the latest rules. The GitHub Action builds from source on every run, so it always uses the latest rules.

---

## 15. Glossary

| Term | Definition |
|------|-----------|
| **CI/CD** | Continuous Integration / Continuous Delivery — automated build, test, and deploy pipelines |
| **GitHub Actions** | GitHub's built-in CI/CD platform for automating workflows |
| **Workflow** | A YAML file defining an automated process triggered by events |
| **Reusable Workflow** | A workflow in one repo that can be called from other repos |
| **Job** | A group of steps that run on the same machine within a workflow |
| **Step** | A single task within a job (e.g., run a command, use an action) |
| **Runner** | The virtual machine that executes a workflow job |
| **Trigger** | The event that starts a workflow (push, PR, schedule, manual) |
| **Pre-Commit Hook** | A script that runs before `git commit` creates the commit |
| **Staged Area** | Git's index — files marked for the next commit via `git add` |
| **Exit Code** | A number returned by a program indicating success (0) or failure (non-zero) |
| **Pipeline Gate** | A checkpoint in CI/CD that blocks progress if criteria aren't met |
| **Shift-Left** | Moving security checks earlier in the development process |
| **Artifact** | A file produced by a CI/CD workflow that can be downloaded later |
| **Fail-Open** | When an error occurs, allow the operation to proceed (don't block) |
| **Fail-Closed** | When an error occurs, block the operation (safer but can halt development) |
| **Defense in Depth** | Multiple overlapping security layers so no single failure is catastrophic |
| **YAML** | A human-readable data format used for configuration files |

---

## 16. Interview Tips — CI/CD Integration

### If asked: "How would you integrate a secrets scanner into a CI/CD pipeline?"

> "I'd implement two layers: a pre-commit hook for local development and a GitHub Action for cloud-based scanning. The pre-commit hook scans only staged files — it extracts them from git's index to a temp directory and runs the scanner on them. This catches secrets before they ever enter version control. The GitHub Action runs as a reusable workflow that other repos can call with one line of YAML. It builds the scanner from source, runs it on the repository, and posts a PR comment if secrets are found. Both use the same scanner engine and zero-trust pipeline — no raw secrets ever appear in logs or output."

### If asked: "What exit codes would you use?"

> "Exit 0 for clean, exit 1 for findings detected, exit 2 for scanner error. This follows Unix convention where 0 = success and non-zero = failure. The distinction between 1 and 2 is important because they require different responses: exit 1 means a developer needs to fix the code, exit 2 means the DevOps team needs to fix the scanner."

### If asked: "How do you handle false positives in CI/CD?"

> "Through configurable thresholds. The workflow accepts `min-confidence` (0.0–1.0) and `min-severity` (info through critical) inputs. Teams can start with `fail-on-secrets: false` (audit mode) to see what the scanner finds, then gradually tighten thresholds. There's also a `CREDVIGIL_SKIP` environment variable for the pre-commit hook in genuine emergencies."

### If asked: "What's 'shift-left security'?"

> "It means catching security issues as early as possible in the development lifecycle. CredVigil's pre-commit hook is the ultimate shift-left — it catches hardcoded secrets before they even enter version control. The GitHub Action is a second layer that catches anything that slips past. The further left you catch a problem, the cheaper and faster it is to fix."

### If asked: "How do you ensure the scanner itself doesn't leak secrets?"

> "Zero-trust output pipeline. Every finding passes through five stages: hash, redact, enrich, fingerprint, and sanitize. The sanitize stage physically clears the raw secret from memory. GitHub Action logs, PR comments, uploaded artifacts, and pre-commit hook terminal output all contain only SHA-256 hashes and redacted previews — never raw credentials. This is a structural guarantee, not a policy."

---

## 17. What's Next?

With CI/CD integration complete, CredVigil now has **six production-ready components**:

| # | Component | Status |
|---|-----------|:------:|
| 1 | Core Detection Engine | ✅ |
| 2 | Secure Hashing & Metadata Pipeline | ✅ |
| 3 | Git Integration Layer | ✅ |
| 4 | File System Watcher | ✅ |
| 5 | Event Bus | ✅ |
| 6 | CI/CD Integration | ✅ |

The next components on the roadmap:

- **Storage Layer** — Persistent storage for findings, enabling trend tracking and audit trails
- **API Server** — REST API for programmatic integration with dashboards and tools
- **Notification Engine** — Slack, email, and webhook alerts when secrets are detected
- **Web Dashboard** — Visual overview of credential risk across repositories

Each new component will have its own training module with the same depth and practical focus.

---

*End of Module 6. If you've followed along from Module 1, you now understand the complete detection → processing → scanning → monitoring → communication → automation pipeline. CredVigil catches secrets at every stage: in files, in git history, in real-time, and now — automatically in every commit and PR.*
