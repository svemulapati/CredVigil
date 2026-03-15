# CredVigil — System Design (Simplified for Interviews)

> **What is CredVigil?** A command-line tool that finds leaked secrets (passwords, API keys, tokens) in your code — before hackers do. Think of it like a **spell-checker, but for secrets**.

---

## Table of Contents

1. [System Overview — What & Why](#1-system-overview--what--why)
2. [High-Level Architecture — The Big Picture](#2-high-level-architecture--the-big-picture)
3. [Package Structure — How Code is Organized](#3-package-structure--how-code-is-organized)
4. [End-to-End Flow — What Happens When You Run a Scan](#4-end-to-end-flow--what-happens-when-you-run-a-scan)
5. [CLI Layer — The Front Door](#5-cli-layer--the-front-door)
6. [Configuration — Settings & Defaults](#6-configuration--settings--defaults)
7. [Data Model — The Core Data Structures](#7-data-model--the-core-data-structures)
8. [Rule Engine — The Pattern Database](#8-rule-engine--the-pattern-database)
9. [Detection Engine — The Brain](#9-detection-engine--the-brain)
10. [Entropy Analysis — Catching Unknown Secrets](#10-entropy-analysis--catching-unknown-secrets)
11. [Confidence Scoring — How Sure Are We?](#11-confidence-scoring--how-sure-are-we)
12. [File Scanner — Scanning Multiple Files Fast](#12-file-scanner--scanning-multiple-files-fast)
13. [Post-Processing Pipeline — Cleaning Up Results](#13-post-processing-pipeline--cleaning-up-results)
14. [Git Integration — Scanning Code History](#14-git-integration--scanning-code-history)
15. [File Watcher — Real-Time Monitoring](#15-file-watcher--real-time-monitoring)
16. [Security — Protecting the Secrets We Find](#16-security--protecting-the-secrets-we-find)
17. [Concurrency — Doing Many Things at Once](#17-concurrency--doing-many-things-at-once)
18. [Design Patterns — Proven Solution Templates](#18-design-patterns--proven-solution-templates)
19. [Error Handling — What Happens When Things Go Wrong](#19-error-handling--what-happens-when-things-go-wrong)
20. [Extensibility — Adding New Features Easily](#20-extensibility--adding-new-features-easily)
21. [Performance — Speed & Memory](#21-performance--speed--memory)
22. [Interview Quick-Reference Cards](#22-interview-quick-reference-cards)

---

## 1. System Overview — What & Why

### What Problem Does CredVigil Solve?

Developers accidentally leave secrets (passwords, API keys, tokens) in their code all the time. If this code goes to GitHub, anyone can find and steal those secrets. CredVigil scans your code and tells you exactly where these secrets are hiding.

### Real-World Analogy

> Think of CredVigil like an **airport security scanner**. Just like how airport security checks your bags for dangerous items, CredVigil checks your code for dangerous secrets. It has a list of "what to look for" (331 known patterns) and also checks for anything that "looks suspicious" (random-looking strings that might be passwords).

### Key Design Principles (Simple Version)

| Principle | What It Means | Real-World Example |
|-----------|--------------|-------------------|
| **Two Detection Methods** | Uses both known patterns AND randomness detection | Like police having both a suspect photo AND a behavior profile |
| **Never Show Raw Secrets** | Found secrets are always masked in output | Like a bank showing `****1234` instead of your full card number |
| **Works on Multiple Sources** | Can scan files, folders, git history, and watch files live | Like a security camera that works at every entrance |
| **Runs Tasks in Parallel** | Scans multiple files at the same time for speed | Like having 4 cashiers instead of 1 at a store |

### How to Talk About This in an Interview

> "I built CredVigil, a command-line tool that detects leaked secrets in source code. It has 331 built-in rules for known secret patterns like AWS keys and GitHub tokens, plus an entropy analyzer that catches unknown secrets by detecting random-looking strings. It can scan individual files, entire directories, git commit history, and even watch files in real-time. The output never shows the actual secret — it always masks it for security."

---

## 2. High-Level Architecture — The Big Picture

### The 4 Layers

Think of CredVigil like a **factory assembly line** with 4 stations:

```mermaid
graph TD
    subgraph "Layer 1: INPUT - Where data comes in"
        A["Command Line"] --> B["Read files, git history, or stdin"]
    end

    subgraph "Layer 2: DETECTION - Finding secrets"
        C["331 Regex Rules<br/>Known patterns"]
        D["Entropy Analyzer<br/>Random-looking strings"]
    end

    subgraph "Layer 3: POST-PROCESSING - Cleaning up"
        E["Hash the secret"]
        F["Mask the secret"]
        G["Add extra info"]
        H["Remove raw secret"]
    end

    subgraph "Layer 4: OUTPUT - Showing results"
        I["Text output for terminal"]
        J["JSON output for automation"]
    end

    B --> C & D
    C & D --> E --> F --> G --> H
    H --> I & J

    style C fill:#ff6b6b,stroke:#333,color:#fff
    style D fill:#748ffc,stroke:#333,color:#fff
    style H fill:#51cf66,stroke:#333
```

### Simple Explanation

1. **Input Layer**: You tell CredVigil what to scan (a file, folder, git repo, or piped text)
2. **Detection Layer**: Two engines work together — one matches known patterns (like AWS keys always start with `AKIA`), the other catches random-looking strings that might be passwords
3. **Post-Processing Layer**: Each found secret gets hashed (for tracking), masked (for display), enriched (with extra info), and then the raw secret is deleted from memory
4. **Output Layer**: Results are shown in the terminal (colorful text) or as JSON (for CI/CD tools)

### How to Talk About This in an Interview

> "The architecture has 4 clean layers: input, detection, post-processing, and output. Each layer has a single responsibility. The detection layer uses two methods — pattern matching for known secrets and entropy analysis for unknown ones. The post-processing layer ensures we never expose the raw secret in our output. This layered design makes it easy to add new features without changing existing code."

---

## 3. Package Structure — How Code is Organized

### The 8 Packages

Think of packages like **departments in a company** — each department handles one thing:

```mermaid
graph TD
    CMD["cmd/credvigil<br/>The front desk<br/>Handles user commands"]

    CFG["internal/config<br/>Settings manager<br/>Stores all config options"]

    DET["pkg/detector<br/>The detective<br/>Finds secrets in code"]

    ENT["pkg/entropy<br/>The randomness checker<br/>Measures string randomness"]

    RULES["pkg/rules<br/>The rulebook<br/>331 known patterns"]

    MODELS["pkg/models<br/>The data templates<br/>Defines what a Finding looks like"]

    PIPE["pkg/pipeline<br/>The assembly line<br/>Processes each finding"]

    GIT["pkg/git<br/>The historian<br/>Scans git commit history"]

    WATCH["pkg/watcher<br/>The security guard<br/>Watches files for changes"]

    CMD --> DET & GIT & WATCH & CFG
    DET --> RULES & ENT & MODELS
    PIPE --> MODELS
    GIT --> DET & PIPE & MODELS

    style CMD fill:#339af0,stroke:#333,color:#fff
    style DET fill:#ff6b6b,stroke:#333,color:#fff
    style PIPE fill:#51cf66,stroke:#333
```

### Key Rule: No Circular Dependencies

> **Simple Rule**: Department A can use Department B, but if A uses B, then B cannot use A. This prevents confusing loops.
>
> For example: The `detector` package uses the `rules` package, but `rules` never uses `detector`. This keeps the code clean and easy to understand.

### How to Talk About This in an Interview

> "I organized the code into 8 packages, each with a single responsibility. The detector finds secrets, the rules package stores patterns, the pipeline processes results, the git package handles history scanning, and the watcher monitors files live. There are no circular dependencies — information flows in one direction, which makes the code easy to test and maintain."

---

## 4. End-to-End Flow — What Happens When You Run a Scan

### Step-by-Step: What happens when you type `credvigil scan -d ./myproject`

```mermaid
sequenceDiagram
    participant You as You (User)
    participant CLI as Command Line
    participant Scanner as File Scanner
    participant Engine as Detection Engine
    participant Pipeline as Post-Processor
    participant Output as Output

    You->>CLI: credvigil scan -d ./myproject
    CLI->>Scanner: Scan this directory

    Scanner->>Scanner: Walk through all files
    Scanner->>Scanner: Skip binary files, images, etc.

    loop For each text file
        Scanner->>Engine: Check this file for secrets
        Engine->>Engine: Run 331 regex patterns
        Engine->>Engine: Check for random-looking strings
        Engine-->>Scanner: Found 2 secrets!
    end

    Scanner->>Pipeline: Process all findings
    Pipeline->>Pipeline: Hash each secret
    Pipeline->>Pipeline: Mask each secret
    Pipeline->>Pipeline: Delete raw secret from memory
    Pipeline-->>Output: Clean results ready

    Output->>You: Shows findings with masked secrets
```

### The Life of a Single Finding

When CredVigil finds a secret, here's what happens to it:

```mermaid
graph LR
    A["Secret Found<br/>AKIAIOSFODNN7EXAMPLE"] --> B["Hashed<br/>SHA-256: a3f2...c9d1"]
    B --> C["Masked<br/>AKIA****MPLE"]
    C --> D["Enriched<br/>Type: AWS Key<br/>File: config.go"]
    D --> E["Fingerprinted<br/>Unique ID for tracking"]
    E --> F["Sanitized<br/>Raw secret deleted!"]

    style A fill:#ff6b6b,stroke:#333,color:#fff
    style F fill:#51cf66,stroke:#333
```

### How to Talk About This in an Interview

> "When you run a scan, CredVigil walks through every file, skips binary/image files, and runs each text file through the detection engine. The engine checks against 331 known patterns and also analyzes string randomness. Each finding then goes through a 5-step pipeline: hash it (for tracking across scans), mask it (for safe display), enrich it (add file type and category info), fingerprint it (for deduplication), and finally sanitize it (delete the raw secret from memory). The output only shows masked versions like `AKIA****MPLE` — never the real secret."

---

## 5. CLI Layer — The Front Door

### Available Commands

```mermaid
graph TD
    CV["credvigil"]

    SCAN["scan<br/>Scan files or folders"]
    GIT["git-scan<br/>Scan git history"]
    STDIN["scan --stdin<br/>Scan piped text"]
    WATCH["watch<br/>Watch files live"]
    VER["version<br/>Show version"]
    HELP["help<br/>Show help"]

    CV --> SCAN & GIT & STDIN & WATCH & VER & HELP

    style CV fill:#339af0,stroke:#333,color:#fff
    style SCAN fill:#51cf66,stroke:#333
    style GIT fill:#ffd43b,stroke:#333
```

### Common Usage Examples

```bash
# Scan a single file
credvigil scan -f config.yaml

# Scan a whole directory
credvigil scan -d ./myproject

# Scan and get JSON output (for CI/CD)
credvigil scan -d ./myproject --json

# Scan git history of a local repo
credvigil git-scan --repo ./myproject

# Scan a remote GitHub repo
credvigil git-scan --remote https://github.com/user/repo

# Watch a folder for changes in real-time
credvigil watch ./myproject

# Pipe text into the scanner
cat secrets.txt | credvigil scan --stdin
```

### How to Talk About This in an Interview

> "The CLI supports 4 main commands: `scan` for files and directories, `git-scan` for repository history, `watch` for real-time monitoring, and `version`. It uses Go's standard `flag` package — no external dependencies. Output can be plain text (with colors for the terminal) or JSON (for CI/CD pipelines and automation tools). The tool returns exit code 1 when secrets are found, so CI/CD pipelines can automatically fail builds that contain leaked credentials."

---

## 6. Configuration — Settings & Defaults

### How Settings Work

Think of it like **volume controls on a stereo** — you have defaults, but you can turn knobs up or down:

```mermaid
graph TD
    subgraph "Default Settings - Works out of the box"
        D1["Min Confidence: 0.3<br/>How sure we need to be"]
        D2["Min Severity: Info<br/>Show everything"]
        D3["Workers: 4<br/>Scan 4 files at once"]
        D4["Max File Size: 10MB<br/>Skip huge files"]
        D5["Entropy: ON<br/>Check for random strings"]
    end

    subgraph "You Can Override With Flags"
        F1["--min-confidence 0.7<br/>Only show high-confidence"]
        F2["--min-severity high<br/>Only critical stuff"]
        F3["--workers 8<br/>Use 8 parallel scanners"]
        F4["--json<br/>Output as JSON"]
    end

    D1 -.->|override| F1
    D2 -.->|override| F2
    D3 -.->|override| F3

    style D1 fill:#51cf66,stroke:#333
    style F1 fill:#ffd43b,stroke:#333
```

### Important Default Values

| Setting | Default | What It Does |
|---------|---------|-------------|
| Min Confidence | 0.3 (30%) | If a finding is less than 30% likely to be real, skip it |
| Min Severity | Info | Show all severity levels |
| Workers | 4 | Scan 4 files in parallel |
| Entropy Detection | ON | Also check for random-looking strings |
| Max File Size | 10 MB | Skip files bigger than 10 MB |

### How to Talk About This in an Interview

> "The tool follows a 'convention over configuration' approach — it works well out of the box with sensible defaults, but you can customize everything via command-line flags. For example, in a CI/CD pipeline you might set `--min-confidence 0.7 --min-severity high --json` to only catch high-confidence, critical issues and output as JSON for automated processing."

---

## 7. Data Model — The Core Data Structures

### The Finding — Heart of the System

A "Finding" is what we create when we detect a secret. Think of it like a **police report** — it records everything about what was found:

```mermaid
classDiagram
    class Finding {
        ID: Unique identifier
        SecretType: What kind of secret
        RuleID: Which rule caught it
        Severity: How dangerous
        Confidence: How sure we are
        RawMatch: The actual secret
        RedactedMatch: Masked version
        SecretHash: Fingerprint of secret
        Source: Where it was found
        Line: Line number
        Context: Surrounding code
        Entropy: Randomness score
    }

    class Severity {
        Info
        Low
        Medium
        High
        Critical
    }

    Finding --> Severity : has
```

### Severity Levels — How Dangerous Is It?

| Level | What It Means | Example |
|-------|--------------|---------|
| **Critical** | Could cause immediate damage | AWS Secret Key, Database password |
| **High** | Serious security risk | GitHub token, Stripe API key |
| **Medium** | Moderate risk | Slack webhook URL, generic API key |
| **Low** | Minor risk | Test credentials, internal tokens |
| **Info** | Just informational | Possible false positive |

### Secret Types — What We Can Find (180+ Types!)

```mermaid
mindmap
    root((180+ Secret Types))
        Cloud Providers
            AWS Keys
            GCP Service Accounts
            Azure Secrets
        Code Platforms
            GitHub Tokens
            GitLab Tokens
            Bitbucket Tokens
        Messaging
            Slack Tokens
            Discord Tokens
            Twilio Keys
        Databases
            Database URLs
            MongoDB URIs
            Redis Passwords
        Private Keys
            RSA Keys
            SSH Keys
            PGP Keys
        Payments
            Stripe Keys
            PayPal Secrets
        AI Services
            OpenAI Keys
            Anthropic Keys
```

### How Secrets Are Masked (Redaction)

```
Long secrets (>12 chars):  Show first 4 + **** + last 4
   "AKIAIOSFODNN7EXAMPLE" → "AKIA****MPLE"

Medium secrets (5-12):     Show first 2 + ****
   "mypasswd" → "my****"

Short secrets (<5):        Fully hidden
   "abc" → "****"
```

> **Why?** Long secrets have enough characters to safely show both ends without giving away the whole thing. Short secrets would be too exposed, so we hide them completely.

### How to Talk About This in an Interview

> "The core data structure is the `Finding` — it's like a police report for a detected secret. It contains what was found, where, how confident we are, the severity level, and a masked version. The `Severity` enum goes from Info to Critical. We support 180+ secret types across cloud providers, code platforms, databases, payment systems, and more. Secrets are always masked in the output — we show just enough to identify which credential it is, like how banks show `****1234`."

---

## 8. Rule Engine — The Pattern Database

### What Is a Rule?

A rule is like a **wanted poster** — it describes exactly what a specific type of secret looks like:

```mermaid
graph TD
    subgraph "What a Rule Contains"
        ID["ID: aws-access-key"]
        DESC["Description: AWS Access Key ID"]
        PATTERN["Pattern: Starts with AKIA + 16 characters"]
        SEVERITY["Severity: Critical"]
        CONFIDENCE["Base Confidence: 95%"]
        KEYWORDS["Keywords: aws, amazon, iam"]
        FP["False Positive Patterns: example, test, dummy"]
    end

    style ID fill:#339af0,stroke:#333,color:#fff
    style PATTERN fill:#ff6b6b,stroke:#333,color:#fff
    style CONFIDENCE fill:#51cf66,stroke:#333
```

### Example: How the AWS Key Rule Works

```
Looking for: AKIA followed by exactly 16 uppercase letters/numbers
Example match: AKIAIOSFODNN7EXAMPLE
Confidence: 95% (very specific pattern — hard to produce by accident)
Keywords: "aws", "amazon", "iam" (if found nearby, even more confident)
```

### We Have 331 Rules!

```mermaid
graph TD
    ALL["331 Rules Total<br/>Loaded at startup"]

    ALL --> AWS["AWS: 8 rules"]
    ALL --> GCP["GCP: 5 rules"]
    ALL --> AZURE["Azure: 6 rules"]
    ALL --> GITHUB["GitHub: 6 rules"]
    ALL --> SLACK["Slack: 3 rules"]
    ALL --> DB["Database: 10+ rules"]
    ALL --> KEYS["Private Keys: 5+ rules"]
    ALL --> PAYMENT["Payment: 5+ rules"]
    ALL --> GENERIC["Generic: 50+ rules"]
    ALL --> MORE["... and 200+ more"]

    style ALL fill:#ffd43b,stroke:#333,stroke-width:2px
```

### False Positive Protection

Every rule also knows what a **fake match** looks like:

```
Words that mean "this is NOT a real secret":
  - example, sample, test, dummy, fake, placeholder
  - xxxx, yyyy, 0000, 1234, abcd
  - ${VAR} or {{VAR}} (template variables)
```

> **Think of it like this**: If a rule finds `AKIAIOSFODNN7EXAMPLE`, it notices the word "EXAMPLE" and says "hmm, this is probably just example code, not a real leaked key."

### How to Talk About This in an Interview

> "The rule engine is essentially a database of 331 known secret patterns. Each rule has a regex pattern that describes what the secret looks like, keywords that boost confidence when found nearby, and false positive patterns to avoid flagging example code as real secrets. All patterns are pre-compiled at startup, so there's zero overhead during scanning. For example, the AWS access key rule looks for strings starting with `AKIA` followed by exactly 16 characters — this pattern is so specific that it gets a 95% base confidence score."

---

## 9. Detection Engine — The Brain

### Two Ways to Find Secrets

The engine uses **two complementary methods**, like having both a photo and a behavior profile:

```mermaid
graph LR
    subgraph "Method 1: Pattern Matching"
        R1["Knows exactly what to look for"]
        R2["331 specific patterns"]
        R3["Very accurate, few false alarms"]
        R4["Cannot catch unknown formats"]
    end

    subgraph "Method 2: Entropy Analysis"
        E1["Looks for random-looking strings"]
        E2["Catches secrets with no known pattern"]
        E3["Catches custom/new API keys"]
        E4["More false alarms possible"]
    end

    subgraph "Together"
        T["Best of both worlds!<br/>Known patterns caught precisely<br/>Unknown patterns caught by randomness"]
    end

    R1 --> T
    E1 --> T

    style R1 fill:#ff6b6b,stroke:#333,color:#fff
    style E1 fill:#748ffc,stroke:#333,color:#fff
    style T fill:#51cf66,stroke:#333
```

### How Detection Works Step-by-Step

```mermaid
flowchart TD
    START["File content arrives"] --> RULES["Step 1: Run all 331 rules<br/>Check every known pattern"]
    RULES --> ENTROPY["Step 2: Run entropy analysis<br/>Look for random-looking strings"]
    ENTROPY --> DEDUP["Step 3: Remove duplicates<br/>Same secret on same line = 1 finding"]
    DEDUP --> FILTER["Step 4: Filter results<br/>Remove low-confidence findings"]
    FILTER --> DONE["Done! Return all findings"]

    style START fill:#339af0,stroke:#333,color:#fff
    style DONE fill:#51cf66,stroke:#333
```

### Smart Extraction — Getting Just the Secret

```
Rule: Look for password = "something"

Input:   password = "SuperSecret123"

Bad:     password = "SuperSecret123"    ← includes the keyword (not useful)
Good:    SuperSecret123                 ← just the secret value!
```

> The engine is smart enough to extract **just the secret value**, not the surrounding code. This makes masking and hashing more accurate.

### Removing Duplicates

If the same secret appears on the same line and is caught by the same rule, we only report it once:

```mermaid
graph TD
    F1["AWS Key at line 10 - First time"] -->|KEEP| R["Results"]
    F2["AWS Key at line 10 - Duplicate!"] -->|DROP| X["Removed"]
    F3["AWS Key at line 25 - Different line"] -->|KEEP| R

    style R fill:#51cf66,stroke:#333
    style X fill:#ff6b6b,stroke:#333,color:#fff
```

### How to Talk About This in an Interview

> "The detection engine uses a dual approach: pattern matching with 331 rules for known secrets, and entropy analysis for unknown ones. This is like security that has both a wanted poster AND a behavior profiler. Results are deduplicated — if the same secret is found on the same line by the same rule, we only report it once. The engine is also smart about extraction — when a rule matches `password = 'mySecret'`, it extracts just `mySecret`, not the whole line, which makes hashing and masking more accurate."

---

## 10. Entropy Analysis — Catching Unknown Secrets

### What Is Entropy? (Simple Version)

**Entropy measures how random a string is.** A real password or API key looks very random. Normal code and English words don't.

| String | Entropy | Why? |
|--------|---------|------|
| `aaaaaa` | Very Low | Completely predictable |
| `password` | Low | Common English word |
| `myVariable` | Low | Looks like code |
| `a7f2b9c1e4d3` | **High** | Looks random — probably a secret! |
| `sk-proj-abc123xyz` | **High** | Looks like an API key! |

### Real-World Analogy

> Think of it like **shaking a bag of Scrabble tiles**. If you pull out "AAAAAA" — that's not random, someone put those there on purpose (low entropy). If you pull out "XJQMVL" — that's very random (high entropy). Secrets tend to be random, while normal code isn't.

### How It Works

```mermaid
flowchart TD
    INPUT["Input: api_key = 'a7f2b9c1e4d3'"]
    SPLIT["Break into words"]
    FILTER["Only check words longer than 12 characters"]
    MEASURE["Measure randomness of each word"]
    DECIDE{"Is it random enough?"}
    YES["Yes! Flag as potential secret"]
    NO["No, looks like normal text"]

    INPUT --> SPLIT --> FILTER --> MEASURE --> DECIDE
    DECIDE -->|yes| YES
    DECIDE -->|no| NO

    style YES fill:#ff6b6b,stroke:#333,color:#fff
    style NO fill:#51cf66,stroke:#333
```

### Why Different Thresholds for Different Character Sets?

Not all characters are equally random:

| Character Set | Example | Max Possible Randomness |
|--------------|---------|------------------------|
| **Hex** (0-9, a-f) | `a7f2b9c1` | Lower (only 16 possible chars) |
| **Base64** (A-Z, a-z, 0-9, +, /) | `aGVsbG8=` | Higher (64 possible chars) |
| **All characters** | `p@ss!w0rd` | Highest (many possible chars) |

> A hex string with high randomness for its type is very suspicious. A Base64 string needs to be even more random to be suspicious, because Base64 naturally looks more varied.

### How to Talk About This in an Interview

> "Entropy analysis catches secrets that don't match any known pattern. It measures how random a string is — real secrets like API keys and passwords tend to be very random, while normal code and English words aren't. We use different thresholds for different character types because hex strings (16 possible characters) and Base64 strings (64 possible characters) have fundamentally different levels of natural randomness. The final score combines randomness quality (70%) with string length (30%) — longer random strings are more likely to be real secrets."

---

## 11. Confidence Scoring — How Sure Are We?

### The 5-Factor System

When CredVigil finds something, it asks 5 questions to decide how confident it is:

```mermaid
graph TD
    Q1["Question 1: How specific is the rule?<br/>AWS key pattern = 95% sure<br/>Generic password pattern = 60% sure"]

    Q2["Question 2: Is the string random?<br/>High randomness: +10% boost<br/>Low randomness: -20% penalty"]

    Q3["Question 3: Are there keywords nearby?<br/>Found 'password' near the match: +10% boost"]

    Q4["Question 4: Does it look like example code?<br/>Contains 'example' or 'sample': -25% penalty"]

    Q5["Question 5: Is it a placeholder?<br/>Contains 'test', 'xxxx', 'changeme': -40% penalty"]

    RESULT["Final Score: 0% to 100%"]

    Q1 --> Q2 --> Q3 --> Q4 --> Q5 --> RESULT

    style Q1 fill:#339af0,stroke:#333,color:#fff
    style Q4 fill:#ffd43b,stroke:#333
    style Q5 fill:#ff6b6b,stroke:#333,color:#fff
    style RESULT fill:#51cf66,stroke:#333
```

### Walk-Through: Real AWS Key vs. Example Key

**Scenario 1: Real AWS key**
```
Found: AKIAIOSFODNN7REAL42
Start: 95% (specific AWS pattern)
+ Entropy high: +10% → 105%
+ "aws" keyword nearby: +5% → 110%
- No false positive words: 0% → 110%
- Not a placeholder: 0% → 110%
= Final: 100% (capped at 100%)
→ Definitely a real secret!
```

**Scenario 2: Example AWS key**
```
Found: AKIAIOSFODNN7EXAMPLE
Start: 95% (specific AWS pattern)
+ Entropy high: +10% → 105%
+ "aws" keyword nearby: +5% → 110%
- Contains "EXAMPLE"! → -25% → 85%
- "EXAMPLE" is a placeholder! → -40% → 45%
= Final: 45%
→ Probably just example code, not a real leak
```

### Why This Matters

> Without confidence scoring, we'd report every match equally. But `AKIAIOSFODNN7EXAMPLE` in documentation is **not** a real leak — it's example code. The 5-factor system automatically detects this and gives it a low score, so you don't waste time investigating false alarms.

### How to Talk About This in an Interview

> "We use a 5-factor confidence scoring system. It starts with how specific the pattern is (AWS keys get 95% because that pattern is very unique), then adjusts for string randomness, nearby keywords like 'password' or 'token', false positive indicators like 'example' or 'sample', and placeholder content like 'changeme' or 'xxxx'. This means a real AWS key scores 95%+ while `AKIAIOSFODNN7EXAMPLE` in documentation drops to about 45% — correctly identified as probably not a real leak. Users can set a minimum confidence threshold to control their precision vs. recall tradeoff."

---

## 12. File Scanner — Scanning Multiple Files Fast

### The Worker Pool — Like Having Multiple Cashiers

Instead of scanning files one by one (slow!), CredVigil scans 4 files at the same time:

```mermaid
graph TD
    FILES["100 files to scan"]

    subgraph "4 Workers Running in Parallel"
        W1["Worker 1<br/>Scanning file A"]
        W2["Worker 2<br/>Scanning file B"]
        W3["Worker 3<br/>Scanning file C"]
        W4["Worker 4<br/>Scanning file D"]
    end

    W5["Worker 5 waiting...<br/>Starts when any worker finishes"]

    RESULTS["All results combined"]

    FILES --> W1 & W2 & W3 & W4
    W4 -.->|"finishes"| W5
    W1 & W2 & W3 & W4 --> RESULTS

    style FILES fill:#339af0,stroke:#333,color:#fff
    style RESULTS fill:#51cf66,stroke:#333
    style W5 fill:#ffd43b,stroke:#333
```

> **Analogy**: Imagine a grocery store with 100 customers (files) and 4 checkout lanes (workers). Instead of making everyone wait in one line, 4 customers are served at once. When one lane finishes, the next customer steps up. Much faster!

### Smart File Filtering — Don't Waste Time on Irrelevant Files

```mermaid
flowchart TD
    FILE["Incoming file"]

    C1{"In .git or node_modules?"}
    C2{"Is it an image or binary?<br/>.exe, .png, .zip, etc."}
    C3{"Bigger than 10 MB?"}
    C4{"Contains null bytes?<br/>Means its a binary file"}

    SCAN["Scan this file"]
    SKIP["Skip this file"]

    FILE --> C1
    C1 -->|yes| SKIP
    C1 -->|no| C2
    C2 -->|yes| SKIP
    C2 -->|no| C3
    C3 -->|yes| SKIP
    C3 -->|no| C4
    C4 -->|yes| SKIP
    C4 -->|no| SCAN

    style SCAN fill:#51cf66,stroke:#333
    style SKIP fill:#ff6b6b,stroke:#333,color:#fff
```

### How to Talk About This in an Interview

> "The file scanner uses a worker pool pattern — by default, 4 files are scanned in parallel using Go goroutines with a channel-based semaphore for concurrency control. Before scanning, files pass through a filter pipeline that skips irrelevant files: directories like `.git` and `node_modules`, binary files, images, and files over 10 MB. The binary check looks for null bytes in the first 512 bytes — text files virtually never have null bytes, so this is a fast and reliable way to detect binaries."

---

## 13. Post-Processing Pipeline — Cleaning Up Results

### The 5-Stage Assembly Line

Every finding goes through 5 stages, like a product on an assembly line:

```mermaid
graph LR
    RAW["Raw Finding<br/>Contains actual secret"] --> S1["Stage 1: HASH<br/>Create unique fingerprint"]
    S1 --> S2["Stage 2: MASK<br/>Hide most of the secret"]
    S2 --> S3["Stage 3: ENRICH<br/>Add file type and category"]
    S3 --> S4["Stage 4: FINGERPRINT<br/>Create tracking ID"]
    S4 --> S5["Stage 5: SANITIZE<br/>Delete raw secret forever"]
    S5 --> SAFE["Safe Finding<br/>No raw secret anywhere!"]

    style RAW fill:#ff6b6b,stroke:#333,color:#fff
    style SAFE fill:#51cf66,stroke:#333
    style S5 fill:#51cf66,stroke:#333,stroke-width:3px
```

### What Each Stage Does

| Stage | What It Does | Why It Matters |
|-------|-------------|---------------|
| **1. Hash** | Creates a SHA-256 fingerprint of the secret | Lets you compare secrets across scans without seeing the actual secret |
| **2. Mask** | Creates a preview like `AKIA****MPLE` | Shows enough to identify which key, but not enough to use it |
| **3. Enrich** | Adds file type (Go, Python, etc.), environment (prod, dev), and category (cloud, database) | Makes the report more useful |
| **4. Fingerprint** | Creates a unique ID combining rule + file + line | Lets you track "is this the same finding from last week?" |
| **5. Sanitize** | Deletes the raw secret from memory | **This is the security guarantee** — even if output is leaked, the secret is gone |

### Why Order Matters

```
Hash MUST come before Sanitize (it needs the raw secret to hash)
Mask MUST come before Sanitize (it needs the raw secret to mask)
Sanitize MUST be LAST (it deletes the raw secret permanently)
```

### What If a Stage Fails?

If any stage fails, the entire finding is **dropped** — it's never shown in the output:

> **Why?** It's better to miss a finding than to accidentally output a raw secret because the Sanitize step didn't run.

### How to Talk About This in an Interview

> "Findings go through a 5-stage pipeline: hash, mask, enrich, fingerprint, and sanitize. The order is important — hashing and masking need the raw secret, so they run before sanitize, which deletes it permanently. If any stage fails, the finding is dropped entirely — it's a fail-safe design where missing a finding is better than accidentally exposing a raw secret. The pipeline uses the Chain of Responsibility pattern, and each stage implements a simple 2-method interface, making it easy to add new stages."

---

## 14. Git Integration — Scanning Code History

### Why Scan Git History?

> Deleting a secret from your code today doesn't help if it was committed 6 months ago — **anyone can go back and see the old commit**. CredVigil scans every commit in your history to find secrets that were ever added.

### How Git Scanning Works

```mermaid
graph TD
    subgraph "Step 1: Get the Repo"
        LOCAL["Local repo on your computer"]
        REMOTE["Remote repo - clone it first"]
    end

    subgraph "Step 2: Walk Through History"
        LIST["List all commits"]
        SKIP["Skip merge commits"]
        DIFF["For each commit: what changed?"]
    end

    subgraph "Step 3: Check Only New Lines"
        ADDED["Lines that were ADDED"]
        REMOVED["Lines that were REMOVED - ignore these"]
    end

    subgraph "Step 4: Detect Secrets"
        SCAN["Run detection engine on added lines"]
        PIPELINE["Run through pipeline"]
        RESULTS["Collect all findings"]
    end

    LOCAL --> LIST
    REMOTE -->|"clone to temp folder"| LIST
    LIST --> SKIP --> DIFF
    DIFF --> ADDED & REMOVED
    ADDED --> SCAN --> PIPELINE --> RESULTS

    style REMOVED fill:#868e96,stroke:#333,color:#fff
    style ADDED fill:#51cf66,stroke:#333
    style RESULTS fill:#ffd43b,stroke:#333
```

### Why Only Scan Added Lines?

> We only care about what was **introduced** (added), not what was removed. If a secret was removed, we'll catch it when scanning the commit where it was first added. This cuts the work in half!

### Options for Git Scanning

| Option | What It Does | Example |
|--------|-------------|---------|
| `--branch` | Scan a specific branch | `--branch develop` |
| `--since-commit` | Only scan commits after this one | For incremental CI/CD scans |
| `--max-commits` | Limit how many commits to scan | `--max-commits 100` for quick checks |
| `--all-branches` | Scan every branch | Full security audit |
| `--depth` | Shallow clone (only recent history) | Faster for remote repos |

### Cleanup After Remote Scans

When scanning a remote repo, CredVigil clones it to a temporary folder and **automatically deletes it** after scanning. No leftover files!

### How to Talk About This in an Interview

> "The git scanner goes through every commit in the repository history and checks what lines were added. We only scan added lines because removed lines are captured when scanning the commit where they were first added. For remote repos, we clone to a temp directory and automatically clean up after. The scanner supports incremental scanning with `--since-commit` for CI/CD pipelines — so you only scan new commits, not the entire history every time. We use the git CLI directly via Go's `os/exec` instead of a library, keeping the project dependency-free."

---

## 15. File Watcher — Real-Time Monitoring

### What It Does

The watcher monitors a folder and **automatically scans any file that changes** — like a security camera for your code.

### How It Works

```mermaid
graph TD
    subgraph "Operating System"
        OS["File system events<br/>Create, Modify, Delete, Rename"]
    end

    subgraph "Watcher"
        RECEIVE["Receive event"]
        SKIP{"Should skip?<br/>Is it in .git?<br/>Is it a binary?"}
        DEBOUNCE{"Same file changed<br/>in the last 500ms?"}
        HANDLER["Trigger scan!"]
    end

    OS --> RECEIVE
    RECEIVE --> SKIP
    SKIP -->|yes| DROP["Ignore"]
    SKIP -->|no| DEBOUNCE
    DEBOUNCE -->|yes| DROP2["Ignore - already handled"]
    DEBOUNCE -->|no| HANDLER

    style HANDLER fill:#51cf66,stroke:#333
    style DROP fill:#868e96,stroke:#333,color:#fff
    style DROP2 fill:#868e96,stroke:#333,color:#fff
```

### Why Debouncing? (The 500ms Buffer)

When you save a file in VS Code, the operating system fires 3-5 events (create temp file, write, update permissions, delete temp). Without debouncing, we'd scan the same file 3-5 times for a single save!

> **Debouncing** means: "If I already processed this file in the last 500 milliseconds, ignore the new event." Result: 1 scan instead of 5.

```mermaid
sequenceDiagram
    participant VS as VS Code (Save)
    participant OS as File System
    participant W as Watcher

    VS->>OS: Event 1: WRITE config.go
    OS->>W: config.go changed
    W->>W: First event - SCAN!

    VS->>OS: Event 2: CHMOD config.go (10ms later)
    OS->>W: config.go changed
    W->>W: Only 10ms since last scan - IGNORE

    VS->>OS: Event 3: WRITE config.go (20ms later)
    OS->>W: config.go changed
    W->>W: Only 30ms since last scan - IGNORE

    Note over W: Result: 1 scan instead of 3!
```

### How to Talk About This in an Interview

> "The file watcher uses the `fsnotify` library which wraps OS-level file system events — `inotify` on Linux, `kqueue` on macOS. The key challenge is event deduplication: saving a file in an editor generates multiple OS events, so we use a debounce mechanism — if we've already processed the same file within 500 milliseconds, we skip the new event. New directories are automatically watched when they're created. The handler runs in a separate goroutine so slow scans don't block event processing."

---

## 16. Security — Protecting the Secrets We Find

### The Core Problem

> We're a tool that finds secrets. If our **output** contains those secrets in plain text, we're making the problem worse! Imagine a security guard who finds a lost credit card and then announces the card number over loudspeakers.

### Our Zero-Trust Security Model

"Zero-trust" means: **assume the worst** — assume our output will be seen by the wrong people (logged in CI, shared on Slack, stored in a database).

```mermaid
graph TD
    subgraph "Threats"
        T1["Raw secret in scan output"]
        T2["Raw secret in memory"]
        T3["Cloned repo left on disk"]
    end

    subgraph "How We Protect Against Each"
        M1["Pipeline sanitizes output<br/>Raw secret is deleted"]
        M2["Go garbage collector<br/>reclaims memory"]
        M3["Automatic cleanup<br/>Temp folder deleted"]
    end

    T1 --> M1
    T2 --> M2
    T3 --> M3

    style T1 fill:#ff6b6b,stroke:#333,color:#fff
    style M1 fill:#51cf66,stroke:#333
```

### Defense in Depth — Multiple Layers

```mermaid
graph LR
    L1["Layer 1: HASH<br/>One-way fingerprint<br/>Cannot be reversed"] --> L2["Layer 2: MASK<br/>Show just enough<br/>to identify"]
    L2 --> L3["Layer 3: SANITIZE<br/>Delete raw secret<br/>from memory"]
    L3 --> L4["Layer 4: OUTPUT<br/>Only hash + mask<br/>in final result"]

    style L1 fill:#339af0,stroke:#333,color:#fff
    style L3 fill:#51cf66,stroke:#333
```

### What If Output Is Leaked?

| Scenario | What Attackers Get |
|----------|-------------------|
| Someone reads our JSON output | Only hashes and masked previews — useless to attackers |
| CI/CD logs are exposed | Logs show `AKIA****MPLE`, not the real key |
| Scan results emailed to team | Email contains redacted forms only |

### How to Talk About This in an Interview

> "CredVigil follows a zero-trust security model — we assume our scan output could end up in insecure places like CI logs or Slack messages. The pipeline guarantees that raw secrets never appear in the output. This is enforced architecturally: the Sanitize processor is always the last stage and it permanently deletes the raw secret from memory. The output only contains SHA-256 hashes (for tracking) and masked previews (for identification). For cloned repos, we automatically delete the temp directory after scanning. It's defense in depth — multiple independent security layers."

---

## 17. Concurrency — Doing Many Things at Once

### Why Do We Need Concurrency?

> If you have 1,000 files to scan and each takes 1 second, scanning one-by-one takes **1,000 seconds** (~17 minutes). With 4 workers scanning in parallel, it takes **250 seconds** (~4 minutes). That's 4x faster!

### The Three Concurrency Tools We Use

```mermaid
graph TD
    subgraph "Tool 1: Semaphore Channel"
        S["Controls how many workers<br/>can run at the same time"]
        S1["Like a parking lot with 4 spots<br/>Car 5 waits until someone leaves"]
    end

    subgraph "Tool 2: Mutex Lock"
        M["Protects shared data<br/>from being corrupted"]
        M1["Like a bathroom door lock<br/>Only one person at a time"]
    end

    subgraph "Tool 3: WaitGroup"
        W["Waits for all workers<br/>to finish"]
        W1["Like a teacher counting<br/>students back on the bus"]
    end

    style S fill:#ff6b6b,stroke:#333,color:#fff
    style M fill:#ffd43b,stroke:#333
    style W fill:#51cf66,stroke:#333
```

### How They Work Together

```mermaid
sequenceDiagram
    participant Main as Main Program
    participant Sem as Parking Lot (4 spots)
    participant W1 as Worker 1
    participant W2 as Worker 2
    participant W3 as Worker 3
    participant W4 as Worker 4
    participant W5 as Worker 5 (waiting)
    participant Lock as Door Lock
    participant Results as Shared Results

    Main->>W1: Go scan file 1!
    W1->>Sem: Take spot 1
    Main->>W2: Go scan file 2!
    W2->>Sem: Take spot 2
    Main->>W3: Go scan file 3!
    W3->>Sem: Take spot 3
    Main->>W4: Go scan file 4!
    W4->>Sem: Take spot 4 (FULL!)
    Main->>W5: Go scan file 5!
    W5->>Sem: No spots... WAIT

    W1->>Lock: Lock the door
    W1->>Results: Add my results
    W1->>Lock: Unlock the door
    W1->>Sem: Leave my spot

    W5->>Sem: Take freed spot!
    Note over W5: Now worker 5 can run!
```

### Why Not Just Use Simple Locks Everywhere?

We use a special "Reader-Writer" lock for things that are read often but written rarely:

| Situation | What We Use | Why |
|-----------|-------------|-----|
| Finding counter (written every time) | Regular Lock | Only one writer at a time |
| Rule list (read millions of times, written once) | Reader-Writer Lock | Multiple readers at the same time! |

> **Analogy**: A regular lock is like a single-person bathroom — one at a time. A reader-writer lock is like a library — many people can read books at the same time, but only one person can reshelf books at a time.

### How to Talk About This in an Interview

> "I use three Go concurrency primitives: a channel-based semaphore to limit parallel workers (like a parking lot with limited spots), mutexes to protect shared data (like a door lock), and WaitGroups to wait for all workers to finish (like a teacher counting students). For read-heavy data like the rule set — loaded once, read millions of times — I use a reader-writer lock that allows concurrent reads, which gives much better performance than an exclusive lock."

---

## 18. Design Patterns — Proven Solution Templates

### What Are Design Patterns?

Design patterns are **proven solutions to common programming problems**. Think of them like cooking recipes — you don't invent how to make pasta from scratch every time, you follow a proven recipe.

### Patterns Used in CredVigil

```mermaid
mindmap
    root((Patterns Used))
        Strategy Pattern
            Swappable algorithms
            Each pipeline stage
        Chain of Responsibility
            Processing pipeline
            Stage after stage
        Worker Pool
            Parallel file scanning
            Limited workers
        Observer Pattern
            File watcher
            React to changes
        Facade Pattern
            Git scanner
            Simple API hides complexity
        Factory Pattern
            Creating components
            NewEngine, NewDefault
```

### Pattern 1: Strategy — Swappable Parts

> **Recipe analogy**: Like interchangeable blender attachments — same blender, different attachments for different jobs.

Each pipeline stage (Hash, Mask, Enrich, etc.) implements the same simple interface. You can swap them, reorder them, or add new ones without changing anything else.

### Pattern 2: Chain of Responsibility — Assembly Line

> **Factory analogy**: Like a car assembly line — each station does one thing, then passes the car to the next station.

Findings pass through Hash → Mask → Enrich → Fingerprint → Sanitize, one stage at a time.

### Pattern 3: Worker Pool — Limited Parallel Workers

> **Restaurant analogy**: A restaurant with 4 chefs — they cook meals in parallel, but you can't have 100 chefs in one kitchen (chaos!).

We limit to 4 goroutines scanning files simultaneously.

### Pattern 4: Observer — React to Events

> **Doorbell analogy**: You don't constantly check if someone is at the door — you wait for the doorbell to ring.

The file watcher doesn't constantly check files — it waits for the OS to notify it of changes.

### Pattern 5: Facade — Hide Complexity

> **Car driving analogy**: You turn a key (simple) — but under the hood, hundreds of parts work together (complex). The ignition is the facade.

`git-scan` is one simple command, but it orchestrates 7 subsystems: repo management, commit walking, diff parsing, filtering, detection, pipeline processing, and progress tracking.

### Pattern 6: Factory — Proper Initialization

> **Restaurant analogy**: You order "burger" (simple) — the kitchen handles all the prep, cooking, and plating (complex initialization).

`NewEngine()`, `NewDefault()`, `DefaultRuleSet()` — these factory functions create properly initialized components.

### How to Talk About This in an Interview

> "I used 6 design patterns in CredVigil: Strategy for interchangeable pipeline processors, Chain of Responsibility for the processing pipeline, Worker Pool for concurrent file scanning, Observer for the file watcher, Facade for the git scanner that hides 7 subsystems behind a simple API, and Factory for component creation. Each pattern solves a specific problem: Strategy enables extensibility, the pipeline enables composability, the worker pool enables performance, the observer enables reactivity, the facade enables usability, and factories ensure components are always properly initialized."

---

## 19. Error Handling — What Happens When Things Go Wrong

### Our Philosophy: Don't Crash, Keep Going

> **Analogy**: If one cashier at a grocery store has a problem, you don't close the whole store — the other cashiers keep working.

```mermaid
graph TD
    subgraph "Stop Everything - Serious Problem"
        E1["Git not installed<br/>Cannot scan at all"]
        E2["Invalid configuration<br/>Cannot start properly"]
    end

    subgraph "Skip and Continue - Minor Problem"
        E3["Cannot read one file<br/>Skip it, scan the rest"]
        E4["Pipeline stage fails<br/>Drop that finding, continue"]
        E5["One git commit fails<br/>Skip it, scan other commits"]
    end

    style E1 fill:#ff6b6b,stroke:#333,color:#fff
    style E2 fill:#ff6b6b,stroke:#333,color:#fff
    style E3 fill:#ffd43b,stroke:#333
    style E4 fill:#ffd43b,stroke:#333
    style E5 fill:#ffd43b,stroke:#333
```

### Key Principle: Better to Miss a Finding Than to Expose a Secret

> If the masking or sanitizing step fails for a finding, we **drop the entire finding** instead of outputting it with the raw secret exposed. Security always wins over completeness.

### How to Talk About This in an Interview

> "Error handling follows a fail-safe philosophy: it's better to miss a finding than to crash the entire scan or expose a raw secret. File-level errors cause that file to be skipped, not the scan to abort. Pipeline errors cause the individual finding to be dropped. Only critical errors like missing prerequisites cause immediate failure. This is inspired by the bulkhead pattern from resilience engineering — a failure in one area doesn't bring down the whole system."

---

## 20. Extensibility — Adding New Features Easily

### 5 Ways to Extend CredVigil

```mermaid
graph TD
    subgraph "1. Add New Rules"
        R["Define a new pattern<br/>Add it to the rule set<br/>Engine picks it up automatically!"]
    end

    subgraph "2. Add Pipeline Stage"
        P["Create a new processor<br/>Implement 2 methods: Name and Process<br/>Insert it into the pipeline"]
    end

    subgraph "3. Add Verification"
        V["In the future: call AWS or GitHub APIs<br/>to check if a found secret is actually valid"]
    end

    subgraph "4. Add Input Source"
        I["Today: files, git, stdin<br/>Could add: S3 buckets, Slack messages, etc."]
    end

    subgraph "5. Add Output Format"
        O["Today: text and JSON<br/>Could add: HTML, CSV, SARIF, etc."]
    end

    style R fill:#51cf66,stroke:#333
    style P fill:#339af0,stroke:#333,color:#fff
```

### Adding a New Rule Is Just 3 Lines

```
1. Define the pattern (what to look for)
2. Set the confidence and severity
3. Add it to the rule set — done!
```

> The engine automatically picks up new rules without any code changes.

### How to Talk About This in an Interview

> "The system follows the Open-Closed Principle — it's open for extension but closed for modification. There are 5 extension points: add new detection rules, add pipeline processors, add secret verification, add input sources, and add output formats. Each extension point uses a Go interface, so you just implement the interface — you don't need to modify existing code. For example, adding a new detection rule is literally defining a pattern and adding it to the rule set — the engine automatically picks it up."

---

## 21. Performance — Speed & Memory

### Where Time Is Spent

```mermaid
graph LR
    subgraph "Fast - Milliseconds"
        F1["Loading 331 rules"]
        F2["Pipeline processing"]
    end

    subgraph "Medium - Seconds"
        F3["Scanning files from disk"]
        F4["Running regex patterns"]
    end

    subgraph "Slow - Minutes"
        F5["Cloning a remote repo"]
        F6["Walking thousands of commits"]
    end

    style F1 fill:#51cf66,stroke:#333
    style F3 fill:#ffd43b,stroke:#333
    style F5 fill:#ff6b6b,stroke:#333,color:#fff
```

### How We Stay Fast

| Optimization | What It Does | Impact |
|-------------|-------------|--------|
| Pre-compiled patterns | All 331 regex patterns are compiled once at startup | No compilation delay during scanning |
| Worker pool | 4 files scanned in parallel | ~4x faster than sequential |
| File filtering | Skip binaries, images, node_modules | Avoid wasting time on irrelevant files |
| Only added lines in git | Only check new lines in each commit | Half the work for git scans |
| Shallow clones | `--depth` flag for remote repos | Download less history |

### Memory Usage

| Component | Memory Used | Notes |
|-----------|------------|-------|
| 331 compiled rules | ~2-3 MB | Constant, loaded once |
| File content | Up to 10 MB per file | Only one file at a time per worker |
| Findings | ~1 KB each | Grows with number of findings |

### How to Talk About This in an Interview

> "Performance is mostly I/O-bound for file scanning and CPU-bound for pattern matching. We optimize with pre-compiled regex patterns (no compilation during scanning), a worker pool for parallel file processing, smart file filtering (skip binaries, images, lock files), and for git scanning we only check added lines which cuts the work in half. Memory is bounded — we never load more than 10 MB per file, and the compiled rules are constant at about 2-3 MB."

---

## 22. Interview Quick-Reference Cards

Use these cards to quickly answer common interview questions:

---

### Card 1: "Tell me about your project"

> "I built CredVigil, a command-line tool that detects leaked secrets in source code. It has 331 built-in detection rules for known secret patterns like AWS keys and GitHub tokens, plus an entropy analyzer that catches unknown secrets by measuring string randomness. It can scan files, directories, git commit history, and watch files in real-time. The tool follows a zero-trust security model — found secrets are always masked in the output, so even if the scan results are leaked, the actual secrets remain protected."

---

### Card 2: "Walk me through the architecture"

> "It's a 4-layer pipeline: Input (CLI, files, git, watcher), Detection (331 regex rules + entropy analysis with 5-factor confidence scoring), Post-Processing (5-stage pipeline: hash, mask, enrich, fingerprint, sanitize), and Output (text or JSON). The code is organized into 8 packages with no circular dependencies. The `Finding` struct is the shared data model all components communicate through."

---

### Card 3: "How do you handle concurrency?"

> "I use three Go concurrency tools: a channel-based semaphore that limits parallel file scanning to 4 workers (like a parking lot with 4 spots), mutexes to protect shared data from corruption, and WaitGroups to wait for all workers to finish. For read-heavy data like the rule set, I use a reader-writer lock that allows many goroutines to read concurrently while ensuring exclusive access for writes."

---

### Card 4: "How do you reduce false positives?"

> "Through a 5-factor confidence scoring system. Starting from a rule's base confidence (how specific the pattern is), it adjusts for string randomness, nearby keywords like 'password', false positive indicators like 'example', and placeholder content like 'changeme'. So a real AWS key scores 95%+ while an example key in documentation drops to about 45%. Users can set a minimum confidence threshold to filter results."

---

### Card 5: "How is security built in?"

> "Zero-trust pipeline — we assume our output will end up in insecure places. Raw secrets go through: hashing (one-way fingerprint for tracking), masking (show only enough to identify), and sanitizing (permanently delete the raw secret from memory). Even if our JSON output is leaked, attackers only get hashes and masked previews like `AKIA****MPLE`. Cloned repos are automatically cleaned up."

---

### Card 6: "What design patterns did you use?"

> "Six patterns: Strategy for interchangeable pipeline processors, Chain of Responsibility for the processing pipeline, Worker Pool for concurrent scanning, Observer for file watching, Facade for the git scanner (simple API hiding 7 subsystems), and Factory for component creation. Each pattern solves a specific problem — extensibility, composability, performance, reactivity, usability, and correct initialization."

---

### Card 7: "How does entropy detection work?"

> "It measures how random a string is. Real secrets like API keys tend to be very random, while normal code and English words aren't. We use different thresholds for different character types — hex strings have a lower randomness ceiling than Base64, so they need different thresholds. The final score is 70% randomness quality and 30% length — longer random strings are more likely to be real secrets."

---

### Card 8: "How would you scale this?"

> "Three strategies: Horizontal — each repo scan is independent, so distribute across CI workers. Incremental — the `--since-commit` flag scans only new commits. Deduplication — fingerprints track which findings are new vs. already known. The modular architecture means you could add a database writer or webhook notifier just by implementing the Processor interface — no changes to existing code."

---

## Quick Reference: Complete File List

| File | What It Does |
|------|-------------|
| `cmd/credvigil/main.go` | CLI entry point — handles commands and output |
| `internal/config/config.go` | Configuration structs and defaults |
| `pkg/models/finding.go` | Data structures: Finding, Severity, SecretType |
| `pkg/rules/rules.go` | All 331 detection rules |
| `pkg/detector/engine.go` | Detection engine: regex + entropy |
| `pkg/detector/scanner.go` | File scanner with worker pool |
| `pkg/entropy/entropy.go` | Shannon entropy analysis |
| `pkg/pipeline/pipeline.go` | Pipeline: Processor interface and orchestration |
| `pkg/pipeline/hash.go` | SHA-256 hashing of secrets |
| `pkg/pipeline/redact.go` | Masking: `AKIA****MPLE` |
| `pkg/pipeline/enrich.go` | File type, environment, category classification |
| `pkg/pipeline/fingerprint.go` | Cross-scan deduplication |
| `pkg/pipeline/sanitize.go` | Zero-trust: delete raw secret |
| `pkg/pipeline/verify.go` | Placeholder for future verification |
| `pkg/git/git.go` | Git data structures and helpers |
| `pkg/git/scanner.go` | Git scanning orchestrator |
| `pkg/git/diff.go` | Diff parser |
| `pkg/git/walker.go` | Commit walker |
| `pkg/git/clone.go` | Repository open/clone/cleanup |
| `pkg/watcher/watcher.go` | File system watcher |

---

*This simplified document covers the same system design as the detailed version, but explained in plain English with real-world analogies. Every concept here maps directly to the actual CredVigil source code.*
