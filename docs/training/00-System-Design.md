# CredVigil — Complete System Design & Architecture

> **Purpose**: This document covers **every** architectural decision, design pattern, data structure, algorithm, and concurrency mechanism in CredVigil. It is designed so you can explain each concept in a system design interview **like a champion**.

---

## Table of Contents

1. [System Overview & Philosophy](#1-system-overview--philosophy)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Package Dependency Graph](#3-package-dependency-graph)
4. [End-to-End Data Flow](#4-end-to-end-data-flow)
5. [CLI Layer — Command Routing & Orchestration](#5-cli-layer--command-routing--orchestration)
6. [Configuration System](#6-configuration-system)
7. [Data Model — The Lingua Franca](#7-data-model--the-lingua-franca)
8. [Rule Engine — Pattern Matching at Scale](#8-rule-engine--pattern-matching-at-scale)
9. [Detection Engine — The Brain](#9-detection-engine--the-brain)
10. [Shannon Entropy Analysis — Information Theory in Practice](#10-shannon-entropy-analysis--information-theory-in-practice)
11. [Confidence Scoring — 5-Factor Algorithm](#11-confidence-scoring--5-factor-algorithm)
12. [File Scanner — Concurrent I/O with Worker Pool](#12-file-scanner--concurrent-io-with-worker-pool)
13. [Post-Processing Pipeline — Chain of Responsibility](#13-post-processing-pipeline--chain-of-responsibility)
14. [Git Integration — History Archaeology](#14-git-integration--history-archaeology)
15. [File Watcher — Real-Time Monitoring](#15-file-watcher--real-time-monitoring)
16. [Security Architecture — Zero-Trust Pipeline](#16-security-architecture--zero-trust-pipeline)
17. [Concurrency Model — Goroutines, Channels & Mutexes](#17-concurrency-model--goroutines-channels--mutexes)
18. [Design Patterns Catalog](#18-design-patterns-catalog)
19. [Error Handling Philosophy](#19-error-handling-philosophy)
20. [Extensibility & Plugin Points](#20-extensibility--plugin-points)
21. [Performance Characteristics](#21-performance-characteristics)
22. [Interview Quick-Reference Cards](#22-interview-quick-reference-cards)

---

## 1. System Overview & Philosophy

### What is CredVigil?

CredVigil is a **static analysis security tool** that detects hardcoded secrets (API keys, passwords, tokens, private keys) in source code, configuration files, and git history. Think of it as a "spell-checker for secrets."

### Core Design Principles

| Principle | Description | How It's Implemented |
|-----------|-------------|---------------------|
| **Zero-Trust** | Raw secrets never leave the system boundary | Pipeline sanitizes every finding before output |
| **Defense in Depth** | Multiple detection layers catch what others miss | Regex rules + Shannon entropy = dual detection |
| **Fail-Safe Defaults** | Secure out of the box | `MinConfidence=0.3`, `EnableEntropy=true`, auto-pipeline |
| **Separation of Concerns** | Each package has one responsibility | 8 packages, each with a single purpose |
| **Dependency Minimization** | Only one external dependency (fsnotify) | Git integration uses `os/exec`, no libgit2 |
| **Composability** | Components are mix-and-match | Pipeline processors are plug-and-play |

### Interview Talking Points

- **"Why build another secret scanner?"** — CredVigil combines regex-based pattern matching with information-theoretic entropy analysis. Most tools do one or the other. The dual-engine approach catches both known patterns (AWS keys) and unknown high-entropy strings (custom tokens).
- **"How is it different from tools like truffleHog or gitleaks?"** — Zero-trust post-processing pipeline (secrets are hashed and redacted before output), 5-factor confidence scoring reduces false positives, and the pipeline architecture is extensible without modifying core code.

---

## 2. High-Level Architecture

### System Architecture Diagram

```mermaid
graph TB
    subgraph "Input Sources"
        CLI["CLI Arguments<br/>credvigil scan"]
        STDIN["Standard Input<br/>pipe / redirect"]
        GIT["Git Repository<br/>local or remote"]
        FS["File System Events<br/>fsnotify watcher"]
    end

    subgraph "Core Engine Layer"
        CONFIG["Configuration<br/>internal/config"]
        RULES["Rule Engine<br/>pkg/rules<br/>331 compiled regex patterns"]
        DETECTOR["Detection Engine<br/>pkg/detector<br/>Regex + Entropy dual-mode"]
        ENTROPY["Entropy Analyzer<br/>pkg/entropy<br/>Shannon entropy per charset"]
    end

    subgraph "I/O Layer"
        SCANNER["File Scanner<br/>pkg/detector/scanner<br/>Worker pool concurrency"]
        GITSCANNER["Git Scanner<br/>pkg/git<br/>Commit walker + diff parser"]
        WATCHER["File Watcher<br/>pkg/watcher<br/>Debounced event loop"]
    end

    subgraph "Post-Processing Pipeline"
        HASH["1. HashProcessor<br/>SHA-256 of raw secret"]
        REDACT["2. RedactProcessor<br/>Masked preview"]
        ENRICH["3. EnrichProcessor<br/>File type, env, category"]
        FINGERPRINT["4. FingerprintProcessor<br/>Cross-scan dedup ID"]
        SANITIZE["5. SanitizeProcessor<br/>Clear raw secret (zero-trust)"]
    end

    subgraph "Output Layer"
        TEXT["Text Output<br/>Color-coded terminal"]
        JSON["JSON Output<br/>Machine-readable"]
    end

    CLI --> CONFIG
    CONFIG --> SCANNER
    CONFIG --> GITSCANNER
    STDIN --> SCANNER

    SCANNER --> DETECTOR
    GITSCANNER --> DETECTOR
    WATCHER --> SCANNER

    RULES --> DETECTOR
    ENTROPY --> DETECTOR

    DETECTOR --> HASH
    HASH --> REDACT
    REDACT --> ENRICH
    ENRICH --> FINGERPRINT
    FINGERPRINT --> SANITIZE

    SANITIZE --> TEXT
    SANITIZE --> JSON

    style DETECTOR fill:#ff6b6b,stroke:#333,stroke-width:3px,color:#fff
    style SANITIZE fill:#51cf66,stroke:#333,stroke-width:2px,color:#fff
    style RULES fill:#ffd43b,stroke:#333,stroke-width:2px
    style ENTROPY fill:#748ffc,stroke:#333,stroke-width:2px,color:#fff
```

### Architecture Style: **Layered Pipeline Architecture**

- **Layer 1 — Input**: Multiple input adapters (CLI, stdin, git, filesystem watcher)
- **Layer 2 — Detection**: Core engine with dual detection modes
- **Layer 3 — Post-Processing**: Sequential pipeline transforms findings
- **Layer 4 — Output**: Format adapters for human and machine consumption

### Interview Explanation

> "CredVigil uses a **layered pipeline architecture**. Input flows through multiple adapters, gets processed by a dual-engine detector (regex + entropy), then passes through a 5-stage post-processing pipeline that hashes, redacts, enriches, fingerprints, and sanitizes each finding. This architecture separates concerns cleanly — the detection engine doesn't know about output formatting, and the pipeline processors don't know about input sources. Each layer communicates through shared data models (`Finding`, `ScanResult`), making the system composable and testable."

---

## 3. Package Dependency Graph

### Module Structure

```mermaid
graph LR
    subgraph "Entry Point"
        CMD["cmd/credvigil/main.go<br/>CLI + Orchestration<br/>625 lines"]
    end

    subgraph "Internal"
        CFG["internal/config<br/>AppConfig structs<br/>63 lines"]
    end

    subgraph "Public Packages (pkg/)"
        MODELS["pkg/models<br/>Finding, Source, ScanResult<br/>697 lines"]
        RULES["pkg/rules<br/>331 detection rules<br/>3747 lines"]
        ENTROPY["pkg/entropy<br/>Shannon entropy<br/>275 lines"]
        DETECTOR["pkg/detector<br/>Engine + FileScanner<br/>879 lines"]
        PIPELINE["pkg/pipeline<br/>5 processors<br/>~900 lines"]
        GITPKG["pkg/git<br/>5 files, commit walking<br/>~1100 lines"]
        WATCHER["pkg/watcher<br/>fsnotify wrapper<br/>445 lines"]
    end

    CMD --> CFG
    CMD --> MODELS
    CMD --> DETECTOR
    CMD --> PIPELINE
    CMD --> GITPKG

    DETECTOR --> MODELS
    DETECTOR --> RULES
    DETECTOR --> ENTROPY

    PIPELINE --> MODELS

    GITPKG --> MODELS
    GITPKG --> DETECTOR
    GITPKG --> PIPELINE

    WATCHER --> |standalone| WATCHER

    RULES --> MODELS
    ENTROPY --> |standalone| ENTROPY

    style CMD fill:#339af0,stroke:#333,stroke-width:2px,color:#fff
    style MODELS fill:#ffd43b,stroke:#333,stroke-width:2px
    style DETECTOR fill:#ff6b6b,stroke:#333,stroke-width:2px,color:#fff
    style PIPELINE fill:#51cf66,stroke:#333,stroke-width:2px
```

### Dependency Rules

| Rule | Explanation |
|------|-------------|
| **No circular dependencies** | Dependencies flow in one direction: cmd → pkg, never pkg → cmd |
| **Models are the shared contract** | Every package depends on `pkg/models` — it's the "protobuf" of the system |
| **Entropy is standalone** | `pkg/entropy` has zero internal dependencies — pure algorithm, reusable anywhere |
| **Watcher is standalone** | `pkg/watcher` only depends on `fsnotify` — can be used independently |
| **internal/ is private** | `internal/config` is only importable by code in this module (Go visibility rule) |

### Interview Explanation

> "The dependency graph is **acyclic** — a DAG (Directed Acyclic Graph). The `models` package is at the bottom as the shared data contract. `entropy` and `watcher` are leaf nodes with zero internal dependencies, meaning they're highly reusable. The `detector` package depends on `rules` and `entropy` for its detection logic, while `pipeline` only depends on `models` — it doesn't know HOW findings are detected, only how to process them. This clean separation means we can swap out the detection engine without touching the pipeline, or add new pipeline stages without modifying the detector."

---

## 4. End-to-End Data Flow

### Complete Scan Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI as main.go (CLI)
    participant Config as AppConfig
    participant Engine as Detection Engine
    participant Rules as RuleSet (331 rules)
    participant Entropy as Entropy Analyzer
    participant Scanner as FileScanner
    participant Pipeline as Pipeline (5 stages)
    participant Output as Text/JSON Output

    User->>CLI: credvigil scan ./src --severity medium
    CLI->>Config: Parse flags → DefaultConfig()
    CLI->>Rules: DefaultRuleSet() → 331 rules loaded
    CLI->>Engine: NewEngine(ruleSet, config)
    CLI->>Scanner: NewFileScanner(engine, fileScanConfig)

    loop For each target path
        Scanner->>Scanner: filepath.Walk() → collect files
        Scanner->>Scanner: Skip binary, excluded, oversized files

        par Worker Pool (4 goroutines)
            Scanner->>Scanner: Worker 1: ScanFile(file_a)
            Scanner->>Scanner: Worker 2: ScanFile(file_b)
            Scanner->>Scanner: Worker 3: ScanFile(file_c)
            Scanner->>Scanner: Worker 4: ScanFile(file_d)
        end

        Scanner->>Engine: ScanContent(content, source)

        loop For each of 331 rules
            Engine->>Rules: matchRule(content, rule)
            Rules-->>Engine: regex matches + capture groups
            Engine->>Engine: computeConfidence(5-factor)
        end

        Engine->>Entropy: entropyDetection(content)
        Entropy-->>Engine: high-entropy words detected

        Engine->>Engine: Deduplicate via seen map
        Engine->>Engine: Filter by min confidence/severity
        Engine-->>Scanner: ScanResult{findings, counts}
    end

    Scanner-->>CLI: Combined ScanResult

    CLI->>Pipeline: ProcessResult(ctx, result, metadata)

    Pipeline->>Pipeline: HashProcessor → SHA-256
    Pipeline->>Pipeline: RedactProcessor → mask secret
    Pipeline->>Pipeline: EnrichProcessor → file type, env, category
    Pipeline->>Pipeline: FingerprintProcessor → dedup ID
    Pipeline->>Pipeline: SanitizeProcessor → clear raw secret

    Pipeline-->>CLI: Processed ScanResult

    alt --json flag
        CLI->>Output: outputJSON(result)
    else default
        CLI->>Output: outputText(result) with ANSI colors
    end

    Output-->>User: Findings displayed

    Note over CLI: Exit code = 1 if findings found<br/>Exit code = 0 if clean
```

### Data Flow Through the Finding Lifecycle

```mermaid
graph LR
    subgraph "Birth"
        A["Raw Match Detected<br/>RawMatch = AKIAIOSFODNN7EXAMPLE"]
    end

    subgraph "Stage 1: Hash"
        B["SecretHash = SHA-256(raw)<br/>= a3f2...c9d1"]
    end

    subgraph "Stage 2: Redact"
        C["RedactedMatch = AKIA****MPLE<br/>first4 + **** + last4"]
    end

    subgraph "Stage 3: Enrich"
        D["FileType = go-source<br/>Environment = production<br/>Category = cloud"]
    end

    subgraph "Stage 4: Fingerprint"
        E["Fingerprint = SHA-256(<br/>ruleID:location:line:secretHash)<br/>= b7e4...f2a1"]
    end

    subgraph "Stage 5: Sanitize"
        F["RawMatch = '' (CLEARED)<br/>Zero-trust enforced"]
    end

    A --> B --> C --> D --> E --> F

    style A fill:#ff6b6b,stroke:#333,color:#fff
    style F fill:#51cf66,stroke:#333,color:#fff
```

### Interview Explanation

> "A Finding goes through a complete lifecycle. It's born when the detection engine matches a regex or detects high entropy. At birth, it contains the raw secret — the actual API key or password. Then it flows through a 5-stage pipeline: **Hash** creates a SHA-256 fingerprint of the secret value, **Redact** creates a masked preview for human display, **Enrich** adds contextual metadata like file type and environment, **Fingerprint** creates a unique ID for cross-scan deduplication, and finally **Sanitize** clears the raw secret entirely. After sanitization, the `Finding` struct contains everything needed for reporting WITHOUT the actual secret. This is the zero-trust principle — we never output a raw secret, even in JSON."

---

## 5. CLI Layer — Command Routing & Orchestration

### Command Routing Architecture

```mermaid
graph TD
    ENTRY["os.Args parsing<br/>main()"] --> ROUTE{Command Router<br/>switch args[1]}

    ROUTE -->|"scan"| SCAN["cmdScan()<br/>File/directory/git scanning"]
    ROUTE -->|"rules"| RULES["cmdRules()<br/>List all 331 rules"]
    ROUTE -->|"version"| VER["cmdVersion()<br/>Print version info"]
    ROUTE -->|"help / -h"| HELP["cmdHelp()<br/>Usage text"]
    ROUTE -->|"--help"| HELP
    ROUTE -->|"unknown"| ERR["Print error + help<br/>Exit code 1"]

    SCAN --> FLAGS["Parse Scan Flags<br/>--severity, --json,<br/>--min-confidence,<br/>--entropy, --workers"]
    FLAGS --> INIT["Initialize Components<br/>RuleSet → Engine → Scanner"]
    INIT --> MODE{Input Mode?}

    MODE -->|"os.Stdin has data"| STDIN["ScanStdin()<br/>Read pipe/redirect"]
    MODE -->|"path arguments"| TARGETS["Loop over target paths"]

    TARGETS --> FTYPE{Path Type?}
    FTYPE -->|"IsDir()"| DIR["ScanDirectory(path)"]
    FTYPE -->|"IsFile()"| FILE["ScanFile(path)"]

    subgraph "Post-Scan"
        PIPELINE["Pipeline.ProcessResult()"]
        OUTPUT{--json flag?}
        TEXT["outputText() with ANSI"]
        JSON["outputJSON() with encoding/json"]
        EXIT{Findings > 0?}
        EXIT0["Exit code 0 ✓"]
        EXIT1["Exit code 1 ✗"]
    end

    STDIN --> PIPELINE
    DIR --> PIPELINE
    FILE --> PIPELINE
    PIPELINE --> OUTPUT
    OUTPUT -->|yes| JSON
    OUTPUT -->|no| TEXT
    JSON --> EXIT
    TEXT --> EXIT
    EXIT -->|no| EXIT0
    EXIT -->|yes| EXIT1

    style SCAN fill:#339af0,stroke:#333,color:#fff
    style PIPELINE fill:#51cf66,stroke:#333
    style EXIT1 fill:#ff6b6b,stroke:#333,color:#fff
```

### Key Implementation Details

- **Flag parsing**: Uses Go's `flag.NewFlagSet("scan", ...)` for subcommand-specific flags
- **Stdin detection**: `os.Stdin.Stat()` checks `ModeCharDevice` — if NOT a char device, data is being piped
- **Exit codes**: CI/CD integration — `os.Exit(1)` when findings exist, so pipelines fail on leaked secrets
- **Color output**: ANSI escape codes for severity highlighting:
  - Critical → Red (`\033[1;31m`)
  - High → Yellow (`\033[1;33m`)
  - Medium → Cyan (`\033[36m`)
  - Low → White (default)
  - Info → Gray (`\033[90m`)

### Interview Explanation

> "The CLI follows the **command-subcommand pattern** like `git` or `docker`. The main function acts as a router, dispatching to `cmdScan()`, `cmdRules()`, etc. `cmdScan()` is the orchestrator — it initializes the rule engine, creates the file scanner, processes all targets, runs the pipeline, and formats output. Exit codes are CI-friendly: 0 for clean, 1 for findings. This design means CredVigil can be dropped into any CI/CD pipeline as a gate check."

---

## 6. Configuration System

### Configuration Hierarchy

```mermaid
graph TD
    subgraph "Configuration Structs"
        APP["AppConfig<br/>Top-level container"]
        DET["DetectionConfig<br/>Engine behavior"]
        FS["FileScanningConfig<br/>I/O behavior"]
    end

    APP --> DET
    APP --> FS

    subgraph "DetectionConfig Fields"
        D1["MinConfidence = 0.3<br/>Minimum score to report"]
        D2["MinSeverity = 'info'<br/>Minimum severity level"]
        D3["EnableEntropy = true<br/>Shannon entropy enabled"]
        D4["EntropyMinLength = 12<br/>Min string length for entropy"]
        D5["ContextLines = 2<br/>Lines of context around match"]
    end

    subgraph "FileScanningConfig Fields"
        F1["MaxFileSize = 10 MB<br/>Skip files larger than this"]
        F2["Workers = 4<br/>Concurrent goroutines"]
        F3["ExcludeDirs = [...]<br/>.git, node_modules, etc."]
        F4["ExcludeExtensions = [...]<br/>.exe, .png, .zip, etc."]
    end

    DET --> D1 & D2 & D3 & D4 & D5
    FS --> F1 & F2 & F3 & F4

    style APP fill:#339af0,stroke:#333,color:#fff
    style DET fill:#ffd43b,stroke:#333
    style FS fill:#51cf66,stroke:#333
```

### Config Defaults — Why These Values?

| Config | Default | Reasoning |
|--------|---------|-----------|
| `MinConfidence = 0.3` | Low threshold catches more secrets; users can increase for fewer false positives |
| `EnableEntropy = true` | Catches secrets not covered by regex rules |
| `EntropyMinLength = 12` | Short strings have low entropy variance; 12+ gives meaningful measurements |
| `ContextLines = 2` | Enough to understand where the secret is without revealing too much |
| `MaxFileSize = 10MB` | Avoids OOM on large binaries; 99% of source files are < 1MB |
| `Workers = 4` | Matches common CPU core counts; more workers = diminishing returns due to I/O |

### Interview Explanation

> "The config system uses **nested structs** — `AppConfig` contains `DetectionConfig` and `FileScanningConfig`. This is the **Builder pattern** applied through `DefaultConfig()`. Each default was chosen intentionally: `MinConfidence=0.3` is permissive by default (it's better to have a false positive than miss a real secret), `Workers=4` balances parallelism with I/O contention, and `MaxFileSize=10MB` prevents the scanner from choking on binary blobs. Users override these via CLI flags, which is the **Override pattern** — flags take precedence over defaults."

---

## 7. Data Model — The Lingua Franca

### Core Data Structures

```mermaid
classDiagram
    class Finding {
        +string ID "CVF-{unixmilli}-{count}"
        +SecretType SecretType "~180+ enum values"
        +string Description
        +Severity Severity "Info|Low|Medium|High|Critical"
        +string RuleID
        +Source Source
        +string RawMatch "Cleared by pipeline"
        +string RedactedMatch "AKIA****MPLE"
        +string SecretHash "SHA-256"
        +string Fingerprint "Cross-scan dedup"
        +float64 Entropy
        +float64 Confidence "0.0 – 1.0"
        +bool Verified
        +time.Time DetectedAt
        +string FileType "go-source, yaml-config..."
        +string Environment "production, staging..."
        +string Category "cloud, database, auth..."
        +map Metadata "Extensible key-value"
        +Redact()
        +ClearRawMatch()
    }

    class Source {
        +string Type "file | git-commit | stdin"
        +string Location "file path"
        +int Line
        +int Column
        +int EndLine
        +string Context "surrounding lines"
        +string CommitHash "git only"
        +string Author "git only"
        +string Branch "git only"
        +string MachineID
        +string ProcessName
    }

    class ScanResult {
        +[]Finding Findings
        +int TotalFindings
        +map CountBySeverity
        +Source Source
    }

    class ScanRequest {
        +string Content "text to scan"
        +Source Source "where it came from"
    }

    class ScanMetadata {
        +string ScannerVersion
        +time.Time StartedAt
        +string SourceType
        +string SourcePath
        +int RuleCount
    }

    class Severity {
        <<enumeration>>
        Info = 0
        Low = 1
        Medium = 2
        High = 3
        Critical = 4
        +String() string
        +MarshalJSON()
        +UnmarshalJSON()
    }

    Finding --> Source : contains
    Finding --> Severity : has
    ScanResult --> Finding : contains many
    ScanResult --> Source : has
    ScanRequest --> Source : has
```

### Severity Enum — Custom JSON Marshaling

```mermaid
graph LR
    subgraph "Go Internal (iota)"
        I0["Info = 0"]
        I1["Low = 1"]
        I2["Medium = 2"]
        I3["High = 3"]
        I4["Critical = 4"]
    end

    subgraph "JSON Output (string)"
        J0['"info"']
        J1['"low"']
        J2['"medium"']
        J3['"high"']
        J4['"critical"']
    end

    I0 --> J0
    I1 --> J1
    I2 --> J2
    I3 --> J3
    I4 --> J4

    subgraph "Backward Compat"
        BC["UnmarshalJSON accepts<br/>BOTH string AND int<br/>e.g., 3 → High<br/>and 'high' → High"]
    end
```

### SecretType — 180+ Constants Organized by Category

```mermaid
mindmap
    root((SecretType))
        Cloud
            AWSAccessKey
            AWSSecretKey
            GCPServiceAccount
            AzureClientSecret
            AzureStorageKey
            DigitalOceanToken
            HerokuAPIKey
        SCM
            GitHubPAT
            GitHubOAuth
            GitLabPAT
            BitbucketToken
        Collaboration
            SlackBotToken
            SlackWebhook
            DiscordToken
            TeamsWebhook
        Database
            DatabaseURL
            MongoDBURI
            RedisPassword
            PostgresConn
        Auth
            JWTSecret
            OAuth2Secret
            Auth0Key
            OktaToken
        Private Keys
            RSAPrivateKey
            ECPrivateKey
            SSHPrivateKey
            PGPPrivateKey
        Payment
            StripeSecretKey
            PayPalSecret
            SquareAccessToken
        AI/ML
            OpenAIKey
            AnthropicKey
            HuggingFaceToken
        Messaging
            TwilioAuthToken
            SendGridKey
            MailgunKey
        Infrastructure
            DockerRegistryAuth
            KubernetesToken
            TerraformToken
            VaultToken
        CI/CD
            CircleCIToken
            TravisCIToken
            JenkinsSecret
```

### Interview Explanation

> "The data model is the **lingua franca** — every component speaks through `Finding` and `ScanResult`. The `Finding` struct has 20+ fields but they're populated at different stages: the detection engine sets `RawMatch`, `Confidence`, `Entropy`, and `Severity`; the pipeline adds `SecretHash`, `RedactedMatch`, `FileType`, `Environment`, `Category`, and `Fingerprint`; finally `Sanitize` clears `RawMatch`. The `Severity` enum uses Go's `iota` for type-safe comparisons internally, but marshals to human-readable strings in JSON. The `UnmarshalJSON` method is backward-compatible — it accepts both `\"high\"` AND `3` — so older JSON outputs still parse correctly. This is a common pattern for API versioning."

### Redaction Algorithm

```
if len(secret) > 12:
    redacted = first4chars + "****" + last4chars
    Example: "AKIAIOSFODNN7EXAMPLE" → "AKIA****MPLE"

else if len(secret) >= 5:
    redacted = first2chars + "****"
    Example: "mypasswd" → "my****"

else:
    redacted = "****"
    Example: "abc" → "****"
```

- **Why these thresholds?** Long secrets (>12) have enough characters to safely show both ends. Short secrets (5-12) only show the start. Very short ones (<5) are fully masked because any partial reveal would expose too much.

---

## 8. Rule Engine — Pattern Matching at Scale

### Rule Structure

```mermaid
classDiagram
    class Rule {
        +string ID "e.g., aws-access-key"
        +string Description "Human-readable explanation"
        +SecretType SecretType "AWS Access Key, etc."
        +Severity Severity "Critical, High, Medium..."
        +*regexp.Regexp Pattern "Compiled regex (main)"
        +[]*regexp.Regexp SecondaryPatterns "Additional validators"
        +[]*regexp.Regexp FalsePositivePatterns "Known non-secrets"
        +[]string Keywords "Proximity keywords"
        +bool MultiLine "Multi-line match mode"
        +float64 BaseConfidence "Starting confidence"
        +bool Verifiable "Can be verified online"
        +float64 MinEntropy "Minimum entropy required"
    }

    class RuleSet {
        -sync.RWMutex mu
        -[]Rule rules "All 331 rules"
        -map byID "Hash map for O(1) lookup by ID"
        +Add(Rule)
        +Rules() []Rule
        +GetByID(string) Rule
        +Count() int
    }

    RuleSet --> Rule : contains 331
```

### How Rules Are Organized

```mermaid
graph TD
    subgraph "Rule Categories (331 total)"
        AWS["AWS (8 rules)<br/>Access Key, Secret, Session,<br/>MWS, ARN, etc."]
        GCP["GCP (5 rules)<br/>Service Account, API Key,<br/>OAuth Client, etc."]
        AZURE["Azure (6 rules)<br/>Client Secret, Storage Key,<br/>SAS Token, etc."]
        GITHUB["GitHub (6 rules)<br/>PAT Classic, Fine-grained,<br/>OAuth, App, Deploy"]
        GITLAB["GitLab (3 rules)<br/>PAT, Pipeline Trigger,<br/>Runner Token"]
        SLACK["Slack (3 rules)<br/>Bot Token, User Token,<br/>Webhook URL"]
        DB["Database (10+ rules)<br/>Connection strings,<br/>passwords, URIs"]
        KEYS["Private Keys (5+ rules)<br/>RSA, EC, SSH, PGP,<br/>PKCS8"]
        PAYMENT["Payment (5+ rules)<br/>Stripe, PayPal, Square,<br/>Braintree"]
        GENERIC["Generic (50+ rules)<br/>Password patterns,<br/>Bearer tokens, API keys"]
        MORE["... 200+ more rules"]
    end

    ALL["DefaultRuleSet()<br/>Loads all 331 rules<br/>at startup"] --> AWS & GCP & AZURE & GITHUB & GITLAB & SLACK & DB & KEYS & PAYMENT & GENERIC & MORE

    style ALL fill:#ffd43b,stroke:#333,stroke-width:2px
```

### Rule Example: AWS Access Key

```
Rule{
    ID:             "aws-access-key-id"
    Description:    "AWS Access Key ID"
    SecretType:     AWSAccessKey
    Severity:       Critical
    Pattern:        `(AKIA[0-9A-Z]{16})`        ← capture group!
    Keywords:       ["aws", "amazon", "iam"]
    BaseConfidence: 0.95                          ← high: format is very specific
    Verifiable:     true                          ← can call AWS STS to verify
    MinEntropy:     0                             ← not needed: format is deterministic
}
```

### False Positive Pattern — The Safety Net

Every rule can define `FalsePositivePatterns`:

```go
var fpPatterns = []*regexp.Regexp{
    regexp.MustCompile(`(?i)(example|sample|test|dummy|fake|placeholder|your[_-])`),
    regexp.MustCompile(`(?i)(xxxx|yyyy|0000|1234|abcd)`),
    regexp.MustCompile(`\$\{[^}]+\}`),    // ${VAR} template syntax
    regexp.MustCompile(`\{\{[^}]+\}\}`),   // {{VAR}} template syntax
}
```

### RuleSet Thread Safety

```mermaid
sequenceDiagram
    participant G1 as Goroutine 1 (Scanner)
    participant RS as RuleSet (sync.RWMutex)
    participant G2 as Goroutine 2 (Scanner)

    G1->>RS: RLock() — read rules
    G2->>RS: RLock() — read rules (concurrent reads OK!)
    G1->>RS: Rules() → returns slice
    G2->>RS: Rules() → returns slice
    G1->>RS: RUnlock()
    G2->>RS: RUnlock()

    Note over RS: Multiple readers can access<br/>rules simultaneously.<br/>Only Add() requires full Lock().
```

### Interview Explanation

> "The rule engine is a **compiled regex database**. At startup, `DefaultRuleSet()` loads all 331 rules — each regex is pre-compiled with `regexp.MustCompile()`, so there's zero compilation overhead at scan time. Rules are stored in a slice (for iteration during scanning) AND a hash map `byID` (for O(1) lookup). The `RuleSet` uses a `sync.RWMutex` — multiple scanner goroutines can read rules concurrently (`RLock()`), but adding rules requires an exclusive write lock (`Lock()`). Each rule has a `BaseConfidence` score that reflects how specific its pattern is: AWS keys (`AKIA[0-9A-Z]{16}`) get 0.95 because that format is nearly impossible to produce accidentally, while generic password patterns might get 0.60."

---

## 9. Detection Engine — The Brain

### Engine Architecture

```mermaid
graph TD
    subgraph "Engine Struct"
        RS["RuleSet<br/>331 compiled regex rules"]
        MU["sync.RWMutex<br/>Thread-safe finding counter"]
        CFG["DetectionConfig<br/>Confidence, entropy, severity settings"]
        FC["findingCount uint64<br/>Monotonic counter for unique IDs"]
    end

    subgraph "ScanContent() Flow"
        INPUT["Input: ScanRequest<br/>{Content, Source}"]
        VALIDATE["Validate: content not empty,<br/>build exclusion sets"]
        REGEX["Phase 1: Regex Scanning<br/>Loop through all 331 rules"]
        ENTROP["Phase 2: Entropy Detection<br/>Find high-entropy words"]
        DEDUP["Deduplication<br/>seen map: hash:ruleID:line → bool"]
        FILTER["Filter<br/>min confidence, min severity"]
        OUTPUT["Output: ScanResult<br/>{Findings, TotalFindings, CountBySeverity}"]
    end

    INPUT --> VALIDATE --> REGEX --> ENTROP --> DEDUP --> FILTER --> OUTPUT

    RS --> REGEX
    CFG --> FILTER
    MU --> FC

    style INPUT fill:#339af0,stroke:#333,color:#fff
    style OUTPUT fill:#51cf66,stroke:#333
    style REGEX fill:#ff6b6b,stroke:#333,color:#fff
    style ENTROP fill:#748ffc,stroke:#333,color:#fff
```

### Dual Detection Mode — Why Two Engines?

```mermaid
graph LR
    subgraph "Regex Engine"
        R1["Known patterns<br/>AKIA... → AWS Key"]
        R2["Precise matches<br/>Low false positives"]
        R3["Can't catch unknown formats<br/>Blind to custom tokens"]
    end

    subgraph "Entropy Engine"
        E1["Unknown patterns<br/>a7f2b9c1e4d3... → suspicious"]
        E2["Catches novel secrets<br/>Custom API tokens"]
        E3["Higher false positive rate<br/>Needs keyword context"]
    end

    subgraph "Combined Result"
        C1["Best of both worlds:<br/>Known patterns caught precisely,<br/>Unknown patterns caught probabilistically"]
    end

    R1 & E1 --> C1

    style R1 fill:#ff6b6b,stroke:#333,color:#fff
    style E1 fill:#748ffc,stroke:#333,color:#fff
    style C1 fill:#51cf66,stroke:#333
```

### matchRule() — Regex Matching Deep Dive

```mermaid
flowchart TD
    START["matchRule(content, rule, source)"] --> COMPILE["FindAllStringSubmatchIndex()<br/>Find all regex matches with positions"]
    COMPILE --> LOOP{For each match}

    LOOP --> EXTRACT["Extract matched text:<br/>Prefer capture group 1 over full match<br/>(e.g., capture password FROM password=secret)"]
    EXTRACT --> LINE["Calculate line number:<br/>Count newlines before match position"]
    LINE --> CONTEXT["Get context:<br/>±2 lines around the match"]
    CONTEXT --> CONFIDENCE["computeConfidence()<br/>5-factor scoring"]
    CONFIDENCE --> BUILD["Build Finding struct:<br/>ID, SecretType, RuleID, Severity,<br/>Confidence, Entropy, Source, etc."]
    BUILD --> APPEND["Append to findings"]
    APPEND --> LOOP

    LOOP -->|done| RETURN["Return all findings"]

    style START fill:#339af0,stroke:#333,color:#fff
    style CONFIDENCE fill:#ffd43b,stroke:#333,stroke-width:2px
    style EXTRACT fill:#ff6b6b,stroke:#333,color:#fff
```

### Capture Group Extraction — Why It Matters

```
Rule pattern:  (?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]+)
                                                     ↑ group 1 = secret value only

Input text:    password = "SuperSecret123"

Full match:    password = "SuperSecret123"     ← includes keyword (not useful)
Group 1:       SuperSecret123                  ← just the secret (what we want!)
```

- The engine **prefers capture group 1** over the full match
- This means rules can match the keyword + secret but only extract the secret
- Enables better hashing, redaction, and deduplication

### Deduplication — The `seen` Map

```mermaid
graph TD
    F1["Finding: AWS Key at line 10<br/>Hash: abc123, Rule: aws-access-key"]
    F2["Finding: AWS Key at line 10<br/>Hash: abc123, Rule: aws-access-key"]
    F3["Finding: AWS Key at line 25<br/>Hash: abc123, Rule: aws-access-key"]

    SEEN["seen map<br/>key = 'hash:ruleID:line'"]

    F1 --> SEEN
    SEEN -->|"abc123:aws-access-key:10<br/>NOT in map → KEEP"| KEEP1["✓ Keep"]

    F2 --> SEEN
    SEEN -->|"abc123:aws-access-key:10<br/>ALREADY in map → DROP"| DROP1["✗ Drop"]

    F3 --> SEEN
    SEEN -->|"abc123:aws-access-key:25<br/>NOT in map (diff line) → KEEP"| KEEP2["✓ Keep"]

    style KEEP1 fill:#51cf66,stroke:#333
    style KEEP2 fill:#51cf66,stroke:#333
    style DROP1 fill:#ff6b6b,stroke:#333,color:#fff
```

- **Why 3-part key?** Same secret on different lines is a separate finding. Same secret with different rules (e.g., regex + entropy) should count once per rule.

### ID Generation — Thread-Safe Monotonic Counter

```go
func (e *Engine) generateID() string {
    e.mu.Lock()                              // Exclusive lock
    e.findingCount++                         // Increment monotonic counter
    count := e.findingCount                  // Copy to local variable
    e.mu.Unlock()                            // Release immediately
    return fmt.Sprintf("CVF-%d-%d",          // Format: CVF-{unixmilli}-{count}
        time.Now().UnixMilli(), count)
}
```

- **Why mutex?** Multiple goroutines in the worker pool call `generateID()` concurrently. Without locking, two goroutines could get the same ID (race condition).
- **Why not atomic?** We could use `atomic.AddUint64()`, but the mutex approach is clearer and the lock is held for nanoseconds — no contention concern.

### Interview Explanation

> "The detection engine uses a **dual-mode approach**: regex rules for known patterns, Shannon entropy for unknown ones. The `ScanContent()` method runs ALL 331 regex rules against the input, then runs entropy detection on the same input. Results are deduplicated using a composite key (`hash:ruleID:line`) in a hash map. The engine uses `FindAllStringSubmatchIndex` instead of `FindAllString` because we need byte positions for capture group extraction — rules prefer capturing just the secret value, not the surrounding keyword. Each finding gets a unique ID via a mutex-protected monotonic counter. The ID format `CVF-{timestamp}-{counter}` is both human-readable and sortable."

---

## 10. Shannon Entropy Analysis — Information Theory in Practice

### What is Shannon Entropy?

Shannon entropy measures **information density** — how unpredictable a string is. A password like `aaaaaa` has zero entropy (completely predictable). A string like `a7f2b9c1` has high entropy (each character is surprising).

### The Math

$$H = -\sum_{i=1}^{n} p(x_i) \cdot \log_2 p(x_i)$$

Where:
- $H$ = entropy in bits
- $p(x_i)$ = probability of character $x_i$ (frequency / total length)
- $n$ = number of unique characters

### Entropy Calculation Visualization

```mermaid
graph TD
    INPUT["Input: 'a7f2b9c1e4d3'<br/>(12 characters)"]

    FREQ["Build Frequency Map:<br/>a→1, 7→1, f→1, 2→1,<br/>b→1, 9→1, c→1, 1→1,<br/>e→1, 4→1, d→1, 3→1"]

    CALC["Calculate Probabilities:<br/>Each char: 1/12 = 0.0833<br/>12 unique characters"]

    ENTROPY["H = -12 × (1/12 × log₂(1/12))<br/>H = -12 × (0.0833 × -3.585)<br/>H = 3.585 bits per character"]

    NORMALIZE["Normalize by charset:<br/>Detected: Hex charset<br/>Max possible: log₂(16) = 4.0<br/>Normalized: 3.585/4.0 = 0.896"]

    SCORE["EntropyScore:<br/>0.7 × normalized + 0.3 × lengthFactor<br/>= 0.7 × 0.896 + 0.3 × 1.0<br/>= 0.927"]

    VERDICT["Score 0.927 > 0.5 threshold<br/>→ HIGH ENTROPY DETECTED"]

    INPUT --> FREQ --> CALC --> ENTROPY --> NORMALIZE --> SCORE --> VERDICT

    style INPUT fill:#339af0,stroke:#333,color:#fff
    style VERDICT fill:#ff6b6b,stroke:#333,color:#fff
```

### Charset-Specific Thresholds

```mermaid
graph LR
    subgraph "Charset Detection"
        HEX["Hex<br/>[0-9a-fA-F]<br/>e.g., a7f2b9c1"]
        B64["Base64<br/>[A-Za-z0-9+/=]<br/>e.g., aGVsbG8="]
        B64URL["Base64URL<br/>[A-Za-z0-9_-]<br/>e.g., eyJhbGci"]
        ALNUM["Alphanumeric<br/>[A-Za-z0-9]<br/>e.g., MyToken42"]
        ASCII["PrintableASCII<br/>All printable<br/>e.g., p@ss!w0rd"]
    end

    subgraph "Thresholds"
        T_HEX["Suspicious: 3.0<br/>Likely: 3.5"]
        T_B64["Suspicious: 4.0<br/>Likely: 4.5"]
        T_GEN["Suspicious: 4.5<br/>Likely: 5.0"]
    end

    HEX --> T_HEX
    B64 --> T_B64
    B64URL --> T_B64
    ALNUM --> T_GEN
    ASCII --> T_GEN
```

**Why different thresholds per charset?**
- Hex has only 16 characters → maximum entropy is $\log_2(16) = 4.0$ bits
- Base64 has 64 characters → maximum entropy is $\log_2(64) = 6.0$ bits
- A hex string at 3.5 bits is almost maxed out (87% of max), while a Base64 string at 3.5 bits is mediocre (58% of max)
- Per-charset thresholds normalize for these differences

### ExtractHighEntropyWords Flow

```mermaid
flowchart TD
    INPUT["Input line: api_key = 'a7f2b9c1e4d3f5g6'"]
    SPLIT["splitOnDelimiters()<br/>Split on: spaces, quotes,<br/>colons, equals, commas,<br/>braces, brackets"]
    WORDS["Words: ['api_key', '=', 'a7f2b9c1e4d3f5g6']"]
    FILTER["Filter by minLength (12+)"]
    KEPT["Candidates: ['a7f2b9c1e4d3f5g6']"]
    CHARSET["DetectCharset()<br/>→ Hex"]
    THRESHOLD["Threshold(Hex) → 3.0"]
    ENTROPY["Shannon('a7f2b9c1e4d3f5g6')<br/>→ 3.75 bits"]
    CHECK{3.75 > 3.0?}
    YES["✓ High entropy word detected!<br/>HighEntropyMatch{<br/>  Word, Score, Charset, Line}"]
    NO["✗ Skip — not suspicious"]

    INPUT --> SPLIT --> WORDS --> FILTER --> KEPT --> CHARSET --> THRESHOLD --> ENTROPY --> CHECK
    CHECK -->|yes| YES
    CHECK -->|no| NO

    style YES fill:#ff6b6b,stroke:#333,color:#fff
    style NO fill:#51cf66,stroke:#333
```

### EntropyScore — Composite Scoring

```
EntropyScore = 0.7 × normalized_entropy + 0.3 × length_factor

Where:
- normalized_entropy = Shannon(s) / max_entropy_for_charset
  - For hex: max = 4.0, for base64: max = 6.0
  - Measures how close to "perfectly random" the string is

- length_factor = min(1.0, len(s) / 32.0)
  - 32+ characters → factor = 1.0 (full weight)
  - 16 characters → factor = 0.5 (half weight)
  - Longer strings are more likely to be real secrets
```

### Interview Explanation

> "We use Shannon entropy from information theory to detect secrets that don't match any known regex pattern. The idea is that real secrets (API keys, random passwords) have high entropy — each character is unpredictable — while normal code has low entropy — variable names, English words. The formula is $H = -\sum p(x) \log_2 p(x)$. But raw entropy isn't enough: a hex string with 3.5 bits is nearly maximal (max is 4.0), while a Base64 string with 3.5 bits is mediocre (max is 6.0). So we use **charset-specific thresholds** — we first detect whether the string is hex, base64, or alphanumeric, then apply the appropriate threshold. The final `EntropyScore` is a weighted composite: 70% entropy quality and 30% length factor, because longer high-entropy strings are more likely to be real secrets."

---

## 11. Confidence Scoring — 5-Factor Algorithm

### The 5 Factors

```mermaid
graph TD
    BASE["Factor 1: Base Confidence<br/>From rule definition<br/>e.g., AWS Key = 0.95"]

    ENTROPY["Factor 2: Entropy Adjustment<br/>High entropy: +0.10 boost<br/>Low entropy: -0.20 penalty"]

    KEYWORD["Factor 3: Keyword Proximity<br/>Search ±200 chars for keywords<br/>Up to +0.10 boost<br/>e.g., 'password' near the match"]

    FP["Factor 4: False Positive Check<br/>Match against FP patterns<br/>-0.25 penalty if matched<br/>e.g., contains 'example'"]

    PLACEHOLDER["Factor 5: Placeholder Check<br/>Check for placeholder content<br/>-0.40 penalty<br/>e.g., 'xxxx', 'changeme', 'test'"]

    CLAMP["Final: Clamp to [0.0, 1.0]<br/>Round to 2 decimal places"]

    BASE --> ENTROPY --> KEYWORD --> FP --> PLACEHOLDER --> CLAMP

    style BASE fill:#339af0,stroke:#333,color:#fff
    style ENTROPY fill:#748ffc,stroke:#333,color:#fff
    style KEYWORD fill:#51cf66,stroke:#333
    style FP fill:#ffd43b,stroke:#333
    style PLACEHOLDER fill:#ff6b6b,stroke:#333,color:#fff
    style CLAMP fill:#868e96,stroke:#333,color:#fff
```

### Scoring Walk-Through Example

```mermaid
graph LR
    subgraph "Input"
        MATCH["Match: AKIAIOSFODNN7EXAMPLE<br/>Rule: aws-access-key<br/>Context: aws_key = 'AKIAIOSFODNN7EXAMPLE'"]
    end

    subgraph "Factor 1"
        F1["Base: 0.95"]
    end

    subgraph "Factor 2"
        F2["Shannon = 3.42 bits (hex-like)<br/>High entropy → +0.10<br/>Running: 0.95 + 0.10 = 1.05"]
    end

    subgraph "Factor 3"
        F3["'aws' found in ±200 chars<br/>Keyword hit → +0.05<br/>Running: 1.05 + 0.05 = 1.10"]
    end

    subgraph "Factor 4"
        F4["'EXAMPLE' matches FP pattern!<br/>→ -0.25<br/>Running: 1.10 - 0.25 = 0.85"]
    end

    subgraph "Factor 5"
        F5["'EXAMPLE' is placeholder-like<br/>→ -0.40<br/>Running: 0.85 - 0.40 = 0.45"]
    end

    subgraph "Result"
        FINAL["Clamp [0.0, 1.0]: 0.45<br/>Round: 0.45<br/>Final confidence: 0.45"]
    end

    MATCH --> F1 --> F2 --> F3 --> F4 --> F5 --> FINAL

    style MATCH fill:#339af0,stroke:#333,color:#fff
    style FINAL fill:#ffd43b,stroke:#333,stroke-width:2px
```

In this example, an AWS key with "EXAMPLE" in it gets penalized twice (FP pattern + placeholder check), dropping from 0.95 to 0.45 — correctly identified as likely a false positive.

### computeConfidence() Implementation Details

| Factor | Condition | Adjustment | Reasoning |
|--------|-----------|------------|-----------|
| **Entropy Boost** | Entropy score > 0.5 | `+0.10` | High-entropy matches are more likely real secrets |
| **Entropy Penalty** | Entropy score < 0.3 | `-0.20` | Low-entropy matches might be constants, not secrets |
| **Keyword Proximity** | Keywords found within ±200 chars | `+0.02 to +0.10` | Secret keywords like "password", "token", "key" near the match = good signal |
| **False Positive** | FP pattern matches | `-0.25` | Contains "example", "sample", template syntax |
| **Placeholder** | Looks like placeholder | `-0.40` | Contains "xxxx", "changeme", "test", all-same-char |
| **Short match** | Length < 8 chars | `-0.10` | Very short strings are less likely real secrets |
| **Long match** | Length > 40 chars | `+0.05` | Long high-entropy strings are almost certainly secrets |

### isLikelyPlaceholder() Checks

```mermaid
graph TD
    INPUT["Input string: 'test_key_12345'"]

    C1{"Contains 'xxxx' or 'yyyy'?"}
    C2{"Contains 'example' or 'sample'?"}
    C3{"Contains 'changeme' or 'replace'?"}
    C4{"Contains 'test' or 'dummy'?"}
    C5{"All same character?<br/>'aaaaaaa'"}
    C6{"All zeros? '0000000'"}

    C1 -->|no| C2
    C2 -->|no| C3
    C3 -->|no| C4
    C4 -->|yes| RESULT["✓ Is a placeholder<br/>Penalty: -0.40"]

    C1 -->|yes| RESULT
    C2 -->|yes| RESULT
    C3 -->|yes| RESULT
    C5 -->|yes| RESULT
    C6 -->|yes| RESULT

    C4 -->|no| C5
    C5 -->|no| C6
    C6 -->|no| NOT["✗ Not a placeholder"]

    style RESULT fill:#ff6b6b,stroke:#333,color:#fff
    style NOT fill:#51cf66,stroke:#333
```

### isLikelyIdentifier() Checks

```mermaid
graph TD
    INPUT["Input: 'myVariableName'"]

    C1{"All letters/underscores?<br/>(looks like variable name)"}
    C2{"CamelCase pattern?<br/>lowercase followed by UPPERCASE"}
    C3{"Contains snake_case?<br/>word_word pattern"}

    C1 -->|yes| ID["✓ Likely identifier, not a secret"]
    C2 -->|yes| ID
    C3 -->|yes| ID
    C1 -->|no| C2
    C2 -->|no| C3
    C3 -->|no| NOT["✗ Not an identifier — proceed"]

    style ID fill:#ffd43b,stroke:#333
    style NOT fill:#51cf66,stroke:#333
```

### Interview Explanation

> "The confidence scoring uses 5 independent factors that stack additively. Starting from a rule's `BaseConfidence` (how specific the regex pattern is), we adjust based on entropy quality (+0.10 or -0.20), keyword proximity (finding 'password' near the match boosts confidence), false positive patterns (-0.25 for 'example', 'sample', template syntax), and placeholder detection (-0.40 for 'changeme', 'xxxx', test data). The final score is clamped to [0.0, 1.0]. This multi-factor approach reduces false positives significantly — a real AWS key scores 0.95+ while `AKIAIOSFODNN7EXAMPLE` scores only 0.45 because it's penalized for containing 'EXAMPLE'. Users can adjust `MinConfidence` to balance precision vs. recall."

---

## 12. File Scanner — Concurrent I/O with Worker Pool

### Worker Pool Architecture

```mermaid
graph TD
    subgraph "FileScanner"
        WALK["filepath.Walk()<br/>Collect all file paths"]
        FILTER["Filter: skip excluded dirs,<br/>extensions, oversized files"]
        FILES["File paths slice:<br/>[file1, file2, ..., fileN]"]
    end

    subgraph "Worker Pool (scanFiles)"
        SEM["Semaphore Channel<br/>make(chan struct{}, 4)<br/>Limits to 4 concurrent goroutines"]
        WG["sync.WaitGroup<br/>Wait for all goroutines to finish"]

        G1["Goroutine 1<br/>ScanFile(file_a)"]
        G2["Goroutine 2<br/>ScanFile(file_b)"]
        G3["Goroutine 3<br/>ScanFile(file_c)"]
        G4["Goroutine 4<br/>ScanFile(file_d)"]
        G5["Goroutine 5<br/>(blocked on semaphore)"]
    end

    subgraph "Results Aggregation"
        MU["sync.Mutex<br/>Protects results slice"]
        RESULTS["[]ScanResult<br/>Thread-safe append"]
    end

    WALK --> FILTER --> FILES
    FILES --> SEM
    SEM --> G1 & G2 & G3 & G4
    G4 -.->|"G4 releases slot"| G5
    G1 & G2 & G3 & G4 --> MU
    MU --> RESULTS

    style SEM fill:#ff6b6b,stroke:#333,color:#fff
    style MU fill:#ffd43b,stroke:#333
    style WG fill:#748ffc,stroke:#333,color:#fff
```

### Worker Pool Code Pattern

```mermaid
sequenceDiagram
    participant Main as scanFiles()
    participant Sem as Semaphore (chan, cap=4)
    participant WG as WaitGroup
    participant G as Goroutines
    participant Mu as Mutex
    participant Results as []ScanResult

    Main->>Sem: sem := make(chan struct{}, 4)
    Main->>WG: wg := sync.WaitGroup{}

    loop For each file
        Main->>WG: wg.Add(1)
        Main->>G: go func(file) { ... }
        G->>Sem: sem <- struct{}{} (acquire slot)
        Note over G,Sem: Blocks if 4 goroutines already running
        G->>G: ScanFile(file) — read + scan
        G->>Mu: mu.Lock()
        G->>Results: append(results, scanResult)
        G->>Mu: mu.Unlock()
        G->>Sem: <-sem (release slot)
        G->>WG: wg.Done()
    end

    Main->>WG: wg.Wait() — block until all done
    Main->>Main: Return combined results
```

### File Filtering Pipeline

```mermaid
flowchart TD
    FILE["Incoming file path<br/>e.g., src/config/secrets.go"]

    CHECK1{"In ExcludeDirs?<br/>.git, node_modules,<br/>vendor, __pycache__,<br/>... (15 dirs)"}
    CHECK2{"File in ExcludeFiles?<br/>package-lock.json,<br/>yarn.lock, go.sum,<br/>... (7 files)"}
    CHECK3{"Extension in ExcludeExtensions?<br/>.exe, .png, .zip,<br/>... (30+ extensions)"}
    CHECK4{"Size > MaxFileSize?<br/>Default: 5 MB"}
    CHECK5{"Is binary content?<br/>Check first 512 bytes<br/>for null bytes"}
    CHECK6{"If IncludeExtensions set,<br/>extension matches?"}

    SCAN["✓ Proceed to scan"]
    SKIP["✗ Skip file"]

    FILE --> CHECK1
    CHECK1 -->|yes| SKIP
    CHECK1 -->|no| CHECK2
    CHECK2 -->|yes| SKIP
    CHECK2 -->|no| CHECK3
    CHECK3 -->|yes| SKIP
    CHECK3 -->|no| CHECK4
    CHECK4 -->|yes| SKIP
    CHECK4 -->|no| CHECK5
    CHECK5 -->|yes| SKIP
    CHECK5 -->|no| CHECK6
    CHECK6 -->|no match| SKIP
    CHECK6 -->|match or none set| SCAN

    style SCAN fill:#51cf66,stroke:#333
    style SKIP fill:#ff6b6b,stroke:#333,color:#fff
```

### Binary Detection — The 512-Byte Trick

```go
func isBinaryContent(data []byte) bool {
    checkLen := 512
    if len(data) < checkLen {
        checkLen = len(data)
    }
    for i := 0; i < checkLen; i++ {
        if data[i] == 0 {  // Null byte found
            return true    // Almost certainly binary
        }
    }
    return false
}
```

- **Why 512 bytes?** Matches the HTTP `content-type` sniffing spec. Text files virtually never contain null bytes. Checking the first 512 bytes catches binaries fast without reading the whole file.

### Interview Explanation

> "The file scanner uses a **channel-based semaphore** for concurrency control — `make(chan struct{}, workers)` creates a buffered channel that limits active goroutines to `workers` (default: 4). This is the Go idiom for a counting semaphore. Each goroutine sends to the channel before starting (acquiring a slot) and receives after finishing (releasing the slot). If all slots are full, the send blocks — natural backpressure. Results are aggregated into a shared slice protected by a `sync.Mutex`. The `sync.WaitGroup` ensures we don't return until all goroutines complete. Files are filtered through a multi-stage pipeline: directory exclusions, filename exclusions, extension exclusions, size limits, and binary detection. The binary check uses the same trick as HTTP content sniffing — look for null bytes in the first 512 bytes."

---

## 13. Post-Processing Pipeline — Chain of Responsibility

### Pipeline Architecture

```mermaid
graph TD
    subgraph "Pipeline Design"
        IFACE["Processor Interface<br/>Name() string<br/>Process(ctx, *Finding, *ScanMetadata) error"]

        P1["HashProcessor<br/>SHA-256 of raw secret"]
        P2["RedactProcessor<br/>Create masked preview"]
        P3["EnrichProcessor<br/>Add file type, env, category"]
        P4["FingerprintProcessor<br/>Create dedup fingerprint"]
        P5["SanitizeProcessor<br/>Clear raw secret"]

        PIPE["Pipeline struct<br/>mu sync.RWMutex<br/>processors []Processor"]
    end

    IFACE -.->|implements| P1
    IFACE -.->|implements| P2
    IFACE -.->|implements| P3
    IFACE -.->|implements| P4
    IFACE -.->|implements| P5

    PIPE --> P1
    PIPE --> P2
    PIPE --> P3
    PIPE --> P4
    PIPE --> P5

    style IFACE fill:#339af0,stroke:#333,color:#fff
    style PIPE fill:#ffd43b,stroke:#333,stroke-width:2px
```

### Default Pipeline Flow

```mermaid
graph LR
    INPUT["Finding<br/>(raw)"] --> H["1. Hash<br/>SHA-256<br/>of RawMatch"]
    H --> R["2. Redact<br/>Create masked<br/>preview"]
    R --> E["3. Enrich<br/>File type, env,<br/>category"]
    E --> FP["4. Fingerprint<br/>Cross-scan<br/>dedup ID"]
    FP --> S["5. Sanitize<br/>Clear RawMatch<br/>(zero-trust)"]
    S --> OUTPUT["Finding<br/>(safe to output)"]

    style INPUT fill:#ff6b6b,stroke:#333,color:#fff
    style OUTPUT fill:#51cf66,stroke:#333
    style S fill:#51cf66,stroke:#333,stroke-width:3px
```

### Stage 1: HashProcessor

```mermaid
graph LR
    RAW["RawMatch:<br/>'AKIAIOSFODNN7EXAMPLE'"]
    SHA["SHA-256(raw)"]
    HASH["SecretHash:<br/>'a3f2...c9d1'<br/>(64 hex chars)"]
    META["Metadata['sha256']:<br/>'a3f2...c9d1'"]

    RAW --> SHA --> HASH
    SHA --> META
```

**Why hash?**
- Allows comparing secrets across scans without storing actual values
- Two scans of the same repo can identify "is this the same secret?" by comparing hashes
- Hash is irreversible — even if output is leaked, the secret can't be recovered

### Stage 2: RedactProcessor

```mermaid
graph TD
    INPUT["RawMatch"] --> LEN{Length?}

    LEN -->|"> 12 chars"| LONG["first4 + '****' + last4<br/>'AKIAIOSFODNN7EXAMPLE'<br/>→ 'AKIA****MPLE'"]
    LEN -->|"5-12 chars"| MED["first2 + '****'<br/>'mypasswd'<br/>→ 'my****'"]
    LEN -->|"≤ 4 chars"| SHORT["'****'<br/>'abc' → '****'"]

    LONG --> OUT["RedactedMatch set"]
    MED --> OUT
    SHORT --> OUT

    style LONG fill:#ffd43b,stroke:#333
    style MED fill:#ffd43b,stroke:#333
    style SHORT fill:#ffd43b,stroke:#333
```

**Why these lengths?**
- `> 12`: showing 8 chars out of 12+ reveals < 67% — safe enough to identify the secret without exposing it
- `5-12`: showing 2 chars out of 5+ reveals < 40% — just enough to recognize which credential
- `≤ 4`: fully masked — can't afford to show anything

### Stage 3: EnrichProcessor

```mermaid
graph TD
    subgraph "classifyFileType() — 40+ mappings"
        EXT["File Extension"]
        EXT --> GO[".go → go-source"]
        EXT --> PY[".py → python-source"]
        EXT --> JS[".js → javascript-source"]
        EXT --> YML[".yml → yaml-config"]
        EXT --> ENV[".env → env-file"]
        EXT --> DOCKER["Dockerfile → dockerfile"]
        EXT --> TF[".tf → terraform"]
        EXT --> K8S[".yaml + 'kind:' → kubernetes-manifest"]
    end

    subgraph "detectEnvironment() — Pattern Matching"
        PATH["File Path"]
        PATH --> PROD["contains 'prod' → production"]
        PATH --> STAGING["contains 'staging' → staging"]
        PATH --> DEV["contains 'dev' → development"]
        PATH --> CI["contains 'ci','pipeline' → ci"]
        PATH --> TEST["contains 'test','spec' → test"]
    end

    subgraph "categorizeSecret() — By SecretType Prefix"
        TYPE["SecretType"]
        TYPE --> CLOUD["AWS*, GCP*, Azure* → cloud"]
        TYPE --> DB["Database*, Mongo*, Redis* → database"]
        TYPE --> AUTH["JWT*, OAuth*, Auth0* → auth"]
        TYPE --> SCM["GitHub*, GitLab* → scm"]
        TYPE --> PAY["Stripe*, PayPal* → payment"]
        TYPE --> AIML["OpenAI*, Anthropic* → ai-ml"]
    end
```

### Stage 4: FingerprintProcessor

```
Fingerprint = SHA-256("ruleID:location:line:secretHash")

Example:
  ruleID    = "aws-access-key"
  location  = "config/settings.go"
  line      = 42
  secretHash = "a3f2...c9d1"

  Input:  "aws-access-key:config/settings.go:42:a3f2...c9d1"
  Output: "b7e4...f2a1" (SHA-256)
```

**Why fingerprint?**
- **Cross-scan deduplication**: Run CredVigil on Monday, then again Tuesday — fingerprints let you identify "this is the same finding, not a new one"
- **Combines location + value**: Same secret in a different file gets a different fingerprint (it's a separate concern)

### Stage 5: SanitizeProcessor — Zero-Trust Enforcement

```mermaid
graph LR
    BEFORE["Finding.RawMatch =<br/>'AKIAIOSFODNN7EXAMPLE'"]
    SANITIZE["SanitizeProcessor<br/>finding.ClearRawMatch()"]
    AFTER["Finding.RawMatch = ''<br/>Finding.RedactedMatch = 'AKIA****MPLE'<br/>Finding.SecretHash = 'a3f2...c9d1'"]

    BEFORE --> SANITIZE --> AFTER

    style BEFORE fill:#ff6b6b,stroke:#333,color:#fff
    style AFTER fill:#51cf66,stroke:#333
```

**The zero-trust guarantee:**
- After `Sanitize`, the raw secret is gone from memory
- Output only contains the hash (for comparison) and redacted form (for display)
- Even if someone intercepts the JSON output, they cannot recover the secret

### ProcessFindings() — Failure Handling

```mermaid
sequenceDiagram
    participant PF as ProcessFindings()
    participant H as Hash
    participant R as Redact
    participant E as Enrich
    participant FP as Fingerprint
    participant S as Sanitize

    loop For each Finding
        PF->>H: Process(finding)
        H-->>PF: nil (success)
        PF->>R: Process(finding)
        R-->>PF: nil (success)
        PF->>E: Process(finding)
        E-->>PF: error! (enrichment failed)
        Note over PF: Finding is DROPPED<br/>from results.<br/>Better to lose a finding<br/>than output incomplete data.
    end
```

**Fail-safe design**: If any processor returns an error, the finding is dropped. It's better to lose a finding than to output one with a raw secret (e.g., if `Sanitize` fails).

### Pipeline Extensibility

```mermaid
graph TD
    subgraph "Adding a Custom Processor"
        CUSTOM["VerifyProcessor<br/>(future: call AWS STS API)"]
        INSERT["pipeline.InsertProcessor(idx, proc)<br/>or pipeline.AddProcessor(proc)"]
    end

    subgraph "Modified Pipeline"
        P1["1. Hash"]
        P2["2. Redact"]
        P3["3. Enrich"]
        NEW["4. Verify (NEW!)"]
        P4["5. Fingerprint"]
        P5["6. Sanitize"]
    end

    CUSTOM --> INSERT
    INSERT --> P1 --> P2 --> P3 --> NEW --> P4 --> P5

    style NEW fill:#ffd43b,stroke:#333,stroke-width:2px
```

The `Processor` interface has only 2 methods — `Name()` and `Process()` — making it trivial to add new stages.

### Interview Explanation

> "The pipeline implements the **Chain of Responsibility** pattern. Each processor transforms the Finding and passes it to the next. The order matters: Hash must run before Sanitize (because it needs the raw secret), Redact must run before Sanitize (same reason), and Sanitize must be LAST (to ensure zero-trust). The pipeline uses a `sync.RWMutex` so it's safe to process findings from multiple goroutines. If any processor fails, the finding is dropped — this is a **fail-safe** design: we'd rather lose a finding than output one with the raw secret intact. The `Processor` interface is the **Strategy pattern** — each processor encapsulates a specific algorithm, and they can be composed in any order via `InsertProcessor()` or `AddProcessor()`."

---

## 14. Git Integration — History Archaeology

### Git Scanning Architecture

```mermaid
graph TD
    subgraph "Entry Points"
        LOCAL["ScanLocalRepo(path)<br/>Existing repo on disk"]
        REMOTE["ScanRemoteRepo(url)<br/>Clone → scan → cleanup"]
    end

    subgraph "Repository Management"
        OPEN["OpenRepository(path)<br/>Verify .git, find root"]
        CLONE["CloneRepository(url, opts)<br/>git clone to /tmp/<br/>Auto-cleanup on defer"]
        REPO["Repository struct<br/>{Path, isCloned, remoteURL}"]
    end

    subgraph "Commit Walking"
        WALKER["CommitWalker<br/>{repo, ScanOptions}"]
        COUNT["CountCommits()<br/>git log --oneline | wc -l"]
        LIST["ListCommits()<br/>Custom %x00 delimited format"]
        WALK["WalkCommits(callback)<br/>For each commit → GetDiff → callback"]
    end

    subgraph "Diff Parsing"
        GETDIFF["GetDiff(hash)<br/>git diff parent..commit"]
        PARSE["ParseDiff(output)<br/>Unified diff → DiffEntry[]"]
        FILTER["FilterDiffEntries<br/>Include/exclude patterns"]
    end

    subgraph "Detection Integration"
        BUILD["buildScanContent(entry)<br/>Join added lines"]
        SCAN["engine.ScanContent(request)<br/>Regex + entropy"]
        ADJUST["adjustLineNumbers()<br/>Map scan lines → file lines"]
        PIPELINE["pipeline.ProcessResult()<br/>Hash, redact, enrich..."]
    end

    LOCAL --> OPEN --> REPO
    REMOTE --> CLONE --> REPO
    REPO --> WALKER
    WALKER --> COUNT
    WALKER --> LIST
    WALKER --> WALK
    WALK --> GETDIFF --> PARSE --> FILTER --> BUILD
    BUILD --> SCAN --> ADJUST --> PIPELINE

    style WALKER fill:#339af0,stroke:#333,color:#fff
    style SCAN fill:#ff6b6b,stroke:#333,color:#fff
    style CLONE fill:#51cf66,stroke:#333
```

### Commit Walking Strategy

```mermaid
sequenceDiagram
    participant GS as GitScanner
    participant CW as CommitWalker
    participant Git as git CLI (os/exec)
    participant Engine as Detection Engine
    participant Pipe as Pipeline

    GS->>CW: CountCommits()
    CW->>Git: git log --oneline
    Git-->>CW: 150 commits
    CW-->>GS: 150

    GS->>CW: WalkCommits(callback)
    CW->>Git: git log --format="%H%x00%h%x00..."
    Git-->>CW: Parsed commit list

    loop For each commit (oldest → newest)
        CW->>CW: Skip merge commits (unless opted in)
        CW->>Git: git diff parent^..commit --unified=0
        Git-->>CW: Unified diff output
        CW->>CW: ParseDiff() → DiffEntry[]
        CW->>CW: FilterDiffEntries() → filtered
        CW->>GS: callback(commit, entries, index)

        GS->>Engine: ScanContent(addedLines)
        Engine-->>GS: findings

        GS->>GS: adjustLineNumbers()
        GS->>Pipe: ProcessResult()
        Pipe-->>GS: processed findings

        GS->>GS: Aggregate into GitScanResult
    end

    GS-->>GS: Return GitScanResult
```

### Diff Parsing — Only Added Lines Matter

```mermaid
graph TD
    DIFF["Unified Diff Input"]

    HEADER["diff --git a/config.go b/config.go<br/>→ Extract file path"]
    TYPE["new file / deleted file / rename<br/>→ Determine change type (A/D/M/R)"]
    HUNK["@@ -10,5 +20,8 @@<br/>→ Parse new line start (20)"]

    PLUS["+api_key = 'sk-abc123'<br/>→ ADDED LINE → Store in AddedLines[20]"]
    MINUS["-old_config = true<br/>→ DELETED LINE → IGNORE"]
    SPACE[" context_line<br/>→ CONTEXT → increment line counter"]

    DIFF --> HEADER --> TYPE --> HUNK
    HUNK --> PLUS
    HUNK --> MINUS
    HUNK --> SPACE

    style PLUS fill:#51cf66,stroke:#333
    style MINUS fill:#ff6b6b,stroke:#333,color:#fff
    style SPACE fill:#868e96,stroke:#333,color:#fff
```

**Why only added lines?**
- We care about **what was introduced**, not what was removed
- A deleted secret was once visible in the output — it's captured when scanning the commit where it was added
- This halves the content to scan, improving performance

### Line Number Adjustment

```
Diff content:        Actual file:
Line 1: api_key      → Line 20 (hunk starts at +20)
Line 2: = 'secret'   → Line 21
Line 3: db_pass      → Line 25 (gap from deleted lines)

adjustLineNumbers() maps:
  scan_line=1 → file_line=20
  scan_line=2 → file_line=21
  scan_line=3 → file_line=25
```

### ScanOptions — Flexible Git Scanning

| Option | Default | Purpose |
|--------|---------|---------|
| `Branch` | HEAD | Which branch to scan |
| `SinceCommit` | "" | Only scan commits after this hash |
| `UntilCommit` | "" | Only scan up to this hash |
| `MaxCommits` | 0 (all) | Limit number of commits scanned |
| `Depth` | 0 (full) | Clone depth for remote repos |
| `AllBranches` | false | Scan every branch, not just current |
| `MaxDiffSize` | 1MB | Skip massive diffs (generated files) |
| `IncludeMerges` | false | Skip merge commits by default |

### Context Cancellation

```mermaid
graph TD
    CTX["context.WithCancel(parentCtx)"]
    WALK["WalkCommits loop"]
    CHECK{"select { case <-ctx.Done(): }"}

    CTX --> WALK
    WALK --> CHECK
    CHECK -->|cancelled| STOP["Return ctx.Err()<br/>Graceful shutdown"]
    CHECK -->|not cancelled| CONTINUE["Process commit<br/>Continue loop"]
    CONTINUE --> CHECK

    style STOP fill:#ff6b6b,stroke:#333,color:#fff
    style CONTINUE fill:#51cf66,stroke:#333
```

### Interview Explanation

> "The git scanner is a **façade** over the git CLI (`os/exec`). We chose CLI over libgit2 to keep the project dependency-free — git is already installed on every developer machine. The architecture has 4 layers: `Repository` (open/clone/cleanup), `CommitWalker` (iterate history), diff parser (extract added lines), and `GitScanner` (orchestrate everything). The walker uses a **callback pattern** — `WalkCommits(fn)` calls a function for each commit, enabling streaming processing without loading all commits into memory. Only ADDED lines are scanned because we care about what was introduced, not removed. Merge commits are skipped by default because they duplicate content from branch commits. Context cancellation enables graceful shutdown mid-scan — useful for CI timeouts. The `CloneRepository` function clones to a temp directory and the caller uses `defer repo.Cleanup()` to ensure cleanup — this is the **RAII pattern** in Go (Resource Acquisition Is Initialization)."

---

## 15. File Watcher — Real-Time Monitoring

### Watcher Architecture

```mermaid
graph TD
    subgraph "Watcher Components"
        FSN["fsnotify.Watcher<br/>OS-level file system events<br/>Linux: inotify<br/>macOS: kqueue/FSEvents<br/>Windows: ReadDirectoryChanges"]
        CFG["Config<br/>Paths, Recursive, Debounce,<br/>Exclude patterns"]
        HANDLER["Handler function<br/>Callback on file change"]
        STATS["Stats struct<br/>EventsReceived, Emitted,<br/>Dropped, DirsWatched"]
    end

    subgraph "Event Loop"
        RECV["Receive fsnotify event"]
        SKIP{"shouldSkip()?<br/>Check exclusions"}
        DIR{"New directory?<br/>fsnotify.Create + IsDir()"}
        DEBOUNCE{"Debounce check<br/>Same file within 500ms?"}
        MAP["Map event type:<br/>Create→CREATED<br/>Write→MODIFIED<br/>Remove→DELETED<br/>Rename→RENAMED"]
        DISPATCH["go handler(event)<br/>Non-blocking dispatch"]
    end

    FSN --> RECV
    RECV --> SKIP
    SKIP -->|yes| DROP["EventsDropped++"]
    SKIP -->|no| DIR
    DIR -->|yes| WATCH["addPath(dir)<br/>Recursive watch"]
    DIR -->|no| DEBOUNCE
    DEBOUNCE -->|yes| DROP2["EventsDropped++"]
    DEBOUNCE -->|no| MAP
    MAP --> DISPATCH

    style FSN fill:#339af0,stroke:#333,color:#fff
    style DEBOUNCE fill:#ffd43b,stroke:#333
    style DISPATCH fill:#51cf66,stroke:#333
```

### Debouncing — Why It's Essential

```mermaid
sequenceDiagram
    participant FS as File System
    participant W as Watcher
    participant DB as Debounce Map
    participant H as Handler

    Note over FS: User saves file in editor
    FS->>W: CREATE temp.go~ (event 1)
    FS->>W: WRITE config.go (event 2)
    FS->>W: WRITE config.go (event 3, 10ms later)
    FS->>W: CHMOD config.go (event 4, 20ms later)
    FS->>W: REMOVE temp.go~ (event 5)

    W->>DB: Check config.go → not in map
    DB-->>W: Not debounced
    W->>H: Handler(MODIFIED, config.go)
    W->>DB: Record config.go = now

    W->>DB: Check config.go → 10ms ago
    DB-->>W: DEBOUNCED (< 500ms) → DROP

    W->>DB: Check config.go → 20ms ago
    DB-->>W: DEBOUNCED (< 500ms) → DROP

    Note over W: Result: 1 handler call instead of 3
```

**Why debounce?**
- A single "save" in an editor generates 3-5 filesystem events
- Without debouncing, we'd scan the same file 3-5 times
- 500ms default is tuned for editor save behavior

### Recursive Directory Watching

```mermaid
graph TD
    ROOT["Watch: /project"]

    WALK["filepath.Walk()"]
    CHECK{"shouldSkipDir()?"}

    SRC["→ Watch /project/src"]
    PKG["→ Watch /project/src/pkg"]
    CMD["→ Watch /project/src/cmd"]
    GIT["→ Skip .git (excluded)"]
    MODULES["→ Skip node_modules (excluded)"]

    ROOT --> WALK
    WALK --> CHECK
    CHECK -->|not excluded| SRC & PKG & CMD
    CHECK -->|excluded| GIT & MODULES

    NEW["Runtime: new dir created<br/>/project/src/newpkg"]
    AUTO["Auto-watch:<br/>fsnotify.Create + IsDir()<br/>→ addPath(newpkg)"]

    NEW --> AUTO

    style GIT fill:#ff6b6b,stroke:#333,color:#fff
    style MODULES fill:#ff6b6b,stroke:#333,color:#fff
    style AUTO fill:#51cf66,stroke:#333
```

### Stats — Observable Monitoring

```go
type Stats struct {
    mu             sync.RWMutex   // Reader-writer lock
    EventsReceived uint64         // Total OS events received
    EventsEmitted  uint64         // Events passed to handler
    EventsDropped  uint64         // Events filtered or debounced
    DirsWatched    int            // Active directory watches
    StartedAt      time.Time      // When watcher started
}
```

- `Snapshot()` uses `RLock()` to return a consistent copy — safe for concurrent access
- Drop rate = `EventsDropped / EventsReceived` — if high, filtering is working well

### Interview Explanation

> "The file watcher uses **fsnotify**, which wraps OS-specific APIs (Linux `inotify`, macOS `kqueue`/`FSEvents`, Windows `ReadDirectoryChanges`). The key challenge is **event deduplication** — a single file save in VS Code generates multiple events (write, chmod, temp file create/delete). We solve this with a map-based debounce: if we've seen an event for the same file path within 500ms, we drop it. New directories are auto-watched: when `fsnotify.Create` fires for a directory, we call `addPath()` recursively. The handler is dispatched in a goroutine (`go handler(event)`) to prevent slow handlers from blocking the event loop. The `Stats` struct uses `sync.RWMutex` — multiple goroutines can read stats concurrently, but only the event loop writes to them. This is the **Observer pattern** — the watcher observes filesystem events and notifies the handler."

---

## 16. Security Architecture — Zero-Trust Pipeline

### Threat Model

```mermaid
graph TD
    subgraph "Threats"
        T1["Secret in source code<br/>(the thing we detect)"]
        T2["Secret in scan output<br/>(the thing we prevent)"]
        T3["Secret in memory<br/>(the thing we clear)"]
        T4["Secret in logs<br/>(the thing we never write)"]
        T5["Cloned repo on disk<br/>(the thing we clean up)"]
    end

    subgraph "Mitigations"
        M1["Detection Engine<br/>331 rules + entropy"]
        M2["SanitizeProcessor<br/>ClearRawMatch()"]
        M3["Garbage Collection<br/>Go's GC reclaims memory"]
        M4["No logging of raw secrets<br/>Only hashes and redacted forms"]
        M5["repo.Cleanup() on defer<br/>os.RemoveAll(tmpDir)"]
    end

    T1 --> M1
    T2 --> M2
    T3 --> M3
    T4 --> M4
    T5 --> M5

    style T1 fill:#ff6b6b,stroke:#333,color:#fff
    style T2 fill:#ff6b6b,stroke:#333,color:#fff
    style M2 fill:#51cf66,stroke:#333
    style M5 fill:#51cf66,stroke:#333
```

### Security Pipeline — Defense in Depth

```mermaid
graph LR
    subgraph "Layer 1: Hash"
        H["SHA-256 of raw secret<br/>One-way: cannot reverse"]
    end

    subgraph "Layer 2: Redact"
        R["Masked preview<br/>Shows just enough to identify"]
    end

    subgraph "Layer 3: Sanitize"
        S["Clear raw secret<br/>RawMatch = '' permanently"]
    end

    subgraph "Layer 4: Output"
        O["Only hash + redacted form<br/>in text/JSON output"]
    end

    H --> R --> S --> O

    style H fill:#339af0,stroke:#333,color:#fff
    style R fill:#ffd43b,stroke:#333
    style S fill:#51cf66,stroke:#333
    style O fill:#868e96,stroke:#333,color:#fff
```

### Why Zero-Trust?

| Scenario | Without Zero-Trust | With Zero-Trust |
|----------|-------------------|-----------------|
| JSON output to CI log | Raw secrets visible in build logs | Only hashes and `AKIA****MPLE` in logs |
| Scan results shared with team | Email/Slack message contains real secrets | Only redacted forms shared |
| Output file compromised | Attacker gets all secrets | Attacker gets hashes (useless without preimage) |
| Finding stored in database | Database breach exposes secrets | Only fingerprints and metadata exposed |

### Interview Explanation

> "CredVigil follows a **zero-trust security model** — we assume that scan output will be stored insecurely (CI logs, Slack messages, databases). The pipeline guarantees that raw secrets NEVER appear in output. This is enforced architecturally: the `SanitizeProcessor` is the last pipeline stage and it calls `ClearRawMatch()`, which sets `RawMatch = \"\"`. Even if someone removes other processors, `Sanitize` ensures the raw value is cleared. The `HashProcessor` creates a SHA-256 hash for cross-scan comparison (are these the same secret?) without exposing the secret itself. For cloned repos, `Cleanup()` calls `os.RemoveAll()` to securely remove temporary files from disk. This is **defense in depth** — multiple independent layers, each preventing a different threat."

---

## 17. Concurrency Model — Goroutines, Channels & Mutexes

### Concurrency Primitives Used

```mermaid
graph TD
    subgraph "Goroutines"
        G1["FileScanner worker pool<br/>N goroutines per scan"]
        G2["Watcher handler dispatch<br/>go handler(event)"]
    end

    subgraph "Channels"
        C1["Semaphore channel<br/>make(chan struct{}, N)<br/>Limits concurrency"]
    end

    subgraph "sync.Mutex"
        M1["FileScanner results slice<br/>Protects append()"]
        M2["Engine.findingCount<br/>Protects ID generation"]
    end

    subgraph "sync.RWMutex"
        R1["RuleSet<br/>Concurrent read, exclusive write"]
        R2["Pipeline<br/>Concurrent read, exclusive write"]
        R3["Watcher.running<br/>State flag protection"]
        R4["Stats<br/>Concurrent stat reads"]
    end

    subgraph "sync.WaitGroup"
        W1["FileScanner<br/>Wait for all workers to finish"]
    end

    style C1 fill:#ff6b6b,stroke:#333,color:#fff
    style M1 fill:#ffd43b,stroke:#333
    style R1 fill:#339af0,stroke:#333,color:#fff
    style W1 fill:#51cf66,stroke:#333
```

### When to Use What?

```mermaid
graph TD
    Q1{"Need to limit<br/>concurrent goroutines?"}
    Q2{"Need to protect<br/>shared data?"}
    Q3{"Many readers,<br/>few writers?"}
    Q4{"Need to wait<br/>for goroutines?"}

    Q1 -->|yes| CHAN["Channel Semaphore<br/>make(chan struct{}, N)"]
    Q1 -->|no| Q2
    Q2 -->|yes| Q3
    Q2 -->|no| Q4
    Q3 -->|yes| RWMUTEX["sync.RWMutex<br/>RLock for reads,<br/>Lock for writes"]
    Q3 -->|no| MUTEX["sync.Mutex<br/>Exclusive access"]
    Q4 -->|yes| WG["sync.WaitGroup<br/>Add/Done/Wait"]
    Q4 -->|no| NOTHING["No sync needed"]

    style CHAN fill:#ff6b6b,stroke:#333,color:#fff
    style RWMUTEX fill:#339af0,stroke:#333,color:#fff
    style MUTEX fill:#ffd43b,stroke:#333
    style WG fill:#51cf66,stroke:#333
```

### The Semaphore Pattern — Deep Dive

```mermaid
sequenceDiagram
    participant Main
    participant Sem as Channel (cap=4)
    participant G1 as Worker 1
    participant G2 as Worker 2
    participant G3 as Worker 3
    participant G4 as Worker 4
    participant G5 as Worker 5

    Main->>G1: go scan(file1)
    G1->>Sem: send (slot 1/4)
    Main->>G2: go scan(file2)
    G2->>Sem: send (slot 2/4)
    Main->>G3: go scan(file3)
    G3->>Sem: send (slot 3/4)
    Main->>G4: go scan(file4)
    G4->>Sem: send (slot 4/4) — FULL!
    Main->>G5: go scan(file5)
    G5->>Sem: send... BLOCKED!

    Note over G5,Sem: G5 waits until a slot opens

    G1->>Sem: receive (release slot)
    G5->>Sem: send (acquires freed slot)

    Note over G5: G5 now runs
```

### RWMutex vs Mutex — Performance Impact

```mermaid
graph LR
    subgraph "Mutex (Engine.findingCount)"
        MA["Goroutine A: Lock() → increment → Unlock()"]
        MB["Goroutine B: BLOCKED (waiting for A)"]
        MC["One at a time, always"]
    end

    subgraph "RWMutex (RuleSet.rules)"
        RA["Goroutine A: RLock() → read rules → RUnlock()"]
        RB["Goroutine B: RLock() → read rules → RUnlock()"]
        RC["Both run CONCURRENTLY!"]
        RD["Goroutine C: Lock() → add rule → Unlock()"]
        RE["A and B BLOCKED until C finishes"]
    end

    style MC fill:#ffd43b,stroke:#333
    style RC fill:#51cf66,stroke:#333
```

**When to use RWMutex over Mutex:**
- When reads vastly outnumber writes (e.g., rules are loaded once, read millions of times)
- Multiple goroutines can hold `RLock()` simultaneously → better throughput
- `Lock()` still provides exclusive access for writes

### Race Condition Prevention

```mermaid
graph TD
    subgraph "Without Mutex (BUG)"
        G1A["Goroutine 1: read count = 5"]
        G2A["Goroutine 2: read count = 5"]
        G1B["Goroutine 1: write count = 6"]
        G2B["Goroutine 2: write count = 6"]
        BUG["LOST UPDATE!<br/>Expected 7, got 6"]
    end

    subgraph "With Mutex (CORRECT)"
        G1C["Goroutine 1: Lock()"]
        G1D["Goroutine 1: count++ → 6"]
        G1E["Goroutine 1: Unlock()"]
        G2C["Goroutine 2: Lock() (waits...)"]
        G2D["Goroutine 2: count++ → 7"]
        G2E["Goroutine 2: Unlock()"]
        OK["CORRECT: count = 7"]
    end

    G1A --> G2A --> G1B --> G2B --> BUG
    G1C --> G1D --> G1E --> G2C --> G2D --> G2E --> OK

    style BUG fill:#ff6b6b,stroke:#333,color:#fff
    style OK fill:#51cf66,stroke:#333
```

### Interview Explanation

> "CredVigil uses Go's concurrency primitives strategically. The file scanner uses a **channel-based semaphore** (`make(chan struct{}, N)`) instead of a traditional semaphore — it's idiomatic Go and leverages the runtime's channel scheduler. The `sync.RWMutex` is used for read-heavy data structures like `RuleSet` and `Pipeline` — 331 rules are loaded once but read millions of times during scanning, so concurrent `RLock()` gives near-linear throughput scaling. The `sync.Mutex` is reserved for write-heavy operations like the monotonic ID counter. `sync.WaitGroup` coordinates goroutine lifecycle — `Add(1)` before spawning, `Done()` in defer, `Wait()` after the loop. This is the **fan-out/fan-in** pattern: we fan out work to N goroutines and fan in results through a mutex-protected slice."

---

## 18. Design Patterns Catalog

### Patterns Used in CredVigil

```mermaid
mindmap
    root((Design Patterns<br/>in CredVigil))
        Creational
            Factory Method
                NewEngine()
                NewDefault() pipeline
                DefaultRuleSet()
                DefaultConfig()
            Builder
                ScanOptions with field-by-field config
                Config structs with defaults
        Structural
            Façade
                GitScanner wraps walker + parser + engine + pipeline
                cmdScan wraps everything
            Composite
                Pipeline composes Processors
        Behavioral
            Strategy
                Processor interface
                Different scan modes
            Chain of Responsibility
                Pipeline stages
            Iterator
                CommitWalker.WalkCommits
            Observer
                File watcher + handler callback
            Template Method
                ScanContent dual-mode flow
        Concurrency
            Worker Pool
                FileScanner goroutine pool
            Semaphore
                Channel-based concurrency limit
            Fan-Out/Fan-In
                Parallel scan, merge results
            Monitor
                Mutex-protected shared state
```

### Pattern 1: Strategy Pattern — Processor Interface

```mermaid
classDiagram
    class Processor {
        <<interface>>
        +Name() string
        +Process(ctx, *Finding, *ScanMetadata) error
    }

    class HashProcessor {
        +Name() "hash"
        +Process() SHA-256 hash
    }
    class RedactProcessor {
        +Name() "redact"
        +Process() mask secret
    }
    class EnrichProcessor {
        +Name() "enrich"
        +Process() add metadata
    }
    class FingerprintProcessor {
        +Name() "fingerprint"
        +Process() dedup ID
    }
    class SanitizeProcessor {
        +Name() "sanitize"
        +Process() clear raw
    }

    Processor <|.. HashProcessor
    Processor <|.. RedactProcessor
    Processor <|.. EnrichProcessor
    Processor <|.. FingerprintProcessor
    Processor <|.. SanitizeProcessor
```

**Why Strategy?**
- Each processor encapsulates a **single algorithm**
- Processors can be swapped, reordered, or removed without changing others
- New processors (e.g., `VerifyProcessor`) can be added by implementing 2 methods

### Pattern 2: Chain of Responsibility — Pipeline

```mermaid
graph LR
    REQ["Finding<br/>(input)"] --> H["Hash<br/>(handler 1)"]
    H -->|pass along| R["Redact<br/>(handler 2)"]
    R -->|pass along| E["Enrich<br/>(handler 3)"]
    E -->|pass along| FP["Fingerprint<br/>(handler 4)"]
    FP -->|pass along| S["Sanitize<br/>(handler 5)"]
    S --> OUT["Finding<br/>(processed)"]

    H -->|error| DROP1["Finding dropped"]
    R -->|error| DROP2["Finding dropped"]

    style REQ fill:#ff6b6b,stroke:#333,color:#fff
    style OUT fill:#51cf66,stroke:#333
    style DROP1 fill:#868e96,stroke:#333,color:#fff
    style DROP2 fill:#868e96,stroke:#333,color:#fff
```

**Difference from classic CoR:**
- Classic CoR: only one handler processes the request
- Our CoR: ALL handlers process the request sequentially (more like a filter chain)
- Similar to Java Servlet Filters or Go HTTP middleware

### Pattern 3: Worker Pool — Fan-Out/Fan-In

```mermaid
graph TD
    INPUT["100 files to scan"]
    FAN["Fan-Out:<br/>Spawn goroutine per file"]
    W1["Worker 1"]
    W2["Worker 2"]
    W3["Worker 3"]
    W4["Worker 4"]
    SEM["Semaphore: only 4 active"]
    MERGE["Fan-In:<br/>Mutex-protected append"]
    OUTPUT["Combined results"]

    INPUT --> FAN
    FAN --> W1 & W2 & W3 & W4
    SEM -.->|controls| W1 & W2 & W3 & W4
    W1 & W2 & W3 & W4 --> MERGE
    MERGE --> OUTPUT

    style INPUT fill:#339af0,stroke:#333,color:#fff
    style SEM fill:#ff6b6b,stroke:#333,color:#fff
    style OUTPUT fill:#51cf66,stroke:#333
```

### Pattern 4: Observer — File Watcher

```mermaid
graph LR
    SUBJECT["File System<br/>(observable)"]
    OBSERVER["Watcher<br/>(observer)"]
    HANDLER["Handler func<br/>(callback)"]

    SUBJECT -->|emit events| OBSERVER
    OBSERVER -->|debounce + filter| HANDLER
    HANDLER -->|trigger scan| ENGINE["Detection Engine"]

    style SUBJECT fill:#339af0,stroke:#333,color:#fff
    style OBSERVER fill:#ffd43b,stroke:#333
    style HANDLER fill:#51cf66,stroke:#333
```

### Pattern 5: Façade — GitScanner

```mermaid
graph TD
    FACADE["GitScanner<br/>(simple API)"]

    subgraph "Hidden Complexity"
        REPO["Repository management<br/>(open, clone, cleanup)"]
        WALKER["Commit walking<br/>(list, iterate, count)"]
        DIFF["Diff parsing<br/>(unified diff → structured)"]
        FILTER["File filtering<br/>(include/exclude patterns)"]
        ENGINE["Detection engine<br/>(regex + entropy)"]
        PIPELINE["Post-processing<br/>(hash, redact, enrich...)"]
        PROGRESS["Progress tracking<br/>(commits scanned, findings)"]
    end

    FACADE --> REPO & WALKER & DIFF & FILTER & ENGINE & PIPELINE & PROGRESS

    USER["User calls:<br/>scanner.ScanLocalRepo(ctx, path)"]
    USER --> FACADE

    style FACADE fill:#339af0,stroke:#333,color:#fff,stroke-width:3px
```

**The user sees one method call, but it orchestrates 7 subsystems.**

### Pattern 6: Factory Method — Component Creation

```go
// Factory functions return configured instances
engine := detector.NewEngine(ruleSet, config)      // Engine factory
scanner := detector.NewFileScanner(engine, fsConfig) // Scanner factory
pipeline := pipeline.NewDefault()                    // Default pipeline factory
ruleSet := rules.DefaultRuleSet()                    // Default rules factory
watcher := watcher.New(watchConfig, handler)         // Watcher factory
```

**Why factories?**
- Encapsulate complex initialization logic
- Ensure objects are always in a valid state
- `NewDefault()` provides sensible defaults (Convention over Configuration)

### Interview Explanation

> "CredVigil uses 6+ design patterns: **Strategy** for Processor interface (interchangeable algorithms), **Chain of Responsibility** for the pipeline (sequential processing with early termination), **Worker Pool** for concurrent file scanning (fan-out/fan-in with semaphore), **Observer** for file watching (event-driven callbacks), **Façade** for GitScanner (simple API hiding 7 subsystems), and **Factory** for component creation (NewEngine, NewDefault, DefaultRuleSet). Each pattern solves a specific problem: Strategy enables extensibility, CoR enables composability, Worker Pool enables performance, Observer enables reactivity, Façade enables usability, and Factory enables correctness."

---

## 19. Error Handling Philosophy

### Error Handling Strategy

```mermaid
graph TD
    subgraph "Critical Errors → Fail Fast"
        E1["git not installed<br/>→ return error immediately"]
        E2["Can't read file<br/>→ skip file, continue scan"]
        E3["Invalid config<br/>→ print error, exit(1)"]
    end

    subgraph "Recoverable Errors → Continue"
        E4["Single file scan fails<br/>→ skip, scan remaining files"]
        E5["Pipeline processor fails<br/>→ drop finding, continue"]
        E6["Git diff fails for commit<br/>→ skip commit, continue"]
        E7["Can't watch directory<br/>→ log warning, skip dir"]
    end

    subgraph "Annotation Errors → Warn"
        E8["Enrichment data unavailable<br/>→ leave field empty"]
        E9["Stats update fails<br/>→ continue without stats"]
    end

    style E1 fill:#ff6b6b,stroke:#333,color:#fff
    style E4 fill:#ffd43b,stroke:#333
    style E8 fill:#51cf66,stroke:#333
```

### Error Propagation Flow

```mermaid
graph LR
    FILE["File read error"] --> SCANNER["FileScanner:<br/>skip file,<br/>continue scanning"]
    REGEX["Regex panic"] --> ENGINE["Engine:<br/>recover(),<br/>skip rule"]
    PIPELINE_ERR["Processor error"] --> PIPELINE["Pipeline:<br/>drop finding,<br/>log error"]
    GIT_ERR["Git CLI error"] --> WALKER["Walker:<br/>skip commit,<br/>log error"]
    CONTEXT["Context cancelled"] --> ALL["All components:<br/>graceful shutdown"]

    style FILE fill:#ffd43b,stroke:#333
    style REGEX fill:#ff6b6b,stroke:#333,color:#fff
    style CONTEXT fill:#868e96,stroke:#333,color:#fff
```

### Interview Explanation

> "Our error handling follows a **fail-safe philosophy**: it's better to miss a finding than to crash the entire scan. File-level errors (can't read, too large, binary) cause the file to be skipped, not the scan to abort. Pipeline errors cause the finding to be dropped (better than outputting a raw secret). Git errors cause individual commits to be skipped. Only configuration errors and missing prerequisites (git not installed) cause immediate failure. This is the **bulkhead pattern** from resilience engineering — a failure in one component doesn't sink the whole ship."

---

## 20. Extensibility & Plugin Points

### Extension Points

```mermaid
graph TD
    subgraph "1. Add New Rules"
        R1["Create Rule struct<br/>with Pattern, Keywords, etc."]
        R2["ruleSet.Add(newRule)"]
        R3["Auto-picked up by Engine"]
    end

    subgraph "2. Add Pipeline Processor"
        P1["Implement Processor interface<br/>Name() + Process()"]
        P2["pipeline.AddProcessor(proc)<br/>or InsertProcessor(idx, proc)"]
    end

    subgraph "3. Add Verification"
        V1["Implement VerificationHook<br/>CanVerify() + Process()"]
        V2["Insert into pipeline"]
    end

    subgraph "4. Add Input Source"
        I1["Create struct that produces<br/>ScanRequest objects"]
        I2["Feed to engine.ScanContent()"]
    end

    subgraph "5. Add Output Format"
        O1["Read ScanResult struct"]
        O2["Write custom formatter"]
    end

    style R1 fill:#339af0,stroke:#333,color:#fff
    style P1 fill:#ffd43b,stroke:#333
    style V1 fill:#ff6b6b,stroke:#333,color:#fff
    style I1 fill:#51cf66,stroke:#333
    style O1 fill:#748ffc,stroke:#333,color:#fff
```

### VerificationHook Interface — Future Extension

```mermaid
classDiagram
    class VerificationHook {
        <<interface>>
        +CanVerify(SecretType) bool
        +Process(ctx, *Finding, *ScanMetadata) error
    }

    class NoOpVerifier {
        +CanVerify() false
        +Process() nil
    }

    class AWSVerifier {
        +CanVerify() true for AWSAccessKey
        +Process() call STS GetCallerIdentity
    }

    class GitHubVerifier {
        +CanVerify() true for GitHubPAT
        +Process() call /user endpoint
    }

    VerificationHook <|.. NoOpVerifier
    VerificationHook <|.. AWSVerifier
    VerificationHook <|.. GitHubVerifier

    note for NoOpVerifier "Current implementation:<br/>placeholder for future work"
```

### How to Add a Custom Rule (3 Steps)

```go
// Step 1: Define the rule
myRule := rules.Rule{
    ID:             "my-custom-api-key",
    Description:    "My Custom Service API Key",
    SecretType:     models.GenericAPIKey,
    Severity:       models.High,
    Pattern:        regexp.MustCompile(`MYSERVICE_[a-zA-Z0-9]{32}`),
    Keywords:       []string{"myservice", "custom"},
    BaseConfidence: 0.85,
}

// Step 2: Add to rule set
ruleSet.Add(myRule)

// Step 3: That's it! The engine picks it up automatically.
```

### Interview Explanation

> "CredVigil is designed with the **Open-Closed Principle** — open for extension, closed for modification. There are 5 extension points: (1) Add new rules to the RuleSet without touching the engine, (2) Add pipeline processors via the `Processor` interface, (3) Add secret verification via the `VerificationHook` interface, (4) Add input sources by creating anything that produces `ScanRequest` objects, (5) Add output formats by reading `ScanResult`. Each extension point uses an interface, so new functionality is added by implementing an interface, not modifying existing code. The `VerificationHook` is a placeholder today — it has a `NoOpVerifier` — but the interface is designed for future verifiers that could call AWS STS, GitHub API, etc. to confirm if a detected secret is actually valid."

---

## 21. Performance Characteristics

### Performance Profile

```mermaid
graph TD
    subgraph "Startup (< 10ms)"
        S1["Load 331 rules<br/>Compile 331 regex patterns"]
        S2["Initialize engine + scanner"]
        S3["Create pipeline (5 processors)"]
    end

    subgraph "Per-File (< 1ms typical)"
        F1["Read file (I/O bound)"]
        F2["Run 331 regex patterns<br/>(CPU bound)"]
        F3["Entropy analysis<br/>(CPU bound)"]
        F4["Pipeline processing<br/>(CPU bound, fast)"]
    end

    subgraph "Git Scan (varies)"
        G1["Clone repo (network I/O)"]
        G2["Walk N commits"]
        G3["Parse diffs (CPU)"]
        G4["Scan added lines (CPU)"]
    end

    style S1 fill:#51cf66,stroke:#333
    style F2 fill:#ffd43b,stroke:#333
    style G1 fill:#ff6b6b,stroke:#333,color:#fff
```

### Bottleneck Analysis

| Operation | Bound | Cost | Optimization |
|-----------|-------|------|-------------|
| File reading | I/O | Variable | Worker pool parallelizes I/O wait |
| Regex matching | CPU | O(rules × filesize) | Pre-compiled regexes, skip excluded files |
| Entropy calc | CPU | O(n) per word | Only runs on words > 12 chars |
| Pipeline | CPU | O(5) per finding | Each stage is O(1) |
| Git clone | Network | Seconds to minutes | `--depth` flag for shallow clones |
| Diff parsing | CPU | O(diffsize) | `--unified=0` reduces diff size |

### Memory Usage

```mermaid
graph LR
    subgraph "Constant Memory"
        M1["331 compiled regexes<br/>~2-3 MB"]
        M2["Pipeline (5 processors)<br/>~1 KB"]
        M3["Config structs<br/>~1 KB"]
    end

    subgraph "Per-Scan Memory"
        M4["File content in memory<br/>Limited by MaxFileSize (5-10 MB)"]
        M5["Findings slice<br/>~1-2 KB per finding"]
        M6["Dedup seen map<br/>~100 bytes per entry"]
    end

    subgraph "Git-Specific"
        M7["Commit list in memory<br/>~500 bytes per commit"]
        M8["Diff strings<br/>Limited by MaxDiffSize (1 MB)"]
    end

    style M1 fill:#339af0,stroke:#333,color:#fff
    style M4 fill:#ffd43b,stroke:#333
    style M7 fill:#51cf66,stroke:#333
```

### Interview Explanation

> "Performance is I/O-bound for file scanning (reading from disk) and CPU-bound for detection (running 331 regex patterns). The worker pool parallelizes file I/O so while one goroutine is waiting for disk, others are running regex. Pre-compiled regexes avoid the compilation cost at scan time. Entropy analysis is O(n) per word but only runs on words longer than 12 characters, which filters out most content. The pipeline is O(1) per finding — each stage does constant-time work (hashing, string manipulation). Memory is bounded: we never load more than `MaxFileSize` bytes per file, and the dedup map grows linearly with unique findings. For git scanning, `--depth` enables shallow clones for remote repos, and `--unified=0` reduces diff size by not including context lines."

---

## 22. Interview Quick-Reference Cards

### Card 1: "Walk me through the architecture"

> "CredVigil is a **layered pipeline architecture** with 4 layers:
> 1. **Input layer** — CLI parsing, stdin reading, git integration, file watching
> 2. **Detection layer** — Dual-engine: 331 compiled regex rules + Shannon entropy analysis, with 5-factor confidence scoring
> 3. **Post-processing layer** — 5-stage pipeline: Hash → Redact → Enrich → Fingerprint → Sanitize (zero-trust)
> 4. **Output layer** — Text (color-coded for terminals) or JSON (for CI/CD integration)
>
> The architecture is modular — 8 packages with no circular dependencies. The `Finding` struct is the shared data model that all components communicate through."

### Card 2: "How do you handle concurrency?"

> "Three concurrency mechanisms:
> 1. **Worker pool with channel semaphore** for file scanning — `make(chan struct{}, 4)` limits to 4 concurrent goroutines. Natural backpressure.
> 2. **sync.RWMutex** for read-heavy structures (RuleSet, Pipeline) — multiple readers, single writer. Rules are loaded once, read millions of times.
> 3. **sync.Mutex** for write-heavy data (finding counter) — exclusive access for ID generation.
>
> Results are aggregated via mutex-protected slice append. `sync.WaitGroup` manages goroutine lifecycle."

### Card 3: "How do you reduce false positives?"

> "Two mechanisms: **5-factor confidence scoring** and **false positive patterns**. Confidence starts from a rule's base score (how specific its regex is), then adjusts for entropy quality (+0.10/-0.20), keyword proximity (+0.10), false positive patterns (-0.25 for 'example', 'sample', template syntax), and placeholder detection (-0.40 for 'changeme', 'xxxx'). An AWS key with 'EXAMPLE' in it drops from 0.95 to 0.45 confidence. Users can set `--min-confidence` to filter below a threshold."

### Card 4: "How is security built in?"

> "**Zero-trust pipeline** — we assume scan output will be stored insecurely. Raw secrets are:
> 1. **Hashed** (SHA-256, irreversible) for cross-scan comparison
> 2. **Redacted** (masked preview: `AKIA****MPLE`) for display
> 3. **Sanitized** (raw value cleared from memory) before output
>
> Even if JSON output is leaked, attackers get only hashes and masked previews. Cloned repos are cleaned up via `defer repo.Cleanup()`. No raw secrets are ever logged."

### Card 5: "What design patterns did you use?"

> "Six patterns:
> - **Strategy** → `Processor` interface: interchangeable algorithms
> - **Chain of Responsibility** → Pipeline: sequential processor chain
> - **Worker Pool** → FileScanner: bounded concurrency
> - **Observer** → File watcher: event-driven scanning
> - **Façade** → GitScanner: simple API over 7 subsystems
> - **Factory** → NewEngine, NewDefault, DefaultRuleSet: encapsulated initialization
>
> Each pattern solves a specific problem: extensibility, composability, performance, reactivity, usability, and correctness."

### Card 6: "How does entropy detection work?"

> "Shannon entropy from information theory: $H = -\sum p(x) \log_2 p(x)$. It measures string randomness — real secrets have high entropy, variable names have low entropy. We use **charset-specific thresholds** because hex (16 chars, max 4.0 bits) and base64 (64 chars, max 6.0 bits) have different entropy ceilings. The `EntropyScore` is a weighted composite: 70% entropy quality + 30% length factor. Strings scoring above 0.5 are flagged as high-entropy secrets if they appear near secret-like keywords (password, key, token)."

### Card 7: "How is the git scanner designed?"

> "It's a **façade** over the git CLI using `os/exec` — no libgit2 dependency. The `CommitWalker` iterates through history with a callback pattern: `WalkCommits(fn)` calls a function per commit. Only ADDED lines from diffs are scanned (we care about what was introduced, not removed). Merge commits are skipped by default. Context cancellation enables graceful shutdown. For remote repos, `CloneRepository` creates a temp directory and `defer Cleanup()` ensures it's removed — the RAII pattern in Go."

### Card 8: "How would you scale this to a large organization?"

> "Three scaling strategies:
> 1. **Horizontal**: Each repo scan is independent — distribute across CI workers
> 2. **Incremental**: `--since-commit` flag for git scanning — only scan new commits
> 3. **Pipeline**: The `Fingerprint` enables cross-scan deduplication — track which findings are new vs. already known
>
> The modular architecture means scaling doesn't require monolithic changes: you could add a `DatabaseSink` pipeline processor to store results, or a `WebhookNotifier` to alert on critical findings, all by implementing the `Processor` interface."

---

## Appendix: Complete File Inventory

| File | Lines | Purpose |
|------|-------|---------|
| `cmd/credvigil/main.go` | 625 | CLI entry point, command routing, scan orchestration, output formatting |
| `internal/config/config.go` | 63 | AppConfig, DetectionConfig, FileScanningConfig structs |
| `pkg/models/finding.go` | 697 | Finding, Source, ScanResult, ScanRequest, Severity enum, SecretType constants |
| `pkg/rules/rules.go` | 3747 | 331 detection rules as compiled regex patterns |
| `pkg/detector/engine.go` | 579 | Detection engine: regex + entropy, confidence scoring, deduplication |
| `pkg/detector/scanner.go` | ~300 | File scanner with worker pool, binary detection, file filtering |
| `pkg/entropy/entropy.go` | 275 | Shannon entropy, charset detection, threshold system |
| `pkg/pipeline/pipeline.go` | ~200 | Pipeline struct, Processor interface, ProcessFindings, ProcessResult |
| `pkg/pipeline/hash.go` | ~30 | SHA-256 hash of raw secret |
| `pkg/pipeline/redact.go` | ~30 | Masked preview creation |
| `pkg/pipeline/enrich.go` | 452 | File type, environment, category classification |
| `pkg/pipeline/fingerprint.go` | ~30 | Cross-scan deduplication fingerprint |
| `pkg/pipeline/sanitize.go` | ~30 | Zero-trust raw secret clearing |
| `pkg/pipeline/verify.go` | ~40 | VerificationHook interface + NoOpVerifier |
| `pkg/git/git.go` | 163 | Repository, Commit, DiffEntry structs, git CLI helpers |
| `pkg/git/scanner.go` | 312 | GitScanner, ScanRepository, commit scanning, GitScanResult |
| `pkg/git/diff.go` | 237 | Unified diff parser, line number extraction |
| `pkg/git/walker.go` | 230 | CommitWalker, WalkCommits, commit listing |
| `pkg/git/clone.go` | 158 | OpenRepository, CloneRepository, Cleanup |
| `pkg/watcher/watcher.go` | 445 | File system watcher, debouncing, recursive watching |
| **Total** | **~8,642** | |

---

*Document generated from source code analysis of CredVigil v0.1.0. Every diagram and explanation is derived from the actual implementation, not hypothetical designs.*
