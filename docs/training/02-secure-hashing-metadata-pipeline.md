# CredVigil Training Guide — Module 2: Secure Hashing & Metadata Pipeline

> **Version**: 0.1.0  
> **Component**: Secure Hashing & Metadata Pipeline (Component 2 of 15)  
> **Audience**: Developers, security engineers, DevOps teams  
> **Prerequisites**: Completion of Module 1 (Core Detection Engine). Go 1.21+ installed.

---

## Table of Contents

1. [What Is the Metadata Pipeline?](#1-what-is-the-metadata-pipeline)
2. [Why Do We Need Post-Processing?](#2-why-do-we-need-post-processing)
3. [Key Concepts Explained](#3-key-concepts-explained)
   - 3.1 [What Is a Processing Pipeline?](#31-what-is-a-processing-pipeline)
   - 3.2 [What Is SHA-256 Hashing?](#32-what-is-sha-256-hashing)
   - 3.3 [What Is Redaction?](#33-what-is-redaction)
   - 3.4 [What Is Enrichment?](#34-what-is-enrichment)
   - 3.5 [What Is a Fingerprint?](#35-what-is-a-fingerprint)
   - 3.6 [What Is Sanitization?](#36-what-is-sanitization)
   - 3.7 [What Is the Zero-Trust Guarantee?](#37-what-is-the-zero-trust-guarantee)
4. [Architecture Overview](#4-architecture-overview)
5. [The Five Default Processors](#5-the-five-default-processors)
   - 5.1 [HashProcessor](#51-hashprocessor)
   - 5.2 [RedactProcessor](#52-redactprocessor)
   - 5.3 [EnrichProcessor](#53-enrichprocessor)
   - 5.4 [FingerprintProcessor](#54-fingerprintprocessor)
   - 5.5 [SanitizeProcessor](#55-sanitizeprocessor)
6. [The Processor Interface](#6-the-processor-interface)
7. [Pipeline Orchestration](#7-pipeline-orchestration)
8. [How It Integrates with the Detection Engine](#8-how-it-integrates-with-the-detection-engine)
9. [Understanding the Output Changes](#9-understanding-the-output-changes)
10. [Hands-On Exercises](#10-hands-on-exercises)
11. [Deep Dive: Code Walkthrough](#11-deep-dive-code-walkthrough)
12. [Writing Custom Processors](#12-writing-custom-processors)
13. [Verification Hooks (Preview)](#13-verification-hooks-preview)
14. [Error Handling & Resilience](#14-error-handling--resilience)
15. [Frequently Asked Questions](#15-frequently-asked-questions)
16. [Glossary](#16-glossary)
17. [What's Next?](#17-whats-next)

---

## 1. What Is the Metadata Pipeline?

In Module 1, you learned how CredVigil's **Core Detection Engine** finds secrets in your code using regex patterns and entropy analysis. But detection is only the first step.

Once a secret is detected, we need to:

- **Hash** it — create a unique fingerprint of the secret for tracking, without storing the raw value
- **Redact** it — replace the secret with a partial representation (e.g., `AKIA****MPLE`)
- **Enrich** it — classify the file type, detect the environment (production, staging, dev), and categorize the secret
- **Fingerprint** it — create a stable cross-scan identifier so we can track the same finding across multiple scans
- **Sanitize** it — permanently remove the raw secret from memory before any output or storage

The **Metadata Pipeline** is a modular, composable processing chain that performs all of these operations on every detected finding. It is the bridge between "we found a secret" and "here is a safe, enriched, actionable report."

```mermaid
flowchart LR
    A["🔍 Detection\nEngine"] --> B["📦 Raw Finding"]
    B --> C["⚙️ Metadata\nPipeline"]
    C --> D["✅ Safe, Enriched\nActionable Report"]
    style A fill:#3498DB,stroke:#2980B9,color:#fff
    style B fill:#E74C3C,stroke:#C0392B,color:#fff
    style C fill:#9B59B6,stroke:#8E44AD,color:#fff
    style D fill:#27AE60,stroke:#1E8449,color:#fff
```

---

## 2. Why Do We Need Post-Processing?

### The Problem with Raw Detection

The detection engine (Component 1) necessarily has access to the raw secret — it must read the actual text to match patterns. But once detection is complete, keeping the raw secret in memory creates risk:

| Risk | What Could Happen |
|------|-------------------|
| **Log leakage** | Raw secrets could end up in application logs |
| **Memory dumps** | A crash dump could expose secrets in plain text |
| **Transport exposure** | Sending findings to a dashboard, API, or storage could leak the actual credential |
| **Screenshot exposure** | A developer viewing terminal output could inadvertently photograph a real key |
| **Compliance violation** | SOC 2, ISO 27001, and PCI-DSS require secrets to be handled with "least privilege" — if you don't need the raw value, don't keep it |

### The Zero-Trust Approach

CredVigil follows a **zero-trust principle for finding data**: no component downstream of the pipeline should ever see a raw secret. The pipeline guarantees this by:

1. Computing a SHA-256 hash (for identification)
2. Creating a redacted display version (for human readability)
3. **Permanently erasing** the raw secret from the finding struct

This is not optional — it's enforced by the SanitizeProcessor, which is always the last step in the default pipeline.

```mermaid
flowchart TD
    A["🚨 Raw Secret\nin Memory"] --> B{"Post-Processing"}
    B --> C["🔐 SHA-256 Hash\nfor identification"]
    B --> D["🔒 Redacted\nfor display"]
    B --> E["🗑️ Raw Erased\npermanently"]
    C & D --> F["✅ Safe to:\nLog, Store, Transmit, Display"]
    E -.->|"never reaches\ndownstream"| G["❌ Logs, APIs,\nDashboards"]
    style A fill:#E74C3C,stroke:#C0392B,color:#fff
    style E fill:#7F8C8D,stroke:#616A6B,color:#fff
    style F fill:#27AE60,stroke:#1E8449,color:#fff
```

---

## 3. Key Concepts Explained

### 3.1 What Is a Processing Pipeline?

A **pipeline** is a series of steps (called **processors**) that run in a fixed order, each transforming the data before passing it to the next step.

Think of it like an assembly line in a factory:

```
Raw Finding → [Hash] → [Redact] → [Enrich] → [Fingerprint] → [Sanitize] → Safe Finding
```

Each processor does exactly one job. They are independent, testable, and replaceable. You can add, remove, or reorder processors to customize the pipeline.

```mermaid
flowchart LR
    A["📥 Raw\nFinding"] --> B["🔢 Hash"]
    B --> C["🔒 Redact"]
    C --> D["📊 Enrich"]
    D --> E["🧭 Fingerprint"]
    E --> F["🧹 Sanitize"]
    F --> G["✅ Safe\nFinding"]
    style A fill:#E74C3C,stroke:#C0392B,color:#fff
    style B fill:#3498DB,stroke:#2980B9,color:#fff
    style C fill:#9B59B6,stroke:#8E44AD,color:#fff
    style D fill:#E67E22,stroke:#D35400,color:#fff
    style E fill:#1ABC9C,stroke:#16A085,color:#fff
    style F fill:#7F8C8D,stroke:#616A6B,color:#fff
    style G fill:#27AE60,stroke:#1E8449,color:#fff
```

### 3.2 What Is SHA-256 Hashing?

SHA-256 is a **one-way cryptographic function** that converts any input into a fixed-length 64-character hexadecimal string.

```
Input:  "AKIAIOSFODNN7EXAMPLE"
SHA-256: "5e6bf1b9e9c6e0b93a3e1f4f2c0aec8d7b9e0f1a2c3d4e5f6a7b8c9d0e1f2a3b"
```

Key properties:
- **Deterministic**: The same input always produces the same hash
- **One-way**: You cannot reverse the hash to get the original secret
- **Unique**: Different inputs produce different hashes (collision-resistant)
- **Fixed-length**: Always 64 hex characters, regardless of input size

We use SHA-256 so that we can track and deduplicate secrets without ever storing them.

```mermaid
flowchart LR
    A["AKIAIOSFODNN7EXAMPLE"] -->|"SHA-256"| B["5e6bf1b9...e1f2a3b\n(64 hex chars)"]
    C["AKIAIOSFODNN7EXAMPLE"] -->|"SHA-256"| D["5e6bf1b9...e1f2a3b\n(identical!)"]
    E["ghp_ABCDEFGHIJKLMN..."] -->|"SHA-256"| F["a3c7d9e1...f4b2c8d\n(different)"]
    style B fill:#9B59B6,stroke:#8E44AD,color:#fff
    style D fill:#9B59B6,stroke:#8E44AD,color:#fff
    style F fill:#E67E22,stroke:#D35400,color:#fff
```

### 3.3 What Is Redaction?

Redaction replaces most of a secret with asterisks while keeping just enough characters to identify it.

| Secret Length | Redaction Rule | Example |
|:---:|---|---|
| > 12 chars | First 4 + `****` + Last 4 | `AKIAIOSFODNN7EXAMPLE` → `AKIA****MPLE` |
| 5–12 chars | First 2 + `****` | `Secret!` → `Se****` |
| ≤ 4 chars | `****` | `pass` → `****` |

This lets security teams identify *which* key was leaked (e.g., "the AWS key starting with AKIA") without exposing the full credential.

```mermaid
flowchart TD
    A["AKIAIOSFODNN7EXAMPLE\n(20 chars)"] --> B["> 12 chars"]
    B --> C["AKIA + **** + MPLE"]
    D["Secret!\n(7 chars)"] --> E["5–12 chars"]
    E --> F["Se + ****"]
    G["pass\n(4 chars)"] --> H["≤ 4 chars"]
    H --> I["****"]
    style C fill:#27AE60,stroke:#1E8449,color:#fff
    style F fill:#F39C12,stroke:#D68910,color:#fff
    style I fill:#E74C3C,stroke:#C0392B,color:#fff
```

### 3.4 What Is Enrichment?

Enrichment adds **context** to a finding based on where it was found and what type of secret it is:

- **File Type**: Was this found in a `.go` file? A `.env` file? A `Dockerfile`?
- **Environment**: Is the file in a `production/` directory? A `staging/` config? A `test/` fixture?
- **Category**: Is this a `cloud` credential? A `database` password? A `payment` key?
- **Scan Metadata**: What scanner version produced this finding? What was the scan ID?

Enrichment transforms a bare match into an actionable intelligence report.

```mermaid
flowchart TD
    A["📦 Bare Finding"] --> B{"Enrich Processor"}
    B --> C["📁 File Type\ngo, python, yaml..."]
    B --> D["🌍 Environment\nprod, staging, dev..."]
    B --> E["🏷️ Category\ncloud, database, payment..."]
    B --> F["📝 Scan Metadata\nversion, ID, config hash"]
    C & D & E & F --> G["✅ Enriched Finding"]
    style A fill:#7F8C8D,stroke:#616A6B,color:#fff
    style G fill:#27AE60,stroke:#1E8449,color:#fff
    style B fill:#E67E22,stroke:#D35400,color:#fff
```

### 3.5 What Is a Fingerprint?

A **fingerprint** is a stable identifier that uniquely identifies a specific finding across multiple scans. It is computed as:

```
SHA-256(ruleID + ":" + location + ":" + line + ":" + secretHash)
```

Why do we need this?

- **Deduplication across scans**: If you scan the same project twice, the same finding produces the same fingerprint
- **Tracking over time**: You can track whether a specific finding has been fixed, suppressed, or is still active
- **Ignore lists**: You can add a fingerprint to an ignore list to suppress known false positives

A fingerprint is different from a hash — the hash identifies the *secret*, while the fingerprint identifies the *finding* (secret + location).

```mermaid
flowchart TD
    subgraph Hash["Secret Hash"]
        A["Same secret = same hash\nregardless of where found"]
    end
    subgraph FP["Fingerprint"]
        B["Same secret + same location\n= same fingerprint"]
        C["Same secret + different location\n= different fingerprint"]
    end
    style Hash fill:#9B59B6,stroke:#8E44AD,color:#fff
    style FP fill:#1ABC9C,stroke:#16A085,color:#fff
```

### 3.6 What Is Sanitization?

Sanitization is the **final, irreversible step** that clears the raw secret from memory. After sanitization:

- `RawMatch` is set to an empty string
- The finding can safely be logged, stored, transmitted, or displayed
- No component downstream can access the original secret

```mermaid
flowchart LR
    A["🔑 RawMatch:\nAKIAIOSFODNN7EXAMPLE"] -->|"Sanitize"| B["🗑️ RawMatch:\n(empty string)"]
    B --> C["✅ Safe to log"]
    B --> D["✅ Safe to store"]
    B --> E["✅ Safe to transmit"]
    style A fill:#E74C3C,stroke:#C0392B,color:#fff
    style B fill:#7F8C8D,stroke:#616A6B,color:#fff
    style C fill:#27AE60,stroke:#1E8449,color:#fff
    style D fill:#27AE60,stroke:#1E8449,color:#fff
    style E fill:#27AE60,stroke:#1E8449,color:#fff
```

### 3.7 What Is the Zero-Trust Guarantee?

The zero-trust guarantee means: **every finding that exits the pipeline has been sanitized**. The raw secret is never present in the output, regardless of the output format (text, JSON, or future API responses).

The pipeline enforces this by:
1. Always including `SanitizeProcessor` as the last processor in the default chain
2. Clearing `RawMatch` unconditionally
3. Being the only path findings take before output

```mermaid
flowchart LR
    A["🔍 Detection"] --> B["⚙️ Pipeline"]
    B --> C["🧹 Sanitize\n(always last)"]
    C --> D{"RawMatch == ''?"}
    D -->|"✅ Yes"| E["📄 Output"]
    D -->|"❌ No"| F["🛑 BLOCKED\n(never happens)"]
    style C fill:#7F8C8D,stroke:#616A6B,color:#fff
    style E fill:#27AE60,stroke:#1E8449,color:#fff
    style F fill:#E74C3C,stroke:#C0392B,color:#fff
```

---

## 4. Architecture Overview

```
                    CredVigil Architecture (Component 2 Highlighted)
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│  Source Code / Config Files / stdin / Git History                                │
│       │                                                                         │
│       ▼                                                                         │
│  ┌──────────────────────────────────┐                                           │
│  │   Core Detection Engine          │  ← Component 1                            │
│  │   (276 rules, entropy, scoring)  │                                           │
│  │   Output: []Finding with         │                                           │
│  │   RawMatch, SecretHash, etc.     │                                           │
│  └──────────────┬───────────────────┘                                           │
│                 │                                                                │
│                 ▼                                                                │
│  ╔══════════════════════════════════╗                                            │
│  ║  Metadata Pipeline (Component 2) ║  ← YOU ARE HERE                           │
│  ╠══════════════════════════════════╣                                            │
│  ║  ┌──────────┐                    ║                                            │
│  ║  │  Hash    │ SHA-256 of secret  ║                                            │
│  ║  └────┬─────┘                    ║                                            │
│  ║       ▼                          ║                                            │
│  ║  ┌──────────┐                    ║                                            │
│  ║  │  Redact  │ Partial masking    ║                                            │
│  ║  └────┬─────┘                    ║                                            │
│  ║       ▼                          ║                                            │
│  ║  ┌──────────┐ File type, env,    ║                                            │
│  ║  │  Enrich  │ category, metadata ║                                            │
│  ║  └────┬─────┘                    ║                                            │
│  ║       ▼                          ║                                            │
│  ║  ┌──────────────┐ Stable cross-  ║                                            │
│  ║  │  Fingerprint │ scan identifier║                                            │
│  ║  └────┬─────────┘                ║                                            │
│  ║       ▼                          ║                                            │
│  ║  ┌──────────┐ Clear RawMatch     ║                                            │
│  ║  │ Sanitize │ (zero-trust)       ║                                            │
│  ║  └────┬─────┘                    ║                                            │
│  ╚═══════╪══════════════════════════╝                                            │
│          │                                                                       │
│          ▼                                                                       │
│  ┌────────────────────────┐                                                      │
│  │  Output (text / JSON)  │  Sanitized — no raw secrets                          │
│  └────────────────────────┘                                                      │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. The Five Default Processors

### 5.1 HashProcessor

**File**: `pkg/pipeline/hash.go`  
**Purpose**: Compute SHA-256 hash of the raw secret

```go
// What it does:
// 1. If RawMatch is empty, skip (no secret to hash)
// 2. Compute SHA-256 of RawMatch
// 3. Store in finding.SecretHash
// 4. Also store in finding.Metadata["sha256"] for backward compatibility
```

**Why it's first**: The hash must be computed while `RawMatch` still exists. Later, the SanitizeProcessor will erase `RawMatch`, so hashing must happen before sanitization.

**Example**:

```
Input:  finding.RawMatch = "AKIAIOSFODNN7EXAMPLE"
Output: finding.SecretHash = "5e6bf1b9e9c6e0b..." (64 hex chars)
        finding.Metadata["sha256"] = "5e6bf1b9e9c6e0b..." (same)
```

**Note**: The detection engine also computes `SecretHash` during scanning (for deduplication). The HashProcessor respects this — if `SecretHash` is already set, it uses the existing value and only adds the `Metadata["sha256"]` entry.

### 5.2 RedactProcessor

**File**: `pkg/pipeline/redact.go`  
**Purpose**: Create a human-readable masked version of the secret

```go
// Redaction rules:
// Length > 12:  first 4 chars + "****" + last 4 chars
// Length 5-12:  first 2 chars + "****"
// Length ≤ 4:   "****"
```

**Why it's second**: Redaction needs `RawMatch` to create the masked version. It must run before sanitization erases `RawMatch`.

**Idempotent**: If `RedactedMatch` is already set (e.g., by a previous run or custom processor), the RedactProcessor skips the finding.

**Examples**:

| RawMatch | RedactedMatch |
|----------|---------------|
| `AKIAIOSFODNN7EXAMPLE` | `AKIA****MPLE` |
| `sk_live_12345...XYz` | `sk_l****VWXz` |
| `ghp_ABCDE` | `gh****` |
| `pass` | `****` |

### 5.3 EnrichProcessor

**File**: `pkg/pipeline/enrich.go`  
**Purpose**: Classify and contextualize the finding

The EnrichProcessor examines the finding's source location and secret type to infer:

#### File Type Classification (60+ extensions)

| Extension | FileType | Extension | FileType |
|-----------|----------|-----------|----------|
| `.go` | `go` | `.py` | `python` |
| `.js` | `javascript` | `.ts` | `typescript` |
| `.java` | `java` | `.rb` | `ruby` |
| `.yml`/`.yaml` | `yaml` | `.json` | `json` |
| `.env` | `env` | `.xml` | `xml` |
| `.sh` | `shell` | `.sql` | `sql` |
| `.tf` | `terraform` | `.hcl` | `hcl` |
| `Dockerfile` | `dockerfile` | `Makefile` | `makefile` |

#### Environment Detection

| Path Pattern | Environment |
|-------------|-------------|
| `/prod/`, `.production`, `production.` | `production` |
| `/staging/`, `.staging` | `staging` |
| `/dev/`, `.development`, `/local/` | `development` |
| `.github/workflows/`, `/ci/`, `/pipeline/` | `ci` |
| `/test/`, `/spec/`, `_test.go` | `test` |
| (no match) | `unknown` |

#### Secret Categorization

| SecretType Pattern | Category |
|-------------------|----------|
| `aws-*`, `azure-*`, `gcp-*` | `cloud` |
| `github-*`, `gitlab-*`, `bitbucket-*` | `scm` |
| `postgres-*`, `mysql-*`, `mongo-*`, `redis-*` | `database` |
| `stripe-*`, `square-*`, `paypal-*` | `payment` |
| `openai-*`, `huggingface-*` | `ai-ml` |
| `private-key-*` | `private-key` |
| `slack-*`, `discord-*` | `messaging` |
| `high-entropy-*` | `entropy` |
| (other) | `generic` |

#### Scan Metadata Injection

When a `ScanMetadata` struct is provided, the EnrichProcessor injects:
- `finding.Metadata["scan_id"]` — unique scan identifier
- `finding.Metadata["scanner_version"]` — CredVigil version
- `finding.Metadata["config_hash"]` — hash of the scan configuration

### 5.4 FingerprintProcessor

**File**: `pkg/pipeline/fingerprint.go`  
**Purpose**: Create a stable cross-scan identifier

```go
fingerprint = SHA-256(ruleID + ":" + location + ":" + lineNumber + ":" + secretHash)
```

The fingerprint is **deterministic**: scanning the same file twice will produce the same fingerprint for the same finding. This enables:

- **Cross-scan deduplication**: Identify findings that haven't changed between scans
- **Suppression lists**: Permanently silence known false positives by fingerprint
- **Trend tracking**: See when a finding first appeared and when it was resolved

**Example**:

```
ruleID:     "aws-access-key"
location:   "src/config/database.go"
line:       42
secretHash: "5e6bf1b9..."

fingerprint = SHA-256("aws-access-key:src/config/database.go:42:5e6bf1b9...")
            = "a1b2c3d4..."  (64 hex chars)
```

### 5.5 SanitizeProcessor

**File**: `pkg/pipeline/sanitize.go`  
**Purpose**: Permanently erase the raw secret from the finding

```go
// Always:
//   finding.RawMatch = ""
//
// Optional (when ClearMetadataSHA = true):
//   delete(finding.Metadata, "sha256")
```

**Why it's last**: Every other processor needs `RawMatch` or its derivatives. The SanitizeProcessor runs last to guarantee that no raw secret leaves the pipeline.

**This is the zero-trust enforcement point.** After the SanitizeProcessor runs, the finding is safe for:
- Logging to stdout/stderr
- JSON serialization
- Storage in a database
- Transmission over a network
- Display on a dashboard

---

## 6. The Processor Interface

Every processor implements a simple two-method interface:

```go
type Processor interface {
    // Name returns a unique identifier for the processor
    Name() string

    // Process transforms a single finding in-place
    // Returns an error if the finding should be dropped
    Process(ctx context.Context, finding *models.Finding, meta *models.ScanMetadata) error
}
```

**Design principles**:

| Principle | How It's Applied |
|-----------|-----------------|
| **Single responsibility** | Each processor does exactly one thing |
| **In-place mutation** | Processors modify the finding directly (pointer receiver) |
| **Error = drop** | If a processor returns an error, the finding is removed from results |
| **Context-aware** | The `context.Context` parameter supports cancellation and timeouts |
| **Metadata-aware** | The `ScanMetadata` parameter provides scan-level context |

```mermaid
classDiagram
    class Processor {
        <<interface>>
        +Name() string
        +Process(ctx, finding, meta) error
    }
    class HashProcessor {
        +Name() string
        +Process() error
    }
    class RedactProcessor {
        +Name() string
        +Process() error
    }
    class EnrichProcessor {
        +Name() string
        +Process() error
    }
    class FingerprintProcessor {
        +Name() string
        +Process() error
    }
    class SanitizeProcessor {
        +ClearMetadataSHA bool
        +Name() string
        +Process() error
    }
    Processor <|.. HashProcessor
    Processor <|.. RedactProcessor
    Processor <|.. EnrichProcessor
    Processor <|.. FingerprintProcessor
    Processor <|.. SanitizeProcessor
```

---

## 7. Pipeline Orchestration

The `Pipeline` struct manages and runs processors in order:

```go
pipe := pipeline.NewDefault()   // Hash → Redact → Enrich → Fingerprint → Sanitize
pipe := pipeline.New()          // Empty pipeline — add your own processors
pipe := pipeline.New(proc1, proc2)  // Custom processor list
```

### Processing Modes

**ProcessFindings**: Process a slice of findings, returning kept findings and errors.

```go
kept, errs := pipe.ProcessFindings(ctx, findings, meta)
```

- Each finding is passed through every processor in order
- If any processor returns an error for a finding, that finding is **dropped**
- Dropped findings are recorded in the error list

**ProcessResult**: Convenience method that processes an entire `ScanResult` in-place.

```go
errs := pipe.ProcessResult(ctx, &result, meta)
```

- Updates `result.Findings` with processed findings
- Recomputes `result.TotalFindings`
- Recomputes `result.CountBySeverity`

### Dynamic Pipeline Modification

```go
// Add a processor to the end (before sanitize — you should reorder manually)
pipe.AddProcessor(myProcessor)

// Insert a processor at a specific position
pipe.InsertProcessor(4, myVerifier)  // Before sanitize (index 4)

// Get the current processor list
procs := pipe.Processors()
```

### Thread Safety

The Pipeline uses a `sync.RWMutex` to protect concurrent access to the processor list. This means:
- Multiple goroutines can call `ProcessFindings` concurrently (read lock)
- Adding/inserting processors acquires an exclusive write lock

```mermaid
sequenceDiagram
    participant C as Caller
    participant P as Pipeline
    participant H as HashProcessor
    participant R as RedactProcessor
    participant E as EnrichProcessor
    participant FP as FingerprintProcessor
    participant S as SanitizeProcessor

    C->>P: ProcessFindings(findings)
    loop For each finding
        P->>H: Process(finding)
        H-->>P: ok (SecretHash set)
        P->>R: Process(finding)
        R-->>P: ok (RedactedMatch set)
        P->>E: Process(finding)
        E-->>P: ok (FileType, Env, Category set)
        P->>FP: Process(finding)
        FP-->>P: ok (Fingerprint set)
        P->>S: Process(finding)
        S-->>P: ok (RawMatch cleared)
    end
    P-->>C: kept findings + errors
```

---

## 8. How It Integrates with the Detection Engine

### Before Component 2 (Module 1)

In Component 1, hashing, redaction, and metadata were handled **inline** inside the detection engine:

```go
// Old approach (inside matchRule):
finding.Metadata["sha256"] = hashSecret(secretValue)
finding.Redact()
```

### After Component 2

Now, the detection engine focuses purely on **detection**. Post-processing is a separate concern:

```go
// New approach (in main.go):
results := engine.ScanContent(request)

// Pipeline handles everything
pipe := pipeline.NewDefault()
meta := &models.ScanMetadata{
    ScannerVersion: version,
    StartedAt:      time.Now(),
    RuleCount:      len(engine.Rules()),
}
pipe.ProcessResult(ctx, &results, meta)
```

**What the engine still does**:
- Computes `SecretHash` during detection for **deduplication** (removing duplicate findings of the same secret)
- Sets `RawMatch`, `Confidence`, `Severity`, `Source`, and other detection-related fields

**What the engine no longer does**:
- No redaction (`Redact()` is not called)
- No metadata injection (no `Metadata["sha256"]`)
- No post-processing of any kind

This **separation of concerns** makes both components simpler, more testable, and independently evolvable.

```mermaid
flowchart TD
    subgraph Before["Before: Component 1 Only"]
        A1["Engine"] --> A2["Detect + Hash + Redact + Metadata"]
    end
    subgraph After["After: Component 1 + 2"]
        B1["Engine"] --> B2["Detect Only"]
        B2 --> B3["Pipeline"]
        B3 --> B4["Hash + Redact + Enrich + Fingerprint + Sanitize"]
    end
    style Before fill:#E74C3C,stroke:#C0392B,color:#fff
    style After fill:#27AE60,stroke:#1E8449,color:#fff
```

---

## 9. Understanding the Output Changes

### Text Output (Before vs. After)

**Before (Component 1 only)**:
```
  Secret:      AKIA****MPLE
  Hash:        5e6bf1b9... (from Metadata)
```

**After (with Pipeline)**:
```
  Secret:      AKIA****MPLE
  Hash:        5e6bf1b9...e1f2a3b4
  Fingerprint: a1b2c3d4e5f6a7b8
  File Type:   go
  Environment: production
  Category:    cloud
```

### JSON Output

The JSON output now includes the new fields:

```json
{
  "id": "f-001",
  "ruleID": "aws-access-key",
  "secretType": "aws-access-key",
  "rawMatch": "",
  "redactedMatch": "AKIA****MPLE",
  "secretHash": "5e6bf1b9e9c6e0b93a3e1f4f2c0aec8d...",
  "fingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6...",
  "fileType": "go",
  "environment": "production",
  "category": "cloud",
  "confidence": 0.95,
  "severity": "HIGH",
  "source": {
    "type": "file",
    "location": "src/config/database.go",
    "line": 42
  },
  "metadata": {
    "sha256": "5e6bf1b9...",
    "scan_id": "scan-abc-123",
    "scanner_version": "0.1.0",
    "config_hash": "cfghash"
  }
}
```

Note that `rawMatch` is always empty — this is the zero-trust guarantee in action.

---

## 10. Hands-On Exercises

### Exercise 1: Observe the Pipeline in Action

Run a scan and examine the enriched output:

```bash
go run ./cmd/credvigil scan testdata/fake_secrets.env
```

For each finding, notice the new fields:
- **Hash**: The first 8 and last 8 characters of the SHA-256 hash
- **Fingerprint**: The first 16 characters of the stable identifier
- **File Type**: The detected file type (should be `env`)
- **Environment**: Should be `unknown` (not in a prod/staging/dev path)
- **Category**: Should vary — `cloud` for AWS keys, `scm` for GitHub tokens, etc.

### Exercise 2: Compare Text and JSON Output

```bash
# Text output
go run ./cmd/credvigil scan testdata/fake_secrets.env

# JSON output
go run ./cmd/credvigil scan testdata/fake_secrets.env --output json | python3 -m json.tool | head -40
```

In the JSON output, verify:
- `rawMatch` is always `""` (empty)
- `secretHash` is always 64 characters
- `fingerprint` is always 64 characters

### Exercise 3: Verify Zero-Trust Guarantee

```bash
go run ./cmd/credvigil scan testdata/fake_secrets.env --output json | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for f in data.get('findings', []):
    if f.get('rawMatch', '') != '':
        print(f'VIOLATION: rawMatch is not empty for {f[\"ruleID\"]}')
        sys.exit(1)
print(f'Zero-trust verified: {len(data.get(\"findings\", []))} findings, all sanitized')
"
```

### Exercise 4: Verify Fingerprint Stability

Run the same scan twice and verify fingerprints are identical:

```bash
# First scan
go run ./cmd/credvigil scan testdata/fake_secrets.env --output json > /tmp/scan1.json

# Second scan
go run ./cmd/credvigil scan testdata/fake_secrets.env --output json > /tmp/scan2.json

# Compare fingerprints
python3 -c "
import json
with open('/tmp/scan1.json') as f: s1 = json.load(f)
with open('/tmp/scan2.json') as f: s2 = json.load(f)
fps1 = sorted([f['fingerprint'] for f in s1['findings']])
fps2 = sorted([f['fingerprint'] for f in s2['findings']])
if fps1 == fps2:
    print(f'Stable: {len(fps1)} fingerprints match across scans')
else:
    print('MISMATCH detected!')
"
```

### Exercise 5: Run the Pipeline Test Suite

```bash
go test ./pkg/pipeline/ -v -count=1
```

You should see 32 tests pass, covering:
- Hash computation and preset-hash handling
- Redaction for long, medium, short, and empty secrets
- File type classification, environment detection, and secret categorization
- Fingerprint determinism and differentiation
- Sanitization (RawMatch clearing, metadata handling)
- Full pipeline chain, ProcessResult, dynamic processor management
- Error handling, partial errors, and the zero-trust guarantee

### Exercise 6: Test a Production Path

Create a file in a "production" directory and scan it:

```bash
mkdir -p /tmp/config/prod/
echo 'AWS_KEY=AKIAIOSFODNN7EXAMPLE' > /tmp/config/prod/database.env
go run ./cmd/credvigil scan /tmp/config/prod/database.env
```

Notice that the **Environment** field should show `production` because the file path contains `/prod/`.

Clean up:
```bash
rm -rf /tmp/config/
```

---

## 11. Deep Dive: Code Walkthrough

### File Structure

```
pkg/pipeline/
├── pipeline.go       # Pipeline orchestrator, Processor interface
├── hash.go           # SHA-256 hashing processor
├── redact.go         # Secret masking processor
├── enrich.go         # File type, environment, category classification
├── fingerprint.go    # Stable cross-scan identifier
├── sanitize.go       # Zero-trust RawMatch clearing
├── verify.go         # Verification hook interface (placeholder)
└── pipeline_test.go  # 32 test functions
```

### pipeline.go — The Orchestrator

```go
// The Processor interface — every step in the pipeline implements this
type Processor interface {
    Name() string
    Process(ctx context.Context, finding *models.Finding, meta *models.ScanMetadata) error
}

// Pipeline holds an ordered list of processors
type Pipeline struct {
    mu         sync.RWMutex
    processors []Processor
}

// NewDefault creates the standard pipeline:
// Hash → Redact → Enrich → Fingerprint → Sanitize
func NewDefault() *Pipeline {
    return New(
        NewHashProcessor(),
        NewRedactProcessor(),
        NewEnrichProcessor(),
        NewFingerprintProcessor(),
        NewSanitizeProcessor(),
    )
}
```

The `ProcessFindings` method iterates over each finding and each processor:

```go
func (p *Pipeline) ProcessFindings(ctx context.Context, findings []models.Finding, meta *models.ScanMetadata) ([]models.Finding, []error) {
    p.mu.RLock()
    procs := make([]Processor, len(p.processors))
    copy(procs, p.processors)
    p.mu.RUnlock()

    var kept []models.Finding
    var errs []error

    for i := range findings {
        var failed bool
        for _, proc := range procs {
            if err := proc.Process(ctx, &findings[i], meta); err != nil {
                errs = append(errs, fmt.Errorf("processor %s: %w", proc.Name(), err))
                failed = true
                break
            }
        }
        if !failed {
            kept = append(kept, findings[i])
        }
    }

    return kept, errs
}
```

### hash.go — Computing the Secret Hash

```go
func sha256Hex(s string) string {
    h := sha256.New()
    h.Write([]byte(s))
    return hex.EncodeToString(h.Sum(nil))
}

func (hp *HashProcessor) Process(_ context.Context, f *models.Finding, _ *models.ScanMetadata) error {
    if f.RawMatch == "" {
        return nil  // Nothing to hash
    }
    hash := sha256Hex(f.RawMatch)
    if f.SecretHash == "" {
        f.SecretHash = hash
    }
    // Backward compatibility
    if f.Metadata == nil {
        f.Metadata = make(map[string]string)
    }
    f.Metadata["sha256"] = f.SecretHash
    return nil
}
```

### enrich.go — Classification Engine

The EnrichProcessor contains three classification functions:

- `classifyFileType(location)` — Maps 60+ file extensions and special filenames to types
- `detectEnvironment(location)` — Matches path patterns against environment keywords
- `categorizeSecret(secretType)` — Uses prefix matching to assign categories

Each function uses prefix or suffix matching (not regex) for performance.

### sanitize.go — The Zero-Trust Enforcer

```go
func (sp *SanitizeProcessor) Process(_ context.Context, f *models.Finding, _ *models.ScanMetadata) error {
    f.RawMatch = ""  // Permanent erasure
    if sp.ClearMetadataSHA {
        delete(f.Metadata, "sha256")
        if len(f.Metadata) == 0 {
            f.Metadata = nil
        }
    }
    return nil
}
```

---

## 12. Writing Custom Processors

You can create custom processors by implementing the `Processor` interface:

```go
package mypipeline

import (
    "context"
    "github.com/credvigil/credvigil/pkg/models"
)

// TagProcessor adds custom tags to findings
type TagProcessor struct {
    Tags map[string]string
}

func (tp *TagProcessor) Name() string { return "tagger" }

func (tp *TagProcessor) Process(_ context.Context, f *models.Finding, _ *models.ScanMetadata) error {
    if f.Metadata == nil {
        f.Metadata = make(map[string]string)
    }
    for k, v := range tp.Tags {
        f.Metadata[k] = v
    }
    return nil
}
```

Insert it into the pipeline before the sanitizer:

```go
pipe := pipeline.NewDefault()
tagger := &mypipeline.TagProcessor{
    Tags: map[string]string{
        "team":    "platform",
        "project": "credvigil",
    },
}
pipe.InsertProcessor(4, tagger)  // Before sanitize (index 4)
```

### Guidelines for Custom Processors

| Guideline | Why |
|-----------|-----|
| Never store `RawMatch` externally | Violates zero-trust |
| Always handle `nil` Metadata maps | Prevent nil-pointer panics |
| Return `error` to drop a finding | Use for validation/filtering |
| Keep processors stateless when possible | Enables concurrent processing |
| Use `Name()` for logging and debugging | Helps trace pipeline issues |

---

## 13. Verification Hooks (Preview)

The pipeline includes a `VerificationHook` interface that extends `Processor`:

```go
type VerificationHook interface {
    Processor
    CanVerify(secretType models.SecretType) bool
}
```

A `NoOpVerifier` placeholder is included but **not** part of the default pipeline. Future components will implement actual verification (e.g., checking if an AWS key is still active by making a safe API call).

To add verification to the pipeline:

```go
pipe := pipeline.NewDefault()
verifier := myVerifier  // Implements VerificationHook
pipe.InsertProcessor(4, verifier)  // Before sanitize
```

```mermaid
flowchart LR
    A["Hash"] --> B["Redact"]
    B --> C["Enrich"]
    C --> D["Fingerprint"]
    D --> E["🔍 Verify\n(future)"]
    E --> F["Sanitize"]
    style E fill:#F39C12,stroke:#D68910,color:#fff,stroke-dasharray: 5 5
```

---

## 14. Error Handling & Resilience

### Processor Errors

If a processor returns an error for a finding, that finding is **dropped** from the results and the error is recorded:

```go
kept, errs := pipe.ProcessFindings(ctx, findings, meta)
// kept  = findings that passed all processors
// errs  = errors from findings that were dropped
```

This ensures that partial failures don't corrupt the entire scan. If 100 findings are processed and 3 fail, you get 97 clean results and 3 errors.

### Error Reporting in CLI

When running via the CLI, pipeline errors are logged to stderr:

```
[pipeline] warning: 3 findings dropped due to processing errors
```

This does not affect the exit code — the scan is still considered successful if at least some findings were processed.

```mermaid
flowchart TD
    A["100 Findings"] --> B["⚙️ Pipeline"]
    B --> C{"Processor Error?"}
    C -->|"✅ No Error"| D["97 Kept Findings"]
    C -->|"❌ Error"| E["3 Dropped\n(logged to stderr)"]
    D --> F["📄 Output"]
    style D fill:#27AE60,stroke:#1E8449,color:#fff
    style E fill:#E74C3C,stroke:#C0392B,color:#fff
```

---

## 15. Frequently Asked Questions

**Q: Can I disable the SanitizeProcessor?**  
A: Technically yes (by using `pipeline.New()` and adding only the processors you want), but this is **strongly discouraged**. Disabling sanitization breaks the zero-trust guarantee and may leak raw secrets.

**Q: Does the pipeline modify the original findings?**  
A: `ProcessFindings` works on copies of the finding slice. `ProcessResult` modifies the `ScanResult` in-place. The detection engine's internal state is not affected.

**Q: Can I run the pipeline multiple times?**  
A: Yes, but the SanitizeProcessor will clear `RawMatch` on the first run. Subsequent runs will hash/redact empty strings. Design your workflow to run the pipeline once.

**Q: Why does the engine still compute SecretHash?**  
A: The engine needs `SecretHash` during scanning for **deduplication** — if the same secret appears on multiple lines, it only reports it once. The HashProcessor respects this pre-computed value.

**Q: How does fingerprinting handle file renames?**  
A: If a file is renamed, the fingerprint changes (because the location is part of the fingerprint input). This is intentional — a renamed file represents a new "finding location" for tracking purposes.

**Q: What happens if a finding has no RawMatch?**  
A: The HashProcessor skips it (no hash), the RedactProcessor sets `"****"`, and the SanitizeProcessor clears the (already empty) field. The pipeline handles edge cases gracefully.

---

## 16. Glossary

| Term | Definition |
|------|-----------|
| **Processor** | A single step in the pipeline that transforms a finding |
| **Pipeline** | An ordered chain of processors |
| **SHA-256** | A cryptographic hash function producing a 64-character hex digest |
| **Redaction** | Masking a secret with asterisks while preserving identifying characters |
| **Enrichment** | Adding contextual metadata (file type, environment, category) |
| **Fingerprint** | A stable identifier for a specific finding across scans |
| **Sanitization** | Permanently removing the raw secret from the finding |
| **Zero-trust** | The principle that no downstream component should see raw secrets |
| **ScanMetadata** | Information about the scan itself (version, ID, config hash, timing) |
| **VerificationHook** | A future processor that can verify if a secret is still active |
| **Idempotent** | A processor that produces the same result if run multiple times |
| **Deduplication** | Removing duplicate findings (same secret at different locations vs. same location) |

---

## 17. What's Next?

You've now learned how CredVigil post-processes detected secrets through a composable, zero-trust pipeline. In the next module, we'll build **Component 3: Git Integration Layer**, which will enable:

- Scanning git commit history for secrets that were committed and later deleted
- Blame analysis to identify who introduced a secret
- Branch-aware scanning
- Pull request diff scanning

Continue to [Module 3: Git Integration Layer](03-git-integration-layer.md) (coming soon).

---

*Copyright 2026 CredVigil Contributors. Licensed under Apache License 2.0.*
