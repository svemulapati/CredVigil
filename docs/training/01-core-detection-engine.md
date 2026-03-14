# CredVigil Training Guide — Module 1: Core Detection Engine

> **Version**: 0.1.0  
> **Component**: Core Detection Engine (Component 1 of 15)  
> **Audience**: Developers, security engineers, DevOps teams, and anyone new to credential detection  
> **Prerequisites**: A computer with Go 1.21+ installed. No prior security experience required.

---

## Table of Contents

1. [What Is CredVigil?](#1-what-is-credvigil)
2. [Why Do We Need Credential Detection?](#2-why-do-we-need-credential-detection)
3. [How CredVigil Works — The Big Picture](#3-how-credvigil-works--the-big-picture)
4. [Key Concepts Explained (For Everyone)](#4-key-concepts-explained-for-everyone)
   - 4.1 [What Is a "Secret" or "Credential"?](#41-what-is-a-secret-or-credential)
   - 4.2 [What Is Regex Pattern Matching?](#42-what-is-regex-pattern-matching)
   - 4.3 [What Is Shannon Entropy?](#43-what-is-shannon-entropy)
   - 4.4 [What Is Confidence Scoring?](#44-what-is-confidence-scoring)
   - 4.5 [What Is Zero-Trust Architecture?](#45-what-is-zero-trust-architecture)
   - 4.6 [What Is SHA-256 Hashing?](#46-what-is-sha-256-hashing)
   - 4.7 [What Is Redaction?](#47-what-is-redaction)
   - 4.8 [What Are False Positives?](#48-what-are-false-positives)
   - 4.9 [What Is Severity?](#49-what-is-severity)
5. [Installation & Setup](#5-installation--setup)
6. [Your First Scan — Step by Step](#6-your-first-scan--step-by-step)
7. [Understanding the Scan Output](#7-understanding-the-scan-output)
8. [All CLI Commands & Options Explained](#8-all-cli-commands--options-explained)
   - 8.1 [The `scan` Command](#81-the-scan-command)
   - 8.2 [The `rules` Command](#82-the-rules-command)
   - 8.3 [The `version` Command](#83-the-version-command)
   - 8.4 [CLI Flags Reference](#84-cli-flags-reference)
9. [Hands-On Exercises](#9-hands-on-exercises)
   - Exercise 1: Scan the Test Data File
   - Exercise 2: Filter by Severity
   - Exercise 3: Use JSON Output
   - Exercise 4: Adjust Confidence Threshold
   - Exercise 5: Disable Entropy Detection
   - Exercise 6: Scan from Standard Input (Piping)
   - Exercise 7: Create Your Own Test File
   - Exercise 8: Scan a Real Project
10. [Deep Dive: How the Detection Engine Works Internally](#10-deep-dive-how-the-detection-engine-works-internally)
    - 10.1 [The Detection Pipeline](#101-the-detection-pipeline)
    - 10.2 [Regex Matching Phase](#102-regex-matching-phase)
    - 10.3 [Entropy Analysis Phase](#103-entropy-analysis-phase)
    - 10.4 [Confidence Scoring Phase](#104-confidence-scoring-phase)
    - 10.5 [False Positive Reduction](#105-false-positive-reduction)
    - 10.6 [Deduplication](#106-deduplication)
    - 10.7 [Hashing & Redaction](#107-hashing--redaction)
11. [Understanding the Codebase — File by File](#11-understanding-the-codebase--file-by-file)
12. [The 161 Detection Rules — Categories & Examples](#12-the-161-detection-rules--categories--examples)
13. [Real-World Scenarios](#13-real-world-scenarios)
14. [Frequently Asked Questions](#14-frequently-asked-questions)
15. [Glossary](#15-glossary)
16. [What's Next?](#16-whats-next)

---

## 1. What Is CredVigil?

CredVigil is a **credential detection tool**. Its job is to find secrets — such as API keys, passwords, tokens, and private keys — that have been accidentally left in source code, configuration files, or any text content.

Think of it like a **spell-checker, but for security**. Just like a spell-checker scans your document for spelling mistakes, CredVigil scans your code for security mistakes.

### Why "CredVigil"?

- **Cred** = Credentials (passwords, API keys, tokens)
- **Vigil** = Watchful guard (from Latin "vigilare" — to keep watch)

CredVigil is your watchful guard against leaked credentials.

```mermaid
flowchart LR
    A["📁 Your Code"] --> B["🔍 CredVigil"]
    B --> C["✅ Clean Report"]
    B --> D["🚨 Secrets Found"]
    D --> E["🔒 Redacted + Hashed"]
    style B fill:#4A90D9,stroke:#2C5F8A,color:#fff
    style D fill:#E74C3C,stroke:#C0392B,color:#fff
    style E fill:#27AE60,stroke:#1E8449,color:#fff
```

---

## 2. Why Do We Need Credential Detection?

### The Problem

Every modern application talks to external services — databases, cloud providers, email services, payment processors, AI APIs, and more. To authenticate with these services, your application uses **secrets**: API keys, passwords, tokens, and certificates.

Here's the dangerous part: **developers frequently, accidentally, commit these secrets into their code.**

```bash
# A developer might write this in their code:
DATABASE_URL=postgresql://admin:MyRealPassword123@db.production.com:5432/myapp

# Or this:
OPENAI_API_KEY=sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
```

Once that code is pushed to a repository (like GitHub), anyone with access to that repository — or anyone who compromises it — can steal those credentials and:

- **Access your database** and steal customer data
- **Run up charges** on your cloud provider or AI API
- **Send emails** from your company's email service
- **Process fake payments** through your payment processor
- **Access internal systems** using stolen tokens

### The Scale of the Problem

- **Millions** of secrets are leaked on GitHub every year
- Automated bots scan GitHub 24/7 specifically looking for leaked credentials
- A leaked AWS key can result in thousands of dollars of charges within minutes
- Data breaches from leaked credentials cost companies millions in fines and reputation damage

```mermaid
flowchart TD
    A["Developer Commits Code"] --> B{"Contains Secrets?"}
    B -->|Yes| C["🚨 Pushed to Repository"]
    C --> D["🤖 Bots Scan GitHub 24/7"]
    D --> E["💸 Stolen Keys Used\nCloud charges, data theft"]
    B -->|No| F["✅ Safe"]
    style C fill:#E74C3C,stroke:#C0392B,color:#fff
    style E fill:#C0392B,stroke:#922B21,color:#fff
    style F fill:#27AE60,stroke:#1E8449,color:#fff
```

### Why Manual Review Isn't Enough

- A single project might have hundreds or thousands of files
- New code is committed daily
- Different services use different key formats — hard to remember them all
- Developers are focused on building features, not auditing every line for secrets
- Copy-pasting from documentation or Stack Overflow can accidentally include real keys

### What CredVigil Does

CredVigil automates this entire process. It:

1. **Scans your code** and configuration files
2. **Identifies potential secrets** using both pattern recognition and mathematical analysis
3. **Scores each finding** with a confidence percentage so you know what to prioritize
4. **Redacts the secrets** so they're not exposed in reports
5. **Shows you exactly where** the secret is located (file, line number, context)

```mermaid
flowchart LR
    A["📂 Scan Code"] --> B["🔎 Identify Secrets"]
    B --> C["📊 Score Confidence"]
    C --> D["🔒 Redact & Hash"]
    D --> E["📍 Report Location"]
    style A fill:#3498DB,stroke:#2980B9,color:#fff
    style B fill:#E67E22,stroke:#D35400,color:#fff
    style C fill:#9B59B6,stroke:#8E44AD,color:#fff
    style D fill:#27AE60,stroke:#1E8449,color:#fff
    style E fill:#1ABC9C,stroke:#16A085,color:#fff
```

---

## 3. How CredVigil Works — The Big Picture

CredVigil uses a **dual detection strategy**. This means it uses two completely different methods to find secrets, and combines the results. This is like having two security guards with different skills — one is good at recognizing faces (known patterns), and the other is good at spotting suspicious behavior (statistical anomalies).

```
┌──────────────────────────────────────────────────────────────────────┐
│                        YOUR CODE / FILES                             │
│   (source code, .env files, config files, YAML, JSON, etc.)         │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    CREDVIGIL DETECTION ENGINE                        │
│                                                                      │
│   ┌─────────────────────────────┐  ┌──────────────────────────────┐  │
│   │  STRATEGY 1: Regex Match    │  │  STRATEGY 2: Entropy Check   │  │
│   │                             │  │                              │  │
│   │  "Does this text match a    │  │  "Is this string random      │  │
│   │   known pattern for a       │  │   enough to be a secret?"    │  │
│   │   specific service?"        │  │                              │  │
│   │                             │  │  Uses Shannon Entropy — a    │  │
│   │  161 rules for services     │  │  mathematical measure of     │  │
│   │  like AWS, GitHub, Stripe,  │  │  randomness.                 │  │
│   │  OpenAI, Slack, etc.        │  │                              │  │
│   └──────────────┬──────────────┘  └──────────────┬───────────────┘  │
│                  │                                │                  │
│                  └──────────┬─────────────────────┘                  │
│                             ▼                                        │
│              ┌──────────────────────────────┐                        │
│              │   CONFIDENCE SCORING          │                        │
│              │                              │                        │
│              │  Combines all signals:       │                        │
│              │  • Pattern match strength    │                        │
│              │  • Entropy value             │                        │
│              │  • Keyword context           │                        │
│              │  • False positive checks     │                        │
│              │  • Secret length             │                        │
│              │                              │                        │
│              │  Result: 0% – 100%           │                        │
│              └──────────────┬───────────────┘                        │
│                             ▼                                        │
│              ┌──────────────────────────────┐                        │
│              │  ZERO-TRUST PROCESSING       │                        │
│              │                              │                        │
│              │  • SHA-256 hash the secret   │                        │
│              │  • Redact the display value   │                        │
│              │  • Clear raw secret from RAM  │                        │
│              └──────────────┬───────────────┘                        │
│                             │                                        │
└─────────────────────────────┼────────────────────────────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         SCAN REPORT                                  │
│                                                                      │
│  Shows: severity, rule, file:line, redacted value, entropy,          │
│         confidence %, SHA-256 hash, surrounding context              │
│                                                                      │
│  Does NOT show: the actual secret in plaintext                       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 4. Key Concepts Explained (For Everyone)

### 4.1 What Is a "Secret" or "Credential"?

A **secret** (also called a **credential**) is any piece of sensitive information that grants access to a system or service. Think of it as a digital key or password.

**Common types of secrets:**

| Type | What It Is | Example Format |
|------|-----------|----------------|
| **API Key** | A unique code that identifies your application to a service | `sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabc` |
| **Password** | A secret word or phrase for authentication | `SuperSecretPassword123!` |
| **Token** | A short-lived credential for accessing services | `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234` |
| **Private Key** | A cryptographic key used for encryption and identity | `-----BEGIN RSA PRIVATE KEY-----` |
| **Connection String** | A URL containing credentials for database access | `postgresql://user:password@host:5432/db` |
| **Webhook URL** | A special URL that triggers actions in external services | `https://hooks.slack.com/services/T.../B.../...` |
| **OAuth Secret** | A secret used in OAuth authentication flows | `client_secret_ABCDEFghijklmnop123456` |

**Why are they dangerous when leaked?**  
Because anyone who has them can pretend to be you. If someone gets your AWS access key, they can spin up servers, delete your data, or access your S3 buckets — all charged to your account.

```mermaid
mindmap
  root((Secrets))
    API Keys
      AWS Access Key
      OpenAI sk-proj-...
      Stripe sk_live_...
    Tokens
      GitHub PAT ghp_...
      OAuth Bearer
      JWT eyJ...
    Passwords
      Database passwords
      Connection strings
      SMTP credentials
    Private Keys
      RSA -----BEGIN RSA...
      SSH id_ed25519
      PGP/GPG
    Webhooks
      Slack hooks
      Discord webhooks
      Generic URLs with tokens
```

---

### 4.2 What Is Regex Pattern Matching?

**Regex** stands for **Regular Expression**. It's a way to describe a text pattern using special syntax. CredVigil uses regex to recognize known secret formats.

**Analogy:** Imagine you're looking for phone numbers in a document. You know phone numbers look like `(555) 123-4567` — three digits in parentheses, a space, three digits, a dash, four digits. A regex is like writing down that pattern so a computer can find all phone numbers automatically.

**How CredVigil uses regex:**

Each service's API keys have a specific format. For example:
- **GitHub tokens** always start with `ghp_` followed by 36 characters
- **AWS access keys** always start with `AKIA` followed by 16 uppercase alphanumeric characters
- **Stripe secret keys** always start with `sk_live_` or `sk_test_`
- **OpenAI API keys** start with `sk-` followed by alphanumeric characters

CredVigil has **161 regex rules**, each designed to match the format of a specific service's credentials. When it scans your code, it checks every line against all 161 patterns.

**Example:**
```
Rule:    AWS Access Key ID
Pattern: AKIA[0-9A-Z]{16}
Matches: AKIAIOSFODNN7EXAMPLE     ✅ (starts with AKIA, followed by 16 uppercase alphanumeric chars)
         AKIA12345               ❌ (too short)
         BKIAIOSFODNN7EXAMPLE    ❌ (doesn't start with AKIA)
         random_text_here        ❌ (doesn't match pattern at all)
```

**Why regex alone isn't enough:**  
Regex can only find secrets it already knows about. If a new service launches tomorrow with a new key format, regex won't catch it. That's why CredVigil also uses entropy analysis (explained next).

```mermaid
flowchart TD
    A["Input Text"] --> B["Apply 276 Regex Rules"]
    B --> C{"Pattern Match?"}
    C -->|"✅ AKIA... matches AWS rule"| D["Finding Created"]
    C -->|"❌ No match"| E["Try Entropy Analysis"]
    style D fill:#27AE60,stroke:#1E8449,color:#fff
    style E fill:#F39C12,stroke:#D68910,color:#fff
```

---

### 4.3 What Is Shannon Entropy?

**Shannon Entropy** is a mathematical concept from information theory that measures **how random or unpredictable a string of text is**. It was invented by Claude Shannon in 1948.

**Analogy:** Imagine two strings of text:
- `aaaaaaaaaaaaa` — very predictable, very boring. **Low entropy.**
- `kJ9mN2pR5tW8x` — looks random, hard to predict. **High entropy.**

Secrets (like API keys and passwords) are **designed to be random and hard to guess**. That's what makes them secure. But this randomness also makes them detectable — because normal code, variable names, and English text are NOT random.

**How entropy is calculated (simplified):**

1. Count how many times each character appears in the string
2. Calculate the probability of each character
3. Use the formula: $H = -\sum p_i \cdot \log_2(p_i)$ where $p_i$ is the probability of each character

Don't worry about the math — just understand the concept:
- **Low entropy (0–3)**: Simple, repetitive text (`hello`, `aaabbb`, `123123`)
- **Medium entropy (3–4.5)**: Normal words, code, variable names
- **High entropy (4.5+)**: Random-looking strings — **likely secrets**

**CredVigil's entropy thresholds:**

| String Type | Suspicious Threshold | Very Likely a Secret |
|-------------|---------------------|---------------------|
| Hex strings (0-9, a-f) | 3.0 | 3.5 |
| Base64 strings | 4.0 | 4.5 |
| Alphanumeric | 4.2 | 4.7 |
| General text | 4.5 | 5.0 |

**Why different thresholds?**  
A hex string uses only 16 characters (0-9, a-f), so its maximum possible entropy is lower than a base64 string that uses 64 characters. The thresholds account for this — what counts as "random" depends on the alphabet being used.

**Real example from CredVigil:**
```
String: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
Entropy: 4.66 (high — this looks like a secret!)
Charset: Base64
Threshold for Base64: 4.0 (suspicious) / 4.5 (very likely)
Result: ⚠️ This is very likely a secret (entropy 4.66 > 4.5 threshold)
```

```mermaid
flowchart LR
    subgraph Low["Low Entropy"]
        A["aaaaaaaaaa\nH = 0.0"]
    end
    subgraph Med["Medium Entropy"]
        B["helloWorld\nH = 3.2"]
    end
    subgraph High["High Entropy 🚨"]
        C["kJ9mN2pR5tW8x\nH = 4.7"]
    end
    Low --> Med --> High
    style Low fill:#27AE60,stroke:#1E8449,color:#fff
    style Med fill:#F39C12,stroke:#D68910,color:#fff
    style High fill:#E74C3C,stroke:#C0392B,color:#fff
```

---

### 4.4 What Is Confidence Scoring?

**Confidence scoring** is CredVigil's way of telling you **how sure it is** that a finding is a real secret, not a false alarm.

Instead of just saying "found!" or "not found!", CredVigil gives every finding a percentage score from 0% to 100%.

**Analogy:** Imagine a smoke detector. A basic one just beeps — you don't know if it's a real fire or burnt toast. A smart smoke detector might say "95% confidence — real fire detected" or "15% confidence — probably steam from the shower." That's what confidence scoring does for secret detection.

**How confidence is calculated:**

CredVigil starts with a **base confidence** from the matching rule (different rules have different base confidences), then adjusts it based on several factors:

| Factor | Effect | Why |
|--------|--------|-----|
| **High entropy** | +10% boost | Random-looking strings are more likely real secrets |
| **Low entropy** | -20% penalty | Predictable strings are less likely real secrets |
| **Keyword proximity** | Up to +10% boost | If words like "password", "secret", or "api_key" appear nearby, it's probably real |
| **False positive pattern** | -25% penalty | If it looks like a placeholder or test value |
| **Placeholder detection** | -40% penalty | Values like "changeme", "EXAMPLE", "your-key-here" |
| **Short length** (<12 chars) | -10% penalty | Very short values are less reliable |
| **Long length** (>30 chars) | +5% boost | Longer secrets are more likely real |

**Example:**
```
Finding: sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz
Base confidence from Stripe rule:     0.85
+ High entropy boost:                +0.10
+ Keyword "STRIPE_SECRET_KEY" nearby: +0.05
- No false positive penalty:          0.00
= Final confidence:                   1.00 (capped at 100%)
```

**How to use confidence scores:**

| Confidence | What It Means | Recommended Action |
|------------|---------------|-------------------|
| **80–100%** | Almost certainly a real secret | **Immediately investigate and rotate** |
| **60–79%** | Very likely a real secret | **Review and probably rotate** |
| **40–59%** | Possible secret | **Review manually** |
| **20–39%** | Low confidence — might be a false positive | **Quick check, probably safe** |
| **0–19%** | Very unlikely to be a real secret | **Likely a false positive** |

By default, CredVigil only shows findings with **30% or higher** confidence (configurable with `--min-confidence`).

```mermaid
flowchart TD
    A["Base Confidence\n(from rule, e.g. 0.85)"] --> B{"Adjustments"}
    B --> C["+0.10 High Entropy"]
    B --> D["+0.10 Keyword Nearby"]
    B --> E["-0.25 False Positive"]
    B --> F["-0.40 Placeholder"]
    C & D & E & F --> G["Final Score\n(clamped 0.0 – 1.0)"]
    style A fill:#3498DB,stroke:#2980B9,color:#fff
    style G fill:#9B59B6,stroke:#8E44AD,color:#fff
```

---

### 4.5 What Is Zero-Trust Architecture?

**Zero-trust** means: **"Trust nothing and no one by default."**

This is a fundamental shift from how security traditionally worked. In the old model (called **perimeter security** or **castle-and-moat**), you trusted everything inside your network and only defended the boundary. Once someone got past the wall, they had free access to everything.

Zero-trust flips this: **every single interaction must be verified, regardless of where it comes from.**

```mermaid
flowchart TD
    subgraph Old["❌ Traditional: Castle & Moat"]
        A1["🏰 Inside the Wall"] --> A2["✅ Trusted by Default"]
        A3["🌍 Outside"] --> A4["🛡️ Firewall"] --> A1
        A5["🦹 Attacker Gets Past Wall"] --> A1
        A5 --> A6["💀 Full Access to Everything"]
    end
    subgraph New["✅ Zero-Trust: Verify Everything"]
        B1["Any Request"] --> B2{"Verified?"}
        B2 -->|"Identity + Context + Policy"| B3["✅ Access Granted\n(minimum needed)"]
        B2 -->|"Not verified"| B4["🚫 Denied"]
    end
    style Old fill:#FADBD8,stroke:#E74C3C
    style New fill:#D5F5E3,stroke:#27AE60
```

#### The Three Pillars of Zero-Trust

Zero-trust architecture rests on three core principles:

| Pillar | Meaning | Example |
|--------|---------|---------|
| **1. Never Trust, Always Verify** | Every request must prove its identity — even if it comes from "inside" | A dashboard requesting findings must authenticate, even if it's on the same server |
| **2. Least Privilege Access** | Grant only the minimum access needed for a task, nothing more | If a component only needs redacted findings, it should never see raw secrets |
| **3. Assume Breach** | Design systems as if an attacker has already gotten in | Even if someone compromises CredVigil's output, they still can't see raw secrets |

#### How Zero-Trust Works: The Handshake Model

In traditional client-server communication, trust is established through a **handshake** — a back-and-forth exchange where both parties verify each other before sharing data. Here's how this applies in a zero-trust model:

**Step 1: Client requests access**

The client (e.g., a dashboard, CI/CD pipeline, or API consumer) sends a request. In zero-trust, this request carries **identity proof** — not just "I'm inside the network."

**Step 2: Server verifies identity**

The server checks the client's credentials, context (IP, device, time), and policy rules. No implicit trust.

**Step 3: Server responds with minimum data**

Even after verification, the server only sends the **least privileged data** the client needs — never the raw secret.

```mermaid
sequenceDiagram
    participant C as 🖥️ Client<br>(Dashboard/CI/CD)
    participant S as 🔒 CredVigil<br>Server
    participant P as 🛡️ Policy<br>Engine

    Note over C,S: Step 1: Authentication Handshake
    C->>S: 1. Request findings<br>+ Auth token + Context
    S->>P: 2. Verify identity<br>+ Check permissions
    P-->>S: 3. ✅ Verified<br>Role: "viewer"

    Note over C,S: Step 2: Least Privilege Response
    S->>S: 4. Apply zero-trust filter:<br>Strip raw secrets,<br>keep only redacted data
    S-->>C: 5. Return sanitized findings<br>(hash + redacted only)

    Note over C,S: ❌ What NEVER happens
    C--xS: ❌ "Give me raw secrets"
    S--xC: ❌ Raw secret in response
```

#### Without Zero-Trust vs. With Zero-Trust

Here's a concrete comparison showing how data flows differently:

```mermaid
sequenceDiagram
    participant D as 📊 Dashboard
    participant CV as 🔍 CredVigil

    Note over D,CV: ❌ WITHOUT Zero-Trust (Dangerous)
    D->>CV: Request scan results
    CV-->>D: Finding: AKIAIOSFODNN7EXAMPLE<br>(⚠️ RAW secret exposed!)
    Note right of D: Dashboard stores raw secret<br>in database, logs, cache...<br>Attacker steals it all.

    Note over D,CV: ─────────────────────

    Note over D,CV: ✅ WITH Zero-Trust (CredVigil's Approach)
    D->>CV: Request scan results
    CV->>CV: Pipeline: Hash → Redact → Sanitize
    CV-->>D: Finding: AKIA****MPLE<br>Hash: 5e6bf1b9...e1f2a3b<br>RawMatch: "" (empty)
    Note right of D: Dashboard can display<br>and track the finding,<br>but CANNOT recover<br>the original secret.
```

#### How CredVigil Applies Zero-Trust

In the context of CredVigil specifically, zero-trust means:

1. **We never trust that our own system won't be compromised.** So we never store or display the actual secret in plaintext.
2. **We never trust the output destination.** Whether findings go to a file, a dashboard, or an API — the raw secret is never included.
3. **We never trust the network.** No plaintext secrets are ever transmitted.
4. **We never trust memory to be safe.** The raw secret is erased from the Finding struct after processing.
5. **We never trust future code changes.** The SanitizeProcessor enforces clearing at the architecture level — it's not optional.

**What CredVigil does instead:**

- **Stores a SHA-256 hash** — a one-way fingerprint of the secret (see next section)
- **Shows a redacted preview** — only the first 4 and last 4 characters, like `wJal****EKEY`
- **Clears the raw value from memory** before any output operation

#### Zero-Trust Data Flow — End to End

The following diagram shows the complete journey of a detected secret through CredVigil's zero-trust pipeline. Notice how the raw secret exists only briefly in memory during detection, then is permanently erased:

```mermaid
flowchart TD
    A["📂 Source File Contains:<br>AWS_KEY=AKIAIOSFODNN7EXAMPLE"] --> B["🔍 Detection Engine<br>reads file, matches regex"]
    B --> C["📦 Raw Finding Created<br>RawMatch = AKIAIOSFODNN7EXAMPLE"]

    C --> D["🔢 Hash Processor<br>SHA-256 → 5e6bf1b9..."]
    D --> E["🔒 Redact Processor<br>→ AKIA****MPLE"]
    E --> F["📊 Enrich Processor<br>FileType, Environment, Category"]
    F --> G["🗺️ Fingerprint Processor<br>Stable cross-scan ID"]
    G --> H["🧹 Sanitize Processor<br>RawMatch = '' (ERASED)"]

    H --> I{"Output Destination"}
    I --> J["🖥️ Terminal"]
    I --> K["📋 JSON File"]
    I --> L["🌐 API (future)"]
    I --> M["📊 Dashboard (future)"]

    style C fill:#E74C3C,stroke:#C0392B,color:#fff
    style H fill:#7F8C8D,stroke:#616A6B,color:#fff
    style J fill:#27AE60,stroke:#1E8449,color:#fff
    style K fill:#27AE60,stroke:#1E8449,color:#fff
    style L fill:#27AE60,stroke:#1E8449,color:#fff
    style M fill:#27AE60,stroke:#1E8449,color:#fff
```

> **Key insight**: The red box (raw finding with the actual secret) exists only momentarily inside the pipeline. By the time data reaches any output destination (green boxes), the raw secret is gone forever.

#### Zero-Trust in the Real World

Zero-trust is not unique to CredVigil — it's the security model used by Google (BeyondCorp), Microsoft (Azure AD), and most modern cloud infrastructure. The core idea is the same everywhere:

| Traditional Security | Zero-Trust Security |
|---------------------|-------------------|
| "You're inside the firewall, so you're trusted" | "Prove who you are on every request" |
| Protect the perimeter | Protect every resource individually |
| Binary: inside = safe, outside = unsafe | Every access decision considers identity + context + policy |
| One breach = full access | One breach = limited to that one resource |
| Secrets flow freely inside the network | Secrets are never exposed, even internally |

**Why this matters for CredVigil:**  
CredVigil is a tool that *finds* secrets. If CredVigil itself leaked those secrets in its output, it would be a security vulnerability — the very thing it's supposed to prevent. Zero-trust ensures that even if someone gains access to CredVigil's logs, output files, or future API responses, they **cannot** recover the actual secret values.

---

### 4.6 What Is SHA-256 Hashing?

**SHA-256** is a **hash function** — it takes any input and produces a fixed-length "fingerprint" that is:

1. **Always the same length** (64 hexadecimal characters)
2. **Unique enough** — different inputs produce different outputs
3. **One-way** — you cannot reverse the hash to get the original input
4. **Deterministic** — the same input always produces the same output

**Analogy:** Think of a hash like a fingerprint. Every person has a unique fingerprint, and you can use it to identify someone — but you can't reconstruct a person from their fingerprint alone.

**Example:**
```
Input:  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
SHA-256: 78314b11a8e0ac3fa4f0ab51e4e0ff0e6af63e68... (64 chars total)
```

**Why CredVigil uses SHA-256:**

- **Tracking without exposure**: You can track whether the same secret appears in multiple places without ever storing the actual secret
- **Verification**: If you think you've found the same secret somewhere else, hash it and compare
- **Audit trail**: You have a record that a specific secret was found, without the risk of re-exposing it
- **Deduplication**: CredVigil uses the hash to avoid reporting the same secret twice in one scan

```mermaid
flowchart LR
    A["Any Input\n(any length)"] -->|"SHA-256"| B["Fixed Output\n(always 64 hex chars)"]
    C["Same Input"] -->|"SHA-256"| D["Same Output"]
    E["Different Input"] -->|"SHA-256"| F["Different Output"]
    style B fill:#9B59B6,stroke:#8E44AD,color:#fff
    style D fill:#9B59B6,stroke:#8E44AD,color:#fff
    style F fill:#E67E22,stroke:#D35400,color:#fff
```

---

### 4.7 What Is Redaction?

**Redaction** means replacing sensitive information with masked characters so it can be safely displayed without revealing the actual value.

**How CredVigil redacts:**

| Secret Length | Redaction Rule | Example |
|--------------|----------------|---------|
| More than 12 characters | Show first 4 + `****` + last 4 | `wJal****EKEY` |
| 5 to 12 characters | Show first 2 + `****` | `sk****` |
| 4 or fewer characters | Show `****` | `****` |

**Why show any characters at all?**  
Showing the first and last few characters helps you quickly identify *which* secret was found. For example, if you have three AWS keys, seeing `AKIA****MPLE` helps you know which specific key to rotate, without revealing the full key.

```mermaid
flowchart TD
    A["Secret Length?"] --> B{"> 12 chars"}
    A --> C{"5–12 chars"}
    A --> D{"≤ 4 chars"}
    B --> E["first4 + **** + last4\nAKIA****MPLE"]
    C --> F["first2 + ****\nsk****"]
    D --> G["****"]
    style E fill:#27AE60,stroke:#1E8449,color:#fff
    style F fill:#F39C12,stroke:#D68910,color:#fff
    style G fill:#E74C3C,stroke:#C0392B,color:#fff
```

---

### 4.8 What Are False Positives?

A **false positive** is when the tool incorrectly identifies something as a secret when it's actually harmless.

**Common false positives:**

| Type | Example | Why It's Not a Real Secret |
|------|---------|---------------------------|
| **Placeholder** | `API_KEY=your-api-key-here` | It's a template, not a real key |
| **Example in documentation** | `AKIAIOSFODNN7EXAMPLE` | AWS's own example key in their docs |
| **Test fixture** | `test_token=fake_token_123` | Used in unit tests, not real |
| **Variable name** | `getSecretAccessKey()` | It's a function name, not a secret value |
| **Hash or ID** | `commit: a1b2c3d4e5f6789...` | A git commit hash, not a secret |

**How CredVigil reduces false positives:**

1. **Placeholder detection**: Scans for words like `example`, `changeme`, `your-key-here`, `TODO`, `FIXME`, `dummy`, `fake`, `test`, `sample`, `placeholder`
2. **Test pattern detection**: Uses regex to identify test fixtures and mock data
3. **Confidence penalty**: Instead of hiding false positives completely, CredVigil lowers their confidence score — so you can still see them if you want, but they won't clutter your high-priority results
4. **Identifier detection**: Recognizes camelCase and snake_case variable names and skips them

```mermaid
flowchart TD
    A["Regex Match Found"] --> B{"Placeholder?\nchangeme, EXAMPLE"}
    B -->|Yes| C["📉 -40% Confidence"]
    B -->|No| D{"Test Pattern?\nfake_, test_"}
    D -->|Yes| E["📉 -25% Confidence"]
    D -->|No| F{"Variable Name?\ncamelCase"}
    F -->|Yes| G["❌ Skipped"]
    F -->|No| H["✅ Real Finding"]
    style C fill:#F39C12,stroke:#D68910,color:#fff
    style E fill:#E67E22,stroke:#D35400,color:#fff
    style G fill:#7F8C8D,stroke:#616A6B,color:#fff
    style H fill:#27AE60,stroke:#1E8449,color:#fff
```

---

### 4.9 What Is Severity?

**Severity** indicates how dangerous a leaked secret would be if it were real. CredVigil assigns one of five severity levels:

| Level | Color | Meaning | Examples |
|-------|-------|---------|----------|
| **CRITICAL** | 🔴 Red | Immediate danger — could lead to full system compromise | Private keys, production database passwords, root AWS credentials |
| **HIGH** | 🟠 Orange | Serious risk — could lead to significant data exposure | API keys for production services, OAuth secrets, payment processor keys |
| **MEDIUM** | 🟡 Yellow | Moderate risk — could lead to limited access | Internal tokens, staging environment keys, webhook URLs |
| **LOW** | 🔵 Blue | Minor risk — limited impact | Test API keys, development tokens, low-privilege read-only keys |
| **INFO** | ⚪ Gray | Informational — worth noting but not immediately dangerous | Generic patterns, entropy-only detections without strong context |

**Why severity matters:**  
In a large codebase, CredVigil might find dozens or even hundreds of potential secrets. Severity helps you **prioritize**: fix CRITICAL and HIGH first, then work your way down.

```mermaid
flowchart TD
    A["🔴 CRITICAL"] --> B["🟠 HIGH"]
    B --> C["🟡 MEDIUM"]
    C --> D["🔵 LOW"]
    D --> E["⚪ INFO"]
    A -.- F["Private keys, root credentials"]
    B -.- G["API keys, OAuth secrets"]
    C -.- H["Internal tokens, webhooks"]
    D -.- I["Test keys, read-only tokens"]
    E -.- J["Generic patterns, entropy-only"]
    style A fill:#E74C3C,stroke:#C0392B,color:#fff
    style B fill:#E67E22,stroke:#D35400,color:#fff
    style C fill:#F1C40F,stroke:#D4AC0D,color:#000
    style D fill:#3498DB,stroke:#2980B9,color:#fff
    style E fill:#BDC3C7,stroke:#95A5A6,color:#000
```

---

## 5. Installation & Setup

### Step 1: Verify Go Is Installed

Open your terminal and run:

```bash
go version
```

You should see something like:
```
go version go1.26.1 darwin/arm64
```

If Go is not installed, download it from [https://go.dev/dl/](https://go.dev/dl/).

### Step 2: Clone the Repository

```bash
cd ~/Github_Projects   # or wherever you keep your projects
git clone https://github.com/credvigil/credvigil.git
cd CredVigil
```

### Step 3: Build the Binary

```bash
go build ./cmd/credvigil
```

This creates a `credvigil` executable in the current directory.

### Step 4: Verify the Installation

```bash
./credvigil version
```

Expected output:
```
CredVigil 0.1.0
Component: core-detection-engine
Build date: 2026-03-12
Go version: see `go version`
```

### Step 5: Run Tests (Optional but Recommended)

```bash
go test ./... -v
```

This runs all unit tests. You should see all tests pass with `PASS` at the end.

```mermaid
flowchart TD
    A["Step 1: go version"] --> B{"Go installed?"}
    B -->|"✅ Yes"| C["Step 2: git clone"]
    B -->|"❌ No"| B2["Install Go\nfrom go.dev/dl"]
    B2 --> A
    C --> D["Step 3: go build ./cmd/credvigil"]
    D --> E["Step 4: ./credvigil version"]
    E --> F{"Version shown?"}
    F -->|"✅ Yes"| G["Step 5: go test ./... -v"]
    F -->|"❌ No"| D
    G --> H{"All PASS?"}
    H -->|"✅ Yes"| I["🎉 Ready to scan!"]
    H -->|"❌ No"| J["Check error messages"]
    style I fill:#27AE60,stroke:#1E8449,color:#fff
    style B2 fill:#F39C12,stroke:#D68910,color:#fff
    style J fill:#E74C3C,stroke:#C0392B,color:#fff
```

---

## 6. Your First Scan — Step by Step

Let's walk through your very first scan using the included test data.

### Step 1: Look at the Test Data

First, let's see what we're going to scan:

```bash
cat testdata/fake_secrets.env
```

This file contains **fake credentials** — they look like real secrets but are not active. They're designed to test CredVigil's detection capabilities. You'll see things like:

```
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234
STRIPE_SECRET_KEY=sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz
```

### Step 2: Run Your First Scan

```bash
./credvigil scan testdata/fake_secrets.env
```

### Step 3: Read the Output

You'll see a report like this:

```
╔═══════════════════════════════════════════════════════════════╗
║                    CredVigil Scan Report                     ║
╚═══════════════════════════════════════════════════════════════╝

[CRITICAL] AWS Secret Access Key
  Rule:       aws-secret-access-key
  Type:       aws-secret-access-key
  File:       testdata/fake_secrets.env:7
  Match:      wJal****EKEY
  Entropy:    4.66
  Confidence: 50%
  SHA-256:    78314b11...080e0598
  Context:
       5 | # AWS
       6 | AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    >  7 | AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
       8 |
       9 | # GitHub
```

Let's break down what each line means:

| Line | Meaning |
|------|---------|
| `[CRITICAL]` | The severity level — this is the most dangerous kind of finding |
| `AWS Secret Access Key` | A human-readable description of what was found |
| `Rule: aws-secret-access-key` | Which detection rule triggered this finding |
| `Type: aws-secret-access-key` | The category of the secret |
| `File: testdata/fake_secrets.env:7` | The file and line number where the secret was found |
| `Match: wJal****EKEY` | The redacted version — showing first 4 and last 4 characters |
| `Entropy: 4.66` | The Shannon entropy of the matched text (higher = more random) |
| `Confidence: 50%` | How confident CredVigil is that this is a real secret |
| `SHA-256: 78314b11...080e0598` | A one-way hash fingerprint of the actual secret |
| `Context:` | The surrounding lines of code for context |

```mermaid
flowchart LR
    A["📁 Scan File"] --> B["🔍 Match Rules"]
    B --> C["📊 Score Confidence"]
    C --> D["🔒 Redact Secret"]
    D --> E["#️⃣ Hash SHA-256"]
    E --> F["📝 Generate Report"]
    style A fill:#3498DB,stroke:#2980B9,color:#fff
    style D fill:#9B59B6,stroke:#8E44AD,color:#fff
    style F fill:#27AE60,stroke:#1E8449,color:#fff
```

### Step 4: Review the Summary

At the bottom of the report, you'll see:

```
─────────────────────────────────────────────────────────────────
  Scan completed in 3ms using 161 rules
  Total findings: 37
  By severity: CRITICAL=10, HIGH=10, MEDIUM=13, LOW=4
─────────────────────────────────────────────────────────────────
  ⚠️  37 potential secret(s) found. Review and remediate.
```

This tells you:
- **3ms**: The scan was extremely fast
- **161 rules**: All 161 detection patterns were checked
- **37 findings**: Total number of potential secrets found
- **By severity**: Breakdown showing 10 CRITICAL, 10 HIGH, 13 MEDIUM, and 4 LOW

### Understanding the Exit Code

CredVigil exits with code **1** if any findings are found, and **0** if no findings are found. This is important for CI/CD integration — a non-zero exit code can automatically fail a pipeline.

```bash
./credvigil scan testdata/fake_secrets.env
echo $?    # Will print "1" because findings were found

./credvigil scan /dev/null
echo $?    # Will print "0" because no findings
```

```mermaid
flowchart LR
    A["CredVigil Scan"] --> B{"Findings?"}
    B -->|"0 findings"| C["Exit Code 0\n✅ CI passes"]
    B -->|"1+ findings"| D["Exit Code 1\n🚨 CI fails"]
    style C fill:#27AE60,stroke:#1E8449,color:#fff
    style D fill:#E74C3C,stroke:#C0392B,color:#fff
```

---

## 7. Understanding the Scan Output

### Text Output (Default)

The default output is human-readable, colored text designed for terminal use:

- 🔴 **CRITICAL** findings are shown in red
- 🟠 **HIGH** findings are shown in orange
- 🟡 **MEDIUM** findings are shown in yellow
- 🔵 **LOW** findings are shown in blue
- ⚪ **INFO** findings are shown in gray

```mermaid
block-beta
    columns 5
    A["🔴 CRITICAL"]:1
    B["🟠 HIGH"]:1
    C["🟡 MEDIUM"]:1
    D["🔵 LOW"]:1
    E["⚪ INFO"]:1
    style A fill:#E74C3C,stroke:#C0392B,color:#fff
    style B fill:#E67E22,stroke:#D35400,color:#fff
    style C fill:#F1C40F,stroke:#D4AC0D,color:#000
    style D fill:#3498DB,stroke:#2980B9,color:#fff
    style E fill:#BDC3C7,stroke:#95A5A6,color:#000
```

### JSON Output

When you use `--format json`, the output is machine-readable JSON:

```json
{
  "version": "0.1.0",
  "scan_duration": "3.456ms",
  "total_findings": 37,
  "results": [
    {
      "findings": [
        {
          "id": "CVF-1710288000000-1",
          "secret_type": "aws-secret-access-key",
          "description": "AWS Secret Access Key",
          "severity": 4,
          "rule_id": "aws-secret-access-key",
          "source": {
            "type": "file",
            "location": "testdata/fake_secrets.env",
            "line": 7
          },
          "redacted_match": "wJal****EKEY",
          "entropy": 4.66,
          "confidence": 0.50,
          "metadata": {
            "sha256": "78314b11..."
          }
        }
      ]
    }
  ]
}
```

**Note for zero-trust:** In JSON output, the `raw_match` field is automatically cleared before output. Only the `redacted_match` is included.

**When to use JSON:**
- Piping results to another tool
- Saving results to a file for later analysis
- CI/CD pipeline integration
- Building dashboards or reports

```mermaid
flowchart LR
    A["CredVigil Scan"] --> B{"--format?"}
    B -->|"text (default)"| C["🖥️ Terminal\nColored, human-readable"]
    B -->|"json"| D["📋 JSON\nMachine-readable"]
    D --> E["CI/CD Pipelines"]
    D --> F["Dashboards"]
    D --> G["Analysis Scripts"]
    style C fill:#3498DB,stroke:#2980B9,color:#fff
    style D fill:#27AE60,stroke:#1E8449,color:#fff
```

---

## 8. All CLI Commands & Options Explained

### 8.1 The `scan` Command

The `scan` command is the primary command. It scans files, directories, or stdin for secrets.

**Basic usage:**

```bash
# Scan a single file
./credvigil scan path/to/file.env

# Scan a directory (recursively scans all files inside)
./credvigil scan ./my-project/

# Scan the current directory
./credvigil scan .

# Scan from standard input (piping)
cat some_file.txt | ./credvigil scan --stdin

# Scan from stdin with a source label
echo 'SECRET=abc123' | ./credvigil scan --stdin --source my-pipeline
```

**What gets scanned automatically:**
- All text files (source code, config, env files, YAML, JSON, etc.)
- Recursively through all subdirectories

**What gets skipped automatically:**
- Binary files (.exe, .dll, .png, .jpg, .zip, etc.)
- Lock files (package-lock.json, go.sum, yarn.lock, etc.)
- Build directories (.git, node_modules, vendor, dist, build, etc.)
- Files larger than 5 MB

```mermaid
flowchart TD
    A["📁 File Found"] --> B{"Binary?"}
    B -->|"❌ Yes"| S1["Skip"]
    B -->|"✅ No"| C{"Lock file?"}
    C -->|"❌ Yes"| S2["Skip"]
    C -->|"✅ No"| D{"Excluded dir?\n.git, node_modules.."}
    D -->|"❌ Yes"| S3["Skip"]
    D -->|"✅ No"| E{"> 5 MB?"}
    E -->|"❌ Yes"| S4["Skip"]
    E -->|"✅ No"| F["🔍 Scan!"]
    style F fill:#27AE60,stroke:#1E8449,color:#fff
    style S1 fill:#BDC3C7,stroke:#95A5A6,color:#000
    style S2 fill:#BDC3C7,stroke:#95A5A6,color:#000
    style S3 fill:#BDC3C7,stroke:#95A5A6,color:#000
    style S4 fill:#BDC3C7,stroke:#95A5A6,color:#000
```

### 8.2 The `rules` Command

Lists all detection rules and the services they cover.

```bash
./credvigil rules
```

Output:
```
CredVigil Detection Rules (161 total)
═══════════════════════════════════════════════════════════════

Loaded 161 detection rules covering:
  • Cloud: AWS, GCP, Azure, DigitalOcean, Cloudflare, Vercel, Netlify
  • Cloud (Modern): Supabase, Railway, Render, Fly.io, Linode
  • AI/ML: OpenAI, Anthropic, Gemini, Hugging Face, Cohere, Mistral
  ...
```

### 8.3 The `version` Command

Shows the current version and build information.

```bash
./credvigil version
```

### 8.4 CLI Flags Reference

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--format` | `text`, `json` | `text` | Output format. Text is human-readable with colors. JSON is machine-readable. |
| `--min-confidence` | `0.0` to `1.0` | `0.3` | Only show findings at or above this confidence level. Set higher (e.g., 0.7) to reduce noise. |
| `--min-severity` | `info`, `low`, `medium`, `high`, `critical` | `info` | Only show findings at or above this severity level. |
| `--no-entropy` | _(flag)_ | enabled | Disable entropy-based detection. Only regex rules will be used. |
| `--no-context` | _(flag)_ | enabled | Don't show surrounding code lines in the output. |
| `--context-lines` | `0`, `1`, `2`, `3`, ... | `2` | Number of lines to show before and after each finding. |
| `--stdin` | _(flag)_ | disabled | Read input from standard input instead of a file/directory. |
| `--source` | any string | auto-detected | Label for the source (shown in output). Useful for pipelines. |

```mermaid
flowchart LR
    subgraph Filtering["Filter Flags"]
        A["--min-severity"]
        B["--min-confidence"]
        C["--no-entropy"]
    end
    subgraph Display["Display Flags"]
        D["--format"]
        E["--context-lines"]
        F["--no-context"]
    end
    subgraph Input["Input Flags"]
        G["--stdin"]
        H["--source"]
    end
    Filtering --> I["🔍 Narrower Results"]
    Display --> J["💻 Output Format"]
    Input --> K["📥 Data Source"]
    style Filtering fill:#3498DB,stroke:#2980B9,color:#fff
    style Display fill:#9B59B6,stroke:#8E44AD,color:#fff
    style Input fill:#E67E22,stroke:#D35400,color:#fff
```

---

## 9. Hands-On Exercises

These exercises are designed to help you learn CredVigil by doing. Work through them in order — each one builds on the previous.

```mermaid
flowchart LR
    E1["Ex 1\nFirst Scan"] --> E2["Ex 2\nFilter Severity"]
    E2 --> E3["Ex 3\nJSON Output"]
    E3 --> E4["Ex 4\nConfidence"]
    E4 --> E5["Ex 5\nEntropy Toggle"]
    E5 --> E6["Ex 6\nStdin Piping"]
    E6 --> E7["Ex 7\nCustom File"]
    E7 --> E8["Ex 8\nReal Project"]
    style E1 fill:#3498DB,stroke:#2980B9,color:#fff
    style E4 fill:#E67E22,stroke:#D35400,color:#fff
    style E8 fill:#27AE60,stroke:#1E8449,color:#fff
```

### Exercise 1: Scan the Test Data File

**Goal:** Run your first scan and see the output.

```bash
./credvigil scan testdata/fake_secrets.env
```

**Questions to answer:**
1. How many total findings were reported?
2. How many CRITICAL findings were there?
3. What was the fastest scan time you observed?
4. Can you identify the redacted Stripe key in the output?

---

### Exercise 2: Filter by Severity

**Goal:** Learn to filter out low-priority findings.

```bash
# Show only HIGH and CRITICAL findings
./credvigil scan --min-severity high testdata/fake_secrets.env
```

**Questions to answer:**
1. How many findings are shown now compared to Exercise 1?
2. What severity levels are missing from the output?

Try other severity levels:
```bash
./credvigil scan --min-severity critical testdata/fake_secrets.env
./credvigil scan --min-severity medium testdata/fake_secrets.env
```

---

### Exercise 3: Use JSON Output

**Goal:** Learn to generate machine-readable output.

```bash
# Generate JSON output
./credvigil scan --format json testdata/fake_secrets.env

# Pretty-print and save to a file
./credvigil scan --format json testdata/fake_secrets.env > scan_results.json 2>/dev/null

# Count findings using jq (if installed)
cat scan_results.json | python3 -c "import json, sys; d=json.load(sys.stdin); print(f'Total: {d[\"total_findings\"]}')"
```

**Questions to answer:**
1. Can you see the `raw_match` field in the JSON? (Hint: you shouldn't — zero-trust!)
2. What is the `severity` value for CRITICAL findings? (Hint: it's a number)

---

### Exercise 4: Adjust Confidence Threshold

**Goal:** Understand how confidence thresholds affect results.

```bash
# Show everything (even very low confidence)
./credvigil scan --min-confidence 0.0 testdata/fake_secrets.env

# Show only high-confidence findings
./credvigil scan --min-confidence 0.7 testdata/fake_secrets.env

# Show only very high-confidence findings
./credvigil scan --min-confidence 0.9 testdata/fake_secrets.env
```

**Questions to answer:**
1. How does the number of findings change as you increase the confidence threshold?
2. At 0.9 confidence, which types of secrets are still shown? Why do you think these are the most confident?

---

### Exercise 5: Disable Entropy Detection

**Goal:** Understand the difference between regex-only and regex+entropy scanning.

```bash
# Scan with both regex and entropy (default)
./credvigil scan testdata/fake_secrets.env 2>/dev/null | tail -5

# Scan with regex only (no entropy)
./credvigil scan --no-entropy testdata/fake_secrets.env 2>/dev/null | tail -5
```

**Questions to answer:**
1. How many findings does regex-only find compared to regex+entropy?
2. What kinds of findings are only caught by entropy? (Look for `Rule: entropy-detection` in the full output)

---

### Exercise 6: Scan from Standard Input (Piping)

**Goal:** Learn to pipe content into CredVigil for on-the-fly scanning.

```bash
# Pipe a single secret
echo 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' | ./credvigil scan --stdin

# Pipe a file's contents
cat testdata/fake_secrets.env | ./credvigil scan --stdin

# Pipe output from another command
git log --oneline -5 | ./credvigil scan --stdin
```

**When to use stdin scanning:**
- Checking clipboard contents
- Scanning output from other commands
- In shell scripts and pipelines
- Checking individual strings quickly

---

### Exercise 7: Create Your Own Test File

**Goal:** Create a custom test file and scan it to see what CredVigil catches.

Create a file called `my_test_secrets.env`:

```bash
cat > my_test_secrets.env << 'EOF'
# My Test Secrets File

# These should be caught (fake credentials):
OPENAI_API_KEY=sk-proj-ThisIsAFakeButRealisticLookingOpenAIKey12345678
GITHUB_PAT=github_pat_11ABCDEFGHIJKLMNOPQRSTUVWX_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop
DATABASE_URL=postgresql://admin:VerySecret@db.production.com:5432/userdata
SLACK_TOKEN=xoxb-123456789012-123456789012-ABCDEFGHIJKLMNOPQRSTUVWXyz

# These should NOT be caught (not secrets):
APP_NAME=my-awesome-app
DEBUG=true
PORT=3000
LOG_LEVEL=info

# This is a tricky one — a high-entropy string that's NOT a secret (a UUID):
REQUEST_ID=550e8400-e29b-41d4-a716-446655440000

# Another tricky one — a placeholder:
API_KEY=your-api-key-here
EOF
```

Now scan it:
```bash
./credvigil scan my_test_secrets.env
```

**Questions to answer:**
1. Did CredVigil catch the OpenAI, GitHub, PostgreSQL, and Slack secrets?
2. Did it correctly ignore APP_NAME, DEBUG, PORT, and LOG_LEVEL?
3. What confidence did the placeholder `your-api-key-here` get? (It should be low due to placeholder detection)
4. Did it flag the UUID? If so, what was the confidence?

Clean up when done:
```bash
rm my_test_secrets.env
```

---

### Exercise 8: Scan a Real Project

**Goal:** Scan an actual project directory and see real-world results.

```bash
# Scan CredVigil's own source code (it should be clean!)
./credvigil scan .

# Scan another project you're working on
./credvigil scan ~/path/to/your/project
```

**Important notes:**
- CredVigil automatically skips `.git`, `node_modules`, `vendor`, and other non-essential directories
- Binary files (images, executables, archives) are automatically skipped
- Files larger than 5 MB are skipped

**Questions to answer:**
1. Did CredVigil find any secrets in its own codebase? (The only findings should be in `testdata/fake_secrets.env` — which are intentional test data)
2. If you scanned another project, how many findings were there?
3. Were any of them false positives? What was their confidence level?

---

## 10. Deep Dive: How the Detection Engine Works Internally

This section explains exactly what happens under the hood when you run `./credvigil scan`. This is important for understanding the source code and for knowing why CredVigil makes the decisions it does.

### 10.1 The Detection Pipeline

When you run a scan, here's the exact sequence of events:

```mermaid
flowchart TD
    A["1. CLI Parses\nCommand & Flags"] --> B["2. FileScanner Walks\nDirectory Tree"]
    B --> C["3. For Each File"]
    C --> D{"Skip?\nbinary / large / excluded"}
    D -->|"❌ Skip"| C
    D -->|"✅ Read"| E["Read File Into Memory"]
    E --> F["4. Engine.ScanContent()"]
    F --> G["Split into lines"]
    G --> H["Run 276 regex rules"]
    H --> I["Extract matches + entropy"]
    I --> J["Compute confidence"]
    J --> K["5. Pipeline:\nHash→Redact→Enrich→FP→Sanitize"]
    K --> L["Deduplicate & Filter"]
    L --> M["6. Aggregate & Display"]
    style A fill:#3498DB,stroke:#2980B9,color:#fff
    style F fill:#9B59B6,stroke:#8E44AD,color:#fff
    style K fill:#E67E22,stroke:#D35400,color:#fff
    style M fill:#27AE60,stroke:#1E8449,color:#fff
```

```
1. CLI parses your command and flags
        │
        ▼
2. FileScanner walks the directory tree
   (or reads from stdin, or opens a single file)
        │
        ▼
3. For each file:
   a. Check if it should be skipped (binary? too large? excluded extension?)
   b. Read the file contents into memory
   c. Create a ScanRequest with the content + source metadata
        │
        ▼
4. Engine.ScanContent() processes the ScanRequest:
   a. Split content into lines
   b. Run all 161 regex rules against the content
   c. For each regex match:
      - Extract the matched secret value
      - Calculate Shannon entropy
      - Compute confidence score
      - Create a Finding with redacted match + SHA-256 hash
   d. Run entropy-based detection on every line
   e. Deduplicate findings (same hash + same line = one finding)
   f. Filter by MinConfidence and MinSeverity
        │
        ▼
5. Aggregate all results and display
```

### 10.2 Regex Matching Phase

For each of the 161 rules, the engine:

1. **Runs the regex** against the entire file content (not line-by-line — this allows multi-line matches like private keys)
2. **Extracts the captured group** — most rules have a capture group `(...)` that isolates just the secret value from the surrounding text. For example, the pattern `AWS_SECRET_ACCESS_KEY[=:]\s*(.{40})` captures the 40-character key, not the variable name
3. **Checks minimum entropy** — some rules require the match to have a minimum entropy value. This prevents matching on placeholder values
4. **Calculates the line number** by counting newlines before the match position

**Why use full-content matching instead of line-by-line?**  
Because some secrets span multiple lines. For example, RSA private keys:
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8Pbn...
aJznm0oFMJbHzlaHTYlMbFBIFWsW+nXPC5JdQ2WKA8...
-----END RSA PRIVATE KEY-----
```

```mermaid
flowchart TD
    A["Full File Content"] --> B["Apply Rule #1"]
    B --> C{"Pattern Match?"}
    C -->|"✅ Match"| D["Extract Capture Group"]
    D --> E{"Min Entropy?"}
    E -->|"✅ Pass"| F["Calculate Line Number"]
    F --> G["📝 Create Finding"]
    E -->|"❌ Fail"| H["Discard Match"]
    C -->|"❌ No Match"| I["Try Next Rule"]
    I --> B
    style G fill:#27AE60,stroke:#1E8449,color:#fff
    style H fill:#BDC3C7,stroke:#95A5A6,color:#000
```

### 10.3 Entropy Analysis Phase

After regex matching is complete, the engine runs a **second pass** looking for high-entropy strings that no regex rule caught.

For each line of the file:

1. **Split the line** on common delimiters (whitespace, quotes, `=`, `:`, commas, braces, etc.)
2. **For each word** that is 12+ characters:
   - Calculate Shannon entropy
   - Determine the charset (hex, base64, alphanumeric, etc.)
   - If entropy exceeds the threshold for that charset, it's a candidate
3. **Check for false positives**:
   - Is the word likely a code identifier (camelCase, snake_case)?
   - Does it appear near secret-related keywords ("key", "token", "password")?
4. **If the word passes all checks**, create a Finding with lower confidence (entropy-only findings get 60% of the entropy score, or 80% if near secret keywords)

**Why two phases?**  
Regex catches known patterns with high confidence. Entropy catches unknown/novel patterns that no rule covers. Together, they provide comprehensive detection.

```mermaid
flowchart LR
    subgraph Phase1["Phase 1: Regex"]
        A["276 Rules"] --> B["Known Patterns"]
    end
    subgraph Phase2["Phase 2: Entropy"]
        C["Shannon Analysis"] --> D["Unknown Patterns"]
    end
    B & D --> E["Combined Findings"]
    style Phase1 fill:#3498DB,stroke:#2980B9,color:#fff
    style Phase2 fill:#E67E22,stroke:#D35400,color:#fff
    style E fill:#27AE60,stroke:#1E8449,color:#fff
```

### 10.4 Confidence Scoring Phase

Every finding gets a confidence score. The scoring algorithm considers:

```
Start with: rule.BaseConfidence (set by the rule author, e.g., 0.85 for Stripe)

Adjustments:
  + 0.10   if entropy >= HighThreshold (very random)
  - 0.20   if entropy < 80% of Threshold (not random enough)
  + up to 0.10  if relevant keywords found nearby
  - 0.25   if false positive regex pattern matches
  - 0.40   if placeholder detected
  - 0.10   if secret is shorter than 12 characters
  + 0.05   if secret is longer than 30 characters

Final: clamp to [0.0, 1.0]
```

**The keyword proximity check** looks at 200 characters before and after the matched text for words from the rule's keyword list. For example, the AWS secret key rule has keywords like `aws`, `secret`, `access_key`, `credential`. If these words appear nearby, confidence goes up.

**The false positive regex check** uses additional patterns defined per rule. For example, the GitHub token rule has false positive patterns that match documentation examples and test fixtures.

```mermaid
flowchart LR
    A["Base Confidence"] --> B["+/- Entropy"]
    B --> C["+/- Keywords"]
    C --> D["-FP Pattern"]
    D --> E["-Placeholder"]
    E --> F["+/- Length"]
    F --> G["Clamp 0.0–1.0"]
    style A fill:#3498DB,stroke:#2980B9,color:#fff
    style G fill:#9B59B6,stroke:#8E44AD,color:#fff
```

### 10.5 False Positive Reduction

CredVigil uses multiple strategies to reduce false positives:

1. **Placeholder detection** — checks for strings containing: `xxxx`, `yyyy`, `changeme`, `replace`, `your_`, `example`, `sample`, `dummy`, `fake`, `test`, `placeholder`, `todo`, `fixme`, or strings where all characters are the same
2. **Identifier detection** — recognizes variable/function names by checking for:
   - Only letters and underscores (no digits) = likely a variable name
   - CamelCase pattern with 10-35% uppercase ratio = likely a class/method name
3. **Per-rule false positive patterns** — regex patterns that match known non-secret strings
4. **Minimum entropy requirements** — some rules require a minimum entropy, filtering out predictable values
5. **Allow-list** — configurable patterns that suppress findings (useful for known safe values)

```mermaid
flowchart TD
    A["Raw Match"] --> B{"Placeholder?\nxxxx, changeme..."}
    B -->|"❌ Yes"| X1["🚫 Confidence -40%"]
    B -->|"✅ No"| C{"Code Identifier?\ncamelCase, snake_case"}
    C -->|"❌ Yes"| X2["🚫 Likely not a secret"]
    C -->|"✅ No"| D{"FP Pattern Match?"}
    D -->|"❌ Yes"| X3["🚫 Confidence -25%"]
    D -->|"✅ No"| E{"Min Entropy?"}
    E -->|"❌ Fail"| X4["🚫 Filtered out"]
    E -->|"✅ Pass"| F{"Allow-listed?"}
    F -->|"❌ Yes"| X5["🚫 Suppressed"]
    F -->|"✅ No"| G["✅ Real Finding"]
    style G fill:#27AE60,stroke:#1E8449,color:#fff
    style X1 fill:#E74C3C,stroke:#C0392B,color:#fff
    style X2 fill:#E74C3C,stroke:#C0392B,color:#fff
    style X3 fill:#E74C3C,stroke:#C0392B,color:#fff
    style X4 fill:#E74C3C,stroke:#C0392B,color:#fff
    style X5 fill:#E74C3C,stroke:#C0392B,color:#fff
```

### 10.6 Deduplication

CredVigil uses SHA-256 hashes to detect duplicate findings within a single scan:

- Each finding is keyed as: `SHA256(secret_value):rule_id:line_number`
- If the same key appears twice, the second occurrence is skipped
- This prevents double-reporting when a regex with different sub-patterns matches the same secret

```mermaid
flowchart LR
    A["Finding A\nhash:rule:line42"] --> B{"Seen before?"}
    B -->|"✅ New"| C["Add to results"]
    A2["Finding B\nhash:rule:line42"] --> B2{"Seen before?"}
    B2 -->|"❌ Duplicate"| D["Skip"]
    A3["Finding C\nhash:rule:line99"] --> B3{"Seen before?"}
    B3 -->|"✅ New"| C3["Add to results"]
    style C fill:#27AE60,stroke:#1E8449,color:#fff
    style C3 fill:#27AE60,stroke:#1E8449,color:#fff
    style D fill:#BDC3C7,stroke:#95A5A6,color:#000
```

### 10.7 Hashing & Redaction

After a finding is created:

1. The `SHA-256 hash` of the raw secret is stored in `Metadata["sha256"]`
2. `Finding.Redact()` is called, which creates the masked `RedactedMatch`
3. For JSON output, `Finding.ClearRawMatch()` is called, which:
   - Calls `Redact()` (if not already done)
   - Sets `RawMatch` to empty string
   - The raw secret value is no longer in memory

```mermaid
sequenceDiagram
    participant E as Engine
    participant F as Finding
    participant H as SHA-256
    participant R as Redactor

    E->>F: Create Finding(RawMatch)
    E->>H: hashSecret(RawMatch)
    H-->>F: SecretHash = "5e6bf1..." 
    E->>R: Redact(RawMatch)
    R-->>F: RedactedMatch = "AKIA****MPLE"
    E->>F: ClearRawMatch()
    Note over F: RawMatch = "" (erased)
    Note over F: Only SecretHash +\nRedactedMatch remain
```

---

## 11. Understanding the Codebase — File by File

Here is a complete guide to every source file in the project, what it does, and what the key functions are.

### Project Directory Layout

```
credvigil/
├── cmd/credvigil/main.go          ← CLI entry point (you run this)
├── pkg/
│   ├── models/finding.go          ← Core data structures
│   ├── entropy/
│   │   ├── entropy.go             ← Shannon entropy math
│   │   └── entropy_test.go        ← Tests for entropy
│   ├── rules/
│   │   ├── rules.go               ← 161 detection rules
│   │   └── rules_test.go          ← Tests for rules
│   └── detector/
│       ├── engine.go              ← Detection engine (the brain)
│       ├── engine_test.go         ← Tests for the engine
│       └── scanner.go             ← File/directory scanning
├── internal/
│   └── config/config.go           ← Configuration structures
├── testdata/
│   └── fake_secrets.env           ← Test data with fake secrets
├── docs/
│   └── training/
│       └── 01-core-detection-engine.md  ← This training guide
├── go.mod                         ← Go module definition
├── LICENSE                        ← Apache 2.0 License
├── SECURITY.md                    ← Security policy & disclaimers
└── README.md                      ← Project overview
```

```mermaid
flowchart TD
    CLI["cmd/credvigil/main.go\n💻 CLI Entry Point"] --> ENG["pkg/detector/engine.go\n🧠 Detection Engine"]
    CLI --> SCN["pkg/detector/scanner.go\n📁 File Scanner"]
    SCN --> ENG
    ENG --> RUL["pkg/rules/rules.go\n📖 276 Rules"]
    ENG --> ENT["pkg/entropy/entropy.go\n📊 Shannon Math"]
    ENG --> MOD["pkg/models/finding.go\n📦 Data Structures"]
    CLI --> PIP["pkg/pipeline/...\n⚙️ Post-Processing"]
    PIP --> MOD
    CLI --> CFG["internal/config/config.go\n⚙️ Configuration"]
    style CLI fill:#3498DB,stroke:#2980B9,color:#fff
    style ENG fill:#9B59B6,stroke:#8E44AD,color:#fff
    style PIP fill:#E67E22,stroke:#D35400,color:#fff
    style MOD fill:#27AE60,stroke:#1E8449,color:#fff
```

### `pkg/models/finding.go` — Core Data Structures

**Purpose:** Defines all the data types that flow through the system.

**Key types:**

| Type | What It Represents |
|------|-------------------|
| `Severity` | Enum: INFO, LOW, MEDIUM, HIGH, CRITICAL |
| `SecretType` | String identifier for each kind of credential (e.g., `"aws-access-key-id"`, `"github-token"`) |
| `Finding` | A single detected secret occurrence — contains type, severity, source location, redacted match, entropy, confidence, SHA-256 hash |
| `Source` | Where the finding was located — file path, line number, context, git commit info |
| `ScanRequest` | Input to the engine — content to scan + source metadata + optional filters |
| `ScanResult` | Output from the engine — list of findings, counts, duration, errors |

**Key methods:**
- `Finding.Redact()` — creates the masked display version
- `Finding.ClearRawMatch()` — removes plaintext from memory (zero-trust)

### `pkg/entropy/entropy.go` — Shannon Entropy Analysis

**Purpose:** The mathematical brain for detecting high-randomness strings.

**Key functions:**

| Function | What It Does |
|----------|-------------|
| `Shannon(s)` | Calculates the Shannon entropy of a string (returns a float like 4.66) |
| `ShannonPerByte(s)` | Normalizes entropy to 0.0-1.0 range |
| `DetectCharset(s)` | Identifies if a string is hex, base64, alphanumeric, etc. |
| `IsHighEntropy(s)` | Quick check: is this string suspicious? |
| `IsVeryHighEntropy(s)` | Quick check: is this string very likely a secret? |
| `EntropyScore(s)` | Returns a 0.0-1.0 confidence score based on entropy analysis |
| `ExtractHighEntropyWords(text, minLen)` | Splits text into words and returns the ones with high entropy |

**The charset system:**  
Different character sets have different entropy ranges. A hex string (16 possible chars) has a lower maximum entropy than a base64 string (64 possible chars). CredVigil adjusts its thresholds accordingly.

### `pkg/rules/rules.go` — 161 Detection Rules

**Purpose:** Contains all the compiled regex patterns for known secret formats.

**Each rule specifies:**

| Field | Purpose |
|-------|---------|
| `ID` | Unique identifier (e.g., `"aws-secret-access-key"`) |
| `Description` | Human-readable name (e.g., `"AWS Secret Access Key"`) |
| `Pattern` | Compiled regex pattern |
| `SecretType` | Maps to a SecretType constant |
| `Severity` | CRITICAL, HIGH, MEDIUM, LOW, or INFO |
| `BaseConfidence` | Starting confidence score (0.0-1.0) |
| `MinEntropy` | Minimum entropy the match must have (optional) |
| `Keywords` | Related words that boost confidence when found nearby |
| `FalsePositivePatterns` | Regex patterns that identify false positives |

**Thread safety:** The `RuleSet` uses `sync.RWMutex` for safe concurrent access from multiple file scanner goroutines.

### `pkg/detector/engine.go` — The Detection Engine

**Purpose:** The central brain that orchestrates regex matching, entropy analysis, confidence scoring, and finding generation.

**Key functions:**

| Function | What It Does |
|----------|-------------|
| `New(cfg)` | Creates a new engine with the given configuration |
| `NewDefault()` | Creates an engine with sensible defaults |
| `ScanContent(req)` | Main entry point — scans text and returns all findings |
| `ScanLines(lines, source)` | Convenience method for scanning individual lines |
| `matchRule(rule, content, lines, source)` | Applies one regex rule to the content |
| `computeConfidence(...)` | Calculates the final confidence score for a finding |
| `entropyDetection(...)` | Runs the entropy-based detection pass |
| `isLikelyPlaceholder(s)` | Checks if a value is a dummy/placeholder |
| `isLikelyIdentifier(s)` | Checks if a string looks like a variable/function name |
| `hashSecret(s)` | Computes the SHA-256 hash of a secret |

### `pkg/detector/scanner.go` — File & Directory Scanner

**Purpose:** Handles reading files, walking directories, and managing concurrent scanning.

**Key features:**

| Feature | Implementation |
|---------|---------------|
| **Concurrent scanning** | Uses a goroutine worker pool (default: 4 workers) |
| **Binary detection** | Checks first 512 bytes for null characters |
| **Extension filtering** | Skips binary extensions (.exe, .png, .zip, etc.) |
| **Directory filtering** | Skips .git, node_modules, vendor, build, dist, etc. |
| **File name filtering** | Skips lock files (package-lock.json, go.sum, etc.) |
| **Size limiting** | Skips files over 5 MB |
| **Stdin support** | Reads from standard input with 10 MB buffer |

### `internal/config/config.go` — Configuration

**Purpose:** Defines the configuration structures for the application.

This file provides `AppConfig`, `DetectionConfig`, and `FileScanningConfig` structures with JSON and YAML tags. These will be used by future components (API server, dashboard) for config file support.

### `cmd/credvigil/main.go` — The CLI

**Purpose:** The user-facing command-line interface.

**Commands:** `scan`, `rules`, `version`

**How it works:**
1. Parses command-line arguments manually (no external dependencies)
2. Creates an `Engine` and `FileScanner` with appropriate configuration
3. Scans the target(s) and collects results
4. Outputs results in the requested format (text with colors, or JSON)
5. Exits with code 1 if findings were found (for CI/CD integration)

---

## 12. The 161 Detection Rules — Categories & Examples

CredVigil covers 25+ categories of secrets. Here's what each category covers and example patterns:

### Cloud Providers (15 rules)

| Service | What's Detected | Example Pattern |
|---------|----------------|-----------------|
| AWS | Access keys, secret keys, session tokens | `AKIA[0-9A-Z]{16}` |
| GCP | Service account keys, OAuth tokens | `"type": "service_account"` |
| Azure | Client secrets, subscription keys, storage keys | `[a-zA-Z0-9+/]{86}==` |
| DigitalOcean | Personal access tokens, spaces keys | `dop_v1_[a-f0-9]{64}` |
| Cloudflare | API tokens, API keys | `[a-z0-9]{40}` with keyword context |
| Vercel | Deployment tokens | Bearer tokens with Vercel context |
| Netlify | Personal access tokens | Tokens with Netlify context |
| Supabase | API keys | `eyJ...` JWT-style keys |
| Railway | API tokens | Railway-specific patterns |
| Render | API keys | `rnd_...` pattern |
| Fly.io | Deploy tokens | `fo1_...` pattern |
| Linode | Personal access tokens | 64-char hex tokens |

### AI/ML Services (11 rules)

| Service | What's Detected | Example Pattern |
|---------|----------------|-----------------|
| OpenAI | API keys | `sk-[a-zA-Z0-9-_]{20,}` |
| Anthropic | API keys | `sk-ant-[a-zA-Z0-9-_]{20,}` |
| Google Gemini | API keys | `AIza[0-9A-Za-z-_]{35}` |
| Hugging Face | API tokens | `hf_[a-zA-Z0-9]{34}` |
| Cohere | API keys | 40-char alphanumeric with Cohere context |
| Mistral | API keys | Keys with Mistral context |
| Replicate | API tokens | `r8_[a-zA-Z0-9]{40}` |
| Groq | API keys | `gsk_[a-zA-Z0-9]{52}` |
| DeepSeek | API keys | Keys with DeepSeek context |
| Perplexity | API keys | `pplx-[a-f0-9]{48}` |
| Stability AI | API keys | `sk-[a-zA-Z0-9]{48}` with Stability context |

### Source Control (7 rules)

| Service | What's Detected | Example Pattern |
|---------|----------------|-----------------|
| GitHub | Classic PATs, fine-grained PATs, OAuth, App tokens | `ghp_[A-Za-z0-9]{36}` |
| GitLab | Personal access tokens, runner tokens | `glpat-[A-Za-z0-9-]{20,}` |
| Bitbucket | App passwords | Tokens with Bitbucket context |

### Payment/Finance (9 rules)

| Service | What's Detected |
|---------|----------------|
| Stripe | Live/test secret keys, publishable keys |
| Square | Access tokens, OAuth secrets |
| PayPal | Client secrets, Braintree tokens |
| Razorpay | API keys and secrets |
| Plaid | Client IDs and secrets |
| Coinbase | API keys |
| Adyen | API keys |

### Databases (12 rules)

| Type | What's Detected |
|------|----------------|
| PostgreSQL | Connection URIs with embedded passwords |
| MySQL | Connection URIs with embedded passwords |
| MongoDB | Connection strings (including SRV format) |
| Redis | Connection URIs with passwords |
| PlanetScale | Service tokens |
| Neon | API keys |
| Turso | Auth tokens |
| Upstash | REST tokens |
| CockroachDB | Connection URIs |

### And 100+ More Rules

Covering: Slack, Jira, Confluence, Teams, Stack Overflow, private keys (RSA/EC/SSH/PGP), JWT, OAuth, SendGrid, Mailgun, Mailchimp, Postmark, Resend, Docker, NPM, PyPI, Heroku, Vault, Terraform, Datadog, New Relic, Sentry, Grafana, Splunk, PagerDuty, OpenTelemetry, CircleCI, Jenkins, Travis CI, Buildkite, Drone, Pulumi, Google Maps, Mapbox, Twitter/X, Facebook, LinkedIn, Cloudinary, Backblaze, Alchemy, Infura, Etherscan, Moralis, Meilisearch, Typesense, HubSpot, Mixpanel, Segment, Intercom, Zendesk, Auth0, Okta, Clerk, and more.

```mermaid
pie title 276 Detection Rules by Category
    "Cloud Providers" : 15
    "AI/ML Services" : 11
    "Source Control" : 7
    "Payment/Finance" : 9
    "Databases" : 12
    "Communication" : 10
    "DevOps/CI" : 15
    "Private Keys" : 8
    "Monitoring" : 12
    "Other Services" : 177
```

---

## 13. Real-World Scenarios

```mermaid
flowchart TD
    subgraph Dev["Development"]
        A["Pre-Commit Scan"]
        B["PR Review Scan"]
    end
    subgraph CI["CI/CD"]
        C["Pipeline Gate"]
    end
    subgraph Ops["Operations"]
        D["Full Audit"]
        E["Config Check"]
        F["Clipboard Scan"]
    end
    A & B --> C --> D
    style Dev fill:#3498DB,stroke:#2980B9,color:#fff
    style CI fill:#E67E22,stroke:#D35400,color:#fff
    style Ops fill:#27AE60,stroke:#1E8449,color:#fff
```

### Scenario 1: Pre-Commit Scan

Before committing code, scan the files you've changed:

```bash
# Check all modified files
git diff --name-only | xargs ./credvigil scan

# If any secrets found, credvigil exits with code 1
# You'll see the findings and can fix before committing
```

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant Git as git diff
    participant CV as CredVigil
    participant Repo as Git Repo

    Dev->>Git: git diff --name-only
    Git-->>CV: changed files list
    CV->>CV: Scan each file
    alt No secrets found
        CV-->>Dev: Exit 0 ✅
        Dev->>Repo: git commit & push
    else Secrets found!
        CV-->>Dev: Exit 1 🚨
        Dev->>Dev: Remove secrets
        Dev->>Git: git diff --name-only
    end
```

### Scenario 2: CI/CD Pipeline Gate

In a GitHub Actions workflow or similar CI/CD system:

```bash
# Run credvigil as a pipeline step
./credvigil scan . --min-severity medium --format json > results.json

# The exit code (1 = findings found) can automatically fail the build
```

```mermaid
flowchart LR
    A["📦 Code Push"] --> B["⚙️ CI Pipeline"]
    B --> C["🔍 CredVigil Scan"]
    C --> D{"Exit Code?"}
    D -->|"0"| E["✅ Build\nContinues"]
    D -->|"1"| F["❌ Build\nFails"]
    F --> G["📧 Alert Developer"]
    style E fill:#27AE60,stroke:#1E8449,color:#fff
    style F fill:#E74C3C,stroke:#C0392B,color:#fff
```

### Scenario 3: Reviewing a Pull Request

Scan only the changed files in a PR:

```bash
# Get list of changed files and scan each one
git diff --name-only origin/main...HEAD | xargs ./credvigil scan --min-confidence 0.5
```

### Scenario 4: Auditing an Existing Codebase

Scan an entire project for the first time:

```bash
# Full scan with JSON output for analysis
./credvigil scan ./my-large-project --format json > full_audit.json

# Quick summary — just high/critical findings
./credvigil scan ./my-large-project --min-severity high
```

### Scenario 5: Checking a Single Configuration File

Quick check of a specific file:

```bash
./credvigil scan .env
./credvigil scan docker-compose.yml
./credvigil scan terraform/main.tf
```

### Scenario 6: Scanning Clipboard or Arbitrary Text

Check if some text contains secrets:

```bash
# Paste and check (macOS)
pbpaste | ./credvigil scan --stdin

# Type directly (press Ctrl+D when done)
./credvigil scan --stdin
```

---

## 14. Frequently Asked Questions

### General Questions

**Q: Does CredVigil send my data anywhere?**  
A: No. CredVigil runs 100% locally on your machine. There are no network calls, no telemetry, no analytics, and no data uploads. Your code never leaves your computer.

**Q: Can CredVigil detect 100% of all secrets?**  
A: No tool can guarantee 100% detection. CredVigil uses two complementary strategies (regex + entropy) to maximize coverage, but some secrets may use unexpected formats or be embedded in unusual ways. CredVigil is a detection **aid**, not a guarantee.

**Q: Will CredVigil expose my secrets in its output?**  
A: No. CredVigil follows zero-trust principles — secrets are always redacted (e.g., `wJal****EKEY`) and hashed (SHA-256). The raw plaintext secret is never included in output.

**Q: Is CredVigil safe to use in CI/CD pipelines?**  
A: Yes. It only requires read access to the files being scanned, produces no network traffic, and redacts all secrets in its output.

### Technical Questions

**Q: How fast is CredVigil?**  
A: Very fast. Scanning a single file takes 1-5 milliseconds. Scanning a typical project directory takes under a second. CredVigil uses concurrent workers (4 by default) for directory scans.

**Q: What file types does CredVigil scan?**  
A: All text files. It automatically skips binary files (images, executables, archives), lock files, and large files (>5 MB). It also skips common non-essential directories like `.git`, `node_modules`, and `vendor`.

**Q: Why is the confidence for some findings low (like 30-50%) even when the regex matches?**  
A: Several factors can lower confidence:
- The matched value contains placeholder words like "EXAMPLE" or "changeme"
- The entropy is low (the value doesn't look random enough)
- The matched text is very short
- False positive patterns are detected in the surrounding context

**Q: Why do some findings from the test file say "EXAMPLE" but still show up?**  
A: Because the default confidence threshold is 0.3 (30%). CredVigil detects the placeholder pattern and lowers the confidence, but some findings still exceed 30%. You can raise the threshold with `--min-confidence 0.7` to filter these out.

**Q: Can I add my own custom detection rules?**  
A: Not yet in the current version. This is planned for Component 15 (Plugin System). For now, the 161 built-in rules cover the vast majority of services.

**Q: What's the difference between `--min-severity` and `--min-confidence`?**  
A: 
- **Severity** is about *how dangerous* the secret type is (e.g., private keys are CRITICAL, generic patterns are LOW)
- **Confidence** is about *how sure CredVigil is* that the finding is a real secret (not a false positive)

They're independent filters. A CRITICAL finding with low confidence (like a private key pattern that matches a test file) and a LOW finding with high confidence (like a definitively-matched test API key) are both possible.

```mermaid
quadrantChart
    title Severity vs Confidence
    x-axis Low Confidence --> High Confidence
    y-axis Low Severity --> High Severity
    quadrant-1 Review immediately
    quadrant-2 Investigate further
    quadrant-3 Low priority
    quadrant-4 Likely safe
    Real AWS key in prod: [0.9, 0.95]
    Test API key: [0.8, 0.2]
    Placeholder in docs: [0.15, 0.6]
    Generic entropy match: [0.4, 0.3]
```

**Q: What does exit code 1 mean?**  
A: CredVigil exits with code 1 if any findings are reported (after applying your filters). This is intentional — it allows CI/CD pipelines to fail builds automatically when secrets are detected. Exit code 0 means no findings.

---

## 15. Glossary

```mermaid
flowchart LR
    subgraph Input["Input Concepts"]
        A["Regex Rule"]
        B["Shannon Entropy"]
    end
    subgraph Process["Processing"]
        C["Finding"]
        D["Confidence Score"]
        E["Severity Level"]
    end
    subgraph Output["Output Safety"]
        F["Redaction"]
        G["SHA-256 Hash"]
        H["Zero-Trust"]
    end
    A & B --> C
    C --> D & E
    C --> F & G
    F & G --> H
    style Input fill:#3498DB,stroke:#2980B9,color:#fff
    style Process fill:#9B59B6,stroke:#8E44AD,color:#fff
    style Output fill:#27AE60,stroke:#1E8449,color:#fff
```

| Term | Definition |
|------|-----------|
| **API Key** | A unique string used to authenticate requests to an API service |
| **Base64** | An encoding scheme that represents binary data using 64 ASCII characters (A-Z, a-z, 0-9, +, /) |
| **Binary File** | A file that contains non-text data (images, executables, etc.) — CredVigil skips these |
| **CI/CD** | Continuous Integration / Continuous Deployment — automated build and deploy pipelines |
| **Confidence Score** | A 0-100% value indicating how likely a finding is a real secret |
| **Credential** | Any secret used for authentication — passwords, keys, tokens, certificates |
| **Deduplication** | Removing duplicate findings (same secret on the same line) |
| **Entropy** | A measure of randomness/unpredictability in a string. Higher = more random |
| **Exit Code** | A number a program returns when it finishes. 0 = success, 1 = findings found |
| **False Positive** | When the tool incorrectly identifies something harmless as a secret |
| **Finding** | A single occurrence of a detected potential secret |
| **Hash (SHA-256)** | A one-way function that converts any input into a fixed-length fingerprint |
| **Hex** | Hexadecimal — a base-16 number system using characters 0-9 and a-f |
| **OAuth** | An authorization framework that lets apps access services on behalf of users |
| **PAT** | Personal Access Token — a long-lived token used instead of a password |
| **Placeholder** | A dummy value like "your-api-key-here" used in documentation or templates |
| **Redaction** | Replacing portions of a secret with `****` for safe display |
| **Regex** | Regular Expression — a pattern-matching language for text |
| **Rule** | A detection pattern in CredVigil — includes regex, severity, keywords, and more |
| **Severity** | How dangerous a secret type is (INFO, LOW, MEDIUM, HIGH, CRITICAL) |
| **SHA-256** | Secure Hash Algorithm producing a 256-bit (64 hex character) hash |
| **Shannon Entropy** | A mathematical measure of information content/randomness, named after Claude Shannon |
| **Token** | A string used for authentication, often with an expiration time |
| **Webhook** | A URL that receives automated event notifications from external services |
| **Zero-Trust** | A security model that assumes nothing is safe and verifies everything |

---

## 16. What's Next?

This training guide covered **Component 1: Core Detection Engine** — the foundation of CredVigil. Here's what's coming in future components and their training modules:

| Module | Component | What You'll Learn |
|--------|-----------|-------------------|
| **Module 2** | Secure Hashing & Metadata Pipeline | How findings are enriched, normalized, and prepared for storage |
| **Module 3** | Git Integration Layer | Scanning git history, blame analysis, branch/PR scanning |
| **Module 4** | File System Watcher | Real-time monitoring — detecting secrets as they're written |
| **Module 5** | Event Bus | How components communicate using pub/sub messaging |
| **Module 6** | API Server | REST/gRPC API for programmatic access |
| **Module 7** | Storage Layer | Persisting findings, trends, and audit trails |
| **Module 8** | Web Dashboard | Visual interface for credential risk across your organization |
| **Module 9** | Notification Engine | Alerting via Slack, email, webhooks |
| **Module 10** | Policy Engine | Defining and enforcing credential security policies |
| **Module 11** | CI/CD Integration | GitHub Actions, pre-commit hooks, pipeline gates |
| **Module 12** | Compliance Reporter | Generating SOC2, ISO 27001, PCI-DSS reports |
| **Module 13** | Secret Rotation Tracker | Tracking whether leaked secrets are actually rotated |
| **Module 14** | ML Anomaly Detection | Using machine learning to catch novel secret patterns |
| **Module 15** | Plugin System | Extending CredVigil with custom rules and integrations |

Each training module will be added to the `docs/training/` directory as its corresponding component is built.

---

**Congratulations!** You now understand how CredVigil's Core Detection Engine works — from the high-level concepts to the internal code. Practice with the hands-on exercises above, and you'll be ready for Module 2.

---

*CredVigil — Your watchful guard against leaked credentials.*
