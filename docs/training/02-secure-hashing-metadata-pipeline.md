# CredVigil Training Guide — Module 2: Secure Hashing & Metadata Pipeline

> **Version**: 0.1.0  
> **Component**: Secure Hashing & Metadata Pipeline (Component 2 of 15)  
> **Audience**: Everyone — no programming or IT background required. Written for learners preparing for interviews.  
> **Prerequisites**: Completion of Module 1 (Core Detection Engine). Go 1.21+ installed (for hands-on exercises only).

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
17. [Interview Tips — Secure Hashing & Metadata Pipeline](#17-interview-tips--secure-hashing--metadata-pipeline)
18. [Marketing Tips — Secure Hashing & Metadata Pipeline](#18-marketing-tips--secure-hashing--metadata-pipeline)
19. [What's Next?](#19-whats-next)

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

SHA-256 is a **one-way mathematical function** that converts any input into a fixed-length 64-character code. Think of it as a **magic blender** — you put ingredients in and get a unique smoothie out, but you can never "un-blend" the smoothie back into the original ingredients.

#### Real-World Analogy: The Library Card Catalog

Imagine a library with millions of books. Instead of carrying the actual book around to prove you own it, the librarian gives you a **unique catalog number** for each book:

| Book Title | Catalog Number |
|---|---|
| "Harry Potter and the Philosopher's Stone" | `A7B3C9` |
| "The Great Gatsby" | `F2E8D1` |
| "Harry Potter and the Philosopher's Stone" (same book!) | `A7B3C9` (same number!) |

You can show someone the catalog number without showing them the book. Two people with the same book always get the same number. But looking at `A7B3C9` alone, nobody can reconstruct the book.

**SHA-256 works exactly the same way, but for secrets.**

```mermaid
flowchart TD
    subgraph RealWorld["Real-World Analogy"]
        A["Actual Book"] -->|"Library stamps it"| B["Catalog Number\nA7B3C9"]
        C["Same Book Again"] -->|"Library stamps it"| D["Same Number\nA7B3C9"]
        E["Different Book"] -->|"Library stamps it"| F["Different Number\nF2E8D1"]
    end
    subgraph Digital["How SHA-256 Works"]
        G["Actual Secret\nAKIA...EXAMPLE"] -->|"SHA-256"| H["Hash\n5e6bf1b9..."]
        I["Same Secret Again"] -->|"SHA-256"| J["Same Hash\n5e6bf1b9..."]
        K["Different Secret\nghp_ABCDEF..."] -->|"SHA-256"| L["Different Hash\na3c7d9e1..."]
    end
    style B fill:#9B59B6,stroke:#8E44AD,color:#fff
    style D fill:#9B59B6,stroke:#8E44AD,color:#fff
    style F fill:#E67E22,stroke:#D35400,color:#fff
    style H fill:#9B59B6,stroke:#8E44AD,color:#fff
    style J fill:#9B59B6,stroke:#8E44AD,color:#fff
    style L fill:#E67E22,stroke:#D35400,color:#fff
```

#### The Four Superpowers of SHA-256

| Property | What It Means | Everyday Example |
|---|---|---|
| **Deterministic** | Same input = same output, every single time | Scanning the same barcode always shows the same price |
| **One-way** | You can NOT reverse it to find the original | You can taste a cake but can't figure out the exact recipe |
| **Unique** | Different inputs produce different outputs | Every person's fingerprint is unique |
| **Fixed-length** | Output is always 64 characters, no matter the input | A zip code is always 5 digits whether the city is "LA" or "San Francisco" |

#### Step-by-Step Example

Let's trace what happens when CredVigil hashes an AWS secret key:

```
Step 1: The secret is detected
  RawMatch = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

Step 2: SHA-256 processes it (math happens inside)
  → The algorithm chops, shuffles, and transforms the text
  → This is done 64 rounds internally (seriously!)

Step 3: Out comes the hash
  SecretHash = "78314b11a2177f39cff3a45008a0e2b0f5e6c0d1...080e0598"
  (always exactly 64 hex characters)

Step 4: Now we can throw away the original secret!
  → We keep only the hash for tracking
  → If we see hash "78314b11..." again next week, we know it's the SAME secret
```

```mermaid
sequenceDiagram
    participant S as Secret
    participant H as SHA-256 Algorithm
    participant R as Result

    S->>H: "wJalrXUtnFEMI/K7MDENG..."
    Note over H: Chop into 512-bit blocks
    Note over H: Run 64 rounds of math
    Note over H: Mix, shift, combine
    H->>R: "78314b11...080e0598"
    Note over R: Always 64 hex chars
    Note over R: Cannot be reversed!
```

#### Why Can't You Reverse a Hash?

Think of it like this:

- **Forward (easy):** You have 3 and 5. Multiply them: 3 x 5 = 15 ✅
- **Reverse (hard):** You have 15. What two numbers made it? Could be 3x5, or 1x15, or 2.5x6... 🤷

Now imagine that problem with numbers that are **78 digits long**. That's why SHA-256 is practically impossible to reverse — even the fastest supercomputer would take longer than the age of the universe.

#### Why Do We Need This in CredVigil?

| Use Case | How SHA-256 Helps |
|---|---|
| **"Is this the same secret we saw last week?"** | Compare hashes — if they match, it's the same secret |
| **"How many unique secrets leaked?"** | Count unique hashes instead of comparing raw secrets |
| **"Store findings safely"** | Save the hash in a database, never the raw secret |
| **"Report to management"** | Say "we found hash 78314b11..." instead of sharing the actual key |

### 3.3 What Is Redaction?

Redaction replaces most of a secret with asterisks while keeping just enough characters to identify it.

#### Real-World Analogy: Credit Card Receipts

When you buy something with a credit card, the receipt doesn't show your full card number. It shows something like:

```
Card ending in **** **** **** 4242
```

This tells you *which* card was used (the one ending in 4242) without exposing the full number to anyone who sees the receipt. That's exactly what redaction does for secrets!

```mermaid
flowchart LR
    subgraph CreditCard["Credit Card Receipt"]
        CC1["4532 1234 5678 4242"] -->|"Redact"| CC2["**** **** **** 4242"]
    end
    subgraph AWSKey["CredVigil Redaction"]
        AK1["AKIAIOSFODNN7EXAMPLE"] -->|"Redact"| AK2["AKIA****MPLE"]
    end
    style CC2 fill:#27AE60,stroke:#1E8449,color:#fff
    style AK2 fill:#27AE60,stroke:#1E8449,color:#fff
    style CC1 fill:#E74C3C,stroke:#C0392B,color:#fff
    style AK1 fill:#E74C3C,stroke:#C0392B,color:#fff
```

#### The Three Redaction Rules

CredVigil uses three simple rules based on how long the secret is:

| Secret Length | Rule | Why? |
|:---:|---|---|
| **More than 12 characters** | Show first 4 + `****` + last 4 | Long secrets have enough characters to show a snippet safely |
| **5 to 12 characters** | Show first 2 + `****` | Short secrets need less revealed to stay safe |
| **4 or fewer characters** | Just show `****` | Too short to reveal anything safely |

#### Step-by-Step Examples

**Example 1: A long AWS secret key (40 characters)**
```
Original:  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Length:    40 characters (> 12, so use Rule 1)
First 4:   wJal
Last 4:    EKEY
Redacted:  wJal****EKEY
```

**Example 2: A GitHub token (40 characters)**
```
Original:  ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234
Length:    40 characters (> 12, so use Rule 1)
First 4:   ghp_
Last 4:    1234
Redacted:  ghp_****1234
```

**Example 3: A short API key (8 characters)**
```
Original:  MyKey123
Length:    8 characters (5–12, so use Rule 2)
First 2:   My
Redacted:  My****
```

**Example 4: A tiny password (3 characters)**
```
Original:  abc
Length:    3 characters (≤ 4, so use Rule 3)
Redacted:  ****
```

#### Why Not Just Hide Everything?

You might think: "Why not replace the ENTIRE secret with asterisks?" Because security teams need to know **which specific key** was leaked so they can rotate (replace) the right one!

Imagine a company has 50 AWS keys. If CredVigil just says "an AWS key was found," they'd have to rotate all 50. But if it says `AKIA****MPLE`, they can look up exactly which key starts with AKIA and ends with MPLE and rotate just that one.

```mermaid
flowchart TD
    A["50 AWS Keys in Use"] --> B{"Which one leaked?"}
    B -->|"Full redaction: ****"| C["🤷 No idea which one!\nMust rotate ALL 50"]
    B -->|"Smart redaction: AKIA****MPLE"| D["🎯 Found it!\nRotate only this one"]
    style C fill:#E74C3C,stroke:#C0392B,color:#fff
    style D fill:#27AE60,stroke:#1E8449,color:#fff
```

```mermaid
flowchart TD
    A["AKIAIOSFODNN7EXAMPLE\n(20 chars)"] --> B["> 12 chars"]
    B --> C["AKIA + **** + MPLE"]
    D["Secret!\n(7 chars)"] --> E["5–12 chars"]
    E --> F["Se + ****"]
    G["pass\n(4 chars)"] --> H["4 or fewer chars"]
    H --> I["****"]
    style C fill:#27AE60,stroke:#1E8449,color:#fff
    style F fill:#F39C12,stroke:#D68910,color:#fff
    style I fill:#E74C3C,stroke:#C0392B,color:#fff
```

### 3.4 What Is Enrichment?

#### Real-World Analogy: Crime Scene Investigation

When police find evidence at a crime scene, they don't just bag the item and walk away. They also record:

- **Where was it found?** (kitchen, bedroom, parking lot)
- **What type of evidence?** (weapon, DNA, fingerprint, document)
- **What environment?** (residential home, office building, public park)
- **When was it collected?** (timestamp, officer ID, case number)

The evidence itself is important, but the **context around it** is what makes it useful in court.

CredVigil's EnrichProcessor works the same way — it adds context to each detected secret:

- **File Type**: Was this found in a `.go` file? A `.env` file? A `Dockerfile`?
- **Environment**: Is the file in a `production/` directory? A `staging/` config? A `test/` fixture?
- **Category**: Is this a `cloud` credential? A `database` password? A `payment` key?
- **Scan Metadata**: What scanner version produced this finding? What was the scan ID?

Enrichment transforms a bare match into an actionable intelligence report.

```mermaid
flowchart TD
    subgraph Crime["Crime Scene Analogy"]
        EV["Knife Found"] --> L1["Where: Kitchen"]
        EV --> L2["Type: Weapon"]
        EV --> L3["Environment: Residential"]
        EV --> L4["Collected: 3pm, Officer Smith"]
    end
    subgraph CV["CredVigil Enrichment"]
        F["AWS Key Found"] --> M1["FileType: env"]
        F --> M2["Category: cloud"]
        F --> M3["Environment: production"]
        F --> M4["Scan: v0.1.0, ID: scan-abc"]
    end
    style Crime fill:#3498DB,stroke:#2980B9,color:#fff
    style CV fill:#E67E22,stroke:#D35400,color:#fff
```

#### Why Does Context Matter?

The same secret in different places means very different things:

| Finding | Without Enrichment | With Enrichment | Priority |
|---|---|---|---|
| AWS key in `prod/config.env` | "AWS key found" | "AWS key in **production** environment, **env** file" | 🔴 URGENT |
| AWS key in `test/fixtures/fake.env` | "AWS key found" | "AWS key in **test** environment, **env** file" | 🟢 Probably fake |
| Stripe key in `billing/charges.go` | "Stripe key found" | "Payment key in **production**, **go** file" | 🔴 URGENT |
| API key in `docs/example.yaml` | "API key found" | "Generic key in **unknown** env, **yaml** file" | 🟡 Review |

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

#### Real-World Analogy: Package Tracking Numbers

When you order something from Amazon, you get a **tracking number** like `1Z999AA10123456784`. This number doesn't describe what's in the package — it uniquely identifies **this specific shipment** (this item, from this warehouse, on this date, to this address).

If you order the exact same item again tomorrow, you get a **different tracking number** because it's a different shipment.

CredVigil fingerprints work the same way — they uniquely identify **this specific finding** (this secret, in this file, on this line, detected by this rule).

A **fingerprint** is a stable identifier that uniquely identifies a specific finding across multiple scans. It is computed as:

```
SHA-256(ruleID + ":" + location + ":" + line + ":" + secretHash)
```

#### Fingerprint vs. Hash — What's the Difference?

This is a common source of confusion, so let's make it crystal clear:

| | **Hash** | **Fingerprint** |
|---|---|---|
| **Identifies** | The **secret itself** | The **finding** (secret + where it was found) |
| **Analogy** | A person's DNA | A person's home address |
| **Same secret, 2 files** | Same hash | **Different** fingerprints |
| **Same secret, same file** | Same hash | Same fingerprint |
| **Different secrets, same file** | **Different** hashes | **Different** fingerprints |

```mermaid
flowchart TD
    subgraph Example1["Same secret in TWO files"]
        S1["AWS key AKIA...\nin config.env line 5"] --> H1["Hash: abc123"]
        S2["AWS key AKIA...\nin backup.env line 10"] --> H2["Hash: abc123\n(same secret!)"]
        S1 --> F1["Fingerprint: xxx111"]
        S2 --> F2["Fingerprint: yyy222\n(different location!)"]
    end
    subgraph Example2["Scan today vs next week"]
        T1["AWS key AKIA...\nin config.env line 5\nScanned Monday"] --> FP1["Fingerprint: xxx111"]
        T2["AWS key AKIA...\nin config.env line 5\nScanned Friday"] --> FP2["Fingerprint: xxx111\n(identical!)"]
    end
    style H1 fill:#9B59B6,stroke:#8E44AD,color:#fff
    style H2 fill:#9B59B6,stroke:#8E44AD,color:#fff
    style F1 fill:#1ABC9C,stroke:#16A085,color:#fff
    style F2 fill:#E67E22,stroke:#D35400,color:#fff
    style FP1 fill:#1ABC9C,stroke:#16A085,color:#fff
    style FP2 fill:#1ABC9C,stroke:#16A085,color:#fff
```

#### Why Do We Need Fingerprints?

| Use Case | How Fingerprints Help | Real-World Parallel |
|---|---|---|
| **"Is this a new finding or one we already know about?"** | Compare fingerprints across scans | Checking if a package was already delivered |
| **"We reviewed this and it's a false alarm"** | Add fingerprint to ignore list | Marking a spam email as "not spam" |
| **"When did this secret first appear?"** | Track fingerprint appearance over time | Checking when a warranty claim was first filed |
| **"Has this been fixed yet?"** | If fingerprint is missing from latest scan, it's fixed! | Checking if a recalled product was returned |

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

#### Real-World Analogy: Shredding Documents

Imagine a hospital that processes patient records. After extracting the needed information (diagnosis, billing codes, appointment dates), they **shred the original paper forms** that contained Social Security numbers and credit card details. The useful information has been extracted; the dangerous originals are destroyed.

That's exactly what sanitization does in CredVigil:

1. The pipeline has already extracted everything useful (hash, redacted version, fingerprint, enrichment)
2. Now the **original raw secret is permanently erased** from the computer's memory
3. It's like running the original through a paper shredder — gone forever

Sanitization is the **final, irreversible step** that clears the raw secret from memory. After sanitization:

- `RawMatch` is set to an empty string
- The finding can safely be logged, stored, transmitted, or displayed
- No component downstream can access the original secret

```mermaid
flowchart TD
    subgraph Hospital["Hospital Analogy"]
        H1["📄 Patient Form\nSSN: 123-45-6789"] --> H2["📝 Extract Info\nDiagnosis, billing"] --> H3["🗏️ Shred Original\nSSN destroyed"]
    end
    subgraph CV["CredVigil Sanitization"]
        C1["🔑 Finding\nRawMatch: AKIA..."] --> C2["⚙️ Extract Info\nhash, redact, enrich"] --> C3["🗑️ Erase Original\nRawMatch = empty"]
    end
    style H3 fill:#7F8C8D,stroke:#616A6B,color:#fff
    style C3 fill:#7F8C8D,stroke:#616A6B,color:#fff
    style H1 fill:#E74C3C,stroke:#C0392B,color:#fff
    style C1 fill:#E74C3C,stroke:#C0392B,color:#fff
```

#### What Exactly Gets Erased?

| Before Sanitization | After Sanitization |
|---|---|
| `RawMatch = "AKIAIOSFODNN7EXAMPLE"` | `RawMatch = ""` (empty — gone forever) |
| `SecretHash = "5e6bf1b9..."` | `SecretHash = "5e6bf1b9..."` (kept! We need this) |
| `RedactedMatch = "AKIA****MPLE"` | `RedactedMatch = "AKIA****MPLE"` (kept! Safe to display) |
| `Fingerprint = "a1b2c3d4..."` | `Fingerprint = "a1b2c3d4..."` (kept! For tracking) |

Notice: **only** the dangerous raw secret is erased. Everything else (the hash, redacted display, fingerprint, enrichment data) is safe and remains intact.

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

#### Real-World Analogy: Airport Security

Think about airport security. The principle is: **trust nobody, verify everything**. It doesn't matter if you're the pilot, a frequent flyer, or the airport CEO — everyone goes through the same security checkpoint. No exceptions.

This is the **zero-trust model**:
- In the old days ("castle and moat"), once you were inside the company network, you were trusted
- In zero-trust, **nobody is trusted** — every request is verified, every piece of data is checked

CredVigil applies zero-trust to secret handling: **no raw secret is allowed to leave the pipeline, ever, period.** It doesn't matter if the output is going to a trusted dashboard, a secure database, or just your own terminal — the raw secret is always erased first.

#### How Does CredVigil Enforce This?

Think of the pipeline as having a **mandatory security gate at the exit**:

```mermaid
flowchart TD
    subgraph Airport["Airport Security Analogy"]
        P1["Passenger Arrives"] --> G1{"Security Gate"}
        G1 -->|"Has weapons?"| R1["Denied Boarding"]
        G1 -->|"Clean"| B1["Allowed to Board"]
    end
    subgraph Pipeline["CredVigil Pipeline"]
        P2["Finding Ready"] --> G2{"Sanitize Check"}
        G2 -->|"RawMatch present?"| R2["BLOCKED"]
        G2 -->|"RawMatch empty"| B2["Allowed to Output"]
    end
    style R1 fill:#E74C3C,stroke:#C0392B,color:#fff
    style B1 fill:#27AE60,stroke:#1E8449,color:#fff
    style R2 fill:#E74C3C,stroke:#C0392B,color:#fff
    style B2 fill:#27AE60,stroke:#1E8449,color:#fff
```

The zero-trust guarantee means: **every finding that exits the pipeline has been sanitized**. The raw secret is never present in the output, regardless of the output format (text, JSON, or future API responses).

The pipeline enforces this by:
1. Always including `SanitizeProcessor` as the last processor in the default chain
2. Clearing `RawMatch` unconditionally
3. Being the only path findings take before output

#### Why Is This So Important?

| Without Zero-Trust | With Zero-Trust |
|---|---|
| A log file might contain `AWS_KEY=wJalrXUtn...` | Log file only shows `AWS_KEY=wJal****EKEY` |
| A crash dump could expose 50 raw passwords | Crash dump shows only hashes and redacted versions |
| Sending findings to Slack might leak credentials | Slack message shows `AKIA****MPLE` — safe to share |
| A screenshot of your terminal reveals everything | Screenshot shows hash `78314b11...` — useless to attackers |

#### The Guarantee in Action

Let's trace a finding through the entire pipeline to see how zero-trust works:

```
STEP 1 - Detection:
  RawMatch = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  DANGER

STEP 2 - HashProcessor:
  SecretHash = "78314b11a2177f39..."   Safe (can't be reversed)
  RawMatch still exists   (needed by next steps)

STEP 3 - RedactProcessor:
  RedactedMatch = "wJal****EKEY"   Safe (partial, not useful to attacker)
  RawMatch still exists   (will be cleaned soon)

STEP 4 - EnrichProcessor:
  FileType = "env", Environment = "production", Category = "cloud"   Safe
  RawMatch still exists   (one more step...)

STEP 5 - FingerprintProcessor:
  Fingerprint = "a1b2c3d4e5f6..."   Safe
  RawMatch still exists   (almost there!)

STEP 6 - SanitizeProcessor:
  RawMatch = ""   ERASED PERMANENTLY

RESULT: Everything useful is preserved. The dangerous raw secret is GONE.
```

```mermaid
sequenceDiagram
    participant F as Finding
    participant H as Hash
    participant R as Redact
    participant E as Enrich
    participant FP as Fingerprint
    participant S as Sanitize

    Note over F: RawMatch = "wJalr..."
    F->>H: Process
    Note over H: SecretHash = "78314..."
    H->>R: Process
    Note over R: RedactedMatch = "wJal****EKEY"
    R->>E: Process
    Note over E: FileType, Env, Category
    E->>FP: Process
    Note over FP: Fingerprint = "a1b2c3..."
    FP->>S: Process
    Note over S: RawMatch = "" (ERASED!)
    S-->>F: Safe Finding
    Note over F: Raw secret is GONE forever
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
│  │   (309 rules, entropy, scoring)  │                                           │
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

```mermaid
flowchart TD
    A["Finding arrives"] --> B{"RawMatch empty?"}
    B -->|"❌ Yes"| C["Skip hashing"]
    B -->|"✅ Has value"| D{"SecretHash\nalready set?"}
    D -->|"✅ Yes"| E["Keep existing hash"]
    D -->|"❌ No"| F["Compute SHA-256"]
    F --> G["Set SecretHash"]
    E & G --> H["Set Metadata sha256"]
    style F fill:#3498DB,stroke:#2980B9,color:#fff
    style H fill:#27AE60,stroke:#1E8449,color:#fff
    style C fill:#BDC3C7,stroke:#95A5A6,color:#000
```

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

```mermaid
flowchart TD
    A["Finding arrives"] --> B{"RedactedMatch\nalready set?"}
    B -->|"✅ Yes"| C["Skip (idempotent)"]
    B -->|"❌ No"| D{"Length of RawMatch?"}
    D -->|"more than 12 chars"| E["first4 + **** + last4"]
    D -->|"5 to 12 chars"| F["first2 + ****"]
    D -->|"4 or fewer chars"| G["****"]
    E & F & G --> H["✅ RedactedMatch set"]
    style H fill:#27AE60,stroke:#1E8449,color:#fff
    style C fill:#BDC3C7,stroke:#95A5A6,color:#000
```

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

```mermaid
flowchart LR
    A["ruleID"] --> E["Concatenate\nwith : separator"]
    B["location"] --> E
    C["line #"] --> E
    D["secretHash"] --> E
    E --> F["SHA-256"]
    F --> G["Fingerprint\n64 hex chars"]
    style E fill:#1ABC9C,stroke:#16A085,color:#fff
    style G fill:#9B59B6,stroke:#8E44AD,color:#fff
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

```mermaid
flowchart TD
    A["Finding with RawMatch"] --> B["SanitizeProcessor"]
    B --> C["RawMatch = ''"]
    C --> D{"ClearMetadataSHA?"}
    D -->|"✅ Yes"| E["Delete Metadata sha256"]
    D -->|"❌ No"| F["Keep Metadata sha256"]
    E & F --> G["✅ Safe Finding"]
    G --> H["📝 Log"]
    G --> I["💾 Store"]
    G --> J["📡 Transmit"]
    G --> K["💻 Display"]
    style B fill:#7F8C8D,stroke:#616A6B,color:#fff
    style G fill:#27AE60,stroke:#1E8449,color:#fff
```

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

```mermaid
flowchart LR
    subgraph PF["ProcessFindings"]
        A["[]Finding"] --> B["⚙️ Pipeline"]
        B --> C["kept []Finding"]
        B --> D["[]error"]
    end
    subgraph PR["ProcessResult"]
        E["ScanResult"] --> F["⚙️ Pipeline"]
        F --> G["Updated ScanResult\nin-place"]
    end
    style PF fill:#3498DB,stroke:#2980B9,color:#fff
    style PR fill:#9B59B6,stroke:#8E44AD,color:#fff
```

### Dynamic Pipeline Modification

```go
// Add a processor to the end (before sanitize — you should reorder manually)
pipe.AddProcessor(myProcessor)

// Insert a processor at a specific position
pipe.InsertProcessor(4, myVerifier)  // Before sanitize (index 4)

// Get the current processor list
procs := pipe.Processors()
```

```mermaid
flowchart LR
    A["Hash"] --> B["Redact"]
    B --> C["Enrich"]
    C --> D["Fingerprint"]
    D --> E["Sanitize"]
    
    F["🆕 Custom Proc"] -.->|"InsertProcessor(4,...)"| D2["Fingerprint"]
    D2 -.-> F
    F -.-> E
    style F fill:#F39C12,stroke:#D68910,color:#fff,stroke-dasharray: 5 5
```

### Thread Safety

#### What Is "Thread Safety"? (For Non-Programmers)

Imagine a **shared bathroom** in an office. If two people try to use it at the same time, chaos ensues. The solution? A **lock on the door**. When someone's inside, the door is locked. Others must wait their turn.

In software, "threads" are like people, and "data" is like the bathroom. When multiple parts of a program try to modify the same data simultaneously, things can break. A **mutex** (mutual exclusion) is the lock on the door.

```mermaid
flowchart TD
    subgraph Bathroom["Bathroom Analogy"]
        P1["Person A"] --> D1{"Door locked?"}
        D1 -->|"No"| E1["Enter and lock door"]
        P2["Person B"] --> D2{"Door locked?"}
        D2 -->|"Yes"| W1["Wait outside..."]
        E1 --> U1["Use bathroom"]
        U1 --> X1["Exit and unlock"]
        X1 --> W1
        W1 --> E2["Now enter"]
    end
    subgraph Software["CredVigil Thread Safety"]
        T1["Scanner Thread 1"] --> L1{"Pipeline locked?"}
        L1 -->|"No"| R1["Lock and process"]
        T2["Scanner Thread 2"] --> L2{"Pipeline locked?"}
        L2 -->|"Yes"| W2["Wait..."]
        R1 --> D3["Process findings"]
        D3 --> X2["Unlock"]
        X2 --> W2
        W2 --> R2["Now process"]
    end
    style E1 fill:#27AE60,stroke:#1E8449,color:#fff
    style W1 fill:#F39C12,stroke:#D68910,color:#fff
    style R1 fill:#27AE60,stroke:#1E8449,color:#fff
    style W2 fill:#F39C12,stroke:#D68910,color:#fff
```

CredVigil's Pipeline uses a **read-write lock** — a smarter version of a lock:
- **Reading** (processing findings): Multiple threads can read at the same time, like many people reading the same bulletin board
- **Writing** (adding a new processor): Only one thread can modify the pipeline at a time, like only one person can edit the bulletin board

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

### What Is "Separation of Concerns"? (For Non-Programmers)

Imagine a **hospital**. In a tiny rural clinic, one doctor does EVERYTHING — diagnoses the illness, performs surgery, fills prescriptions, does physical therapy, and sends the bill. That doctor is overwhelmed, and when something goes wrong, it's impossible to know which part failed.

Now imagine a **large modern hospital**:

| Specialist | Role |
|-----------|------|
| **Diagnostic Doctor** | Figures out what's wrong |
| **Surgeon** | Performs operations |
| **Pharmacist** | Prepares medications |
| **Physical Therapist** | Helps recovery |
| **Billing Department** | Handles payments |

Each specialist does **ONE thing extremely well**, and they all work together through a shared patient chart.

```mermaid
flowchart TD
    subgraph Clinic["Tiny Clinic: One Doctor Does Everything"]
        D1["Dr. Smith"] --> ALL["Diagnose + Operate +\nMedicate + Therapy + Bill"]
        ALL --> P1["Overwhelmed!\nHard to improve"]
    end
    subgraph Hospital["Modern Hospital: Specialists"]
        P2["Patient"] --> DIAG["Diagnostics"]
        DIAG --> SURG["Surgery"]
        SURG --> PHARM["Pharmacy"]
        PHARM --> THER["Therapy"]
        THER --> BILL["Billing"]
    end
    style Clinic fill:#E74C3C,stroke:#C0392B,color:#fff
    style Hospital fill:#27AE60,stroke:#1E8449,color:#fff
```

**This is exactly what happened with CredVigil!**

In Component 1 (Module 1), the detection engine was like the overworked rural doctor — it detected secrets AND hashed them AND redacted them AND added metadata. In Component 2, we hired specialists (the pipeline processors), and now the detection engine only does what it's best at: **finding secrets**.

#### Why Is Separation of Concerns So Important?

| Benefit | Hospital Analogy | CredVigil Reality |
|---------|-----------------|-------------------|
| **Easier to improve** | You can hire a better surgeon without replacing the pharmacist | You can improve redaction without touching detection |
| **Easier to test** | You can test if the pharmacy gives correct medicine, separately | You can test hashing alone, redaction alone, etc. |
| **Easier to understand** | A new nurse only needs to learn their department | A new developer only needs to understand one processor |
| **Easier to replace** | You can switch billing companies without affecting patient care | You can swap our hash algorithm without changing enrichment |
| **Fewer mistakes** | A pharmacist focused on medications makes fewer errors than a doctor who also does surgery while filling prescriptions | Each processor does one thing, so bugs are isolated |

> **Interview Tip**: "Separation of concerns means each piece of the system has one specific job. Just like a hospital where the surgeon doesn't also handle billing, our detection engine doesn't also handle redaction — that's the pipeline's job."

### Before Component 2 (Module 1)

In Component 1, hashing, redaction, and metadata were handled **inline** inside the detection engine — our "overworked doctor":

```go
// Old approach (inside matchRule):
finding.Metadata["sha256"] = hashSecret(secretValue)
finding.Redact()
```

The engine was doing detection AND post-processing, which made it:
- Harder to test (you couldn't test redaction without running the full engine)
- Harder to modify (changing how we hash meant editing the detection code)
- More fragile (a bug in redaction could break detection)

### After Component 2

Now, the detection engine focuses purely on **detection**. Post-processing is a separate concern, handled by the pipeline:

```go
// New approach (in main.go):
results := engine.ScanContent(request)

// Pipeline handles everything — the engine doesn't need to know about any of this
pipe := pipeline.NewDefault()
meta := &models.ScanMetadata{
    ScannerVersion: version,
    StartedAt:      time.Now(),
    RuleCount:      len(engine.Rules()),
}
pipe.ProcessResult(ctx, &results, meta)
```

**What the engine still does** (its ONE specialty):
- Scans code for secrets using pattern matching and entropy analysis
- Computes `SecretHash` during detection for **deduplication** (removing duplicate findings of the same secret)
- Sets `RawMatch`, `Confidence`, `Severity`, `Source`, and other detection-related fields

**What the engine no longer does** (handed to specialists):
- No redaction (`Redact()` is not called) — that's the RedactProcessor's job now
- No metadata injection (no `Metadata["sha256"]`) — that's the HashProcessor's job now
- No post-processing of any kind — that's the Pipeline's job now

```mermaid
flowchart TD
    subgraph Before["Before: Overworked Doctor"]
        A1["Engine"] --> A2["Detect + Hash + Redact + Metadata"]
        A2 --> A3["Hard to test\nHard to improve\nMore bugs"]
    end
    subgraph After["After: Specialist Hospital"]
        B1["Engine"] --> B2["Detect Only\n(one job)"]
        B2 --> B3["Pipeline"]
        B3 --> B4["Hash"] --> B5["Redact"] --> B6["Enrich"] --> B7["Fingerprint"] --> B8["Sanitize"]
    end
    style Before fill:#E74C3C,stroke:#C0392B,color:#fff
    style After fill:#27AE60,stroke:#1E8449,color:#fff
    style B2 fill:#3498DB,stroke:#2980B9,color:#fff
```

#### Step-by-Step: How the Handoff Works

Think of it like a relay race — the detection engine runs the first leg and hands the baton to the pipeline:

```mermaid
sequenceDiagram
    participant U as User
    participant CLI as Command Line
    participant E as Detection Engine
    participant P as Pipeline
    participant O as Output

    U->>CLI: "Scan my code"
    CLI->>E: ScanContent(files)
    Note over E: Engine finds secrets\n(its ONE job)
    E-->>CLI: Raw findings with secrets still visible
    CLI->>P: ProcessResult(findings)
    Note over P: Pipeline processes each finding:\n1. Hash  2. Redact  3. Enrich\n4. Fingerprint  5. Sanitize
    P-->>CLI: Safe findings (secrets erased)
    CLI->>O: Display results
    Note over O: User sees redacted output\nNever sees raw secrets
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

```mermaid
flowchart LR
    subgraph Before["Before Pipeline"]
        A["RawMatch: AKIA...\nNo FileType\nNo Environment\nNo Fingerprint"]
    end
    subgraph After["After Pipeline"]
        B["RawMatch: ''\nSecretHash: 5e6b...\nRedacted: AKIA****MPLE\nFileType: go\nEnvironment: production\nCategory: cloud\nFingerprint: a1b2..."]
    end
    Before -->|"⚙️ Pipeline"| After
    style Before fill:#E74C3C,stroke:#C0392B,color:#fff
    style After fill:#27AE60,stroke:#1E8449,color:#fff
```

---

## 10. Hands-On Exercises

```mermaid
flowchart LR
    E1["Ex 1\nObserve Output"] --> E2["Ex 2\nText vs JSON"]
    E2 --> E3["Ex 3\nZero-Trust"]
    E3 --> E4["Ex 4\nFingerprints"]
    E4 --> E5["Ex 5\nTest Suite"]
    E5 --> E6["Ex 6\nProd Path"]
    style E1 fill:#3498DB,stroke:#2980B9,color:#fff
    style E3 fill:#E67E22,stroke:#D35400,color:#fff
    style E6 fill:#27AE60,stroke:#1E8449,color:#fff
```

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

```mermaid
flowchart TD
    PIPE["pipeline.go\n🎯 Orchestrator"] --> HASH["hash.go\n🔢 SHA-256"]
    PIPE --> RED["redact.go\n🔒 Masking"]
    PIPE --> ENR["enrich.go\n📊 Classify"]
    PIPE --> FP["fingerprint.go\n🧬 Identifier"]
    PIPE --> SAN["sanitize.go\n🧹 Erase"]
    PIPE --> VER["verify.go\n🔍 Hooks"]
    TEST["pipeline_test.go\n🧪 32 Tests"] --> PIPE
    PIPE --> MOD["models/finding.go\n📦 Data"]
    style PIPE fill:#9B59B6,stroke:#8E44AD,color:#fff
    style TEST fill:#3498DB,stroke:#2980B9,color:#fff
    style MOD fill:#27AE60,stroke:#1E8449,color:#fff
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

```mermaid
flowchart LR
    A["classifyFileType\n60+ extensions"] --> D["FileType"]
    B["detectEnvironment\npath patterns"] --> E["Environment"]
    C["categorizeSecret\nprefix matching"] --> F["Category"]
    style A fill:#3498DB,stroke:#2980B9,color:#fff
    style B fill:#E67E22,stroke:#D35400,color:#fff
    style C fill:#9B59B6,stroke:#8E44AD,color:#fff
```

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

### What Are Custom Processors? (For Non-Programmers)

Remember the **assembly line analogy** from earlier? The default pipeline has 5 stations (Hash, Redact, Enrich, Fingerprint, Sanitize). But what if your factory needs an extra step? Maybe you want to **stamp each product with your company logo** before it's shipped out.

Custom processors let you **add your own stations** to the assembly line. You get to choose:
- **What** the station does (its job)
- **Where** it goes in the line (its position)

#### The LEGO Analogy

Think of the pipeline like a **LEGO tower**. The default tower has 5 blocks:

```mermaid
flowchart TD
    subgraph Default["Default Tower (5 blocks)"]
        B1["🔢 Hash"]
        B2["🔒 Redact"]
        B3["📊 Enrich"]
        B4["🧬 Fingerprint"]
        B5["🧹 Sanitize"]
        B1 --> B2 --> B3 --> B4 --> B5
    end
    subgraph Custom["Your Custom Tower (6 blocks)"]
        C1["🔢 Hash"]
        C2["🔒 Redact"]
        C3["📊 Enrich"]
        C4["🧬 Fingerprint"]
        C5["🏷️ YOUR\nCustom Block"]
        C6["🧹 Sanitize"]
        C1 --> C2 --> C3 --> C4 --> C5 --> C6
    end
    style C5 fill:#F39C12,stroke:#D68910,color:#fff
    style Default fill:#3498DB,stroke:#2980B9,color:#fff
    style Custom fill:#27AE60,stroke:#1E8449,color:#fff
```

You can snap in your custom LEGO block wherever you want — but you MUST keep the Sanitize block at the end (because the secret must always be erased before the data leaves the pipeline).

> **Interview Tip**: "CredVigil's pipeline is extensible — you can add custom processing steps without modifying the existing ones. This follows the Open/Closed Principle: open for extension, closed for modification."

#### Example: Adding a "Tag" Processor

Let's say your security team wants every finding tagged with the **team name** and **project name**. This is like adding a "stamp" station to the assembly line that marks each product with your department's label.

```go
package mypipeline

import (
    "context"
    "github.com/credvigil/credvigil/pkg/models"
)

// TagProcessor adds custom tags to findings
// Think of it as a "stamp station" that labels each finding
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

```mermaid
flowchart LR
    A["Hash"] --> B["Redact"]
    B --> C["Enrich"]
    C --> D["Fingerprint"]
    D --> T["🆕 TagProcessor\nAdds team & project"]
    T --> E["Sanitize"]
    style T fill:#F39C12,stroke:#D68910,color:#fff
```

#### Step-by-Step: What Happens to a Finding

Let's trace a finding through the pipeline with our custom TagProcessor added:

| Step | Station | What Goes In | What Changes | What Comes Out |
|------|---------|-------------|-------------|----------------|
| 1 | Hash | Raw finding | `SecretHash` gets set | Finding + hash |
| 2 | Redact | Finding + hash | `RedactedMatch` gets set | Finding + hash + redacted |
| 3 | Enrich | Finding + hash + redacted | `FileType`, `Environment`, `Category` set | Finding + all metadata |
| 4 | Fingerprint | Finding + metadata | `Fingerprint` gets set | Finding + fingerprint |
| 5 | **Tag** (custom) | Finding + fingerprint | `team=platform`, `project=credvigil` added | Finding + tags |
| 6 | Sanitize | Finding + tags | `RawMatch` permanently erased | Safe finding |

#### Why Custom Processors Are Powerful — Real-World Examples

| Custom Processor Idea | What It Does | Real-World Analogy |
|----------------------|--------------|-------------------|
| **Priority Scorer** | Assigns urgency (P1-P4) based on rules | Hospital triage — "this patient needs attention NOW" |
| **Team Router** | Tags findings with the responsible team | Mail room sorting letters into department mailboxes |
| **Slack Notifier** | Sends alerts for critical findings | Fire alarm — when smoke is detected, ring the bell |
| **Duplicate Filter** | Skips findings already seen before | Library — "we already have this book, no need to catalog it again" |
| **Compliance Tagger** | Adds regulatory labels (PCI, HIPAA) | Customs inspector stamping packages with import classifications |

### Guidelines for Custom Processors

| Guideline | Why | Everyday Analogy |
|-----------|-----|-----------------|
| Never store `RawMatch` externally | Violates zero-trust — leaks the raw secret | A hospital nurse shouldn't photocopy patient credit cards "just in case" |
| Always handle `nil` Metadata maps | Prevents the program from crashing | Check if a mailbox exists before putting mail in it |
| Return `error` to drop a finding | Use for validation/filtering | A quality inspector can reject a defective product |
| Keep processors stateless | Enables multiple workers (threads) at once | A stamp machine doesn't need to remember the LAST item it stamped |
| Use `Name()` for logging | Helps trace pipeline issues | Every station on an assembly line has a sign with its name |

> **Key Rule**: Custom processors MUST be inserted **before** the SanitizeProcessor. Since Sanitize erases the raw secret, any custom processor that needs access to `RawMatch` must run before sanitization. Think of it like this: you can't stamp a letter after it's been shredded.

---

## 13. Verification Hooks (Preview)

### What Is "Verification"? (For Non-Programmers)

Imagine you're a building inspector. You find a **fire alarm** on the wall. You've detected it! But here's the important question: **does it actually work?** If you pull the alarm and it rings, it's a **verified, active alarm**. If you pull it and nothing happens, it's a **dead alarm** — detected but not actually functional.

This is exactly what verification does in CredVigil. The detection engine finds things that LOOK like secrets (like a string that matches the pattern of an AWS key). But is that key actually valid? Can someone use it right now to access your systems?

```mermaid
flowchart TD
    subgraph DetectOnly["Detection Only (Current)"]
        D1["Found: AKIA...EXAMPLE"] --> D2{"Is it a real key?"}
        D2 --> D3["We don't know yet..."]
    end
    subgraph WithVerify["Detection + Verification (Future)"]
        V1["Found: AKIA...EXAMPLE"] --> V2["Try safe API call"]
        V2 --> V3{"Response?"}
        V3 -->|"Access denied"| V4["Verified: ACTIVE key!\nURGENT - revoke now"]
        V3 -->|"Invalid key"| V5["Verified: DEAD key\nLow priority"]
        V3 -->|"Can't check"| V6["Unverified\nTreat as active"]
    end
    style D3 fill:#F39C12,stroke:#D68910,color:#fff
    style V4 fill:#E74C3C,stroke:#C0392B,color:#fff
    style V5 fill:#27AE60,stroke:#1E8449,color:#fff
    style V6 fill:#F39C12,stroke:#D68910,color:#fff
```

#### Why Does Verification Matter?

| Scenario | Without Verification | With Verification |
|----------|---------------------|-------------------|
| AWS key found in old code | "We found a key, it MIGHT be active" | "This key is STILL ACTIVE — revoke it NOW" |
| GitHub token in deleted branch | "There's a token here" | "This token expired 6 months ago — low priority" |
| Database password in config | "A password was detected" | "This password works! Someone could access your database RIGHT NOW" |

Think of it like a doctor's diagnosis versus a lab test:
- **Detection** = The doctor says, "This LOOKS like strep throat" (educated guess based on symptoms)
- **Verification** = The lab test confirms, "Yes, it IS strep throat" (confirmed by testing)

#### The Verification Hook Interface

The pipeline includes a `VerificationHook` interface that extends `Processor`:

```go
type VerificationHook interface {
    Processor
    CanVerify(secretType models.SecretType) bool
}
```

This interface adds one extra question: **"Can you verify this TYPE of secret?"** Not all verifiers can check all secret types — an AWS verifier can check AWS keys, but it can't check GitHub tokens.

A `NoOpVerifier` placeholder is included but **not** part of the default pipeline. Future components will implement actual verification (e.g., checking if an AWS key is still active by making a safe API call).

#### How Verification Will Fit in the Pipeline

```mermaid
flowchart LR
    A["Hash"] --> B["Redact"]
    B --> C["Enrich"]
    C --> D["Fingerprint"]
    D --> E["Verify\n(future)"]
    E --> F["Sanitize"]
    style E fill:#F39C12,stroke:#D68910,color:#fff,stroke-dasharray: 5 5
```

Notice that Verify comes **before** Sanitize. This is critical — the verifier might need the raw secret to make the API call, so it must run before the secret is permanently erased.

To add verification to the pipeline:

```go
pipe := pipeline.NewDefault()
verifier := myVerifier  // Implements VerificationHook
pipe.InsertProcessor(4, verifier)  // Before sanitize
```

> **Interview Tip**: "Our pipeline supports verification hooks — pluggable modules that can check if a detected secret is actually still active. This turns a passive scanner into an active security tool that can prioritize real threats over expired credentials."

---

## 14. Error Handling & Resilience

### What Is "Resilience"? (For Non-Programmers)

Imagine you're at a **post office** sorting 100 packages. You pick up package #47 and notice it's damaged — the label is torn and you can't read the address. Do you:

**(A)** Throw away ALL 100 packages and go home?  
**(B)** Set aside the damaged package, note the problem, and continue sorting the other 99?

Obviously **(B)**! That's exactly how CredVigil's pipeline handles errors. If one finding causes a problem during processing, we don't crash the entire scan. We **set aside the bad one**, record what went wrong, and keep processing the rest.

```mermaid
flowchart TD
    A["100 Findings enter the Pipeline"]
    A --> B["Finding #1 - OK"]
    A --> C["Finding #2 - OK"]
    A --> D["..."]
    A --> E["Finding #47 - ERROR!\nProcessor couldn't handle it"]
    A --> F["..."]
    A --> G["Finding #100 - OK"]
    B --> H["97 Kept Findings\n(Successfully processed)"]
    C --> H
    D --> H
    G --> H
    E --> I["3 Dropped Findings\n(Logged for review)"]
    H --> J["Output to User"]
    I --> K["Logged to stderr"]
    style H fill:#27AE60,stroke:#1E8449,color:#fff
    style I fill:#E74C3C,stroke:#C0392B,color:#fff
    style E fill:#F39C12,stroke:#D68910,color:#fff
```

#### The Airplane Engine Analogy

Modern airplanes have **multiple engines**. If one engine fails mid-flight, the plane doesn't crash — it continues flying safely on the remaining engines. The pilot is alerted, the problem is logged, and the plane lands safely. After landing, mechanics diagnose and fix the failed engine.

CredVigil's pipeline works the same way:
- **Each finding is processed independently** (like each engine runs independently)
- **One failure doesn't stop the others** (the pipeline keeps going)
- **Failures are logged** (so you can investigate later)
- **The scan still succeeds** (you get all the good results)

| Concept | Airplane Analogy | CredVigil Pipeline |
|---------|-----------------|-------------------|
| **Normal operation** | All engines running | All findings processed successfully |
| **Partial failure** | One engine out | One finding fails a processor step |
| **System response** | Keep flying on other engines | Keep processing other findings |
| **Alert** | Cockpit warning light | Error logged to stderr |
| **Recovery** | Land safely, fix engine later | Output good results, investigate errors later |
| **Total failure** | Would need ALL engines to fail | Would need the pipeline itself to crash (extremely rare) |

> **Interview Tip**: "Our pipeline is designed for resilience. If processing fails for one finding out of a hundred, the other 99 are still processed and delivered. We follow the principle of 'partial failure tolerance' — a single bad input shouldn't bring down the entire system."

### How It Works in Practice

#### Processor Errors

If a processor returns an error for a finding, that finding is **dropped** from the results and the error is recorded:

```go
kept, errs := pipe.ProcessFindings(ctx, findings, meta)
// kept  = findings that passed all processors
// errs  = errors from findings that were dropped
```

Let's trace through an example with 5 findings:

```mermaid
sequenceDiagram
    participant P as Pipeline
    participant H as HashProcessor
    participant R as RedactProcessor

    Note over P: Processing Finding #1
    P->>H: Process(finding1)
    H-->>P: OK
    P->>R: Process(finding1)
    R-->>P: OK
    Note over P: Finding #1 kept

    Note over P: Processing Finding #2
    P->>H: Process(finding2)
    H-->>P: ERROR!
    Note over P: Finding #2 DROPPED\nError recorded\nSkip remaining processors

    Note over P: Processing Finding #3
    P->>H: Process(finding3)
    H-->>P: OK
    P->>R: Process(finding3)
    R-->>P: OK
    Note over P: Finding #3 kept
```

Notice that when Finding #2 fails at the Hash step, the pipeline:
1. Records the error
2. Does NOT try the remaining processors for that finding
3. Moves on to Finding #3 as if nothing happened

#### A Concrete Example

Imagine you scan a project and get 100 findings:

| What Happens | Count | Result |
|-------------|-------|--------|
| Findings that pass all 5 processors perfectly | 97 | Included in output |
| Finding with corrupt data that crashes the hash step | 1 | Dropped, error logged |
| Finding with unusual characters that breaks redaction | 1 | Dropped, error logged |
| Finding with missing file path that causes enrich to fail | 1 | Dropped, error logged |
| **Total findings processed** | **100** | **97 good + 3 errors** |

You get 97 clean, enriched, safe results — AND you get 3 error messages telling you exactly which findings had problems and why.

### Error Reporting in CLI

When running via the CLI, pipeline errors are logged to stderr:

```
[pipeline] warning: 3 findings dropped due to processing errors
```

This does not affect the exit code — the scan is still considered successful if at least some findings were processed. Think of it like a teacher grading 30 exams — if 3 papers are illegible, the teacher grades the other 27 and notes that 3 couldn't be read. The grading session was still successful.

```mermaid
flowchart TD
    A["100 Findings"] --> B["Pipeline"]
    B --> C{"Processor Error?"}
    C -->|"No Error"| D["97 Kept Findings"]
    C -->|"Error"| E["3 Dropped\n(logged to stderr)"]
    D --> F["Output\n(text or JSON)"]
    E --> G["Warning message\nfor investigation"]
    style D fill:#27AE60,stroke:#1E8449,color:#fff
    style E fill:#E74C3C,stroke:#C0392B,color:#fff
    style F fill:#3498DB,stroke:#2980B9,color:#fff
```

### Why Not Try to Fix the Error?

You might ask: "Why not try to fix the finding and process it again?" Great question! Here's why:

| Approach | Problem |
|----------|---------|
| **Retry the failing processor** | If it failed once, it'll likely fail again with the same input — wasting time |
| **Skip just that one processor** | Dangerous! If the Hash step fails, the finding has no hash. If Sanitize is skipped, the raw secret leaks! |
| **Try to "fix" the data** | The pipeline shouldn't guess what the data should look like — guessing could introduce security issues |
| **Drop the finding and log it (current approach)** | Safe, fast, and gives humans the information to investigate |

> **Key Takeaway**: CredVigil's pipeline follows a simple philosophy: **do it right or don't do it at all**. A partially processed finding is more dangerous than a dropped finding with an error log.

---

## 15. Frequently Asked Questions

### General Questions

**Q: What does the pipeline actually DO in one sentence?**  
A: It takes a raw detected secret and transforms it into a safe, enriched report — hashing it for identification, masking it for display, adding context, creating a tracking ID, and permanently erasing the original secret. Think of it as a factory assembly line that turns a dangerous raw material into a safe, labeled, tracked product.

**Q: Can I disable the SanitizeProcessor?**  
A: Technically yes (by using `pipeline.New()` and adding only the processors you want), but this is **strongly discouraged**. Disabling sanitization breaks the zero-trust guarantee and may leak raw secrets. It's like removing the safety belt from a car — technically possible, but extremely dangerous. The SanitizeProcessor exists to protect you.

**Q: Does the pipeline modify the original findings?**  
A: `ProcessFindings` works on copies of the finding slice. `ProcessResult` modifies the `ScanResult` in-place. The detection engine's internal state is not affected. Think of it like making photocopies of documents — the pipeline works on the copies, not the originals.

**Q: Can I run the pipeline multiple times?**  
A: Yes, but the SanitizeProcessor will clear `RawMatch` on the first run. Subsequent runs will hash/redact empty strings. Design your workflow to run the pipeline once. It's like washing dishes — wash them once and they're clean. Washing already-clean dishes doesn't help.

### Hash & Fingerprint Questions

**Q: What's the difference between a hash and a fingerprint?**  
A: 

| Feature | Hash (`SecretHash`) | Fingerprint |
|---------|-------------------|-------------|
| **What it identifies** | The secret VALUE itself | The secret in its LOCATION |
| **Same secret, two files** | Same hash (same value) | Different fingerprints (different locations) |
| **Secret changes, same file** | Different hash (different value) | Different fingerprint (different content) |
| **Analogy** | DNA test — identifies the PERSON | Home address — identifies WHERE they live |
| **Used for** | "Have we seen this password before?" | "Is this the same finding we saw last Tuesday?" |

**Q: Why does the engine still compute SecretHash?**  
A: The engine needs `SecretHash` during scanning for **deduplication** — if the same secret appears on multiple lines, it only reports it once. Think of it like a librarian checking if a book is already on the shelf before adding a new copy. The HashProcessor respects this pre-computed value and doesn't overwrite it.

**Q: How does fingerprinting handle file renames?**  
A: If a file is renamed, the fingerprint changes (because the location is part of the fingerprint input). This is intentional — a renamed file represents a new "finding location" for tracking purposes. It's like how your mailing address changes when you move, even though you're still the same person.

### Security Questions

**Q: Can someone reverse the hash to get the original secret?**  
A: No. SHA-256 is a one-way function. Given the hash, it is computationally impossible to determine the original input. It's like knowing that a cake weighs 2 pounds — you can't figure out the exact recipe from just the weight. See section 3.2 for more details on why hashing is irreversible.

**Q: What if the same secret is found in multiple files?**  
A: Each location gets its own finding with its own fingerprint, but they'll share the same `SecretHash` (because the secret value is the same). Think of it like finding the same person's photo in three different rooms — the person (hash) is the same, but the locations (fingerprints) are different.

**Q: What happens if a finding has no RawMatch?**  
A: The HashProcessor skips it (no hash), the RedactProcessor sets `"****"`, and the SanitizeProcessor clears the (already empty) field. The pipeline handles edge cases gracefully. It's like an empty package on the assembly line — each station checks "is there anything here?" and acts accordingly.

### Pipeline Design Questions

**Q: Why is the order of processors so important?**  
A: Because each processor depends on the work of previous ones. The FingerprintProcessor needs the hash (computed by HashProcessor) to create its identifier. The SanitizeProcessor must be last because it erases the raw secret — no processor after it can access that data. Think of building a house: you must pour the foundation before building the walls, and the walls must exist before you add the roof.

```mermaid
flowchart LR
    H["Hash\n(needs RawMatch)"] --> R["Redact\n(needs RawMatch)"]
    R --> E["Enrich\n(needs file path)"]
    E --> F["Fingerprint\n(needs Hash)"]
    F --> S["Sanitize\n(erases RawMatch)"]
    S --> X["After this point:\nRawMatch is GONE forever"]
    style S fill:#E74C3C,stroke:#C0392B,color:#fff
    style X fill:#7F8C8D,stroke:#616A6B,color:#fff
```

**Q: Can I add a processor AFTER the SanitizeProcessor?**  
A: You can, but it won't have access to `RawMatch` (it's been erased). Only add processors after sanitization if they don't need the raw secret — for example, a logging processor that records which findings were processed.

**Q: What happens if the pipeline crashes completely?**  
A: If the pipeline itself crashes (not just a single finding), no output is produced and an error is returned. This is by design — a partially sanitized output could leak raw secrets. It's better to produce no output than to produce unsafe output. Think of it like a bank vault: if the locking mechanism fails, the vault stays sealed rather than opening accidentally.

---

## 16. Glossary

```mermaid
flowchart TD
    subgraph Core["Core Concepts"]
        A["Processor"]
        B["Pipeline"]
    end
    subgraph Operations["What Processors Do"]
        C["SHA-256 Hash"]
        D["Redaction"]
        E["Enrichment"]
        F["Fingerprint"]
        G["Sanitization"]
    end
    subgraph Principles["Guiding Principles"]
        H["Zero-Trust"]
        I["Idempotent"]
    end
    B --> A
    A --> C & D & E & F & G
    G --> H
    D --> I
    style Core fill:#3498DB,stroke:#2980B9,color:#fff
    style Operations fill:#9B59B6,stroke:#8E44AD,color:#fff
    style Principles fill:#27AE60,stroke:#1E8449,color:#fff
```

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

## 17. Interview Tips — Secure Hashing & Metadata Pipeline

These interview-ready answers focus on post-processing, pipeline architecture, hashing, and zero-trust concepts. Module 2 is rich territory for system design and security interview questions.

### 17.1 "What happens after a secret is detected?"

> **Interview Tip**: "Detection is only step one. CredVigil runs every finding through a 5-stage post-processing pipeline: SHA-256 hashing, smart redaction, metadata enrichment, fingerprint generation, and raw-secret sanitization. The pipeline follows the Chain of Responsibility pattern — each processor transforms the finding and passes it to the next stage."

### 17.2 "Why SHA-256 and not MD5 or SHA-1?"

> **Interview Tip**: "MD5 has known collision attacks — two different inputs can produce the same hash. SHA-1 was broken by Google's SHAttered attack in 2017. SHA-256 has no known practical attacks and produces a 256-bit digest (64 hex characters). For secret fingerprinting, collision resistance is critical — if two different secrets produce the same hash, you'd incorrectly deduplicate them."

### 17.3 "What is the Processor Interface pattern?"

> **Interview Tip**: "Each pipeline stage implements a single interface: `Process(finding) -> finding`. This is the Strategy pattern combined with Chain of Responsibility. New processors can be added without modifying existing ones — the Open/Closed Principle in action. For example, we can add a VerificationProcessor that checks if a secret is still live, without touching the hash or redaction logic."

### 17.4 "How do you ensure the raw secret is never leaked?"

> **Interview Tip**: "The SanitizeProcessor is always the last stage in the pipeline. It calls `ClearRawMatch()` which first generates the redacted preview, then permanently sets `RawMatch` to empty string. After this point, no code — not even CredVigil itself — can access the original secret. The SHA-256 hash is the only trace, and hashes are one-way functions — you can't reverse them."

### 17.5 "Explain idempotency in your pipeline"

> **Interview Tip**: "Every processor is idempotent — running it twice produces the same result as running it once. SHA-256 of the same input always gives the same hash. Redacting an already-redacted string is a no-op. This matters because in distributed systems, messages can be delivered more than once. Idempotent processors mean duplicate processing is harmless."

### 17.6 "How does fingerprinting work for deduplication?"

> **Interview Tip**: "The fingerprint is SHA-256 of three things concatenated: rule_id + source_location + secret_hash. This means the same secret detected by the same rule at the same location always gets the same fingerprint, even across different scan runs. This enables cross-scan deduplication and trend tracking — you can tell if a finding is new or was seen in yesterday's scan."

### 17.7 "What is enrichment and why does it matter?"

> **Interview Tip**: "The EnrichProcessor adds contextual metadata that humans need for triage: file type (is it a .py file or a .env?), environment detection (is the file path under /production/ or /staging/?), and category grouping (is this a cloud credential, a database password, or an auth token?). Without enrichment, every finding is just a regex match with no actionable context."

### 17.8 "How does your pipeline handle errors?"

> **Interview Tip**: "Partial failure tolerance. If processor stage 3 fails on finding #47 out of 100, findings #1-46 and #48-100 are still processed and delivered. The failed finding is dropped and the error is recorded. This is critical for production reliability — a malformed input shouldn't crash the entire pipeline. We follow the same principle as Erlang's 'let it crash' philosophy but at the finding level, not the process level."

### 17.9 "Why is the pipeline composable?"

> **Interview Tip**: "You can insert, remove, or reorder processors without changing any code in the pipeline itself. Want to add encryption? Insert an EncryptProcessor before Sanitize. Want to skip enrichment for speed? Remove the EnrichProcessor. The pipeline just iterates through whatever processors are registered. This is the Plugin pattern — the pipeline is the framework, processors are the plugins."

### 17.10 "What is smart redaction?"

> **Interview Tip**: "Our redaction preserves enough of the secret for humans to identify which key it is without exposing it. For secrets longer than 12 characters, we show the first 4 and last 4 characters: 'AKIA****MPLE'. For shorter secrets, first 2 characters plus asterisks. This lets a developer look at a finding and say 'Oh, that's the production AWS key for the billing service' without the key being usable by an attacker."

### 17.11 "How does your system handle the same secret in multiple files?"

> **Interview Tip**: "CredVigil reports each occurrence as a separate finding with its own source location, but they share the same secret_hash since they're the same underlying secret. The fingerprint is different because location is part of the fingerprint formula. This lets you answer two questions: 'How many unique secrets are leaked?' (count unique secret_hashes) and 'How many places is each secret exposed?' (count findings per secret_hash)."

### 17.12 "What concurrency model does the pipeline use?"

> **Interview Tip**: "The pipeline uses sync.RWMutex for thread-safe processor registration. Multiple goroutines can process findings concurrently (read lock), while processor registration requires an exclusive write lock. Each finding is processed independently, so the pipeline is embarrassingly parallel — you can shard findings across worker pools with zero coordination overhead."

---

## 18. Marketing Tips — Secure Hashing & Metadata Pipeline

Detailed marketing content specifically about Component 2's differentiators: zero-trust output, pipeline architecture, and compliance-ready results.

### 18.1 Positioning Statement

> **Marketing Copy**: "CredVigil is the only secret scanner whose output is safe to store, transmit, and share. Raw secrets never appear in scan results — only SHA-256 hashes and smart redacted previews. Your CI/CD logs, SIEM, and Slack alerts stay clean."

### 18.2 The Problem Statement (For Landing Page — Pipeline Section)

**Headline**: "Your secret scanner is leaking secrets."

**Subheadline**: "Most scanners put the actual API key right in the output JSON. That means your CI logs, Slack alerts, Jira tickets, and SIEM dashboards now contain the secret you're trying to protect. CredVigil's zero-trust pipeline ensures the raw secret never leaves the scanning process."

**Visual**: A before/after comparison showing a typical scanner's output with `"match": "AKIAIOSFODNN7EXAMPLE"` vs CredVigil's `"secret_hash": "a3f2...", "redacted_match": "AKIA****MPLE"`.

### 18.3 Feature-Benefit Matrix (Pipeline-Specific)

| Feature | Benefit | What to Say |
|---------|---------|-------------|
| SHA-256 hashing | Track secrets without storing them | "We fingerprint secrets cryptographically. You can track, deduplicate, and audit without ever seeing the raw value" |
| Smart redaction | Identify without exposing | "Developers know WHICH key leaked — 'AKIA****MPLE' — without the key being exploitable" |
| Metadata enrichment | Actionable context | "Every finding includes file type, environment, category, and severity — your team triages in seconds, not hours" |
| Cross-scan fingerprinting | Trend tracking | "Is this secret new or was it in yesterday's scan? Fingerprints give you drift detection for free" |
| Composable pipeline | Extensibility | "Add custom processing stages — encryption, webhook notification, SIEM forwarding — without modifying core code" |
| Raw secret sanitization | Compliance | "SOC2 auditors love us. The scan output itself passes a security review because it contains no sensitive data" |

### 18.4 Compliance & Audit Messaging

**For SOC2 / ISO 27001 / PCI-DSS conversations:**

> "CredVigil's pipeline was designed for compliance from day one. Three key properties make it audit-friendly:
> 1. **Secret non-retention**: Raw secrets are hashed and cleared in-memory. Scan results contain only hashes and redacted previews.
> 2. **Deterministic fingerprinting**: Every finding has a reproducible fingerprint. An auditor can re-run the same scan and verify the same fingerprint — proving the finding is real.
> 3. **Full metadata trail**: Every finding includes scan ID, scanner version, config hash, timestamp, and source location. This is the audit trail auditors need."

### 18.5 Competitor Comparison Points

**vs TruffleHog output:**
> "Run TruffleHog and look at the JSON. The raw secret is right there in the `rawV2` field. Now imagine that output goes to your CI log, your Slack channel, your Jira ticket. You just created 4 new places where the secret is exposed. CredVigil outputs `secret_hash` and `redacted_match` — safe to store everywhere."

**vs GitLeaks output:**
> "GitLeaks puts the secret in the `Secret` field of its JSON output. Their documentation explicitly says 'the actual secret.' CredVigil's zero-trust pipeline means even we don't keep the secret after processing."

### 18.6 Blog Post Ideas (Pipeline-Specific)

| # | Title | Hook |
|---|-------|------|
| 1 | **"Your Secret Scanner's Output Is a Security Vulnerability"** | Expose how most scanners leak secrets in their own output |
| 2 | **"SHA-256 for Secret Tracking: How to Fingerprint Without Exposing"** | Technical deep-dive with code examples |
| 3 | **"Building a Zero-Trust Pipeline in 500 Lines of Go"** | Open-source engineering blog — show pipeline architecture |
| 4 | **"Why Smart Redaction Beats Full Masking"** | UX angle — 'AKIA****MPLE' is more useful than '********' |
| 5 | **"From Detection to SIEM: How CredVigil's Pipeline Feeds Your SOC"** | Enterprise integration use case |
| 6 | **"The Composable Processor Pattern: Plugin Architecture for Security Tools"** | Architecture blog for the developer community |

### 18.7 Social Media Copy (Pipeline-Focused)

**LinkedIn Post:**
> 🔒 Hot take: Your secret scanner is probably leaking secrets.
>
> I just checked the output of three popular scanners. All three put the actual API key in their JSON output.
>
> That means your CI logs now contain the secret. Your Slack alerts contain the secret. Your Jira tickets contain the secret.
>
> CredVigil's approach: SHA-256 hash + smart redaction. The output shows "AKIA****MPLE" — enough to identify which key, useless for exploitation.
>
> Zero-trust doesn't stop at network architecture. Your tooling output matters too.
>
> #zerotrust #devsecops #appsec #credvigil

**Twitter/X Thread:**
> 🧵 Most secret scanners have a dirty secret of their own:
>
> They put the actual leaked credential IN THEIR OWN OUTPUT.
>
> Your CI log? Now contains the secret.
> Your Slack alert? Contains the secret.
> Your SIEM? Contains the secret.
>
> We fixed this. Here's how ↓

### 18.8 Demo Script (For Live Presentations)

> **Step 1**: "Let me run a competitor on this test repo. Look at the output... there's the raw AWS key, right in the JSON."
>
> **Step 2**: "Now let me run CredVigil on the same repo. Same finding, same file, same line number. But look at the output: `secret_hash: a3f2...`, `redacted_match: AKIA****MPLE`. The actual key? Gone. Permanently cleared from memory."
>
> **Step 3**: "Both tools found the secret. Only one is safe to put in your CI log."

### 18.9 Enterprise Sales Talking Points

> **For CISOs**: "CredVigil's zero-trust pipeline means your secret scanning program doesn't create new exposure surfaces. The scan results are safe to store in your SIEM, safe to forward to Jira, safe to post in Slack. No secondary leak risk."
>
> **For Compliance Officers**: "Every finding includes a scan ID, scanner version, config hash, and timestamp. This is the tamper-evident audit trail your SOC2 assessor needs. Re-run the scan, get the same fingerprints — proving findings are reproducible."
>
> **For Engineering Leads**: "The pipeline is extensible. Your team can add custom processors — maybe a Jira ticket creator, a PagerDuty alerter, or a secret rotation trigger — without forking the project. It follows the Open/Closed Principle."

### 18.10 Elevator Pitch (Pipeline-Specific, 15 Seconds)

> "CredVigil is the only secret scanner whose output itself passes a security review. Raw secrets are SHA-256 hashed and redacted before they leave the scanning process. Your CI logs stay clean."

---

## 19. What's Next?

You've now learned how CredVigil post-processes detected secrets through a composable, zero-trust pipeline. In the next module, we'll build **Component 3: Git Integration Layer**, which will enable:

- Scanning git commit history for secrets that were committed and later deleted
- Blame analysis to identify who introduced a secret
- Branch-aware scanning
- Pull request diff scanning

Continue to [Module 3: Git Integration Layer](03-git-integration-layer.md) (coming soon).

---

*CredVigil — Your watchful guard against leaked credentials.*

*Copyright 2026 CredVigil Contributors. Licensed under Apache License 2.0.*
