# CredVigil — How It All Works (A Simple Guide)

> **No tech background needed.** This guide explains CredVigil's complete system using everyday language and step-by-step diagrams. Think of it as the "explain it to me like I'm five" version of our system design.

---

## Table of Contents

1. [What Is CredVigil? (30-Second Explanation)](#1-what-is-credvigil-30-second-explanation)
2. [The Five Building Blocks](#2-the-five-building-blocks)
3. [A Day in the Life: Following One Secret](#3-a-day-in-the-life-following-one-secret)
4. [Building Block 1: The Detective (Detection Engine)](#4-building-block-1-the-detective-detection-engine)
5. [Building Block 2: The Clean-Up Crew (Pipeline)](#5-building-block-2-the-clean-up-crew-pipeline)
6. [Building Block 3: The Historian (Git Integration)](#6-building-block-3-the-historian-git-integration)
7. [Building Block 4: The Security Camera (File Watcher)](#7-building-block-4-the-security-camera-file-watcher)
8. [Building Block 5: The Radio Station (Event Bus)](#8-building-block-5-the-radio-station-event-bus)
9. [How All Five Work Together](#9-how-all-five-work-together)
10. [The Complete Journey — From File Save to Alert](#10-the-complete-journey--from-file-save-to-alert)
11. [Key Design Decisions (And Why We Made Them)](#11-key-design-decisions-and-why-we-made-them)
12. [Summary — The Whole System on One Page](#12-summary--the-whole-system-on-one-page)

---

## 1. What Is CredVigil? (30-Second Explanation)

Imagine you're a developer. You accidentally leave your house key inside a book you lend to a friend. Now your friend — and anyone who borrows the book from them — has your house key. That's what happens when developers accidentally put passwords and secret keys inside their code.

**CredVigil is a guard that checks your code for accidentally left-behind secrets — and alerts you before anyone else finds them.**

```mermaid
flowchart LR
    DEV["👨‍💻 Developer\nwrites code"] --> CODE["📄 Code with\na secret hidden inside"]
    CODE --> CV["🔍 CredVigil\nchecks the code"]
    CV --> SAFE["✅ Alert!\n'You left a password\non line 42'"]

    style CV fill:#51cf66,color:white
    style SAFE fill:#e8f5e9
```

---

## 2. The Five Building Blocks

CredVigil is built from five pieces, like five departments in a security company:

```mermaid
flowchart TB
    subgraph SYSTEM["🏢 CredVigil Security Company"]
        direction TB
        B1["🔍 Block 1: The Detective\nFinds secrets in code\n(Detection Engine)"]
        B2["🧹 Block 2: The Clean-Up Crew\nProtects found secrets\n(Pipeline)"]
        B3["📚 Block 3: The Historian\nChecks old versions of code\n(Git Integration)"]
        B4["📹 Block 4: The Security Camera\nWatches files in real-time\n(File Watcher)"]
        B5["📻 Block 5: The Radio Station\nLets departments talk to each other\n(Event Bus)"]
    end

    style B1 fill:#ff6b6b,color:white
    style B2 fill:#51cf66,color:white
    style B3 fill:#339af0,color:white
    style B4 fill:#ffd43b,color:black
    style B5 fill:#cc5de8,color:white
```

| Block | Everyday Name | What It Does | Real-World Analogy |
|-------|--------------|-------------|-------------------|
| 1 | The Detective | Finds secrets in code | A detective comparing fingerprints to a database |
| 2 | The Clean-Up Crew | Protects the secrets it finds | A bank showing `****1234` instead of your full card number |
| 3 | The Historian | Checks old code history | A librarian going through old newspapers looking for clues |
| 4 | The Security Camera | Watches files as they change | A live security camera that alerts when something happens |
| 5 | The Radio Station | Lets all blocks communicate | A radio station broadcasting news to all departments |

---

## 3. A Day in the Life: Following One Secret

Let's follow a real example. A developer named Alex accidentally puts an AWS password in a file called `config.env`:

```
# config.env
DATABASE_URL=localhost:5432
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY    ← This is the secret!
APP_NAME=my-cool-app
```

Here's what happens, step by step:

```mermaid
flowchart TB
    SAVE["1️⃣ Alex saves config.env\nwith a secret inside"]
    CAMERA["2️⃣ Security Camera notices\n'Hey, config.env just changed!'"]
    RADIO["3️⃣ Radio Station broadcasts\n'Attention everyone:\nconfig.env was modified!'"]
    DETECTIVE["4️⃣ Detective checks the file\n'I found an AWS key on line 3!'"]
    CLEANUP["5️⃣ Clean-Up Crew protects it\n'I'll hide the real key\nand just show wJal****EKEY'"]
    ALERT["6️⃣ Alert shown to Alex\n'⚠️ AWS Secret Key found\nin config.env, line 3'"]

    SAVE --> CAMERA --> RADIO --> DETECTIVE --> CLEANUP --> ALERT

    style SAVE fill:#ff6b6b,color:white
    style CAMERA fill:#ffd43b,color:black
    style RADIO fill:#cc5de8,color:white
    style DETECTIVE fill:#ff6b6b,color:white
    style CLEANUP fill:#51cf66,color:white
    style ALERT fill:#e8f5e9
```

**Total time: about 3 milliseconds.** Alex gets warned before even opening a web browser.

Let's look at each block in detail.

---

## 4. Building Block 1: The Detective (Detection Engine)

### What Does the Detective Do?

The Detective reads through code and looks for anything that looks like a password, API key, or secret token. It uses **three methods** — like a real detective uses fingerprints, behavior profiling, and forensic analysis together.

### Method 1: Known Pattern Matching (369 "Wanted Posters")

The Detective has a book of 369 patterns — each one describes exactly what a specific type of secret looks like.

```mermaid
flowchart LR
    subgraph BOOK["📖 Pattern Book (369 Patterns)"]
        P1["AWS Key:\nStarts with 'AKIA'\nfollowed by 16 characters"]
        P2["GitHub Token:\nStarts with 'ghp_'\nfollowed by 36 characters"]
        P3["Stripe Key:\nStarts with 'sk_live_'\nfollowed by characters"]
    end

    CODE["Code to check:\nAKIAIOSFODNN7EXAMPLE"] --> MATCH{"Does it match\nany pattern?"}
    MATCH -->|"Yes! Matches\nAWS Key pattern"| FOUND["🚨 Secret Found!"]
    MATCH -->|"No match"| NEXT["Check Method 2"]

    style FOUND fill:#ff6b6b,color:white
    style BOOK fill:#e3f2fd
```

**Example:**
- The code contains `AKIAIOSFODNN7EXAMPLE`
- Pattern #47 says: "AWS keys start with AKIA followed by 16 characters"
- Match! This looks like an AWS key.

### Method 2: Randomness Detection (The "Gut Feeling")

Some secrets don't follow known patterns. The Detective also checks if a string "looks too random to be normal code."

```mermaid
flowchart LR
    subgraph EXAMPLES["Examples"]
        NORMAL["'hello world'\nRandomness: LOW ✅\nThis is normal text"]
        SUSPICIOUS["aB3xkL9zmN2wpP7\nRandomness: HIGH 🚨\nThis looks like a password!"]
    end

    style NORMAL fill:#e8f5e9
    style SUSPICIOUS fill:#fff3e0
```

**How it works in everyday terms:**

Think about license plates. The plate `AAA-0000` has low randomness — it's a simple pattern. The plate `xK3$mQ9z` has high randomness — it looks like someone mashed the keyboard. Passwords and API keys look like keyboard mashing. Normal code doesn't.

### Method 3: Compression Resistance (The "Packing Test")

This method asks: **"Can we compress this string efficiently?"**

Normal text is full of common letter pairs like `th`, `he`, `in`, `er`, `on`. A smart compressor (called BPE — Byte Pair Encoding) can merge these pairs and shrink the text. Secrets are random — they have no common pairs, so they can't be compressed.

```mermaid
flowchart LR
    subgraph NORMAL["Normal Text"]
        N1["'the function returns'\n20 characters -> 13 tokens\nEfficiency: 1.54\nCompresses well! ✅"]
    end
    subgraph SECRET["Secret"]
        S1["'kJ9mN2pR5tW8xY7'\n16 characters -> 16 tokens\nEfficiency: 1.0\nCannot compress! 🚨"]
    end

    style NORMAL fill:#e8f5e9
    style SECRET fill:#fff3e0
```

**Analogy:** Imagine packing a suitcase. Neatly folded regular clothes (normal text) pack tightly. A bag of random screws and bolts (a secret) takes up way more space because nothing fits together. BPE measures how well text "packs."

**Why three methods instead of two?**

| Method | What It Checks | Strength | Weakness |
|--------|---------------|----------|----------|
| **Pattern Matching** | Known formats (AKIA..., ghp_...) | Very accurate for known secrets | Cant find unknown formats |
| **Randomness** | Character frequency distribution | Catches unknown secrets | Can be fooled by even distributions |
| **Compression** | Resistance to BPE compression | Independent signal, catches edge cases | Needs cross-validation |

When all three methods agree, CredVigil is **very confident**. When they disagree, it lowers the confidence score.

### Confidence Scoring: "How Sure Are We?"

The Detective doesn't just say "yes or no." It says **how confident** it is, from 0% to 100%:

```mermaid
flowchart LR
    subgraph FACTORS["What Affects Confidence"]
        F1["✅ Matches a known pattern\n+50% confidence"]
        F2["✅ High randomness\n+15% confidence"]
        F3["✅ Resists compression\n+8% confidence"]
        F4["✅ Near words like 'password'\n+10% confidence"]
        F5["✅ Both randomness AND compression agree\n+15% confidence"]
        F6["❌ Contains 'EXAMPLE' or 'test'\n-30% confidence"]
    end

    RESULT["Final Score:\n50 + 15 + 8 + 10 + 15 - 0 = 98%\nVery confident!"]

    style F1 fill:#e8f5e9
    style F2 fill:#e8f5e9
    style F3 fill:#e8f5e9
    style F4 fill:#e8f5e9
    style F5 fill:#e8f5e9
    style F6 fill:#fff3e0
    style RESULT fill:#51cf66,color:white
```

**Why this matters:** If a string matches the AWS key pattern AND has high randomness AND resists compression AND is near the word "secret," we're very confident. If a string matches but contains the word "EXAMPLE," we're less confident — it's probably just documentation, not a real leak.

### Activity: How the Detective Processes One File

```mermaid
flowchart TB
    START["📄 Receive a file\n(config.env)"] --> READ["Read line by line"]
    READ --> LINE["Line 3:\nAWS_SECRET_KEY=wJal...KEY"]
    LINE --> REGEX{"Does it match\nany of the 369\npatterns?"}
    REGEX -->|"Yes!\nRule: aws-secret-key"| SCORE["Calculate confidence\nBase: 50%\n+ Randomness: +15%\n+ Compression: +8%\n+ Near 'KEY': +10%\n= 83%"]
    REGEX -->|"No match"| ENTROPY{"Is the randomness\nhigher than 4.0?"}
    ENTROPY -->|"Yes"| BPE{"Does it resist\nBPE compression?"}
    ENTROPY -->|"No"| BPE2{"Does it resist\nBPE compression?"}
    BPE -->|"Yes"| SCORE2["Report as\nhigh-confidence finding\n(both methods agree +15%)"]
    BPE -->|"No"| SCORE3["Report as\nentropy-only finding"]
    BPE2 -->|"Yes"| SCORE4["Report as\nBPE-only finding"]
    BPE2 -->|"No"| CLEAN["Nothing suspicious\non this line ✅"]
    SCORE --> REPORT["🚨 Report Finding:\nAWS Secret Key\nLine 3, 83% confidence\nSeverity: CRITICAL"]

    style START fill:#e3f2fd
    style REPORT fill:#ff6b6b,color:white
    style CLEAN fill:#e8f5e9
```

---

## 5. Building Block 2: The Clean-Up Crew (Pipeline)

### What's the Problem?

The Detective found a secret: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`. But we can't just show this to people — that would be like a security guard finding a lost credit card and announcing the card number over the loudspeakers!

### The 5-Step Assembly Line

The Clean-Up Crew processes every finding through 5 stations, like a factory assembly line:

```mermaid
flowchart LR
    SECRET["🔴 Raw Secret\nwJalrXUtnFEMI/K7MD\nENG/bPxRfiCYEXAMPLEKEY"]
    H["1️⃣ HASH IT\nCreate a fingerprint\na3f2...c9d1"]
    R["2️⃣ MASK IT\nHide the middle\nwJal****EKEY"]
    E["3️⃣ ENRICH IT\nAdd context\nType: AWS Key\nCategory: Cloud"]
    F["4️⃣ FINGERPRINT IT\nCreate a tracking ID\nfor deduplication"]
    S["5️⃣ ERASE IT\nDelete the raw secret\nfrom memory forever"]

    SECRET --> H --> R --> E --> F --> S

    SAFE["✅ Safe Output\nOnly hash + mask remain\nReal secret is GONE"]
    S --> SAFE

    style SECRET fill:#ff6b6b,color:white
    style S fill:#51cf66,color:white
    style SAFE fill:#e8f5e9
```

### What Each Station Does (With the AWS Key Example)

**Station 1 — Hash It (Create a Fingerprint)**

> Like taking a fingerprint of the secret. The fingerprint is unique to this specific secret, but you can't recreate the secret from the fingerprint.
>
> Input: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`  
> Output: `a3f2b1d4...c9d1` (a unique fingerprint)

**Station 2 — Mask It (Hide the Middle)**

> Like how your bank shows `****1234` on receipts. We show just enough to identify which credential it is, but not enough to use it.  
>
> Input: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`  
> Output: `wJal****EKEY`

**Station 3 — Enrich It (Add Context)**

> Add helpful labels. What kind of secret? What category? What type of file was it found in?
>
> Added: `Type: AWS Key`, `Category: Cloud`, `File Type: .env`

**Station 4 — Fingerprint It (Tracking ID)**

> Create a stable ID so we can track this finding across multiple scans. If we scan the same code tomorrow, we recognize it's the same finding.

**Station 5 — Erase It (Delete the Raw Secret)**

> The most important step. We permanently delete the raw secret from memory. After this, even CredVigil itself can't access the original secret anymore.
>
> Before: `RawMatch: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`  
> After: `RawMatch: ""` (empty — gone forever)

### Why Is Erasing So Important?

```mermaid
flowchart LR
    subgraph BAD["❌ Without Erasing"]
        B1["Scan output contains\nreal secret"] --> B2["Output gets logged\nin CI/CD system"] --> B3["Hacker reads logs\nand steals the key! 😱"]
    end

    subgraph GOOD["✅ With Erasing"]
        G1["Scan output contains\nonly wJal****EKEY"] --> G2["Output gets logged\nin CI/CD system"] --> G3["Hacker reads logs\nbut only sees ****\nUseless! 🎉"]
    end

    style BAD fill:#ffe0e0
    style GOOD fill:#e8f5e9
    style B3 fill:#ff6b6b,color:white
    style G3 fill:#51cf66,color:white
```

---

## 6. Building Block 3: The Historian (Git Integration)

### What's the Problem?

Imagine Alex committed a password to the code repository last Tuesday, then deleted it on Wednesday. The password is gone from the *current* code — but it's still sitting in the git history. Anyone who looks at Tuesday's version can see it.

**Deleting a secret from your code doesn't delete it from history.**

```mermaid
flowchart LR
    subgraph HISTORY["📚 Git History Timeline"]
        MON["Monday\n✅ Clean code"]
        TUE["Tuesday\n🔴 Password added"]
        WED["Wednesday\n✅ Password removed"]
        THU["Today\n✅ Code looks clean"]
    end

    MON --> TUE --> WED --> THU

    HACKER["🕵️ Hacker checks\nTuesday's version"] --> TUE
    TUE -->|"Password\nstill visible!"| STOLEN["😱 Secret stolen"]

    style TUE fill:#ff6b6b,color:white
    style STOLEN fill:#ff6b6b,color:white
```

### How the Historian Works

The Historian goes through every version (commit) of your code, one by one, looking for secrets that were ever added:

```mermaid
flowchart TB
    START["📚 Open the\ncode repository"] --> LIST["List all versions\n(commits) in history"]
    LIST --> LOOP["For each version..."]
    LOOP --> DIFF["What changed\nin this version?"]
    DIFF --> ADDED{"Were any new\nlines added?"}
    ADDED -->|"Yes"| CHECK["Send added lines\nto The Detective\n(Building Block 1)"]
    ADDED -->|"No"| SKIP["Skip this version"]
    CHECK --> FOUND{"Secrets\nfound?"}
    FOUND -->|"Yes"| PIPELINE["Send to Clean-Up Crew\n(Building Block 2)"]
    FOUND -->|"No"| NEXT["Move to\nnext version"]
    PIPELINE --> NEXT
    SKIP --> NEXT
    NEXT --> MORE{"More\nversions?"}
    MORE -->|"Yes"| LOOP
    MORE -->|"No"| DONE["📋 Done!\nAll history checked"]

    style START fill:#e3f2fd
    style CHECK fill:#ff6b6b,color:white
    style PIPELINE fill:#51cf66,color:white
    style DONE fill:#e8f5e9
```

### Example: Scanning Alex's Repository

```
Repository has 500 commits (versions).

Version 1: Created project          → Nothing suspicious
Version 2: Added login page         → Nothing suspicious
...
Version 247: Added config.env       → 🚨 AWS key found on line 3!
Version 248: Removed config.env     → Nothing new (only deleted lines)
...
Version 500: Latest version         → Nothing suspicious

Result: 1 secret found, introduced in version 247
```

### Why Only Check Added Lines?

> If a line was **removed**, we don't care — we'll catch it when we check the version where that line was **added**. This cuts the work in half!

---

## 7. Building Block 4: The Security Camera (File Watcher)

### What's the Problem?

The Detective and the Historian work when you **ask** them to scan. But what if Alex saves a file with a secret at 10:00 AM and doesn't run a scan until 3:00 PM? That's 5 hours of the secret sitting there.

The Security Camera watches files **in real-time** — the moment you save a file, it checks for secrets.

### How It Works

```mermaid
flowchart TB
    SAVE["💾 Alex saves\nconfig.env"] --> OS["💻 Operating System notices\n'config.env was modified'"]
    OS --> WATCHER["📹 Security Camera\nreceives notification"]
    WATCHER --> SKIP{"Should we\nskip this file?"}
    SKIP -->|"Yes (it's in .git/\nor is a binary file)"| IGNORE["🟢 Ignore it"]
    SKIP -->|"No, check it!"| DEBOUNCE{"Have we already\nchecked this file\nin the last\nhalf second?"}
    DEBOUNCE -->|"Yes, we just\nchecked it"| IGNORE2["🟢 Skip\n(avoid double-checking)"]
    DEBOUNCE -->|"No, it's been\na while"| TRIGGER["🔍 Send to\nThe Detective!"]

    style SAVE fill:#ffd43b
    style TRIGGER fill:#ff6b6b,color:white
    style IGNORE fill:#e8f5e9
    style IGNORE2 fill:#e8f5e9
```

### Why "Debounce"? (The Half-Second Buffer)

When you press "Save" in your code editor, the operating system actually fires 3–5 separate events (write temp file, rename, update permissions...). Without the half-second buffer, we'd scan the same file 3–5 times for one save!

```mermaid
flowchart LR
    subgraph WITHOUT["❌ Without Debounce"]
        W1["Event 1: Scan!"]
        W2["Event 2: Scan again!"]
        W3["Event 3: Scan AGAIN!"]
    end

    subgraph WITH["✅ With Debounce"]
        D1["Event 1: Scan!"]
        D2["Event 2: Skip\n(only 10ms later)"]
        D3["Event 3: Skip\n(only 20ms later)"]
    end

    style WITHOUT fill:#ffe0e0
    style WITH fill:#e8f5e9
```

**Result:** 1 scan instead of 3. Same coverage, one third the work.

### The Speed Difference

```mermaid
flowchart LR
    subgraph BEFORE["❌ Without Security Camera"]
        A1["10:00 AM\nSecret saved"] --> A2["3:00 PM\nManual scan runs"] --> A3["3:00 PM\nSecret detected"]
        A1 -.->|"5 hours of exposure!"| A3
    end

    subgraph AFTER["✅ With Security Camera"]
        B1["10:00 AM\nSecret saved"] --> B2["10:00 AM\n3ms later —\nSecret detected!"]
    end

    style A1 fill:#ff6b6b,color:white
    style A2 fill:#ff6b6b,color:white
    style B2 fill:#51cf66,color:white
```

---

## 8. Building Block 5: The Radio Station (Event Bus)

### What's the Problem?

In the original design, every block talked directly to the next one — like making phone calls:

```mermaid
flowchart LR
    subgraph PHONE["📞 Phone Calls (Direct)"]
        W["Camera"] -->|"calls"| D["Detective"]
        D -->|"calls"| C["Clean-Up"]
        C -->|"calls"| R["Report"]
    end

    style PHONE fill:#fff3e0
```

This works for 4 blocks, but imagine when we have 15 blocks. Each block would need to know about every other block. Adding a new block means changing all the existing ones. That's a mess.

### The Solution: A Radio Station

Instead of phone calls (1-to-1), we set up a **radio station** (1-to-many). Blocks **broadcast** their news on a channel, and any block that cares can **tune in**.

```mermaid
flowchart TB
    subgraph RADIO["📻 Radio Station (Event Bus)"]
        direction LR
        CH1["Channel:\nfile.changed"]
        CH2["Channel:\nfinding.detected"]
        CH3["Channel:\nscan.completed"]
        CH4["Channel:\nerror"]
    end

    W["📹 Camera\nbroadcasts on\nfile.changed"] --> CH1
    CH1 --> D["🔍 Detective\ntunes into\nfile.changed"]
    D -->|"broadcasts on"| CH2
    CH2 --> C["🧹 Clean-Up\ntunes into\nfinding.detected"]
    CH2 --> L["📝 Logger\ntunes into\nfinding.detected"]
    CH2 --> S["🔔 Slack Alert\ntunes into\nfinding.detected"]

    style RADIO fill:#f3e5f5
    style W fill:#ffd43b,color:black
    style D fill:#ff6b6b,color:white
    style C fill:#51cf66,color:white
```

### Why Is This Better?

```mermaid
flowchart LR
    subgraph OLD["❌ Before: Adding Slack Alerts"]
        O1["Change the Detective code\nto call Slack"] --> O2["Change the Clean-Up code\nto call Slack"] --> O3["Change everything 😰"]
    end

    subgraph NEW["✅ After: Adding Slack Alerts"]
        N1["Just tune into\nfinding.detected\non the radio"] --> N2["Done! 🎉\nNothing else changes"]
    end

    style OLD fill:#ffe0e0
    style NEW fill:#e8f5e9
```

**Adding a new feature = just subscribing to a radio channel. Zero changes to existing code.**

### The 10 Radio Channels

| Channel Name | What Gets Broadcast | Who Listens |
|-------------|--------------------|----|
| `file.changed` | "A file was just modified!" | The Detective |
| `scan.started` | "A scan is beginning!" | Logger, Dashboard |
| `scan.completed` | "A scan just finished!" | Logger, Dashboard |
| `finding.detected` | "A secret was found!" | Clean-Up, Logger, Alerts |
| `finding.processed` | "A finding has been cleaned up!" | Report Generator |
| `git.scan.started` | "Git history scan starting!" | Logger |
| `git.scan.completed` | "Git history scan done!" | Logger, Dashboard |
| `git.commit.scanned` | "One commit was checked!" | Progress Bar |
| `error` | "Something went wrong!" | Logger, Alert System |
| `*` (everything) | ALL of the above | Audit Logger |

### The `*` Channel (The "Listen to Everything" Channel)

One special channel is `*` (the wildcard). Tuning into this channel means you hear **every single broadcast** on every channel. This is perfect for:

- **Audit logging** — Record everything that happens for compliance
- **Debugging** — See all events flowing through the system
- **Monitoring** — Count how many events happen per second

### What Happens When a Listener Is Too Slow?

Imagine the radio station broadcasts 100 messages per second, but one listener can only process 10 per second. The messages pile up!

CredVigil handles this with a **mailbox** (buffer). Each listener has a mailbox that can hold 256 messages. If the mailbox overflows, new messages for that slow listener are dropped — but all other listeners are unaffected.

```mermaid
flowchart LR
    RADIO["📻 Radio\n100 msgs/sec"] --> MAILBOX["📬 Mailbox\n256 slots"]
    MAILBOX --> LISTENER["🐌 Slow Listener\n10 msgs/sec"]
    MAILBOX -->|"Mailbox full!"| DROP["❌ Message dropped\n(counter goes up)"]

    FAST["🐇 Fast Listener\n200 msgs/sec"] --> OK["✅ No problem!"]
    RADIO --> FAST

    style DROP fill:#ff6b6b,color:white
    style OK fill:#e8f5e9
```

**Key point:** One slow listener never slows down anyone else. And we **count** how many messages are dropped, so we know when there's a problem.

### Event Bus Stats (Built-In Health Check)

The radio station keeps a scoreboard:

```
📊 Event Bus Status:
  Messages sent:      142
  Messages delivered:  425  (higher because one message → multiple listeners)
  Messages dropped:    3    (3 messages were lost to a slow listener)
  Active listeners:    5
  Busiest channel:     file.changed (87 messages)
```

If the "dropped" number starts climbing, that's a signal: one of the listeners needs to be faster, or its mailbox needs to be bigger.

---

## 9. How All Five Work Together

Here's the complete picture — all five building blocks working as a team:

```mermaid
flowchart TB
    subgraph INPUT["📥 How Secrets Enter the System"]
        FILE["📁 Scan a file\nor folder"]
        GIT["📚 Scan git\nhistory"]
        WATCH["📹 File changes\nin real-time"]
    end

    subgraph BUS["📻 Radio Station (Event Bus)"]
        FC["file.changed"]
        GS["git.scan.*"]
        FD["finding.detected"]
        FP["finding.processed"]
    end

    subgraph DETECTION["🔍 The Detective"]
        REGEX["369 known\npatterns"]
        ENTROPY["Randomness\ncheck"]
    end

    subgraph PIPELINE["🧹 The Clean-Up Crew"]
        HASH["Hash"] --> MASK["Mask"] --> ENRICH["Enrich"] --> FPRINT["Fingerprint"] --> SANITIZE["Erase"]
    end

    subgraph OUTPUT["📤 Results"]
        ALERT["⚠️ Alert:\nSecret found!\nwJal****EKEY\nLine 3, config.env"]
    end

    WATCH --> FC
    FILE --> REGEX
    GIT --> GS
    GS --> REGEX
    FC --> REGEX
    REGEX --> FD
    ENTROPY --> FD
    FD --> HASH
    SANITIZE --> FP
    FP --> ALERT

    style BUS fill:#f3e5f5
    style DETECTION fill:#ffe0e0
    style PIPELINE fill:#e8f5e9
    style OUTPUT fill:#e3f2fd
```

### The Communication Flow

```
📹 Camera spots a change → broadcasts "file.changed" on the radio
🔍 Detective hears "file.changed" → scans the file → finds a secret
🔍 Detective broadcasts "finding.detected" on the radio
🧹 Clean-Up Crew hears "finding.detected" → processes the finding
🧹 Clean-Up Crew broadcasts "finding.processed" on the radio
📝 Logger hears everything → writes to audit log
⚠️ Alert system hears "finding.detected" → sends notification
```

**No block calls another block directly. They all talk through the radio station.**

---

## 10. The Complete Journey — From File Save to Alert

Let's trace the complete path one more time with our example — Alex saving an AWS key in `config.env`. This time, every step:

```mermaid
flowchart TB
    A["1. 💾 Alex saves config.env\nContains: AWS_SECRET_KEY=wJal...KEY"]
    B["2. 💻 macOS tells CredVigil:\n'config.env was modified'"]
    C["3. 📹 Security Camera receives event\nChecks: Not in .git? ✅ Not binary? ✅\nDebounce: Fresh event? ✅"]
    D["4. 📻 Camera broadcasts:\nchannel 'file.changed'\npayload: '/app/config.env'"]
    E["5. 🔍 Detective hears 'file.changed'\nOpens config.env\nReads line by line"]
    F["6. 🔍 Line 1: DATABASE_URL=localhost\nNo match in 369 patterns ✅\nLow randomness ✅"]
    G["7. 🔍 Line 3: AWS_SECRET_KEY=wJal...KEY\n🚨 Pattern match: aws-secret-key!\nRandomness: 4.66 (high!)\nConfidence: 75%"]
    H["8. 📻 Detective broadcasts:\nchannel 'finding.detected'\npayload: Finding object"]
    I["9. 🧹 Clean-Up Crew hears 'finding.detected'\nStation 1: Hash → a3f2...c9d1\nStation 2: Mask → wJal****EKEY\nStation 3: Enrich → Type: AWS, Category: Cloud\nStation 4: Fingerprint → Tracking ID assigned\nStation 5: Erase → Raw secret DELETED"]
    J["10. 📻 Clean-Up broadcasts:\nchannel 'finding.processed'"]
    K["11. ⚠️ Alert displayed to Alex:\n[CRITICAL] AWS Secret Key\nFile: config.env:3\nMatch: wJal****EKEY\nConfidence: 75%"]

    A --> B --> C --> D --> E --> F --> G --> H --> I --> J --> K

    style A fill:#ff6b6b,color:white
    style G fill:#ff6b6b,color:white
    style I fill:#51cf66,color:white
    style K fill:#e3f2fd
```

### What Alex Sees on Screen

```
╔═══════════════════════════════════════════════════════════════╗
║                    CredVigil Scan Report                     ║
╚═══════════════════════════════════════════════════════════════╝

[CRITICAL] AWS Secret Access Key
  Rule:       aws-secret-access-key
  File:       config.env:3
  Match:      wJal****EKEY
  Entropy:    4.66
  Confidence: 75%
  SHA-256:    a3f2b1d4...c9d1

─────────────────────────────────────────────────────────────────
  Total findings: 1
  By severity: CRITICAL=1
─────────────────────────────────────────────────────────────────
```

**Notice:** The real secret (`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`) is nowhere in the output. Only the masked version (`wJal****EKEY`) and a fingerprint (`a3f2...c9d1`) are shown. The Clean-Up Crew did its job.

---

## 11. Key Design Decisions (And Why We Made Them)

### Decision 1: Three Detection Methods Instead of One

```mermaid
flowchart LR
    subgraph WHY["Why Three Methods?"]
        O["Only patterns?\nMisses new/custom secrets"]
        T["Only randomness?\nToo many false alarms"]
        C["Only compression?\nNeeds cross-validation"]
        B["All three together?\nBest of all worlds \u2705"]
    end

    style B fill:#e8f5e9
```

**Analogy:** Airport security uses metal detectors (known threats), behavioral analysis (suspicious behavior), AND luggage X-rays (hidden items). No single method catches everything — the combination provides the best security.

### Decision 2: Erase Secrets from Memory

**Why?** If our output contains the real secret, we're making the problem worse. Our output gets logged in CI/CD systems, shared on Slack, stored in databases. We erase the raw secret so that even if our output is compromised, the actual credential is safe.

### Decision 3: Event Bus Instead of Direct Calls

**Why?** We're building toward 15 components. If every component called every other component directly, we'd have a tangled mess. The event bus keeps things clean — adding a new component means just subscribing to the channels you care about.

### Decision 4: One Mailbox Per Listener (Backpressure)

**Why?** A slow audit logger shouldn't slow down the security alerts. Each listener gets its own mailbox. If one fills up, that listener's messages are dropped — but everyone else continues at full speed.

### Decision 5: Scan Only Added Lines in Git History

**Why?** If we scanned every line of every version, we'd do 10x more work with zero benefit. A removed line will be caught when we scan the version where it was first added.

---

## 12. Summary — The Whole System on One Page

### The Five Building Blocks

| # | Block | Analogy | One-Line Description |
|---|-------|---------|---------------------|
| 1 | Detection Engine | Detective | Finds secrets using 369 patterns + randomness + BPE compression analysis |
| 2 | Pipeline | Clean-Up Crew | Hashes, masks, and erases raw secrets for safe output |
| 3 | Git Integration | Historian | Scans every version of code in git history |
| 4 | File Watcher | Security Camera | Watches files in real-time, triggers scans instantly |
| 5 | Event Bus | Radio Station | Lets all blocks communicate without knowing about each other |

### How Data Flows

```
File saved → Camera notices → Radio broadcasts "file changed"
→ Detective scans → finds secret → Radio broadcasts "finding detected"
→ Clean-Up processes → erases raw secret → Radio broadcasts "finding processed"
→ Alert shown to user (with masked secret only)
```

### Key Numbers

| Metric | Value |
|--------|-------|
| Detection patterns | 369 |
| Secret types detected | 180+ |
| Pipeline stages | 5 (hash → mask → enrich → fingerprint → erase) |
| Event bus channels | 10 topics |
| Real-time detection speed | ~3 milliseconds |
| External dependencies | 1 (fsnotify for file watching) |
| Tests | 200+ across all components |

### The Core Promise

> **CredVigil finds secrets in your code — past and present — and never exposes them in its output. It detects in milliseconds, processes through a zero-trust pipeline, and communicates through a decoupled event system ready to scale to 15 components.**

---

*CredVigil — Your watchful guard against leaked credentials.*

*Copyright 2026 CredVigil Contributors. Licensed under the Apache License, Version 2.0.*
