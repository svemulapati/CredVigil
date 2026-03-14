# CredVigil Training Guide — Module 3: Git Integration Layer

> **Version**: 0.1.0  
> **Component**: Git Integration Layer (Component 3 of 15)  
> **Audience**: Everyone — no programming or IT background required. Written for learners preparing for interviews.  
> **Prerequisites**: Completion of Modules 1 and 2. Go 1.21+ and Git installed (for hands-on exercises only).

---

## Table of Contents

1. [What Is the Git Integration Layer?](#1-what-is-the-git-integration-layer)
2. [Why Do We Need Git History Scanning?](#2-why-do-we-need-git-history-scanning)
3. [Key Concepts Explained](#3-key-concepts-explained)
   - 3.1 [What Is Git?](#31-what-is-git)
   - 3.2 [What Is a Commit?](#32-what-is-a-commit)
   - 3.3 [What Is a Diff?](#33-what-is-a-diff)
   - 3.4 [What Is a Branch?](#34-what-is-a-branch)
   - 3.5 [What Is a Clone?](#35-what-is-a-clone)
   - 3.6 [What Is "Walking" Commit History?](#36-what-is-walking-commit-history)
   - 3.7 [What Is Incremental Scanning?](#37-what-is-incremental-scanning)
4. [Architecture Overview](#4-architecture-overview)
5. [The Five Source Files](#5-the-five-source-files)
   - 5.1 [git.go — Core Types](#51-gitgo--core-types)
   - 5.2 [clone.go — Repository Management](#52-clonego--repository-management)
   - 5.3 [diff.go — Diff Parser](#53-diffgo--diff-parser)
   - 5.4 [walker.go — Commit Walker](#54-walkergo--commit-walker)
   - 5.5 [scanner.go — Git Scanner Orchestrator](#55-scannergo--git-scanner-orchestrator)
6. [How It All Fits Together](#6-how-it-all-fits-together)
7. [The Scanning Flow Step by Step](#7-the-scanning-flow-step-by-step)
8. [CLI Usage for Git Scanning](#8-cli-usage-for-git-scanning)
9. [Understanding Git Scan Output](#9-understanding-git-scan-output)
10. [Hands-On Exercises](#10-hands-on-exercises)
11. [Deep Dive: Code Walkthrough](#11-deep-dive-code-walkthrough)
    - 11.1 [Core Types (git.go)](#111-core-types-gitgo)
    - 11.2 [Repository Management (clone.go)](#112-repository-management-clonego)
    - 11.3 [Diff Parser (diff.go)](#113-diff-parser-diffgo)
    - 11.4 [Commit Walker (walker.go)](#114-commit-walker-walkergo)
    - 11.5 [Scanner Orchestrator (scanner.go)](#115-scanner-orchestrator-scannergo)
12. [Security Considerations](#12-security-considerations)
13. [Performance & Scalability](#13-performance--scalability)
14. [Error Handling & Resilience](#14-error-handling--resilience)
15. [Frequently Asked Questions](#15-frequently-asked-questions)
16. [Glossary](#16-glossary)
17. [What's Next?](#17-whats-next)

---

## 1. What Is the Git Integration Layer?

In Modules 1 and 2, you learned how CredVigil scans **files** for secrets and then processes findings through a secure pipeline. But scanning only the current files misses a critical danger:

**Secrets that were committed and then deleted are still in the git history.**

The Git Integration Layer adds the ability to scan an entire repository's **commit history** — every change ever made — to find secrets that were introduced at any point, even if they were removed weeks or years ago.

### Real-World Analogy: The Security Camera Archive

Think of your codebase as a store. Scanning current files is like checking the store shelves *right now*. But what if someone placed something dangerous on a shelf last Tuesday and removed it on Wednesday? Looking at the shelves today won't help — you need to review the **security camera footage** (the git history).

```mermaid
flowchart LR
    subgraph TODAY["📸 Current Files Only"]
        A["Shelf looks clean"]
    end
    subgraph HISTORY["📹 Git History (Camera Footage)"]
        B["Mon: Added README"] --> C["Tue: Added API key ⚠️"]
        C --> D["Wed: Deleted API key"]
        D --> E["Thu: Added docs"]
    end
    style C fill:#ff6b6b,color:white
    style A fill:#51cf66,color:white
```

> **Key Insight**: Even though the shelf (current code) looks clean, the security footage (git history) reveals that a dangerous item (API key) was once there. Anyone who saw the footage (cloned the repo) still has access to it.

---

## 2. Why Do We Need Git History Scanning?

### The Problem

When a developer accidentally commits a secret:

1. They realize the mistake
2. They delete the secret from the file
3. They commit: "remove credentials"
4. They think the problem is solved ❌

**But the secret is still in the git history.** Anyone who clones the repository — including attackers — can see every version of every file that was ever committed.

### Real-World Analogy: Writing in Ink Books

Imagine writing a password on page 5 of a notebook. You tear out the page and throw it away. Problem solved? Not if someone photocopied the notebook before you tore the page. Git is like that photocopier — it keeps a perfect copy of every version of every page.

```mermaid
flowchart TB
    subgraph NOTEBOOK["📓 Git Repository"]
        V1["Version 1<br/>Added README"] 
        V2["Version 2<br/>Added password='abc123' ⚠️"]
        V3["Version 3<br/>Removed password"]
        V4["Version 4<br/>Added new feature"]
        V1 --> V2 --> V3 --> V4
    end
    subgraph CURRENT["📄 Current Code"]
        CLEAN["No password visible ✅"]
    end
    V4 --> CLEAN
    subgraph DANGER["💀 The Risk"]
        ATTACKER["git log -p<br/>'abc123' visible!"]
    end
    V2 -.-> ATTACKER
    style V2 fill:#ff6b6b,color:white
    style CLEAN fill:#51cf66,color:white
    style ATTACKER fill:#ff6b6b,color:white
```

### Why Simple File Scanning Isn't Enough

| Approach | Finds Current Secrets | Finds Deleted Secrets | Finds Renamed File Secrets |
|----------|:--------------------:|:--------------------:|:--------------------------:|
| File scanning (Module 1) | ✅ | ❌ | ❌ |
| Git history scanning (Module 3) | ✅ | ✅ | ✅ |

### Real-World Consequences

Here are documented incidents where deleted secrets in git history caused breaches:

| What Happened | Impact |
|---------------|--------|
| Developer committed AWS keys, deleted them an hour later | Keys scraped from public git history within minutes. $6,000 AWS bill from crypto mining. |
| Database password committed to config file, removed in next commit | Attacker found password in history, accessed production database |
| Private SSH key committed to repo, file deleted next day | Key used to access server months later |

> **The Git Integration Layer exists because "git rm" doesn't mean "gone."**

---

## 3. Key Concepts Explained

### 3.1 What Is Git?

Git is a **version control system** — a tool that tracks changes to files over time. It's like a "save history" for your entire project. Every time a developer makes a change and "commits" it, git records exactly what changed, who changed it, and when.

**Everyday Analogy**: Google Docs keeps a version history of every edit you make. Git does the same thing for code, but more precisely — it tracks every single line that was added, removed, or modified.

```mermaid
flowchart LR
    A["📝 Write code"] --> B["💾 git commit<br/>Save snapshot"]
    B --> C["📝 Write more code"] --> D["💾 git commit<br/>Save snapshot"]
    D --> E["📝 Fix a bug"] --> F["💾 git commit<br/>Save snapshot"]
    style B fill:#4dabf7,color:white
    style D fill:#4dabf7,color:white
    style F fill:#4dabf7,color:white
```

### 3.2 What Is a Commit?

A **commit** is a single saved snapshot of your project at a point in time. Each commit has:

| Field | What It Contains | Example |
|-------|-----------------|---------|
| **Hash** | Unique identifier (like a fingerprint) | `a1b2c3d4e5f6...` |
| **Author** | Who made the change | `Alice <alice@company.com>` |
| **Date** | When the change was made | `2026-03-14 10:30:00` |
| **Message** | Description of what changed | `"Add database configuration"` |
| **Parents** | Which commit came before this one | `f7e8d9c0...` |

**Everyday Analogy**: A commit is like a dated entry in a diary. Each entry records what you did that day, and you can flip back through the diary to any previous day.

```mermaid
flowchart LR
    C1["Commit 1<br/>abc123<br/>'Initial setup'<br/>by Alice"] --> C2["Commit 2<br/>def456<br/>'Add config'<br/>by Bob"]
    C2 --> C3["Commit 3<br/>ghi789<br/>'Fix typo'<br/>by Alice"]
    C3 --> C4["Commit 4<br/>jkl012<br/>'Add feature'<br/>by Charlie"]
```

### 3.3 What Is a Diff?

A **diff** (short for "difference") shows exactly what changed between two versions. It lists:
- **Added lines** (marked with `+`) — new content
- **Removed lines** (marked with `-`) — deleted content

**Everyday Analogy**: Think of "Track Changes" in Microsoft Word. Additions are highlighted in green, deletions in red. A diff is exactly that — a before-and-after comparison.

```
Example diff output:

--- a/config.env
+++ b/config.env
@@ -1,2 +1,3 @@
 APP_NAME=CredVigil
+AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY    ← this was added!
 DATABASE_HOST=localhost
```

> **Why CredVigil only looks at ADDED lines**: We only care about lines where new content was introduced — that's where secrets appear. Deleted lines already existed before and would have been caught in a previous scan.

```mermaid
flowchart TB
    DIFF["Git Diff Output"]
    DIFF --> ADDED["+ Added lines<br/>(new content)"]
    DIFF --> REMOVED["- Removed lines<br/>(deleted content)"]
    DIFF --> UNCHANGED["  Unchanged lines<br/>(context)"]
    ADDED --> SCAN["🔍 Scan these<br/>for secrets"]
    REMOVED --> SKIP1["⏭ Skip<br/>(already existed)"]
    UNCHANGED --> SKIP2["⏭ Skip<br/>(no change)"]
    style ADDED fill:#51cf66,color:white
    style SCAN fill:#4dabf7,color:white
    style REMOVED fill:#868e96,color:white
    style UNCHANGED fill:#868e96,color:white
```

### 3.4 What Is a Branch?

A **branch** is like a parallel timeline. Developers create branches to work on features independently, then merge them back into the main codebase.

**Everyday Analogy**: Imagine a tree. The trunk is the `main` branch. Side branches grow out as `feature-login` or `fix-bug-123`, and eventually reconnect to the trunk.

```mermaid
gitGraph
    commit id: "Initial"
    commit id: "Setup"
    branch feature/login
    commit id: "Add login page"
    commit id: "Add API key ⚠️"
    checkout main
    commit id: "Update docs"
    merge feature/login
    commit id: "Release v2"
```

> Secrets can be introduced on any branch. CredVigil can scan all branches or just the default branch.

### 3.5 What Is a Clone?

**Cloning** means downloading a complete copy of a remote repository — including its entire history — to your local machine.

**Everyday Analogy**: Cloning is like photocopying an entire notebook, including all the pages that were torn out (because git keeps those).

```mermaid
sequenceDiagram
    participant R as 🌐 Remote Repo<br/>(GitHub)
    participant L as 💻 Local Clone<br/>(Your Machine)
    
    R->>L: git clone https://github.com/org/repo.git
    Note over L: Full copy of<br/>all files + all history
    L->>L: CredVigil scans<br/>the cloned history
    L->>L: 🗑️ rm -rf clone<br/>(cleanup)
```

> **CredVigil Auto-Cleanup**: When CredVigil clones a repository for scanning, it automatically deletes the clone afterward. This prevents the cloned secrets from lingering on your machine — a **zero-trust** practice.

### 3.6 What Is "Walking" Commit History?

**Walking** commit history means going through each commit one by one, from the most recent to the oldest (or vice versa), and examining the changes.

**Everyday Analogy**: Imagine a security guard reviewing security camera footage. They start from yesterday and rewind day by day, checking each frame for anything suspicious. That's "walking" — systematically reviewing each entry in the timeline.

```mermaid
flowchart LR
    subgraph WALK["🚶 Walking Commits"]
        direction LR
        C4["Commit 4\n(newest)"] --> C3["Commit 3"]
        C3 --> C2["Commit 2"]
        C2 --> C1["Commit 1\n(oldest)"]
    end
    C4 --> D4["Get diff → Scan"]
    C3 --> D3["Get diff → Scan"]
    C2 --> D2["Get diff → Scan"]
    C1 --> D1["Get diff → Scan"]
```

### 3.7 What Is Incremental Scanning?

**Incremental scanning** means scanning only the *new* commits since the last scan, instead of re-scanning the entire history.

**Everyday Analogy**: If you read a 500-page book last week, and 20 new pages were added this week, you only need to read pages 501–520 — not the entire book again.

```mermaid
flowchart LR
    subgraph FULL["🐢 Full Scan"]
        F1["Commit 1"] --> F2["Commit 2"] --> F3["Commit 3"] --> F4["Commit 4"] --> F5["Commit 5"]
        style F1 fill:#4dabf7,color:white
        style F2 fill:#4dabf7,color:white
        style F3 fill:#4dabf7,color:white
        style F4 fill:#4dabf7,color:white
        style F5 fill:#4dabf7,color:white
    end
    subgraph INCREMENTAL["🚀 Incremental Scan"]
        I1["Commit 1"] --> I2["Commit 2"] --> I3["Commit 3"] --> I4["Commit 4"] --> I5["Commit 5"]
        style I1 fill:#868e96,color:white
        style I2 fill:#868e96,color:white
        style I3 fill:#868e96,color:white
        style I4 fill:#4dabf7,color:white
        style I5 fill:#4dabf7,color:white
    end
```

> In the incremental scan, gray = already scanned before, blue = scan now. You pass `--git-since <commit-hash>` to tell CredVigil where you left off.

---

## 4. Architecture Overview

The Git Integration Layer consists of five files that work together like a relay team:

```mermaid
flowchart TB
    subgraph LAYER["Git Integration Layer (pkg/git/)"]
        GIT["git.go<br/>Core Types &<br/>Git Helpers"]
        CLONE["clone.go<br/>Open & Clone<br/>Repositories"]
        DIFF["diff.go<br/>Parse Unified<br/>Diff Output"]
        WALKER["walker.go<br/>Walk Commit<br/>History"]
        SCANNER["scanner.go<br/>Orchestrate<br/>Scanning"]
    end
    
    subgraph ENGINE["From Module 1"]
        DET["Detection<br/>Engine"]
    end
    
    subgraph PIPELINE["From Module 2"]
        PIPE["Processing<br/>Pipeline"]
    end
    
    CLI["CLI<br/>(cmd/credvigil)"] --> SCANNER
    SCANNER --> WALKER
    WALKER --> CLONE
    WALKER --> DIFF
    CLONE --> GIT
    DIFF --> GIT
    SCANNER --> DET
    SCANNER --> PIPE
    
    style GIT fill:#ffd43b,color:black
    style CLONE fill:#69db7c,color:black
    style DIFF fill:#74c0fc,color:black
    style WALKER fill:#b197fc,color:black
    style SCANNER fill:#ff8787,color:black
```

### How Each File Relates to the Others

| File | Role | Analogy |
|------|------|---------|
| **git.go** | Defines the data types everyone uses | The **dictionary** — defines what words (types) mean |
| **clone.go** | Opens local repos or clones remote ones | The **librarian** — brings you the book (repo) to read |
| **diff.go** | Parses raw diff text into structured data | The **translator** — converts raw text into something a computer can understand |
| **walker.go** | Walks through commit history one-by-one | The **security guard** — reviews each day's footage |
| **scanner.go** | Coordinates the whole process | The **detective** — tells the guard what to look for and files the reports |

---

## 5. The Five Source Files

### 5.1 git.go — Core Types

This file defines the vocabulary — the data structures that every other file uses.

#### Repository

Represents a git repository on disk:

```go
type Repository struct {
    Path      string  // Where the repo lives on disk
    isCloned  bool    // Did WE clone this? (vs. already existed)
    remoteURL string  // Original URL if cloned
}
```

**Analogy**: A library card. It tells you *where* the book is, *whether you borrowed it* (need to return it), and *which library it came from*.

#### Commit

Represents a single commit:

```go
type Commit struct {
    Hash        string    // Full SHA-1 hash (unique ID)
    ShortHash   string    // First 8 characters
    AuthorName  string    // Who committed
    AuthorEmail string    // Their email
    AuthorDate  time.Time // When
    Subject     string    // First line of commit message
    Message     string    // Full commit message
    Parents     []string  // Parent commit hashes
}
```

**Analogy**: A diary entry. Date, author, a summary of what happened, and a page number (hash) to find it again.

#### DiffEntry

Represents a single file changed in a commit:

```go
type DiffEntry struct {
    FilePath   string         // Which file changed
    OldPath    string         // Previous path (if renamed)
    ChangeType string         // "A" (added), "M" (modified), "D" (deleted), "R" (renamed)
    AddedLines map[int]string // Line number → content (only added lines)
    Patch      string         // Raw diff text
}
```

**Analogy**: A "track changes" annotation on a single page. It tells you which page changed, what was added, and whether the page was new, edited, or removed.

#### ScanOptions

Controls how the scan behaves:

```go
type ScanOptions struct {
    Branch          string   // Which branch to scan
    SinceCommit     string   // Start from this commit (incremental)
    MaxCommits      int      // Limit how many commits to scan
    Depth           int      // Clone depth for remote repos
    AllBranches     bool     // Scan all branches?
    IncludePatterns []string // Only these files
    ExcludePatterns []string // Skip these files
    MaxDiffSize     int64    // Max diff size (bytes) per commit
    IncludeMerges   bool     // Include merge commits?
}
```

```mermaid
flowchart TB
    OPTS["ScanOptions"]
    OPTS --> B["Branch<br/>Which branch?"]
    OPTS --> S["SinceCommit<br/>Start from where?"]
    OPTS --> M["MaxCommits<br/>How many?"]
    OPTS --> D["Depth<br/>Clone depth?"]
    OPTS --> AB["AllBranches<br/>All or one?"]
    OPTS --> IP["IncludePatterns<br/>Only *.env files?"]
    OPTS --> EP["ExcludePatterns<br/>Skip *.test files?"]
    OPTS --> MS["MaxDiffSize<br/>Skip huge diffs?"]
    OPTS --> IM["IncludeMerges<br/>Include merges?"]
```

### 5.2 clone.go — Repository Management

This file handles getting repositories ready for scanning.

#### Two Ways to Get a Repository

```mermaid
flowchart TB
    INPUT["Repository Input"]
    INPUT --> LOCAL["Local Path<br/>(already on your machine)"]
    INPUT --> REMOTE["Remote URL<br/>(GitHub, GitLab, etc.)"]
    
    LOCAL --> OPEN["OpenRepository(path)<br/>Verifies it's a valid git repo"]
    REMOTE --> CLONE["CloneRepository(url, opts)<br/>Downloads to temp directory"]
    
    OPEN --> REPO["Repository struct ready"]
    CLONE --> REPO
    
    REPO --> SCAN["Scan it!"]
    
    SCAN --> CLEANUP["Cleanup()<br/>If cloned → delete temp files<br/>If local → no-op"]
    
    style OPEN fill:#69db7c,color:black
    style CLONE fill:#69db7c,color:black
    style CLEANUP fill:#ffd43b,color:black
```

**OpenRepository** — Opens a local repo:
1. Checks if git is installed
2. Resolves the absolute path
3. Verifies it's a git repository (`git rev-parse --is-inside-work-tree`)
4. Finds the repository root
5. Returns a `Repository` struct

**CloneRepository** — Clones a remote repo:
1. Checks if git is installed
2. Creates a temporary directory
3. Runs `git clone` with optional depth/branch
4. Returns a `Repository` (marked as `isCloned = true`)

**Cleanup** — Cleans up after scanning:
- If the repo was cloned → deletes the temp directory
- If the repo was local → does nothing (we didn't create it, so we don't delete it)

> **Zero-Trust Practice**: Cloned repositories contain actual secrets in their history. CredVigil deletes them immediately after scanning to minimize the window of exposure.

### 5.3 diff.go — Diff Parser

This file takes the raw text output of `git diff` and converts it into structured `DiffEntry` objects.

#### What Raw Diff Output Looks Like

When git compares two commits, it produces output like this:

```
diff --git a/config.env b/config.env
new file mode 100644
--- /dev/null
+++ b/config.env
@@ -0,0 +1,3 @@
+APP_NAME=CredVigil
+AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
+DATABASE_HOST=localhost
```

The parser extracts:
- **File path**: `config.env`
- **Change type**: `A` (new file, because `--- /dev/null`)
- **Added lines**: Lines starting with `+`
- **Line numbers**: Calculated from the `@@ -0,0 +1,3 @@` hunk header

```mermaid
flowchart LR
    RAW["Raw diff text<br/>(string from git)"] --> PARSER["ParseDiff()"]
    PARSER --> ENTRIES["[]DiffEntry"]
    ENTRIES --> E1["DiffEntry 1<br/>config.env<br/>Type: Added<br/>3 new lines"]
    ENTRIES --> E2["DiffEntry 2<br/>main.go<br/>Type: Modified<br/>5 new lines"]
    ENTRIES --> E3["DiffEntry 3<br/>old.txt<br/>Type: Deleted<br/>0 new lines"]
```

#### Key Implementation Details

**Only Added Lines Matter**: The parser collects lines starting with `+` (but not `+++` which is the header). These are the only lines where secrets could be newly introduced.

**Hunk Headers**: The `@@ -0,0 +1,3 @@` lines tell us where in the file the changes start. The parser uses these to calculate accurate line numbers.

**Change Type Detection**:
| Pattern | Meaning |
|---------|---------|
| `--- /dev/null` | New file (change type `A`) |
| `+++ /dev/null` | Deleted file (change type `D`) |
| `rename from X` | Renamed file (change type `R`) |
| Everything else | Modified file (change type `M`) |

#### File Pattern Filtering

After parsing, `FilterDiffEntries()` can filter entries to include only certain files or exclude others:

```mermaid
flowchart LR
    ALL["All DiffEntries<br/>config.env<br/>main.go<br/>test.js<br/>build.log"] --> FILTER["FilterDiffEntries()"]
    FILTER --> |"include: *.env, *.go"| KEPT["config.env<br/>main.go"]
    FILTER --> |"exclude: *.log"| SKIPPED["build.log ❌"]
```

### 5.4 walker.go — Commit Walker

The walker is the engine that drives through commit history. It uses git commands to list commits and fetch their diffs.

#### How It Works

```mermaid
sequenceDiagram
    participant W as CommitWalker
    participant G as Git CLI
    participant P as ParseDiff()
    
    W->>G: git log --format=... (list commits)
    G-->>W: Commit 1, Commit 2, Commit 3...
    
    loop For each commit
        W->>W: Skip merge commits?
        W->>G: git log -1 -p <hash> (get diff)
        G-->>W: Raw diff text
        W->>P: ParseDiff(rawDiff)
        P-->>W: []DiffEntry
        W->>W: FilterDiffEntries()
        W->>W: Call callback(commit, entries)
    end
```

#### Key Methods

**CountCommits()** — Counts how many commits will be scanned (used for progress bars).

**ListCommits()** — Lists all matching commits with metadata. Uses a custom delimiter format (`\x00` between fields, `\x01` between commits) for reliable parsing.

**GetDiff(hash)** — Gets the diff for a specific commit:
- For the **initial commit** (no parents): uses `git log -1 -p` to show what was added
- For **normal commits**: uses `git diff parent^ commit` to compare with the previous version

**WalkCommits(callback)** — The main loop. Iterates through commits and calls your function for each one:
1. Lists all matching commits
2. Skips merge commits (unless `IncludeMerges` is `true`)
3. Gets the diff for each commit
4. Parses the diff into `DiffEntry` objects
5. Filters by include/exclude patterns
6. Calls the callback with the commit and its entries
7. Stops if `MaxCommits` is reached

```mermaid
flowchart TB
    START["Start Walking"] --> LIST["ListCommits()"]
    LIST --> LOOP["For Each Commit"]
    LOOP --> MERGE{"Merge commit?"}
    MERGE -->|"Yes & IncludeMerges=false"| SKIP["Skip"]
    MERGE -->|"No or IncludeMerges=true"| GETDIFF["GetDiff(hash)"]
    SKIP --> CHECK
    GETDIFF --> PARSE["ParseDiff(diff)"]
    PARSE --> FILTR["FilterDiffEntries()"]
    FILTR --> CALLBACK["callback(commit, entries)"]
    CALLBACK --> CHECK{"MaxCommits\nreached?"}
    CHECK -->|"No"| LOOP
    CHECK -->|"Yes"| DONE["Done"]
    
    style GETDIFF fill:#4dabf7,color:white
    style PARSE fill:#74c0fc,color:black
    style CALLBACK fill:#b197fc,color:black
```

### 5.5 scanner.go — Git Scanner Orchestrator

The scanner is the top-level component that brings everything together. It connects:
- The **CommitWalker** (to walk through commits)
- The **Detection Engine** (from Module 1, to find secrets)
- The **Pipeline** (from Module 2, to hash/redact/enrich findings)

#### The Full Scanning Flow

```mermaid
flowchart TB
    subgraph INPUT["Input"]
        CLI["CLI: --git <repo>"]
    end
    
    subgraph SCANNER["GitScanner"]
        S1["Count commits<br/>(for progress)"]
        S2["Walk each commit"]
        S3["Extract diff entries"]
        S4["Build scannable content<br/>from added lines"]
        S5["Run detection engine<br/>(276 rules + entropy)"]
        S6["Adjust line numbers"]
        S7["Run pipeline<br/>(hash → redact → enrich<br/>→ fingerprint → sanitize)"]
        S8["Aggregate results"]
    end
    
    subgraph OUTPUT["Output"]
        RESULT["GitScanResult<br/>• commits scanned<br/>• findings per commit<br/>• total findings"]
    end
    
    CLI --> S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7 --> S8 --> RESULT
```

#### How scanDiffEntry Works

For each changed file in a commit:

```mermaid
flowchart LR
    ENTRY["DiffEntry<br/>config.env<br/>3 added lines"] --> BUILD["Build content<br/>from added lines"]
    BUILD --> REQ["ScanRequest<br/>content: the lines<br/>source: git-commit<br/>commit: abc123<br/>author: Alice"]
    REQ --> ENGINE["Detection<br/>Engine"]
    ENGINE --> FINDINGS["Findings<br/>(raw)"]
    FINDINGS --> ADJUST["Adjust line numbers<br/>to match actual file"]
    ADJUST --> PIPELINE["Pipeline<br/>hash → redact<br/>→ enrich<br/>→ fingerprint<br/>→ sanitize"]
    PIPELINE --> SAFE["Safe findings<br/>(zero-trust)"]
```

#### Line Number Adjustment

This is a subtle but important detail. When CredVigil scans the added lines from a diff, the detection engine reports line numbers relative to those extracted lines (line 1, 2, 3...). But the actual lines in the file might be at different positions (line 15, 16, 17...).

The `adjustLineNumbers()` function maps back from "line 2 of the scanned content" to "line 16 of the actual file."

```mermaid
flowchart TB
    subgraph SCAN["Scanned Content"]
        L1["Line 1: APP_NAME=CredVigil"]
        L2["Line 2: AWS_KEY=AKIA... ← Engine says 'line 2'"]
        L3["Line 3: DB_HOST=localhost"]
    end
    subgraph FILE["Actual File"]
        F14["Line 14: # Config section"]
        F15["Line 15: APP_NAME=CredVigil"]
        F16["Line 16: AWS_KEY=AKIA... ← Actually line 16"]
        F17["Line 17: DB_HOST=localhost"]
    end
    L2 -.->|"adjustLineNumbers()"| F16
    style L2 fill:#ff6b6b,color:white
    style F16 fill:#ff6b6b,color:white
```

#### GitScanResult

The final output contains:

```go
type GitScanResult struct {
    Repository     string                         // Path or URL
    TotalCommits   int                            // Total in range
    ScannedCommits int                            // Actually scanned
    TotalFindings  int                            // Total secrets found
    CommitResults  map[string]*CommitScanResult   // Per-commit findings
    Errors         []string                        // Non-fatal errors
    Duration       time.Duration                   // How long it took
}
```

---

## 6. How It All Fits Together

Here is the complete flow showing how all three components interact when you run a git scan:

```mermaid
flowchart TB
    subgraph CLI["Command Line"]
        CMD["credvigil scan --git ./repo"]
    end
    
    subgraph C3["Component 3: Git Integration"]
        OPEN["OpenRepository<br/>or CloneRepository"]
        WALKER["CommitWalker<br/>walks commit history"]
        PDIFF["ParseDiff<br/>extracts added lines"]
    end
    
    subgraph C1["Component 1: Detection Engine"]
        ENGINE["ScanContent<br/>276 rules + entropy"]
    end
    
    subgraph C2["Component 2: Pipeline"]
        HASH["Hash"]
        REDACT["Redact"]
        ENRICH["Enrich"]
        FP["Fingerprint"]
        SANITIZE["Sanitize"]
    end
    
    subgraph OUTPUT["Output"]
        REPORT["Git Scan Report<br/>per-commit findings"]
    end
    
    CMD --> OPEN --> WALKER
    WALKER --> PDIFF
    PDIFF --> ENGINE
    ENGINE --> HASH --> REDACT --> ENRICH --> FP --> SANITIZE
    SANITIZE --> REPORT
    
    style C3 fill:#e3f2fd
    style C1 fill:#f3e5f5
    style C2 fill:#e8f5e9
```

---

## 7. The Scanning Flow Step by Step

Let's trace through a real example. Imagine a repository with 3 commits:

| Commit | Message | File | Content |
|--------|---------|------|---------|
| abc123 | "Initial setup" | README.md | `# My App` |
| def456 | "Add config" | config.env | `AWS_KEY=AKIAIOSFODNN7EXAMPLE` |
| ghi789 | "Remove key" | config.env | `# No keys here` |

### Step-by-Step Trace

```mermaid
sequenceDiagram
    participant CLI as CLI
    participant S as GitScanner
    participant W as CommitWalker
    participant G as Git CLI
    participant D as DiffParser
    participant E as Detection Engine
    participant P as Pipeline

    CLI->>S: ScanLocalRepo("./repo")
    S->>S: OpenRepository("./repo")
    S->>W: CountCommits() → 3
    S->>W: WalkCommits(callback)
    
    Note over W,G: Commit ghi789 (newest first)
    W->>G: git diff ghi789^ ghi789
    G-->>W: "removed AWS_KEY line"
    W->>D: ParseDiff(diff)
    D-->>W: [DiffEntry: config.env, no added lines]
    Note over W: No added lines → nothing to scan
    
    Note over W,G: Commit def456
    W->>G: git diff def456^ def456
    G-->>W: "+AWS_KEY=AKIAIOSFODNN7EXAMPLE"
    W->>D: ParseDiff(diff)
    D-->>W: [DiffEntry: config.env, 1 added line]
    W->>S: callback(commit, entries)
    S->>E: ScanContent("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    E-->>S: 1 finding: AWS Access Key!
    S->>P: ProcessResult(finding)
    P-->>S: Hashed, redacted, enriched, sanitized
    
    Note over W,G: Commit abc123 (initial)
    W->>G: git log -1 -p abc123
    G-->>W: "+# My App"
    W->>D: ParseDiff(diff)
    D-->>W: [DiffEntry: README.md, 1 added line]
    W->>S: callback(commit, entries)
    S->>E: ScanContent("# My App")
    E-->>S: 0 findings (clean)
    
    S-->>CLI: GitScanResult: 3 commits, 1 finding
```

> **Key takeaway**: The secret was deleted in commit ghi789, but CredVigil found it in commit def456 where it was *introduced*. Deleting a secret doesn't erase it from history.

---

## 8. CLI Usage for Git Scanning

### Basic Commands

```bash
# Scan a local repository's git history
./credvigil scan --git ./my-project/

# Scan a remote repository (auto-clones and cleans up)
./credvigil scan --git https://github.com/org/repo.git

# JSON output for automation
./credvigil scan --git ./my-project/ --format json
```

### Advanced Options

```bash
# Scan only a specific branch
./credvigil scan --git ./my-project/ --git-branch develop

# Incremental scan (only commits since a known point)
./credvigil scan --git ./my-project/ --git-since abc1234

# Limit to recent commits
./credvigil scan --git ./my-project/ --git-max-commits 50

# Shallow clone for faster remote scans
./credvigil scan --git https://github.com/org/repo.git --git-depth 100

# Scan all branches (not just the default)
./credvigil scan --git ./my-project/ --git-all-branches

# Include merge commits (skipped by default)
./credvigil scan --git ./my-project/ --git-include-merges
```

### CLI Flags Reference

| Flag | Description | Default |
|------|-------------|---------|
| `--git` | Enable git history scanning | (disabled) |
| `--git-branch` | Branch to scan | HEAD (default branch) |
| `--git-since` | Only scan commits after this hash | (scan all) |
| `--git-depth` | Clone depth for remote repos | 0 (full history) |
| `--git-max-commits` | Maximum commits to scan | 0 (unlimited) |
| `--git-all-branches` | Scan all branches | false |
| `--git-include-merges` | Include merge commits | false |

---

## 9. Understanding Git Scan Output

### Text Output Example

```
╔═══════════════════════════════════════════════════════════════╗
║                 CredVigil Git History Report                 ║
╚═══════════════════════════════════════════════════════════════╝

Repository: ./my-project

Commits scanned: 42 / 42

──── Commit def4567 (2026-01-15) ─────────────────────────────
  Author:  Alice <alice@company.com>
  Message: add database config

  [CRITICAL] AWS Secret Access Key
    File:       config.env:3
    Match:      wJal****EKEY
    Confidence: 89%
    SHA-256:    78314b11...080e0598

  [HIGH] Database Password
    File:       config.env:7
    Match:      Super****rd!
    Confidence: 72%

──── Commit abc1234 (2026-01-10) ─────────────────────────────
  Author:  Bob <bob@company.com>
  Message: add deployment script

  [HIGH] GitHub Personal Access Token
    File:       deploy.sh:12
    Match:      ghp_A****ef12
    Confidence: 95%

─────────────────────────────────────────────────────────────────
  Git scan completed in 2.3s
  Commits scanned: 42
  Total findings: 3 across 2 commits
  By severity: CRITICAL=1, HIGH=2
─────────────────────────────────────────────────────────────────
```

### JSON Output Example

```json
{
  "scan_type": "git-history",
  "repository": "./my-project",
  "total_commits": 42,
  "scanned_commits": 42,
  "total_findings": 3,
  "commit_results": {
    "def4567...": {
      "commit": {
        "hash": "def4567...",
        "author_name": "Alice",
        "author_email": "alice@company.com",
        "subject": "add database config"
      },
      "findings": [
        {
          "secret_type": "aws-secret-access-key",
          "severity": "CRITICAL",
          "source": {
            "type": "git-commit",
            "location": "config.env",
            "line": 3,
            "commit_hash": "def4567...",
            "author": "Alice <alice@company.com>"
          },
          "redacted_match": "wJal****EKEY",
          "secret_hash": "78314b11..."
        }
      ]
    }
  }
}
```

### Understanding Commit Context

Each finding in a git scan includes extra information that file scans don't have:

| Field | What It Tells You |
|-------|------------------|
| `commit_hash` | Exactly which commit introduced the secret |
| `author` | Who committed the secret |
| `source.type = "git-commit"` | This was found in history, not in current files |
| `source.location` | Which file in which commit |

> **Why this matters**: When you find a secret in git history, you know exactly *who* to contact, *when* it happened, and *which commit* to reference in your remediation ticket.

---

## 10. Hands-On Exercises

### Exercise 1: Set Up a Test Repository

Create a repo with some intentional "secrets" to practice scanning:

```bash
# Create a test repo
mkdir secret-test && cd secret-test
git init
git checkout -b main

# Commit 1: Clean file
echo "# My App" > README.md
git add . && git commit -m "initial setup"

# Commit 2: Add a secret (intentionally!)
echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" > config.env
echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> config.env
git add . && git commit -m "add aws config"

# Commit 3: Remove the secret
echo "# AWS credentials removed" > config.env
git add . && git commit -m "remove credentials"

# Now the current files have no secrets!
cat config.env
# Output: # AWS credentials removed
```

### Exercise 2: Scan the Git History

```bash
# Go back to the CredVigil directory
cd /path/to/credvigil

# Scan the test repo's history
./credvigil scan --git /path/to/secret-test/
```

**Expected result**: CredVigil should find the AWS keys from Commit 2, even though they were removed in Commit 3.

**Questions to ponder**:
- How many commits were scanned?
- Which commit hash contains the finding?
- What's the author name on the finding?

### Exercise 3: Incremental Scan

```bash
# Get the hash of the first commit
cd /path/to/secret-test
FIRST_HASH=$(git log --reverse --format=%H | head -1)

# Only scan commits AFTER the first one
cd /path/to/credvigil
./credvigil scan --git /path/to/secret-test/ --git-since $FIRST_HASH

# How many commits were scanned now?
```

### Exercise 4: Limit Commits

```bash
# Only scan the most recent 1 commit
./credvigil scan --git /path/to/secret-test/ --git-max-commits 1

# The most recent commit just says "remove credentials" — so no findings!
# Now try with 2:
./credvigil scan --git /path/to/secret-test/ --git-max-commits 2

# This should catch the secret in the second-most-recent commit
```

### Exercise 5: JSON Output for Automation

```bash
./credvigil scan --git /path/to/secret-test/ --format json | python3 -m json.tool

# Look at the JSON structure — each commit with findings has its own section
```

### Exercise 6: Multiple Secrets Across Commits

```bash
cd /path/to/secret-test

# Add more secrets in separate commits
echo "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12" > deploy.sh
git add . && git commit -m "add github deploy token"

echo "SLACK_WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX" > notify.py
git add . && git commit -m "add notification webhook"

# Rescan
cd /path/to/credvigil
./credvigil scan --git /path/to/secret-test/

# How many findings? How many commits now have findings?
```

---

## 11. Deep Dive: Code Walkthrough

### 11.1 Core Types (git.go)

**Purpose**: Defines all data types and provides low-level git helper functions.

#### Helper Functions

**gitAvailable()** — Checks if git is installed:
```go
func gitAvailable() error {
    cmd := exec.Command("git", "--version")
    out, err := cmd.Output()
    if err != nil {
        return fmt.Errorf("git is not installed or not on PATH: %w", err)
    }
    return nil
}
```

**Analogy**: Before opening a book, the librarian checks if the library is open. Before running git commands, we check if git is installed.

**gitExec(dir, args...)** — Runs any git command:
```go
func gitExec(dir string, args ...string) (string, error) {
    cmd := exec.Command("git", args...)
    if dir != "" {
        cmd.Dir = dir
    }
    out, err := cmd.CombinedOutput()
    // ... error handling
    return strings.TrimSpace(string(out)), nil
}
```

**Analogy**: A universal remote control for git. Tell it what command to run and where, and it runs it and hands you the output.

**isGitRepository(path)** — Checks if a path is inside a git repo:
```go
func isGitRepository(path string) bool {
    _, err := gitExec(path, "rev-parse", "--is-inside-work-tree")
    return err == nil
}
```

```mermaid
flowchart TB
    PATH["/some/directory"] --> CHECK["gitExec: git rev-parse\n--is-inside-work-tree"]
    CHECK -->|"Returns 'true'"| YES["✅ Is a git repo"]
    CHECK -->|"Returns error"| NO["❌ Not a git repo"]
```

### 11.2 Repository Management (clone.go)

**OpenRepository** opens a local repo. The key step is resolving to the **repository root** — if you point it at a subdirectory like `repo/src/utils/`, it walks up to find the actual `.git` directory.

```mermaid
flowchart LR
    INPUT["Input: repo/src/utils/"] --> RESOLVE["git rev-parse\n--show-toplevel"]
    RESOLVE --> ROOT["Root: repo/"]
    ROOT --> REPO["Repository{\n  Path: repo/\n  isCloned: false\n}"]
```

**CloneRepository** downloads a remote repo:

```mermaid
sequenceDiagram
    participant CV as CredVigil
    participant OS as File System
    participant GIT as Git CLI
    
    CV->>OS: Create temp directory<br/>/tmp/credvigil-clone-xxx/
    CV->>GIT: git clone [--depth N] [--branch B] url tmpDir
    GIT-->>OS: Download repo to tmpDir
    CV->>CV: Return Repository{isCloned: true}
    
    Note over CV: After scanning...
    CV->>OS: Cleanup() → rm -rf tmpDir
```

**Cleanup** follows the principle: "If you created it, clean it up. If you didn't, leave it alone."

```mermaid
flowchart TB
    CLEANUP["Cleanup()"]
    CLEANUP --> CHECK{"isCloned?"}
    CHECK -->|"true"| DELETE["os.RemoveAll(path)<br/>🗑️ Delete temp files"]
    CHECK -->|"false"| NOOP["No-op<br/>👋 Not our repo"]
```

### 11.3 Diff Parser (diff.go)

**ParseDiff** is the most algorithmic part of the codebase. It processes the raw text output of `git diff` line by line.

#### Parser State Machine

The parser tracks its state as it reads through the diff output:

```mermaid
stateDiagram-v2
    [*] --> WaitingForDiff
    WaitingForDiff --> InDiffHeader: "diff --git" line
    InDiffHeader --> InDiffHeader: meta lines (index, mode)
    InDiffHeader --> InFileHeader: "---" line
    InFileHeader --> InHunk: "+++" line
    InHunk --> InHunk: context/added/removed lines
    InHunk --> InHunk: "@@ ... @@" (new hunk)
    InHunk --> InDiffHeader: "diff --git" (new file)
    InHunk --> [*]: End of input
```

#### Parsing Example

Input:
```
diff --git a/config.env b/config.env
new file mode 100644
--- /dev/null
+++ b/config.env
@@ -0,0 +1,2 @@
+APP_NAME=CredVigil
+AWS_KEY=AKIA1234
```

Step-by-step:

| Line | Parser Action |
|------|--------------|
| `diff --git a/config.env b/config.env` | Start new entry, extract path: `config.env` |
| `new file mode 100644` | File metadata (skip) |
| `--- /dev/null` | Old file was `/dev/null` → new file → change type `A` |
| `+++ b/config.env` | Confirm file path |
| `@@ -0,0 +1,2 @@` | Hunk header → new lines start at line 1 |
| `+APP_NAME=CredVigil` | Added line → store as `line 1: APP_NAME=CredVigil` |
| `+AWS_KEY=AKIA1234` | Added line → store as `line 2: AWS_KEY=AKIA1234` |

Result:
```go
DiffEntry{
    FilePath:   "config.env",
    ChangeType: "A",
    AddedLines: map[int]string{
        1: "APP_NAME=CredVigil",
        2: "AWS_KEY=AKIA1234",
    },
}
```

#### FilterDiffEntries

Applies glob-like pattern matching to include or exclude files:

```go
// Simple pattern matching
func matchPattern(path, pattern string) bool {
    // "*.env" matches "config.env"
    // "src/*" matches "src/main.go"
    // Exact match: "Dockerfile" matches "Dockerfile"
}
```

```mermaid
flowchart TB
    ENTRIES["5 DiffEntries<br/>config.env<br/>main.go<br/>test_data.json<br/>.env.production<br/>node_modules/pkg.js"]
    ENTRIES --> INCLUDE["Include: *.env, *.go"]
    INCLUDE --> EXCLUDE["Exclude: node_modules/*"]
    EXCLUDE --> RESULT["2 entries:<br/>config.env ✅<br/>main.go ✅"]
```

### 11.4 Commit Walker (walker.go)

#### Custom Log Format

The walker uses a clever trick to parse git log output reliably. Instead of parsing human-readable output (which can break if commit messages contain special characters), it uses **null byte delimiters**:

```
Format: %H\x00%h\x00%an\x00%ae\x00%at\x00%s\x00%B\x00%P\x01
```

- `\x00` (null byte) separates fields within a commit
- `\x01` (SOH byte) separates commits from each other
- These bytes almost never appear in commit messages, making parsing reliable

```mermaid
flowchart TB
    GIT["git log output:<br/>abc123\x00abc1\x00Alice\x00alice@co\x00...\x01<br/>def456\x00def4\x00Bob\x00bob@co\x00...\x01"]
    GIT --> SPLIT1["Split by \\x01<br/>(commit separator)"]
    SPLIT1 --> C1["abc123\x00abc1\x00Alice\x00..."]
    SPLIT1 --> C2["def456\x00def4\x00Bob\x00..."]
    C1 --> SPLIT2["Split by \\x00<br/>(field separator)"]
    SPLIT2 --> FIELDS["Hash: abc123<br/>Short: abc1<br/>Author: Alice<br/>Email: alice@co<br/>..."]
```

#### Initial Commit Handling

The first commit in a repository has no parent — there's nothing to compare it against. The walker handles this by using `git log -1 -p` which shows the patch (diff) of what was introduced in that commit:

```mermaid
flowchart TB
    GETDIFF["GetDiff(hash)"]
    GETDIFF --> CHECK{"Has parents?"}
    CHECK -->|"Yes"| NORMAL["git diff parent^ hash<br/>Compare with parent"]
    CHECK -->|"No (initial commit)"| INITIAL["git log -1 -p hash<br/>Show what was added"]
    NORMAL --> RESULT["Diff output"]
    INITIAL --> RESULT
```

#### Diff Size Limits

Large commits (e.g., auto-generated code, data files) can produce enormous diffs. The `truncateDiff()` function caps the diff at `MaxDiffSize` (default: 1 MB) to prevent memory issues:

```mermaid
flowchart LR
    DIFF["Diff: 5 MB"] --> CHECK{"Size > MaxDiffSize?"}
    CHECK -->|"Yes"| TRUNCATE["Truncate to 1 MB"]
    CHECK -->|"No"| KEEP["Keep as-is"]
    TRUNCATE --> SCAN["Scan"]
    KEEP --> SCAN
```

### 11.5 Scanner Orchestrator (scanner.go)

#### ScanRepository — The Main Entry Point

```go
func (gs *GitScanner) ScanRepository(ctx context.Context, repo *Repository) (*GitScanResult, error) {
    // 1. Count commits (for progress reporting)
    // 2. Walk commits with a callback
    //    For each commit:
    //      a. Check context cancellation
    //      b. Scan each diff entry
    //      c. Accumulate findings
    // 3. Return aggregated results
}
```

#### Context Cancellation

The scanner supports **context cancellation** — a Go pattern that lets you stop a long-running operation gracefully:

```mermaid
sequenceDiagram
    participant U as User
    participant S as Scanner
    participant W as Walker
    
    U->>S: ScanRepository(ctx, repo)
    S->>W: Walk commit 1
    W-->>S: entries
    S->>S: Scan entries
    
    U->>U: Press Ctrl+C
    U->>S: ctx.Cancel()
    
    S->>W: Walk commit 2
    Note over S: Check ctx.Done()
    S-->>U: Return partial results
```

**Analogy**: You're watching security footage and your shift ends. You stop reviewing and hand over what you've found so far — you don't throw away the findings from the hours you already reviewed.

#### Progress Reporting

The scanner tracks progress so the CLI can show updates:

```go
type ScanProgress struct {
    TotalCommits   int    // How many to scan
    ScannedCommits int    // How many done
    CurrentCommit  string // Currently processing
    FindingsCount  int    // Found so far
}
```

#### Convenience Methods

Two helper methods simplify common use cases:

```mermaid
flowchart TB
    subgraph LOCAL["ScanLocalRepo(ctx, path)"]
        L1["OpenRepository(path)"] --> L2["ScanRepository(ctx, repo)"]
    end
    
    subgraph REMOTE["ScanRemoteRepo(ctx, url)"]
        R1["CloneRepository(url, opts)"] --> R2["ScanRepository(ctx, repo)"]
        R2 --> R3["repo.Cleanup()"]
    end
    
    style R3 fill:#ff6b6b,color:white
```

---

## 12. Security Considerations

### Cloned Repository Cleanup

When CredVigil clones a remote repository, the clone contains actual secrets in its history. The scanner uses Go's `defer` keyword to guarantee cleanup:

```go
func (gs *GitScanner) ScanRemoteRepo(ctx context.Context, url string) (*GitScanResult, error) {
    repo, err := CloneRepository(url, gs.opts)
    if err != nil {
        return nil, err
    }
    defer repo.Cleanup()  // ← Guaranteed to run, even on error
    return gs.ScanRepository(ctx, repo)
}
```

**Analogy**: It's like having a shredder attached to the copy machine. No matter what happens — even if the power goes out mid-scan — the copy gets shredded.

### Zero-Trust Source Fields

Every finding includes `Source.Type = "git-commit"` and `Source.CommitHash`. This metadata flows through the Module 2 pipeline:
- **Hashing**: The raw secret gets hashed
- **Redaction**: Only a masked preview remains
- **Sanitization**: The raw match is cleared

The git-specific metadata (commit hash, author) is preserved because it's not sensitive — it's just a reference to public commit information.

```mermaid
flowchart LR
    subgraph PRESERVED["Preserved (not sensitive)"]
        CH["CommitHash: def456"]
        AU["Author: Alice"]
        FP["FilePath: config.env"]
    end
    subgraph PROTECTED["Zero-Trust Protected"]
        RAW["RawMatch: '' (cleared)"]
        HASH["SecretHash: 78314b..."]
        REDACT["RedactedMatch: wJal****EKEY"]
    end
    style RAW fill:#51cf66,color:black
    style HASH fill:#51cf66,color:black
    style REDACT fill:#51cf66,color:black
```

### Local Repo Safety

When scanning a local repository (that already exists on disk), CredVigil:
- **Never modifies** the repository
- **Never creates** new branches or commits
- Uses **read-only** git commands (`git log`, `git diff`)
- The `Cleanup()` function is a **no-op** for local repos

---

## 13. Performance & Scalability

### How CredVigil Handles Large Repositories

| Challenge | Solution |
|-----------|----------|
| Thousands of commits | `--git-max-commits` limits scan scope |
| Huge diffs (generated files) | `MaxDiffSize` truncates at 1 MB per diff |
| Slow remote clones | `--git-depth` does a shallow clone |
| Repeated full scans | `--git-since` enables incremental scanning |
| Merge commit noise | Merge commits skipped by default |
| Binary files in diffs | Diff parser naturally skips non-text content |

### Scanning Speed Characteristics

```mermaid
flowchart LR
    subgraph FAST["⚡ Fast Operations"]
        F1["git log<br/>(list commits)"]
        F2["Parse diff text"]
        F3["Regex matching"]
    end
    subgraph MEDIUM["🔶 Medium Operations"]
        M1["git diff per commit"]
        M2["Entropy analysis"]
    end
    subgraph SLOW["🐢 Slow Operations"]
        S1["git clone<br/>(network I/O)"]
        S2["Scanning 10,000+ commits"]
    end
```

### Recommended Strategies for Large Repos

```mermaid
flowchart TB
    SIZE{"Repo Size?"}
    SIZE -->|"< 100 commits"| FULL["Full scan<br/>./credvigil scan --git repo"]
    SIZE -->|"100-1000 commits"| LIMITED["Limited scan<br/>--git-max-commits 200"]
    SIZE -->|"1000+ commits"| INCREMENTAL["Incremental scan<br/>--git-since <last-scan-hash>"]
    SIZE -->|"Remote + huge"| SHALLOW["Shallow clone<br/>--git-depth 100"]
```

---

## 14. Error Handling & Resilience

### Non-Fatal vs Fatal Errors

The Git Integration Layer distinguishes between two types of errors:

```mermaid
flowchart TB
    ERROR["Error Occurs"]
    ERROR --> FATAL{"Fatal?"}
    FATAL -->|"Yes"| STOP["Stop scan,<br/>return error"]
    FATAL -->|"No"| CONTINUE["Log error,<br/>continue scanning"]
    
    subgraph FATAL_EXAMPLES["Fatal Errors"]
        E1["Git not installed"]
        E2["Path doesn't exist"]
        E3["Not a git repository"]
        E4["Clone fails"]
    end
    
    subgraph NONFATAL_EXAMPLES["Non-Fatal Errors"]
        E5["Single commit diff fails"]
        E6["Pipeline processor error"]
        E7["Diff too large (truncated)"]
    end
```

**Analogy**: A factory assembly line:
- **Fatal error** = the power goes out (the whole line stops)
- **Non-fatal error** = one widget is defective (skip it, keep the line running)

### Walker Error Recovery

When `GetDiff` fails for a single commit, the walker doesn't crash — it skips that commit and continues:

```go
diff, err := w.GetDiff(commit.Hash)
if err != nil {
    // Skip this commit, try the next one
    continue
}
```

### GitScanResult Error Collection

Non-fatal errors are collected and included in the final result:

```go
result.Errors = append(result.Errors, err.Error())
```

This lets the caller decide how to handle them — log them, display them, or ignore them.

---

## 15. Frequently Asked Questions

### Q1: Does git history scanning replace file scanning?

**No.** They serve different purposes:
- **File scanning** (Module 1) catches secrets in the current codebase
- **Git scanning** (Module 3) catches secrets that were committed and deleted

Use both for comprehensive coverage.

```mermaid
flowchart LR
    subgraph FILE["File Scanning"]
        FS["Current files on disk"]
    end
    subgraph GIT["Git History Scanning"]
        GS["Every commit ever made"]
    end
    subgraph COMPLETE["Complete Coverage"]
        BOTH["File scan + Git scan"]
    end
    FS --> BOTH
    GS --> BOTH
```

### Q2: Why does CredVigil use the git CLI instead of a Go library?

**Zero dependencies.** CredVigil uses `os/exec` to call git directly rather than importing a Go git library. This keeps the project dependency-free, reduces supply chain risk, and works with any git version the user has installed.

| Approach | Pros | Cons |
|----------|------|------|
| Git CLI (our approach) | Zero dependencies, works with any git version, simple | Requires git installed, slightly slower due to process spawning |
| Go git library | No git needed, faster for batch operations | Adds dependency, supply chain risk, must track library updates |

### Q3: What is a "merge commit" and why do we skip it?

A **merge commit** is created when two branches are combined. It has two parents instead of one. We skip them by default because:
- The actual changes were already in the individual commits on the branch
- Scanning the merge commit would double-count findings
- They're usually auto-generated, not authored by a developer

Set `--git-include-merges` to include them if needed.

### Q4: What happens if I scan a huge monorepo?

Use these flags to control scope:
- `--git-max-commits 100` — scan only the 100 most recent commits
- `--git-since <hash>` — scan only new commits since your last scan
- `--git-depth 50` — shallow clone (remote repos only)

The `MaxDiffSize` (1 MB) also protects against memory issues from auto-generated files.

### Q5: Can CredVigil scan private repositories?

Yes, if your git CLI has access. CredVigil delegates authentication to git:
- SSH keys configured in `~/.ssh/`
- HTTPS credentials from a credential helper
- GitHub CLI (`gh auth login`)

CredVigil itself never asks for or stores credentials.

### Q6: How does the diff parser handle renamed files?

When a file is renamed, git shows the patch with a `rename from`/`rename to` header. The parser detects this and:
- Sets `ChangeType = "R"` (renamed)
- Sets `OldPath` to the previous name
- Sets `FilePath` to the new name
- Still extracts any added lines for scanning

### Q7: What if I cancel a scan partway through (Ctrl+C)?

The scanner uses Go's `context` system. Cancellation is graceful:
1. The scanner checks for cancellation between commits
2. It stops walking and returns the results found so far
3. If a remote repo was cloned, `defer Cleanup()` still runs
4. Partial results are returned — nothing is lost

### Q8: Does scanning the initial commit work?

Yes. The initial commit has no parent to diff against. CredVigil handles this by using `git log -1 -p` which produces the full diff of everything introduced in that first commit. No commit is missed.

### Q9: How does the scanner know which detection rules to use?

It uses the same detection engine from Module 1 — all 276 rules plus entropy detection. The scanner simply feeds the added lines from each diff entry into `engine.ScanContent()`. No git-specific rules are needed because the content is just text, regardless of where it came from.

```mermaid
flowchart LR
    GIT["Added lines from git diff"] --> BUILD["Build content string"]
    BUILD --> ENGINE["Same 276-rule engine<br/>from Module 1"]
    ENGINE --> FINDINGS["Findings"]
    
    FILE["File content<br/>from disk"] --> ENGINE
    
    STDIN["Text from stdin"] --> ENGINE
```

### Q10: Does a shallow clone miss secrets?

Yes, potentially. A `--git-depth 50` clone only downloads the last 50 commits. If a secret was committed 100 commits ago, it won't be found. Use shallow clones only when:
- You're doing regular incremental scans
- You only care about recent history
- Full clone is too slow

### Q11: Why does CredVigil only scan added lines, not full files?

Efficiency and accuracy:
- **Efficiency**: Only scanning changed content is much faster than re-scanning entire files for every commit
- **Accuracy**: An added line is where a secret was *introduced*. Looking at unchanged lines would produce false duplicate findings for secrets that existed before
- **Completeness**: Across all commits, every line that was ever added gets scanned

### Q12: Can I see the scan progress as it runs?

The scanner tracks progress internally via `ScanProgress`:
```go
progress := scanner.Progress()
// progress.TotalCommits = 42
// progress.ScannedCommits = 15
// progress.CurrentCommit = "abc1234"
// progress.FindingsCount = 3
```

Currently, the CLI shows results at the end. Real-time progress display will be added when the Event Bus (Component 5) is ready.

---

## 16. Glossary

| Term | Definition |
|------|-----------|
| **Branch** | A parallel line of development in git. Default branch is usually `main` or `master`. |
| **Clone** | Download a complete copy of a remote repository, including all history. |
| **Commit** | A saved snapshot of the project at a point in time, with author, date, and message. |
| **Commit Hash** | A unique hexadecimal fingerprint (SHA-1) identifying a commit, e.g., `a1b2c3d4e5f6`. |
| **Context Cancellation** | A Go pattern for gracefully stopping long-running operations (e.g., on Ctrl+C). |
| **Diff** | The difference between two versions of a file — shows added and removed lines. |
| **DiffEntry** | CredVigil's structured representation of a single file's changes in a commit. |
| **GitScanner** | The orchestrating component that connects the walker, detection engine, and pipeline. |
| **Hunk** | A section of a diff showing consecutive changed lines, prefixed with `@@ ... @@`. |
| **Incremental Scan** | Scanning only commits that haven't been scanned before (via `--git-since`). |
| **Initial Commit** | The very first commit in a repository — has no parent commit. |
| **Merge Commit** | A commit that combines two branches — has two parent commits. |
| **Shallow Clone** | A partial clone with limited history depth (via `--git-depth`). |
| **Walking** | Iterating through commits one by one, examining each one's changes. |
| **Zero-Trust** | A security model where nothing is trusted by default — raw secrets are never stored or transmitted. |

---

## 17. What's Next?

In **Module 4: File System Watcher**, you'll learn how CredVigil monitors files in real-time — watching for changes as they happen, rather than scanning after the fact. This enables instant detection of secrets as developers save files.

```mermaid
flowchart LR
    subgraph DONE["✅ Completed"]
        M1["Module 1<br/>Detection Engine"]
        M2["Module 2<br/>Pipeline"]
        M3["Module 3<br/>Git Integration"]
    end
    subgraph NEXT["⬜ Next"]
        M4["Module 4<br/>File System Watcher"]
    end
    M1 --> M2 --> M3 --> M4
    style M3 fill:#51cf66,color:white
    style M4 fill:#ffd43b,color:black
```

---

*Copyright 2026 CredVigil Contributors. Licensed under the Apache License, Version 2.0.*
