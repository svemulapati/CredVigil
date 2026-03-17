# CredVigil Training Guide — Module 7: Storage Layer

> **Version**: 0.1.0  
> **Component**: Storage Layer (Component 12 of 15)  
> **Audience**: Everyone — no database background required. Written for learners preparing for interviews.  
> **Prerequisites**: Completion of Modules 1–6. Go 1.21+ installed (for hands-on exercises only).

---

## Table of Contents

1. [What Is the Storage Layer?](#1-what-is-the-storage-layer)
2. [Why Do We Need a Storage Layer?](#2-why-do-we-need-a-storage-layer)
3. [Key Concepts Explained](#3-key-concepts-explained)
   - 3.1 [What Is PostgreSQL?](#31-what-is-postgresql)
   - 3.2 [What Is TimescaleDB?](#32-what-is-timescaledb)
   - 3.3 [What Is a Hypertable?](#33-what-is-a-hypertable)
   - 3.4 [What Is a Connection Pool?](#34-what-is-a-connection-pool)
   - 3.5 [What Is a Repository Pattern?](#35-what-is-a-repository-pattern)
   - 3.6 [What Is a Database Migration?](#36-what-is-a-database-migration)
   - 3.7 [What Is JSONB?](#37-what-is-jsonb)
   - 3.8 [What Is a Continuous Aggregate?](#38-what-is-a-continuous-aggregate)
   - 3.9 [What Is a Retention Policy?](#39-what-is-a-retention-policy)
   - 3.10 [What Is Zero-Trust Persistence?](#310-what-is-zero-trust-persistence)
   - 3.11 [What Is a Transaction?](#311-what-is-a-transaction)
   - 3.12 [What Is a Database Index?](#312-what-is-a-database-index)
4. [Architecture Overview](#4-architecture-overview)
5. [Part 1: Database Schema Design](#5-part-1-database-schema-design)
   - 5.1 [The scan_results Table](#51-the-scan_results-table)
   - 5.2 [The findings Table (Hypertable)](#52-the-findings-table-hypertable)
   - 5.3 [The audit_logs Table (Hypertable)](#53-the-audit_logs-table-hypertable)
   - 5.4 [The daily_risk_summary View](#54-the-daily_risk_summary-view)
   - 5.5 [Indexes for Performance](#55-indexes-for-performance)
   - 5.6 [Retention Policies](#56-retention-policies)
6. [Part 2: Database Models in Go](#6-part-2-database-models-in-go)
   - 6.1 [StoredFinding — Flattened for the Database](#61-storedfinding--flattened-for-the-database)
   - 6.2 [StoredScanResult — Scan Metadata](#62-storedscanresult--scan-metadata)
   - 6.3 [AuditLog — Security Events](#63-auditlog--security-events)
   - 6.4 [JSONMap — JSONB Helper Type](#64-jsonmap--jsonb-helper-type)
   - 6.5 [ToStoredFinding — Model Conversion](#65-tostoredfinding--model-conversion)
   - 6.6 [FindingFilter — Query Predicates](#66-findingfilter--query-predicates)
7. [Part 3: Repository Interface](#7-part-3-repository-interface)
   - 7.1 [Why Use an Interface?](#71-why-use-an-interface)
   - 7.2 [The Repository Contract](#72-the-repository-contract)
   - 7.3 [Method Groups](#73-method-groups)
8. [Part 4: PostgreSQL Implementation](#8-part-4-postgresql-implementation)
   - 8.1 [Connection Pool Setup](#81-connection-pool-setup)
   - 8.2 [Saving Findings](#82-saving-findings)
   - 8.3 [Atomic Scan Result Storage](#83-atomic-scan-result-storage)
   - 8.4 [Dynamic Query Building](#84-dynamic-query-building)
   - 8.5 [TimescaleDB Analytics](#85-timescaledb-analytics)
   - 8.6 [Audit Logging](#86-audit-logging)
9. [Part 5: CLI Integration](#9-part-5-cli-integration)
   - 9.1 [The --store Flag](#91-the---store-flag)
   - 9.2 [The --db Flag](#92-the---db-flag)
   - 9.3 [Environment Variable Configuration](#93-environment-variable-configuration)
   - 9.4 [Backward Compatibility](#94-backward-compatibility)
10. [Practical Examples](#10-practical-examples)
    - 10.1 [Setting Up the Database from Scratch](#101-setting-up-the-database-from-scratch)
    - 10.2 [Running Your First Stored Scan](#102-running-your-first-stored-scan)
    - 10.3 [Querying the Data](#103-querying-the-data)
    - 10.4 [Building a Dashboard Query](#104-building-a-dashboard-query)
11. [How It Connects to Other Components](#11-how-it-connects-to-other-components)
12. [Interview Preparation](#12-interview-preparation)
13. [Summary](#13-summary)

---

## 1. What Is the Storage Layer?

The **Storage Layer** is the component that saves CredVigil's scan results to a database so they can be queried, analyzed, and tracked over time.

Think of it this way: without the storage layer, every time you run `credvigil scan`, the results appear on your screen and then disappear when you close the terminal. The storage layer is like writing those results into a permanent notebook that you can search through later.

**Before the Storage Layer:**
```
credvigil scan .
  → results printed to screen
  → gone forever
```

**After the Storage Layer:**
```
credvigil scan . --store
  → results printed to screen (same as before)
  → ALSO saved to PostgreSQL database
  → queryable weeks/months later
  → trend analysis over time
  → audit trail for compliance
```

The storage layer is **entirely opt-in** — if you don't pass `--store`, CredVigil works exactly as before.

---

## 2. Why Do We Need a Storage Layer?

### Problem 1: No Historical Record
Without storage, you can't answer questions like:
- "Did our last scan find fewer secrets than last week?"
- "What's our most common type of leaked secret?"
- "Have we been improving over the past month?"

### Problem 2: Compliance Requirements
Many organizations (especially in finance, healthcare, and government) require:
- An **audit trail** of every security scan
- Proof that secrets were detected and addressed
- Historical records for SOC2, HIPAA, or PCI-DSS compliance

### Problem 3: Team Visibility
Individual developers run scans locally, but security teams need a central view:
- Which repositories have the most secrets?
- Are CI/CD pipelines catching secrets before they ship?
- What types of secrets are most commonly leaked?

### Problem 4: Time-Series Analysis
Security is not a point-in-time activity — it's a trend:
- "We reduced critical findings from 50/week to 3/week over 6 months"
- "AWS key leaks spiked on Tuesday — let's investigate"
- This requires **time-series data**, which is exactly what TimescaleDB provides

---

## 3. Key Concepts Explained

### 3.1 What Is PostgreSQL?

**PostgreSQL** (often called "Postgres") is a free, open-source relational database. It's one of the most popular databases in the world, used by companies like Apple, Instagram, Spotify, and Netflix.

**Why PostgreSQL for CredVigil?**
- **Reliable**: Data is safe even if the power goes out (ACID compliance)
- **Extensible**: Supports extensions like TimescaleDB
- **Free**: No license fees, no vendor lock-in
- **Widely supported**: Runs everywhere — your laptop, servers, cloud providers

**Analogy**: If your data is like a library of books, PostgreSQL is the librarian who organizes them on shelves, creates an index card system, and can find any book instantly when you ask.

### 3.2 What Is TimescaleDB?

**TimescaleDB** is an extension for PostgreSQL that makes it exceptionally good at handling **time-series data** — data that is indexed by time.

Examples of time-series data:
- Stock prices (every second)
- Temperature readings (every minute)
- **Security scan findings** (every scan run)

**Why TimescaleDB for CredVigil?**
- Our findings have a `scanned_at` timestamp — they are inherently time-series
- We want queries like "show me findings from the last 7 days" to be fast
- We want automatic data management (old data gets cleaned up)

**How it works**: TimescaleDB automatically splits your data into **chunks** organized by time. When you query "last 7 days", it only looks at recent chunks instead of scanning the entire table.

### 3.3 What Is a Hypertable?

A **hypertable** is TimescaleDB's special table type. Externally, it looks like a regular PostgreSQL table, but internally it's split into time-based partitions called **chunks**.

```
Regular table:           Hypertable:
┌──────────────────┐     ┌──────────────────┐
│ All rows in one  │     │ Chunk: Jun 1–7   │
│ big pile         │     ├──────────────────┤
│                  │     │ Chunk: Jun 8–14  │
│                  │     ├──────────────────┤
│                  │     │ Chunk: Jun 15–21 │
└──────────────────┘     └──────────────────┘
```

**CredVigil uses 7-day chunks.** This means:
- Each week's findings are stored together
- Querying "last week's data" only touches one chunk
- Old chunks can be automatically deleted (retention policies)

### 3.4 What Is a Connection Pool?

When your application talks to a database, it creates a **connection** — like a phone call. Creating a new connection takes time (DNS lookup, TCP handshake, authentication).

A **connection pool** keeps several connections open and ready to use, like having multiple phone lines that are always connected.

```
Without pool:                With pool:
App → Create → Use → Close   App → Pool → Use → Return
App → Create → Use → Close        └─ Ready connections ─┘
App → Create → Use → Close
(Slow: connect + disconnect)  (Fast: grab, use, return)
```

**CredVigil's pool settings:**
- `MaxConns = 10`: Up to 10 simultaneous database connections
- `MinConns = 2`: Always keep at least 2 warm connections ready
- `MaxConnLifetime = 30 min`: Recycle connections every 30 minutes
- `HealthCheckPeriod = 30 sec`: Ping connections every 30 seconds to detect failures

### 3.5 What Is a Repository Pattern?

The **Repository Pattern** is a design pattern where you create an **interface** (a contract) that defines all database operations, and then implement that interface for a specific database.

```
Your Code  →  Repository Interface  →  PostgreSQL Implementation
                                   →  (future) SQLite Implementation
                                   →  (future) MySQL Implementation
```

**Why this matters:**
1. **Testability**: You can create a fake (mock) repository for tests without needing a real database
2. **Flexibility**: Switch databases in the future without changing any business logic
3. **Clean boundaries**: Your detection engine doesn't know (or care) what database is being used

**In CredVigil:**
- `Repository` is the interface (contract) defined in `internal/storage/repository.go`
- `PostgresRepository` is the concrete implementation in `internal/storage/postgres.go`

### 3.6 What Is a Database Migration?

A **migration** is a versioned SQL script that creates or modifies your database schema. Migrations provide:

1. **Reproducibility**: Run the same scripts on any machine to get the same database
2. **Version control**: Track schema changes alongside code changes
3. **Rollback capability**: Each migration has an "up" (apply) and "down" (undo)

**CredVigil's migrations:**
- `001_initial_schema.up.sql` — Creates all tables, indexes, hypertables, and retention policies
- `001_initial_schema.down.sql` — Drops everything (for rollback)

**Analogy**: Migrations are like building blueprints. The "up" migration builds the house, the "down" migration demolishes it. Each numbered migration is a version of the blueprints.

### 3.7 What Is JSONB?

**JSONB** is PostgreSQL's binary JSON column type. It stores structured data that doesn't fit neatly into fixed columns.

**Example use in CredVigil:**

In the `scan_results` table, different scans may have different severity distributions:
```json
// Scan A:
{"CRITICAL": 2, "HIGH": 5, "MEDIUM": 10}

// Scan B:
{"LOW": 3, "INFO": 100}
```

Rather than creating separate columns for every severity level, we store this as JSONB — one flexible column that holds any JSON structure.

**CredVigil uses JSONB for:**
- `severity_counts` in `scan_results` — breakdown of findings by severity
- `details` in `audit_logs` — event-specific metadata

### 3.8 What Is a Continuous Aggregate?

A **continuous aggregate** is a TimescaleDB feature that pre-computes summary data and keeps it updated automatically.

**Without continuous aggregate:**
```sql
-- This runs every time someone requests daily totals
-- It must scan millions of rows each time
SELECT date_trunc('day', scanned_at), COUNT(*)
FROM findings
GROUP BY 1;
```

**With continuous aggregate:**
```sql
-- TimescaleDB pre-computed the totals
-- This reads from a small summary table — instant results
SELECT * FROM daily_risk_summary;
```

**CredVigil's `daily_risk_summary`** pre-computes:
- Daily finding count
- Daily critical/high count
- Daily average confidence
- Number of unique secret types

It refreshes automatically and only recomputes data that has changed.

### 3.9 What Is a Retention Policy?

A **retention policy** automatically deletes data older than a specified age. This prevents the database from growing indefinitely.

**CredVigil's retention policies:**
- **Findings**: Deleted after **90 days** (3 months)
- **Audit logs**: Deleted after **365 days** (1 year)

**Why different durations?**
- Findings are high-volume (hundreds per scan) — 90 days gives enough trend data
- Audit logs are low-volume but compliance-critical — 1 year satisfies most regulations

**How it works**: TimescaleDB drops entire chunks (not individual rows), which is extremely fast. Dropping a 7-day chunk of millions of rows takes the same time as dropping 1 row.

### 3.10 What Is Zero-Trust Persistence?

**Zero-trust persistence** means we never store anything in the database that could compromise security if the database were breached.

**What we DO NOT store:**
- ❌ Raw secret values (e.g., the actual AWS access key)
- ❌ Unencrypted passwords
- ❌ Raw API tokens

**What we DO store:**
- ✅ SHA-256 **hash** of the secret (one-way, can't reverse)
- ✅ **Redacted** match (e.g., `AKIA****WXYZ` — first 4 and last 4 chars only)
- ✅ **Fingerprint** for deduplication (derived from rule + location + hash)
- ✅ Metadata: severity, confidence, entropy, file type, line number

**Result**: Even if someone gains unauthorized access to the database, they cannot extract any actual secrets. They would only see hashes and redacted snippets.

### 3.11 What Is a Transaction?

A **transaction** groups multiple database operations into a single "all-or-nothing" unit. Either everything succeeds, or nothing changes.

**CredVigil example:** When saving a scan result:
1. Insert the `scan_results` row
2. Insert 50 `findings` rows
3. Insert 1 `audit_logs` row

If step 2 fails halfway through (say after 25 findings), we don't want a partial result in the database. The transaction ensures all 50 findings are saved, or none are.

```
Without transaction:          With transaction:
Step 1: ✅ scan saved         Step 1: ✅ scan saved
Step 2: 25/50 findings        Step 2: 25/50 findings
Step 3: ❌ crash              Step 3: ❌ crash
Result: Broken data           Result: ROLLBACK — nothing saved
```

### 3.12 What Is a Database Index?

An **index** is a data structure that speeds up queries on specific columns. Without an index, the database must scan every row (like reading every page of a book). With an index, it can jump directly to matching rows (like using a book's table of contents).

**CredVigil creates 8 indexes on the findings table:**

| Index | Purpose |
|-------|---------|
| `idx_findings_fingerprint` | Quick deduplication checks |
| `idx_findings_secret_hash` | Find all occurrences of the same secret |
| `idx_findings_rule_id` | Which rules are firing most? |
| `idx_findings_severity` | Filter by severity level |
| `idx_findings_scan_id_time` | All findings for a given scan |
| `idx_findings_category` | Group findings by category |
| `idx_findings_secret_type` | Count by secret type |
| `idx_findings_severity_time` | Time-series queries filtered by severity |

**Trade-off**: Indexes make reads faster but writes slightly slower (the index must be updated). For CredVigil, reads (dashboards, queries) happen far more often than writes (scan completion), so this trade-off is worth it.

---

## 4. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        CredVigil CLI                            │
│                                                                  │
│  credvigil scan . --store --db "postgres://..."                  │
│                                                                  │
│  ┌──────────────┐    ┌───────────────┐    ┌──────────────────┐  │
│  │ Detection    │───▶│ Pipeline      │───▶│ Output           │  │
│  │ Engine       │    │ (hash, redact │    │ (JSON/text)      │  │
│  │ (369 rules)  │    │  enrich, etc) │    │                  │  │
│  └──────────────┘    └───────────────┘    └──────────────────┘  │
│                              │                                    │
│                              ▼                                    │
│                    ┌──────────────────┐                           │
│                    │ Storage Layer    │  (opt-in via --store)     │
│                    │                  │                           │
│                    │ ┌──────────────┐ │                           │
│                    │ │ Repository   │ │  ← Interface             │
│                    │ │ Interface    │ │                           │
│                    │ └──────┬───────┘ │                           │
│                    │        │         │                           │
│                    │ ┌──────▼───────┐ │                           │
│                    │ │ PostgreSQL   │ │  ← Implementation        │
│                    │ │ Repository   │ │                           │
│                    │ └──────┬───────┘ │                           │
│                    └────────┼─────────┘                           │
│                             │                                     │
└─────────────────────────────┼─────────────────────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  PostgreSQL +      │
                    │  TimescaleDB       │
                    │                    │
                    │  ┌──────────────┐  │
                    │  │ scan_results │  │
                    │  ├──────────────┤  │
                    │  │ findings     │◄─┤── Hypertable (7-day chunks)
                    │  ├──────────────┤  │
                    │  │ audit_logs   │◄─┤── Hypertable (7-day chunks)
                    │  ├──────────────┤  │
                    │  │ daily_risk   │◄─┤── Continuous Aggregate
                    │  │ _summary     │  │
                    │  └──────────────┘  │
                    └────────────────────┘
```

**Data flow:**
1. Detection engine finds secrets → Pipeline enriches them (hash, redact, classify)
2. Results are printed/output as usual (backward compatible)
3. If `--store` is passed, `persistResults()` also saves to PostgreSQL:
   a. Converts each `Finding` → `StoredFinding` (flattens source fields)
   b. Creates a `StoredScanResult` with metadata
   c. Saves everything in a single transaction
   d. Logs an audit event

---

## 5. Part 1: Database Schema Design

The database schema is defined in `migrations/001_initial_schema.up.sql`. Let's walk through each table.

### 5.1 The scan_results Table

This table stores **one row per scan invocation**. Every time you run `credvigil scan`, one row is created.

```sql
CREATE TABLE IF NOT EXISTS scan_results (
    id               TEXT PRIMARY KEY,        -- UUID generated by the app
    scanner_version  TEXT NOT NULL,            -- e.g., "0.1.0"
    scan_type        TEXT NOT NULL,            -- "file", "directory", "git"
    scan_target      TEXT NOT NULL,            -- What was scanned ("/path/to/project")
    started_at       TIMESTAMPTZ NOT NULL,     -- When the scan began
    finished_at      TIMESTAMPTZ NOT NULL,     -- When the scan ended
    duration_ms      BIGINT NOT NULL,          -- Duration in milliseconds
    total_findings   INTEGER NOT NULL,         -- Number of secrets found
    severity_counts  JSONB DEFAULT '{}',       -- {"CRITICAL": 2, "HIGH": 5}
    files_scanned    INTEGER DEFAULT 0,        -- Number of files processed
    rule_count       INTEGER DEFAULT 0,        -- Number of rules loaded
    config_hash      TEXT,                     -- Hash of scan configuration
    machine_name     TEXT,                     -- Hostname of scanning machine
    exit_code        INTEGER DEFAULT 0,        -- 0=clean, 1=findings, 2=error
    is_ci            BOOLEAN DEFAULT FALSE,    -- Was this run in CI/CD?
    ci_job_ref       TEXT                      -- CI job URL/reference
);
```

**Key design decisions:**
- **TEXT primary key**: We use application-generated UUIDs, not auto-increment integers. This allows offline ID generation and avoids sequence contention.
- **JSONB severity_counts**: Flexible — works even if we add new severity levels later.
- **is_ci**: Distinguishes local developer scans from CI/CD pipeline scans.

### 5.2 The findings Table (Hypertable)

This is the main table — it stores **every individual secret detection**. A single scan might produce hundreds of findings.

```sql
CREATE TABLE IF NOT EXISTS findings (
    id               TEXT NOT NULL,            -- UUID
    scan_id          TEXT NOT NULL REFERENCES scan_results(id),
    rule_id          TEXT NOT NULL,            -- Which detection rule fired
    secret_type      TEXT NOT NULL,            -- "aws-access-key-id", "stripe-api-key", etc.
    description      TEXT,                      -- Human-readable description
    severity         TEXT NOT NULL,            -- "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    confidence       DOUBLE PRECISION NOT NULL, -- 0.0 to 1.0
    secret_hash      TEXT NOT NULL,            -- SHA-256 of the actual secret
    fingerprint      TEXT NOT NULL,            -- Stable dedup identifier
    redacted_match   TEXT,                      -- "AKIA****WXYZ"
    entropy          DOUBLE PRECISION DEFAULT 0,
    bpe_efficiency   DOUBLE PRECISION,         -- BPE token efficiency (nullable)
    bpe_tokens       INTEGER,                  -- BPE token count (nullable)
    file_type        TEXT,                      -- "yaml", "json", "python", etc.
    environment      TEXT,                      -- "production", "staging", etc.
    category         TEXT,                      -- "cloud", "auth", "database", etc.
    source_type      TEXT,                      -- "file", "git-commit"
    source_location  TEXT,                      -- File path
    source_line      INTEGER DEFAULT 0,        -- Line number
    commit_hash      TEXT,                      -- Git commit (if applicable)
    author           TEXT,                      -- Git author (if applicable)
    branch           TEXT,                      -- Git branch (if applicable)
    scanned_at       TIMESTAMPTZ NOT NULL,     -- TimescaleDB partition key
    PRIMARY KEY (id, scanned_at)               -- Composite PK for hypertable
);

-- Convert to TimescaleDB hypertable with 7-day chunks
SELECT create_hypertable('findings', 'scanned_at',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists => TRUE
);
```

**Why a composite primary key?** TimescaleDB hypertables require the partition column (`scanned_at`) to be part of the primary key. This is because data is distributed across chunks by this column.

**Why are Source fields flattened?** In Go, a `Finding` has a nested `Source` struct. In the database, we "flatten" these into top-level columns:

```
Go struct:                    Database columns:
Finding {                     findings table:
  Source: {                     source_type TEXT,
    Type:     "file",           source_location TEXT,
    Location: "app.py",         source_line INTEGER,
    Line:     42,               commit_hash TEXT,
    CommitHash: "abc",          author TEXT,
    Author: "dev",              branch TEXT
    Branch: "main",
  }
}
```

**Why flatten?** Because you can't index inside a nested struct in SQL. Flattening allows us to create indexes on `source_location`, `commit_hash`, etc.

### 5.3 The audit_logs Table (Hypertable)

This table records **every security-relevant event** for compliance and forensics.

```sql
CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGSERIAL,                   -- Auto-increment
    timestamp   TIMESTAMPTZ NOT NULL,        -- When the event occurred
    event_type  TEXT NOT NULL,               -- "scan.completed", "finding.detected"
    actor       TEXT NOT NULL,               -- Who/what triggered it ("cli", "ci-bot")
    scan_id     TEXT,                        -- Related scan (if applicable)
    finding_id  TEXT,                        -- Related finding (if applicable)
    details     JSONB DEFAULT '{}',          -- Event-specific metadata
    severity    TEXT DEFAULT 'info',         -- Event severity
    source_ip   TEXT,                        -- Source IP for API events
    PRIMARY KEY (id, timestamp)              -- Composite for hypertable
);

SELECT create_hypertable('audit_logs', 'timestamp',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists => TRUE
);
```

**Example audit events:**
- `scan.completed` — A scan finished (details include duration, target, finding count)
- `scan.failed` — A scan encountered an error
- `finding.suppressed` — A finding was marked as a false positive (future feature)

### 5.4 The daily_risk_summary View

This continuous aggregate pre-computes daily summaries for dashboards:

```sql
CREATE MATERIALIZED VIEW daily_risk_summary
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', scanned_at) AS day,
    COUNT(*)                          AS total_findings,
    COUNT(*) FILTER (WHERE severity IN ('CRITICAL', 'HIGH')) AS critical_high_count,
    COALESCE(AVG(confidence), 0)      AS avg_confidence,
    COUNT(DISTINCT secret_type)       AS unique_secret_types
FROM findings
GROUP BY day
WITH NO DATA;

-- Auto-refresh: update every hour, look back 3 days for late data
SELECT add_continuous_aggregate_policy('daily_risk_summary',
    start_offset    => INTERVAL '3 days',
    end_offset      => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists   => TRUE
);
```

**What this gives you:**
```sql
-- Instant dashboard query (reads from pre-computed table)
SELECT day, total_findings, critical_high_count
FROM daily_risk_summary
ORDER BY day DESC LIMIT 30;
```

### 5.5 Indexes for Performance

The migration creates 8 targeted indexes on the findings table:

```sql
-- Deduplication: "Have we seen this exact secret before?"
CREATE INDEX idx_findings_fingerprint ON findings (fingerprint);

-- Secret tracking: "Where else does this secret appear?"
CREATE INDEX idx_findings_secret_hash ON findings (secret_hash);

-- Rule analysis: "Which rules fire most often?"
CREATE INDEX idx_findings_rule_id ON findings (rule_id);

-- Severity filtering: "Show me only CRITICAL findings"
CREATE INDEX idx_findings_severity ON findings (severity);

-- Scan correlation: "All findings from scan XYZ"
CREATE INDEX idx_findings_scan_id_time ON findings (scan_id, scanned_at DESC);

-- Category grouping: "All cloud-related findings"
CREATE INDEX idx_findings_category ON findings (category);

-- Secret type analysis: "How many AWS keys vs Stripe keys?"
CREATE INDEX idx_findings_secret_type ON findings (secret_type);

-- Compound: "Critical findings in the last week" (most common dashboard query)
CREATE INDEX idx_findings_severity_time ON findings (severity, scanned_at DESC);
```

**Interview tip**: When asked "How would you optimize a database for read-heavy workloads?", indexes are the primary answer. Mention the trade-off: faster reads, slightly slower writes.

### 5.6 Retention Policies

```sql
-- Auto-delete findings older than 90 days
SELECT add_retention_policy('findings', INTERVAL '90 days', if_not_exists => TRUE);

-- Auto-delete audit logs older than 365 days
SELECT add_retention_policy('audit_logs', INTERVAL '365 days', if_not_exists => TRUE);
```

TimescaleDB implements retention by **dropping entire chunks**, not deleting individual rows. This is extremely efficient:
- Deleting 10 million rows one-by-one: ~10 minutes
- Dropping a chunk containing 10 million rows: ~10 milliseconds

---

## 6. Part 2: Database Models in Go

The database models live in `pkg/models/storage.go`. They bridge the gap between Go structs and PostgreSQL tables.

### 6.1 StoredFinding — Flattened for the Database

The in-memory `Finding` struct has nested fields (like `Source`). `StoredFinding` flattens everything for the database:

```go
type StoredFinding struct {
    ID             string    `json:"id" db:"id"`
    ScanID         string    `json:"scan_id" db:"scan_id"`
    RuleID         string    `json:"rule_id" db:"rule_id"`
    SecretType     string    `json:"secret_type" db:"secret_type"`
    Description    string    `json:"description" db:"description"`
    Severity       string    `json:"severity" db:"severity"`
    Confidence     float64   `json:"confidence" db:"confidence"`
    SecretHash     string    `json:"secret_hash" db:"secret_hash"`
    Fingerprint    string    `json:"fingerprint" db:"fingerprint"`
    RedactedMatch  string    `json:"redacted_match" db:"redacted_match"`
    Entropy        float64   `json:"entropy" db:"entropy"`
    BPEEfficiency  *float64  `json:"bpe_efficiency,omitempty" db:"bpe_efficiency"`
    BPETokens      *int      `json:"bpe_tokens,omitempty" db:"bpe_tokens"`
    FileType       string    `json:"file_type" db:"file_type"`
    Environment    string    `json:"environment" db:"environment"`
    Category       string    `json:"category" db:"category"`
    // Flattened source fields:
    SourceType     string    `json:"source_type" db:"source_type"`
    SourceLocation string    `json:"source_location" db:"source_location"`
    SourceLine     int       `json:"source_line" db:"source_line"`
    CommitHash     string    `json:"commit_hash,omitempty" db:"commit_hash"`
    Author         string    `json:"author,omitempty" db:"author"`
    Branch         string    `json:"branch,omitempty" db:"branch"`
    ScannedAt      time.Time `json:"scanned_at" db:"scanned_at"`
}
```

**Why pointers for BPEEfficiency and BPETokens?**
```go
BPEEfficiency *float64  // Pointer = nullable
BPETokens     *int      // nil means "not computed"
```
Not every finding has BPE analysis. In Go, a `float64` has a zero value of `0.0`, which is different from "not computed". Using a pointer allows us to represent `NULL` in the database.

### 6.2 StoredScanResult — Scan Metadata

```go
type StoredScanResult struct {
    ID             string    `json:"id" db:"id"`
    ScannerVersion string    `json:"scanner_version" db:"scanner_version"`
    ScanType       string    `json:"scan_type" db:"scan_type"`
    ScanTarget     string    `json:"scan_target" db:"scan_target"`
    StartedAt      time.Time `json:"started_at" db:"started_at"`
    FinishedAt     time.Time `json:"finished_at" db:"finished_at"`
    DurationMs     int64     `json:"duration_ms" db:"duration_ms"`
    TotalFindings  int       `json:"total_findings" db:"total_findings"`
    SeverityCounts JSONMap   `json:"severity_counts" db:"severity_counts"`
    FilesScanned   int       `json:"files_scanned" db:"files_scanned"`
    RuleCount      int       `json:"rule_count" db:"rule_count"`
    ConfigHash     string    `json:"config_hash,omitempty" db:"config_hash"`
    MachineName    string    `json:"machine_name,omitempty" db:"machine_name"`
    ExitCode       int       `json:"exit_code" db:"exit_code"`
    IsCI           bool      `json:"is_ci" db:"is_ci"`
    CIJobRef       string    `json:"ci_job_ref,omitempty" db:"ci_job_ref"`
}
```

**Notice `SeverityCounts JSONMap`** — this maps to a JSONB column. The `JSONMap` type handles serialization to/from JSON automatically.

### 6.3 AuditLog — Security Events

```go
type AuditLog struct {
    ID        int64     `json:"id" db:"id"`
    Timestamp time.Time `json:"timestamp" db:"timestamp"`
    EventType string    `json:"event_type" db:"event_type"`
    Actor     string    `json:"actor" db:"actor"`
    ScanID    *string   `json:"scan_id,omitempty" db:"scan_id"`
    FindingID *string   `json:"finding_id,omitempty" db:"finding_id"`
    Details   JSONMap   `json:"details" db:"details"`
    Severity  string    `json:"severity" db:"severity"`
    SourceIP  string    `json:"source_ip,omitempty" db:"source_ip"`
}
```

**ScanID and FindingID are pointers** (`*string`) because not every audit event relates to a specific scan or finding. For example, a "system.startup" event has no scan ID.

### 6.4 JSONMap — JSONB Helper Type

```go
type JSONMap map[string]interface{}

// Value converts the map to JSON bytes for PostgreSQL
func (m JSONMap) Value() (driver.Value, error) {
    if m == nil {
        return []byte("{}"), nil
    }
    return json.Marshal(m)
}

// Scan reads JSON bytes from PostgreSQL into the map
func (m *JSONMap) Scan(src interface{}) error {
    // Handles []byte, string, and nil inputs
}
```

This type implements two Go interfaces:
- `driver.Valuer` — tells the database driver how to send data TO the database
- `sql.Scanner` — tells the database driver how to read data FROM the database

**Interview tip**: This is an excellent example of **interface satisfaction** in Go. By implementing just two methods, our custom type integrates seamlessly with any database driver.

### 6.5 ToStoredFinding — Model Conversion

```go
func ToStoredFinding(f *Finding, scanID string, scannedAt time.Time) StoredFinding {
    sf := StoredFinding{
        ID:             f.ID,
        ScanID:         scanID,
        Severity:       f.Severity.String(),    // Enum → string
        SecretType:     string(f.SecretType),    // Type alias → string
        SourceType:     f.Source.Type,           // Flatten nested struct
        SourceLocation: f.Source.Location,
        SourceLine:     f.Source.Line,
        CommitHash:     f.Source.CommitHash,
        // ... all other fields ...
    }

    // Extract BPE metadata from the Metadata map (if present)
    if f.Metadata != nil {
        if eff, ok := f.Metadata["bpe_efficiency"]; ok {
            var v float64
            if _, err := fmt.Sscanf(eff, "%f", &v); err == nil {
                sf.BPEEfficiency = &v
            }
        }
    }

    return sf
}
```

**Why is this a standalone function, not a method on Finding?**
Because `Finding` is in the `models` package (used everywhere) and shouldn't know about database-specific concepts like `scanID` or `scannedAt`. The converter lives in the same package but keeps concerns separated.

### 6.6 FindingFilter — Query Predicates

```go
type FindingFilter struct {
    ScanID        string
    MinSeverity   *Severity
    MinConfidence *float64
    SecretType    string
    Category      string
    RuleID        string
    Fingerprint   string
    SecretHash    string
    Since         *time.Time
    Until         *time.Time
    Limit         int
    Offset        int
}
```

This struct represents all the ways you can filter findings. The `buildFilterQuery` function dynamically constructs SQL WHERE clauses from these fields.

---

## 7. Part 3: Repository Interface

### 7.1 Why Use an Interface?

```go
// Bad: Directly using PostgreSQL everywhere
func saveFinding(pool *pgxpool.Pool, f *StoredFinding) error { ... }

// Good: Program against an interface
type Repository interface {
    SaveFinding(ctx context.Context, f *StoredFinding) error
}
```

Benefits:
1. **Test without a database**: Create a `MockRepository` that stores findings in memory
2. **Swap implementations**: Today PostgreSQL, tomorrow maybe DuckDB for embedded mode
3. **Dependency inversion**: High-level code (CLI) depends on the abstraction, not the implementation

### 7.2 The Repository Contract

```go
type Repository interface {
    // Findings
    SaveFinding(ctx context.Context, f *models.StoredFinding) error
    SaveFindings(ctx context.Context, findings []models.StoredFinding) error
    GetFindingByID(ctx context.Context, id string) (*models.StoredFinding, error)
    FindByFingerprint(ctx context.Context, fingerprint string) ([]models.StoredFinding, error)
    FindBySecretHash(ctx context.Context, secretHash string) ([]models.StoredFinding, error)
    FindByFilter(ctx context.Context, filter models.FindingFilter) ([]models.StoredFinding, error)
    CountFindings(ctx context.Context, filter models.FindingFilter) (int64, error)

    // Scan Results
    SaveScanResult(ctx context.Context, scan *models.StoredScanResult, findings []models.StoredFinding) error
    GetScanResult(ctx context.Context, scanID string) (*models.StoredScanResult, error)
    ListScanResults(ctx context.Context, limit, offset int) ([]models.StoredScanResult, error)

    // Audit Logs
    LogEvent(ctx context.Context, log *models.AuditLog) error
    ListAuditLogs(ctx context.Context, since, until time.Time, eventType string, limit, offset int) ([]models.AuditLog, error)

    // Analytics
    GetRiskTrends(ctx context.Context, since, until time.Time, interval string) ([]models.RiskTrend, error)
    GetCategoryBreakdown(ctx context.Context, since, until time.Time) ([]models.CategoryBreakdown, error)
    GetTopSecretTypes(ctx context.Context, limit int, since, until time.Time) ([]SecretTypeCount, error)

    // Lifecycle
    HealthCheck(ctx context.Context) error
    Close() error
}
```

### 7.3 Method Groups

| Group | Methods | Purpose |
|-------|---------|---------|
| **Findings** | SaveFinding, SaveFindings, GetFindingByID, FindByFingerprint, FindBySecretHash, FindByFilter, CountFindings | CRUD for individual detections |
| **Scan Results** | SaveScanResult, GetScanResult, ListScanResults | Manage scan-level metadata |
| **Audit Logs** | LogEvent, ListAuditLogs | Compliance and forensics |
| **Analytics** | GetRiskTrends, GetCategoryBreakdown, GetTopSecretTypes | Dashboard queries |
| **Lifecycle** | HealthCheck, Close | Connection management |

**Every method takes `context.Context`** as its first parameter. This follows Go best practices and allows:
- **Timeouts**: "Cancel this query if it takes more than 5 seconds"
- **Cancellation**: "The user pressed Ctrl+C, stop all database operations"

---

## 8. Part 4: PostgreSQL Implementation

### 8.1 Connection Pool Setup

```go
func NewPostgresRepository(ctx context.Context, connString string) (*PostgresRepository, error) {
    config, err := pgxpool.ParseConfig(connString)
    if err != nil {
        return nil, fmt.Errorf("storage: invalid connection string: %w", err)
    }

    // Pool tuning for scan workloads (bursty writes, rare reads)
    config.MaxConns = 10
    config.MinConns = 2
    config.MaxConnLifetime = 30 * time.Minute
    config.MaxConnIdleTime = 5 * time.Minute
    config.HealthCheckPeriod = 30 * time.Second

    pool, err := pgxpool.NewWithConfig(ctx, config)
    if err != nil {
        return nil, fmt.Errorf("storage: failed to create connection pool: %w", err)
    }

    // Verify connectivity before returning
    if err := pool.Ping(ctx); err != nil {
        pool.Close()
        return nil, fmt.Errorf("storage: database ping failed: %w", err)
    }

    return &PostgresRepository{pool: pool}, nil
}
```

**Key points:**
- `pgxpool` is the connection pool from the `pgx` library (Go's fastest PostgreSQL driver)
- We call `Ping()` immediately to **fail fast** if the database is unreachable
- If `Ping()` fails, we close the pool to clean up resources

### 8.2 Saving Findings

```go
func (r *PostgresRepository) SaveFinding(ctx context.Context, f *models.StoredFinding) error {
    _, err := r.pool.Exec(ctx, insertFindingSQL,
        f.ID, f.ScanID, f.RuleID, f.SecretType, f.Description, f.Severity,
        f.Confidence, f.SecretHash, f.Fingerprint, f.RedactedMatch, f.Entropy,
        f.BPEEfficiency, f.BPETokens, f.FileType, f.Environment, f.Category,
        f.SourceType, f.SourceLocation, f.SourceLine, f.CommitHash, f.Author,
        f.Branch, f.ScannedAt,
    )
    return err
}
```

The SQL uses `ON CONFLICT (id) DO NOTHING` — if a finding with the same ID already exists, the insert is silently ignored. This makes the operation **idempotent** (safe to retry).

### 8.3 Atomic Scan Result Storage

```go
func (r *PostgresRepository) SaveScanResult(ctx context.Context,
    scan *models.StoredScanResult, findings []models.StoredFinding) error {

    tx, err := r.pool.Begin(ctx)         // Start transaction
    if err != nil {
        return err
    }
    defer tx.Rollback(ctx)               // Rollback if we don't commit

    // 1. Insert scan result
    _, err = tx.Exec(ctx, insertScanResultSQL, scan.ID, ...)

    // 2. Insert all findings (in the same transaction)
    for i := range findings {
        _, err = tx.Exec(ctx, insertFindingSQL, findings[i].ID, ...)
    }

    return tx.Commit(ctx)                // All-or-nothing commit
}
```

**The `defer tx.Rollback(ctx)` is crucial.** If anything fails (or panics) before `Commit()`, the deferred rollback ensures no partial data is left in the database. After a successful `Commit()`, `Rollback()` is a no-op.

### 8.4 Dynamic Query Building

The `buildFilterQuery` function constructs SQL WHERE clauses dynamically:

```go
func buildFilterQuery(base string, filter models.FindingFilter) (string, []interface{}) {
    var conditions []string
    var args []interface{}

    if filter.ScanID != "" {
        args = append(args, filter.ScanID)
        conditions = append(conditions, fmt.Sprintf("scan_id = $%d", len(args)))
    }
    if filter.Category != "" {
        args = append(args, filter.Category)
        conditions = append(conditions, fmt.Sprintf("category = $%d", len(args)))
    }
    // ... more filter fields ...

    query := base
    if len(conditions) > 0 {
        query += " WHERE " + strings.Join(conditions, " AND ")
    }
    return query, args
}
```

**Why parameterized queries ($1, $2, ...)?**
This prevents **SQL injection attacks**. The actual values are sent separately from the SQL command, so a malicious input like `'; DROP TABLE findings;--` is treated as a literal string, not SQL code.

**Severity comparison is interesting:**
```sql
CASE severity
    WHEN 'CRITICAL' THEN 5
    WHEN 'HIGH' THEN 4
    WHEN 'MEDIUM' THEN 3
    WHEN 'LOW' THEN 2
    WHEN 'INFO' THEN 1
    ELSE 0
END >= CASE $1
    WHEN 'CRITICAL' THEN 5
    ...
END
```
Since severity is stored as text, we use a `CASE` expression to map it to a numeric value for comparison. This lets "minimum severity = HIGH" match both HIGH and CRITICAL findings.

### 8.5 TimescaleDB Analytics

The `GetRiskTrends` method uses TimescaleDB's `time_bucket` function:

```go
func (r *PostgresRepository) GetRiskTrends(ctx context.Context,
    since, until time.Time, interval string) ([]models.RiskTrend, error) {

    // SECURITY: Validate interval against whitelist
    validIntervals := map[string]bool{
        "1 hour": true, "6 hours": true, "12 hours": true,
        "1 day": true, "1 week": true, "1 month": true,
    }
    if !validIntervals[interval] {
        return nil, fmt.Errorf("invalid interval %q", interval)
    }

    query := fmt.Sprintf(`
        SELECT
            time_bucket('%s', scanned_at) AS bucket,
            COUNT(*) AS finding_count,
            COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical,
            COUNT(*) FILTER (WHERE severity = 'HIGH') AS high,
            AVG(confidence) AS avg_confidence,
            AVG(entropy) AS avg_entropy,
            COUNT(DISTINCT secret_type) AS unique_types
        FROM findings
        WHERE scanned_at >= $1 AND scanned_at <= $2
        GROUP BY bucket
        ORDER BY bucket ASC
    `, interval)

    rows, err := r.pool.Query(ctx, query, since, until)
    // ... scan rows into []RiskTrend
}
```

**Why whitelist the interval?** Because `interval` is interpolated directly into the SQL string (it's an interval literal, not a parameter). Without validation, an attacker could inject SQL. The whitelist ensures only safe values are accepted.

### 8.6 Audit Logging

```go
func (r *PostgresRepository) LogEvent(ctx context.Context, log *models.AuditLog) error {
    detailsJSON, err := log.Details.Value()  // Convert JSONMap → JSON bytes
    _, err = r.pool.Exec(ctx,
        `INSERT INTO audit_logs (timestamp, event_type, actor, scan_id,
         finding_id, details, severity, source_ip)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        log.Timestamp, log.EventType, log.Actor, log.ScanID,
        log.FindingID, detailsJSON, log.Severity, log.SourceIP,
    )
    return err
}
```

---

## 9. Part 5: CLI Integration

### 9.1 The --store Flag

The `--store` flag tells CredVigil to persist results to the database after scanning:

```bash
credvigil scan . --store
```

**What happens when you add --store:**
1. Scan runs normally (all output is the same)
2. After output, `persistResults()` is called:
   - Connects to PostgreSQL
   - Converts findings to database format
   - Saves scan result + findings + audit log in a transaction
3. If the database is unavailable, a **warning** is printed — the scan still succeeds

**This design means storage failures are non-fatal.** You always get your scan results, even if the database is down.

### 9.2 The --db Flag

Specifies the connection string:

```bash
credvigil scan . --store --db "postgres://user:pass@host:port/dbname"
```

**Connection string format:**
```
postgres://username:password@hostname:port/database?sslmode=disable
│          │        │        │        │    │        │
│          │        │        │        │    │        └─ SSL mode
│          │        │        │        │    └─ Database name
│          │        │        │        └─ Port (default: 5432)
│          │        │        └─ Hostname
│          │        └─ Password
│          └─ Username
└─ Scheme (always "postgres")
```

### 9.3 Environment Variable Configuration

Instead of typing the connection string every time:

```bash
# Set once in your shell profile
export CREDVIGIL_DB="postgres://credvigil:secret@localhost:5432/credvigil"

# Now just use --store
credvigil scan . --store
```

**Precedence:**
1. `--db` flag (highest priority)
2. `CREDVIGIL_DB` environment variable
3. Error if neither is set when `--store` is used

### 9.4 Backward Compatibility

**Without --store** (default):
- No database connection is attempted
- No `pgx` driver code is executed (though it's compiled in)
- Zero overhead — identical behavior to before the storage layer existed

**With --store:**
- Database connection is established only after the scan completes
- If the database is unreachable, a warning is logged and the scan result is still output normally
- Storage never affects the exit code (0 = clean, 1 = findings, 2 = error — same as always)

---

## 10. Practical Examples

### 10.1 Setting Up the Database from Scratch

**Step 1: Start PostgreSQL + TimescaleDB with Docker**

```bash
# Pull and run TimescaleDB (includes PostgreSQL)
docker run -d \
  --name credvigil-db \
  -e POSTGRES_USER=credvigil \
  -e POSTGRES_PASSWORD=secret \
  -e POSTGRES_DB=credvigil \
  -p 5432:5432 \
  timescale/timescaledb:latest-pg16

# Verify it's running
docker logs credvigil-db | tail -5
# You should see: "database system is ready to accept connections"
```

**Step 2: Run the Migration**

```bash
# Apply the schema
psql "postgres://credvigil:secret@localhost:5432/credvigil" \
  -f migrations/001_initial_schema.up.sql

# You should see output like:
# CREATE EXTENSION
# CREATE TABLE
# create_hypertable
# CREATE INDEX (×8)
# ...
```

**Step 3: Verify the Setup**

```bash
# Connect and list tables
psql "postgres://credvigil:secret@localhost:5432/credvigil" -c '\dt'

# Expected output:
#          List of relations
#  Schema |     Name      | Type  |   Owner
# --------+---------------+-------+-----------
#  public | audit_logs    | table | credvigil
#  public | findings      | table | credvigil
#  public | scan_results  | table | credvigil
```

### 10.2 Running Your First Stored Scan

```bash
# Set the connection string
export CREDVIGIL_DB="postgres://credvigil:secret@localhost:5432/credvigil"

# Run a scan with storage enabled
credvigil scan /path/to/your/project --store

# Expected output (normal scan output + storage confirmation):
# === CredVigil Scan Results ===
# Total findings: 5
# [CRITICAL]  AWS Secret Access Key in config/aws.yaml:12
# [HIGH]      Stripe API Key in src/payments.go:88
# ...
# ✓ Results persisted to PostgreSQL (scan abc123, 5 findings)
```

### 10.3 Querying the Data

Connect to your database and explore:

```bash
psql "postgres://credvigil:secret@localhost:5432/credvigil"
```

**How many findings do we have?**
```sql
SELECT COUNT(*) FROM findings;
```

**Recent critical findings:**
```sql
SELECT secret_type, redacted_match, source_location, source_line, scanned_at
FROM findings
WHERE severity = 'CRITICAL'
ORDER BY scanned_at DESC
LIMIT 10;
```

**Findings by category:**
```sql
SELECT category, COUNT(*) AS total,
       ROUND(AVG(confidence)::numeric, 2) AS avg_confidence
FROM findings
GROUP BY category
ORDER BY total DESC;
```

**Scan history:**
```sql
SELECT id, scan_target, total_findings, duration_ms,
       started_at, is_ci
FROM scan_results
ORDER BY started_at DESC
LIMIT 10;
```

**Find duplicate secrets across files:**
```sql
SELECT secret_hash, COUNT(*) AS occurrences,
       array_agg(DISTINCT source_location) AS files
FROM findings
GROUP BY secret_hash
HAVING COUNT(*) > 1
ORDER BY occurrences DESC;
```

### 10.4 Building a Dashboard Query

**Weekly trend (last 4 weeks):**
```sql
SELECT
    time_bucket('1 week', scanned_at) AS week,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical,
    COUNT(*) FILTER (WHERE severity = 'HIGH') AS high,
    COUNT(*) FILTER (WHERE severity = 'MEDIUM') AS medium,
    COUNT(*) FILTER (WHERE severity = 'LOW') AS low,
    ROUND(AVG(confidence)::numeric, 3) AS avg_conf
FROM findings
WHERE scanned_at > NOW() - INTERVAL '4 weeks'
GROUP BY week
ORDER BY week DESC;
```

**Top 10 leaking files:**
```sql
SELECT source_location, COUNT(*) AS secrets_found,
       MAX(severity) AS worst_severity
FROM findings
WHERE scanned_at > NOW() - INTERVAL '30 days'
GROUP BY source_location
ORDER BY secrets_found DESC
LIMIT 10;
```

**CI vs Local scan comparison:**
```sql
SELECT
    CASE WHEN is_ci THEN 'CI/CD' ELSE 'Local' END AS scan_source,
    COUNT(*) AS scan_count,
    SUM(total_findings) AS total_findings,
    ROUND(AVG(duration_ms)) AS avg_duration_ms
FROM scan_results
WHERE started_at > NOW() - INTERVAL '30 days'
GROUP BY is_ci;
```

---

## 11. How It Connects to Other Components

| Component | Connection to Storage Layer |
|-----------|---------------------------|
| **Detection Engine** (Module 1) | Findings from the engine are converted via `ToStoredFinding()` and persisted |
| **Pipeline** (Module 2) | Pipeline enriches findings (hash, redact, classify) before storage — only enriched data is stored |
| **Git Integration** (Module 3) | Git-specific fields (commit hash, author, branch) are stored in the flattened finding model |
| **File Watcher** (Module 4) | Future: real-time watcher findings could be streamed to storage |
| **Event Bus** (Module 5) | Future: storage events could be published on the bus for notifications |
| **CI/CD Integration** (Module 6) | CI/CD scans set `is_ci=true` and `ci_job_ref` in scan results; audit logs track CI activity |

**Zero-Trust Chain:**
1. Detection Engine finds a secret (has raw text)
2. Pipeline takes the raw secret → hashes it (SHA-256), redacts it, clears raw text
3. Storage layer receives ONLY the hashed, redacted, fingerprinted version
4. Database never sees the actual secret

---

## 12. Interview Preparation

### Architecture Questions

**Q: Why did you choose PostgreSQL over MongoDB?**
A: Our data is relational (findings belong to scans, scans relate to audit logs). PostgreSQL's foreign keys enforce data integrity. Additionally, TimescaleDB's time-series optimizations (hypertables, continuous aggregates) are purpose-built for our analytics needs. MongoDB would require more application-level data consistency management.

**Q: Why use the Repository pattern?**
A: Three reasons: (1) Testability — we can mock the repository in unit tests without needing a running database. (2) Flexibility — we could add a SQLite repository for embedded/offline mode. (3) Separation of concerns — the detection engine doesn't know or care about PostgreSQL.

**Q: How do you prevent SQL injection?**
A: All user-controlled values are passed as parameterized query arguments ($1, $2, etc.), never interpolated into SQL strings. The one exception is the time_bucket interval, which is validated against a strict whitelist before interpolation.

**Q: Why are storage failures non-fatal?**
A: The primary purpose of CredVigil is to detect secrets. Storage is a secondary convenience feature. If the database is down, users should still get their scan results printed to stdout. Making storage failures fatal would reduce availability for a non-critical function.

### Performance Questions

**Q: How does the storage layer handle high-volume scans?**
A: Multiple findings are saved in a single transaction, reducing round-trips. The connection pool (pgxpool) reuses connections. Hypertable chunking ensures queries against recent data only touch relevant partitions. 8 indexes optimize common query patterns.

**Q: What happens to old data?**
A: TimescaleDB retention policies automatically drop chunks older than 90 days (findings) or 365 days (audit logs). Chunk-level drops are O(1) regardless of data volume — far faster than row-level DELETE.

**Q: How would you scale this for 1000 repositories?**
A: For moderate scale: increase connection pool size, add read replicas for analytics queries. For large scale: use TimescaleDB's distributed hypertables across multiple nodes. The Repository interface makes it transparent — calling code doesn't change.

### Security Questions

**Q: What if someone gains access to the database?**
A: They would find SHA-256 hashes (irreversible), redacted matches (first 4 + last 4 chars), and metadata. No raw secrets are stored. The database is essentially a record of "where secrets existed" not "what the secrets were."

**Q: How do you handle connection string security?**
A: Connection strings can be passed via environment variable (CREDVIGIL_DB) instead of command-line argument (which would appear in process listings). In CI/CD, it should be stored as a GitHub Secret. The connection string supports sslmode=require for encrypted connections.

---

## 13. Summary

| What | Details |
|------|---------|
| **Database** | PostgreSQL 16 + TimescaleDB extension |
| **Driver** | pgx/v5 — Go's fastest PostgreSQL driver |
| **Connection** | pgxpool connection pool (10 max, 2 min) |
| **Pattern** | Repository interface → PostgreSQL implementation |
| **Tables** | scan_results, findings (hypertable), audit_logs (hypertable) |
| **Indexes** | 8 on findings, 2 on audit_logs |
| **Retention** | 90 days (findings), 365 days (audit logs) |
| **Analytics** | TimescaleDB time_bucket, continuous aggregates |
| **CLI** | `--store` (opt-in), `--db` (connection string) |
| **Zero-Trust** | SHA-256 hashes only — no raw secrets in DB |
| **Tests** | 31 tests: 16 model tests + 15 storage/query builder tests |
| **Files** | pkg/models/storage.go, internal/storage/repository.go, internal/storage/postgres.go, migrations/ |

**What's next?** With the storage layer in place, future components (API Layer, Dashboard, Notifications) have a solid persistence foundation to build on. The Repository interface ensures they can access data without knowing about PostgreSQL internals.
