-- CredVigil Storage Layer — Migration 001: Initial Schema
-- PostgreSQL + TimescaleDB
--
-- Run this migration with:
--   psql -d credvigil -f migrations/001_initial_schema.up.sql
--
-- Prerequisites:
--   CREATE DATABASE credvigil;
--   \c credvigil
--   CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ─────────────────────────────────────────────────────────────────────────────
-- Enable required extensions
-- ─────────────────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─────────────────────────────────────────────────────────────────────────────
-- Table: scan_results
-- One row per scan invocation (CLI run, CI/CD job, pre-commit hook).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scan_results (
    id               TEXT PRIMARY KEY,
    scanner_version  TEXT        NOT NULL DEFAULT '0.1.0',
    scan_type        TEXT        NOT NULL DEFAULT 'file',
    scan_target      TEXT        NOT NULL DEFAULT '.',
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_ms      BIGINT      NOT NULL DEFAULT 0,
    total_findings   INTEGER     NOT NULL DEFAULT 0,
    severity_counts  JSONB       NOT NULL DEFAULT '{}',
    files_scanned    INTEGER     NOT NULL DEFAULT 0,
    rule_count       INTEGER     NOT NULL DEFAULT 0,
    config_hash      TEXT        NOT NULL DEFAULT '',
    machine_name     TEXT        NOT NULL DEFAULT '',
    exit_code        INTEGER     NOT NULL DEFAULT 0,
    is_ci            BOOLEAN     NOT NULL DEFAULT FALSE,
    ci_job_ref       TEXT        NOT NULL DEFAULT ''
);

-- Index on started_at for listing recent scans
CREATE INDEX IF NOT EXISTS idx_scan_results_started_at ON scan_results (started_at DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- Table: findings
-- One row per detected secret. Partitioned by scanned_at as a TimescaleDB
-- hypertable for efficient time-series queries.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS findings (
    id               TEXT        NOT NULL,
    scan_id          TEXT        NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    rule_id          TEXT        NOT NULL,
    secret_type      TEXT        NOT NULL,
    description      TEXT        NOT NULL DEFAULT '',
    severity         TEXT        NOT NULL DEFAULT 'LOW',
    confidence       DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    secret_hash      TEXT        NOT NULL DEFAULT '',
    fingerprint      TEXT        NOT NULL DEFAULT '',
    redacted_match   TEXT        NOT NULL DEFAULT '',
    entropy          DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    bpe_efficiency   DOUBLE PRECISION,
    bpe_tokens       INTEGER,
    file_type        TEXT        NOT NULL DEFAULT '',
    environment      TEXT        NOT NULL DEFAULT 'unknown',
    category         TEXT        NOT NULL DEFAULT '',
    source_type      TEXT        NOT NULL DEFAULT 'file',
    source_location  TEXT        NOT NULL DEFAULT '',
    source_line      INTEGER     NOT NULL DEFAULT 0,
    commit_hash      TEXT        NOT NULL DEFAULT '',
    author           TEXT        NOT NULL DEFAULT '',
    branch           TEXT        NOT NULL DEFAULT '',
    scanned_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Composite primary key (id + scanned_at required by TimescaleDB)
    PRIMARY KEY (id, scanned_at)
);

-- Convert findings to a TimescaleDB hypertable partitioned by scanned_at.
-- chunk_time_interval = 7 days (optimized for weekly query patterns).
SELECT create_hypertable(
    'findings',
    'scanned_at',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists => TRUE
);

-- ─── Performance indexes ───

-- Fingerprint: used for deduplication ("have we seen this exact secret before?")
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings (fingerprint);

-- Secret hash: used to track a specific secret across files and repos
CREATE INDEX IF NOT EXISTS idx_findings_secret_hash ON findings (secret_hash);

-- Rule ID: used for per-rule analytics
CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings (rule_id);

-- Severity: used for filtered queries ("show me only CRITICAL findings")
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);

-- Scan ID: used to list all findings for a specific scan
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id, scanned_at DESC);

-- Category: used for dashboard breakdowns
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings (category);

-- Secret type: used for top-N queries
CREATE INDEX IF NOT EXISTS idx_findings_secret_type ON findings (secret_type);

-- Composite: severity + scanned_at for time-filtered severity queries
CREATE INDEX IF NOT EXISTS idx_findings_severity_time ON findings (severity, scanned_at DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- Table: audit_logs
-- Records security-relevant events for compliance and forensics.
-- Also a TimescaleDB hypertable for efficient time-range queries.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGSERIAL   NOT NULL,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type  TEXT        NOT NULL,
    actor       TEXT        NOT NULL DEFAULT 'system',
    scan_id     TEXT,
    finding_id  TEXT,
    details     JSONB       NOT NULL DEFAULT '{}',
    severity    TEXT        NOT NULL DEFAULT 'info',
    source_ip   TEXT        NOT NULL DEFAULT '',

    PRIMARY KEY (id, timestamp)
);

-- Convert audit_logs to a TimescaleDB hypertable
SELECT create_hypertable(
    'audit_logs',
    'timestamp',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists => TRUE
);

-- Index for event type filtering
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs (event_type, timestamp DESC);

-- Index for actor filtering
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs (actor, timestamp DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- Continuous Aggregate: daily risk summary (materialized view)
-- Automatically maintained by TimescaleDB — no manual refresh needed.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE MATERIALIZED VIEW IF NOT EXISTS daily_risk_summary
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', scanned_at)       AS day,
    COUNT(*)                                AS total_findings,
    COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical_count,
    COUNT(*) FILTER (WHERE severity = 'HIGH')     AS high_count,
    COUNT(*) FILTER (WHERE severity = 'MEDIUM')   AS medium_count,
    COUNT(*) FILTER (WHERE severity = 'LOW')      AS low_count,
    COUNT(*) FILTER (WHERE severity = 'INFO')     AS info_count,
    AVG(confidence)                         AS avg_confidence,
    AVG(entropy)                            AS avg_entropy,
    COUNT(DISTINCT secret_type)             AS unique_types,
    COUNT(DISTINCT scan_id)                 AS scan_count
FROM findings
GROUP BY day
WITH NO DATA;

-- Refresh policy: automatically update the materialized view daily
SELECT add_continuous_aggregate_policy('daily_risk_summary',
    start_offset    => INTERVAL '3 days',
    end_offset      => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 day',
    if_not_exists   => TRUE
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Data retention policy: auto-drop findings older than 90 days
-- (configurable — adjust the interval as needed)
-- ─────────────────────────────────────────────────────────────────────────────

SELECT add_retention_policy('findings',
    drop_after => INTERVAL '90 days',
    if_not_exists => TRUE
);

SELECT add_retention_policy('audit_logs',
    drop_after => INTERVAL '365 days',
    if_not_exists => TRUE
);
