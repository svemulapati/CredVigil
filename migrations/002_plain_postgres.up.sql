-- CredVigil Storage Layer — Migration 002: Plain PostgreSQL Schema
-- For local development without TimescaleDB.
--
-- Run this migration with:
--   psql "$CREDVIGIL_DB" -f migrations/002_plain_postgres.up.sql
--
-- This creates the same tables as 001 but without:
--   - TimescaleDB extension / hypertables
--   - Continuous aggregates
--   - Retention policies
-- All basic CRUD operations (saving scans, findings, audit logs) work identically.

-- ─────────────────────────────────────────────────────────────────────────────
-- Enable uuid-ossp (available in standard PostgreSQL)
-- ─────────────────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─────────────────────────────────────────────────────────────────────────────
-- Table: scan_results
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

CREATE INDEX IF NOT EXISTS idx_scan_results_started_at ON scan_results (started_at DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- Table: findings (plain table — no hypertable)
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

    PRIMARY KEY (id, scanned_at)
);

-- Unique constraint on id alone (needed for ON CONFLICT (id) DO NOTHING in Go code)
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_id_unique ON findings (id);

-- Performance indexes (same as TimescaleDB version)
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint    ON findings (fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_secret_hash    ON findings (secret_hash);
CREATE INDEX IF NOT EXISTS idx_findings_rule_id        ON findings (rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity       ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id        ON findings (scan_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_category       ON findings (category);
CREATE INDEX IF NOT EXISTS idx_findings_secret_type    ON findings (secret_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity_time  ON findings (severity, scanned_at DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- Table: audit_logs (plain table — no hypertable)
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

CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs (event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor      ON audit_logs (actor, timestamp DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- Plain materialized view (manual refresh, no TimescaleDB continuous aggregate)
-- Refresh with: REFRESH MATERIALIZED VIEW daily_risk_summary;
-- ─────────────────────────────────────────────────────────────────────────────

CREATE MATERIALIZED VIEW IF NOT EXISTS daily_risk_summary AS
SELECT
    date_trunc('day', scanned_at)                          AS day,
    COUNT(*)                                                AS total_findings,
    COUNT(*) FILTER (WHERE severity = 'CRITICAL')          AS critical_count,
    COUNT(*) FILTER (WHERE severity = 'HIGH')              AS high_count,
    COUNT(*) FILTER (WHERE severity = 'MEDIUM')            AS medium_count,
    COUNT(*) FILTER (WHERE severity = 'LOW')               AS low_count,
    COUNT(*) FILTER (WHERE severity = 'INFO')              AS info_count,
    AVG(confidence)                                         AS avg_confidence,
    AVG(entropy)                                            AS avg_entropy,
    COUNT(DISTINCT secret_type)                             AS unique_types,
    COUNT(DISTINCT scan_id)                                 AS scan_count
FROM findings
GROUP BY day
WITH NO DATA;
