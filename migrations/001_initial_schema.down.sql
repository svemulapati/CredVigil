-- CredVigil Storage Layer — Migration 001: Rollback
-- Drops all tables, hypertables, continuous aggregates, and policies.
--
-- Run with:
--   psql -d credvigil -f migrations/001_initial_schema.down.sql

-- Drop continuous aggregate first (depends on findings)
DROP MATERIALIZED VIEW IF EXISTS daily_risk_summary CASCADE;

-- Drop tables (CASCADE removes indexes and policies)
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS scan_results CASCADE;
