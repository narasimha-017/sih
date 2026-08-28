CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS cases (case_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), risk_score SMALLINT CHECK(risk_score BETWEEN 0 AND 100), risk_level TEXT NOT NULL, confidence SMALLINT CHECK(confidence BETWEEN 0 AND 100), threat TEXT, subject TEXT, sender_address TEXT, evidence_sha256 CHAR(64));
CREATE TABLE IF NOT EXISTS evidence (evidence_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), case_id UUID NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE, evidence_type TEXT NOT NULL, value JSONB NOT NULL, sha256 CHAR(64), observed_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS indicators (id BIGSERIAL PRIMARY KEY, case_id UUID NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE, kind TEXT NOT NULL, value TEXT NOT NULL, normalized_value TEXT, reputation JSONB, first_seen TIMESTAMPTZ, last_seen TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS analyst_actions (id BIGSERIAL PRIMARY KEY, case_id UUID NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE, action TEXT NOT NULL, actor TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), metadata JSONB DEFAULT '{}'::jsonb);
CREATE INDEX IF NOT EXISTS idx_indicators_normalized ON indicators(kind, normalized_value);
CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at DESC);
