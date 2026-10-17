BEGIN;
CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS tenants (id uuid PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS evidence (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  hash text NOT NULL CHECK (hash ~ '^sha256:[a-f0-9]{64}$'),
  observation jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, hash)
);
CREATE TABLE IF NOT EXISTS assessments (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  id uuid NOT NULL,
  evidence_hash text NOT NULL,
  record_hash text NOT NULL,
  document jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, evidence_hash) REFERENCES evidence(tenant_id, hash),
  CHECK (document->>'tenantId' = tenant_id::text),
  CHECK (document->>'id' = id::text),
  CHECK (document->>'evidenceHash' = evidence_hash)
);
CREATE INDEX IF NOT EXISTS assessments_recent ON assessments (tenant_id, created_at DESC, id);
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE assessments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS evidence_tenant ON evidence;
CREATE POLICY evidence_tenant ON evidence USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS assessment_tenant ON assessments;
CREATE POLICY assessment_tenant ON assessments USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
CREATE OR REPLACE FUNCTION reject_evidence_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Evidence and assessments are append-only'; END; $$;
DROP TRIGGER IF EXISTS evidence_immutable ON evidence;
CREATE TRIGGER evidence_immutable BEFORE UPDATE OR DELETE ON evidence FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();
DROP TRIGGER IF EXISTS assessment_immutable ON assessments;
CREATE TRIGGER assessment_immutable BEFORE UPDATE OR DELETE ON assessments FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();
INSERT INTO schema_migrations(version) VALUES ('001_foundation') ON CONFLICT DO NOTHING;
COMMIT;
