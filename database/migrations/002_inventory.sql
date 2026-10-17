BEGIN;
CREATE TABLE IF NOT EXISTS assets (
 tenant_id uuid NOT NULL REFERENCES tenants(id), asset_id text NOT NULL,
 chain_id bigint NOT NULL, address text NOT NULL, first_seen timestamptz NOT NULL,
 PRIMARY KEY(tenant_id, asset_id), UNIQUE(tenant_id, chain_id, address)
);
CREATE TABLE IF NOT EXISTS scan_requests (
 tenant_id uuid NOT NULL REFERENCES tenants(id), key text NOT NULL, request_hash text NOT NULL,
 assessment_id uuid NOT NULL, PRIMARY KEY(tenant_id, key),
 FOREIGN KEY(tenant_id, assessment_id) REFERENCES assessments(tenant_id, id)
);
CREATE TABLE IF NOT EXISTS graph_edges (
 tenant_id uuid NOT NULL, assessment_id uuid NOT NULL, source text NOT NULL, target text NOT NULL,
 relation text NOT NULL, evidence_hash text NOT NULL,
 PRIMARY KEY(tenant_id, assessment_id, source, target, relation),
 FOREIGN KEY(tenant_id, assessment_id) REFERENCES assessments(tenant_id, id),
 FOREIGN KEY(tenant_id, evidence_hash) REFERENCES evidence(tenant_id, hash)
);
CREATE INDEX IF NOT EXISTS graph_source ON graph_edges(tenant_id, source);
CREATE TABLE IF NOT EXISTS finding_events (
 tenant_id uuid NOT NULL, id uuid NOT NULL, assessment_id uuid NOT NULL, rule_id text NOT NULL,
 status text NOT NULL CHECK(status IN ('open','acknowledged','resolved','excepted')),
 reason text NOT NULL, expires_at timestamptz, actor text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,assessment_id) REFERENCES assessments(tenant_id,id),
 CHECK(status <> 'excepted' OR expires_at IS NOT NULL)
);
CREATE TABLE IF NOT EXISTS audit_events (
 tenant_id uuid NOT NULL REFERENCES tenants(id), id uuid NOT NULL, actor text NOT NULL,
 action text NOT NULL, resource text NOT NULL, details jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['assets','scan_requests','graph_edges','finding_events','audit_events'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('DROP POLICY IF EXISTS tenant_scope ON %I',t);
 EXECUTE format('CREATE POLICY tenant_scope ON %I USING (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)',t);
 EXECUTE format('DROP TRIGGER IF EXISTS immutable ON %I',t);
 EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation()',t);
 END LOOP;
END $$;
INSERT INTO schema_migrations(version) VALUES ('002_inventory') ON CONFLICT DO NOTHING;
COMMIT;
