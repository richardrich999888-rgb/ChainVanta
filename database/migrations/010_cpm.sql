BEGIN;
CREATE TABLE IF NOT EXISTS cryptographic_policies (
 tenant_id uuid NOT NULL REFERENCES tenants(id), id text NOT NULL, active boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS policy_versions (
 tenant_id uuid NOT NULL, policy_id text NOT NULL, version text NOT NULL, document jsonb NOT NULL, content_hash text NOT NULL,
 actor text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,policy_id,version),
 FOREIGN KEY(tenant_id,policy_id) REFERENCES cryptographic_policies(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS policy_assignments (
 tenant_id uuid NOT NULL, asset_id text NOT NULL, policy_id text NOT NULL, policy_version text NOT NULL,
 operational_importance text NOT NULL CHECK(operational_importance IN ('normal','high','critical')),
 actor text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,asset_id),
 FOREIGN KEY(tenant_id,asset_id) REFERENCES assets(tenant_id,asset_id),
 FOREIGN KEY(tenant_id,policy_id,policy_version) REFERENCES policy_versions(tenant_id,policy_id,version)
);
CREATE TABLE IF NOT EXISTS monitoring_schedules (
 tenant_id uuid NOT NULL, id uuid NOT NULL, asset_id text NOT NULL, input jsonb NOT NULL,
 policy_id text NOT NULL, policy_version text NOT NULL, interval_seconds integer NOT NULL CHECK(interval_seconds BETWEEN 60 AND 2592000),
 enabled boolean NOT NULL DEFAULT true, next_run_at timestamptz NOT NULL DEFAULT now(),
 last_success_at timestamptz, last_failure_at timestamptz, last_failure text, actor text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,asset_id) REFERENCES assets(tenant_id,asset_id),
 FOREIGN KEY(tenant_id,policy_id,policy_version) REFERENCES policy_versions(tenant_id,policy_id,version)
);
CREATE INDEX IF NOT EXISTS monitoring_due ON monitoring_schedules(tenant_id,next_run_at) WHERE enabled;
CREATE UNIQUE INDEX IF NOT EXISTS monitoring_one_active ON monitoring_schedules(tenant_id,asset_id,policy_id) WHERE enabled;
CREATE TABLE IF NOT EXISTS assessment_jobs (
 tenant_id uuid NOT NULL, id uuid NOT NULL, schedule_id uuid NOT NULL, idempotency_key text NOT NULL,
 input jsonb NOT NULL, policy_id text NOT NULL, policy_version text NOT NULL,
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','retry','succeeded','failed','cancelled')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5), available_at timestamptz NOT NULL DEFAULT now(),
 lease_token uuid, lease_until timestamptz, worker_id text, started_at timestamptz, finished_at timestamptz,
 assessment_id uuid, error_code text, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,idempotency_key),
 FOREIGN KEY(tenant_id,schedule_id) REFERENCES monitoring_schedules(tenant_id,id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES assessments(tenant_id,id),
 FOREIGN KEY(tenant_id,policy_id,policy_version) REFERENCES policy_versions(tenant_id,policy_id,version),
 CHECK(status <> 'running' OR (lease_token IS NOT NULL AND lease_until IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS jobs_claim ON assessment_jobs(tenant_id,status,available_at);
CREATE UNIQUE INDEX IF NOT EXISTS schedule_one_pending ON assessment_jobs(tenant_id,schedule_id) WHERE status IN ('queued','retry','running');
CREATE TABLE IF NOT EXISTS worker_leases (
 tenant_id uuid NOT NULL REFERENCES tenants(id), worker_id text NOT NULL, heartbeat_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,worker_id)
);
CREATE TABLE IF NOT EXISTS rpc_budgets (
 tenant_id uuid NOT NULL REFERENCES tenants(id), chain_id bigint NOT NULL, window_start timestamptz NOT NULL,
 used integer NOT NULL CHECK(used >= 0), PRIMARY KEY(tenant_id,chain_id)
);
CREATE TABLE IF NOT EXISTS posture_snapshots (
 tenant_id uuid NOT NULL, id text NOT NULL, asset_id text NOT NULL, assessment_id uuid NOT NULL,
 policy_id text NOT NULL, policy_version text NOT NULL, document jsonb NOT NULL, content_hash text NOT NULL,
 observed_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,id),
 UNIQUE(tenant_id,assessment_id,policy_id,policy_version),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES assessments(tenant_id,id),
 FOREIGN KEY(tenant_id,asset_id) REFERENCES assets(tenant_id,asset_id),
 FOREIGN KEY(tenant_id,policy_id,policy_version) REFERENCES policy_versions(tenant_id,policy_id,version)
);
CREATE INDEX IF NOT EXISTS posture_history ON posture_snapshots(tenant_id,asset_id,observed_at DESC,created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS posture_policy_history ON posture_snapshots(tenant_id,asset_id,policy_id,observed_at DESC,created_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS snapshot_invalidations (
 tenant_id uuid NOT NULL, snapshot_id text NOT NULL, reason text NOT NULL, details jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,snapshot_id),
 FOREIGN KEY(tenant_id,snapshot_id) REFERENCES posture_snapshots(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS cryptographic_drift_events (
 tenant_id uuid NOT NULL, id text NOT NULL, previous_snapshot_id text NOT NULL, current_snapshot_id text NOT NULL,
 document jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,previous_snapshot_id) REFERENCES posture_snapshots(tenant_id,id),
 FOREIGN KEY(tenant_id,current_snapshot_id) REFERENCES posture_snapshots(tenant_id,id)
);
CREATE INDEX IF NOT EXISTS drift_recent ON cryptographic_drift_events(tenant_id,created_at DESC,id);
CREATE TABLE IF NOT EXISTS remediation_recommendations (
 tenant_id uuid NOT NULL, snapshot_id text NOT NULL, rule_id text NOT NULL, document jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,snapshot_id,rule_id),
 FOREIGN KEY(tenant_id,snapshot_id) REFERENCES posture_snapshots(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS migration_assessments (
 tenant_id uuid NOT NULL, id uuid NOT NULL, assessment_id uuid NOT NULL, parent_id uuid,
 request jsonb NOT NULL, document jsonb NOT NULL, content_hash text NOT NULL, actor text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES assessments(tenant_id,id),
 FOREIGN KEY(tenant_id,parent_id) REFERENCES migration_assessments(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS notification_events (
 tenant_id uuid NOT NULL REFERENCES tenants(id), id text NOT NULL, kind text NOT NULL, resource text NOT NULL,
 details jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,id)
);
CREATE INDEX IF NOT EXISTS notification_recent ON notification_events(tenant_id,created_at DESC,id);
ALTER TABLE finding_events DROP CONSTRAINT IF EXISTS finding_events_status_check;
ALTER TABLE finding_events ADD CONSTRAINT finding_events_status_check CHECK(status IN ('open','acknowledged','in_remediation','pending_verification','resolved','excepted','administratively_closed'));
ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS asset_id text;
ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS policy_id text;
ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS snapshot_id text;
ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS verification_snapshot_id text;
ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS event_seq bigserial;
CREATE INDEX IF NOT EXISTS finding_latest ON finding_events(tenant_id,asset_id,policy_id,rule_id,event_seq DESC);
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_constraint WHERE conname='finding_snapshot_fk' AND conrelid='finding_events'::regclass) THEN
 ALTER TABLE finding_events ADD CONSTRAINT finding_snapshot_fk FOREIGN KEY(tenant_id,snapshot_id) REFERENCES posture_snapshots(tenant_id,id);
 ALTER TABLE finding_events ADD CONSTRAINT finding_verification_fk FOREIGN KEY(tenant_id,verification_snapshot_id) REFERENCES posture_snapshots(tenant_id,id);
 END IF;
END $$;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['cryptographic_policies','policy_versions','policy_assignments','monitoring_schedules','assessment_jobs','worker_leases','rpc_budgets','posture_snapshots','snapshot_invalidations','cryptographic_drift_events','remediation_recommendations','migration_assessments','notification_events'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('DROP POLICY IF EXISTS tenant_scope ON %I',t);
 EXECUTE format('CREATE POLICY tenant_scope ON %I USING (tenant_id = nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
 FOREACH t IN ARRAY ARRAY['policy_versions','posture_snapshots','snapshot_invalidations','cryptographic_drift_events','remediation_recommendations','migration_assessments','notification_events'] LOOP
 EXECUTE format('DROP TRIGGER IF EXISTS immutable ON %I',t);
 EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation()',t);
 END LOOP;
END $$;
INSERT INTO schema_migrations(version) VALUES('010_cpm') ON CONFLICT DO NOTHING;
COMMIT;
