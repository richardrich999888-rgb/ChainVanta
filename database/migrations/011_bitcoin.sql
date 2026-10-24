BEGIN;
-- Generalize assets to CAIP-2 namespaces. Existing rows are EVM (eip155) and keep their chain_id.
-- Bitcoin (bip122) assets have no numeric chain id; their chain is part of asset_id (CAIP-10).
ALTER TABLE assets ADD COLUMN IF NOT EXISTS namespace text NOT NULL DEFAULT 'eip155';
ALTER TABLE assets ALTER COLUMN chain_id DROP NOT NULL;
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_namespace_check;
ALTER TABLE assets ADD CONSTRAINT assets_namespace_check CHECK (
  (namespace = 'eip155' AND chain_id IS NOT NULL AND asset_id LIKE 'eip155:%')
  OR (namespace = 'bip122' AND chain_id IS NULL AND asset_id LIKE 'bip122:%')
);
-- EVM and Bitcoin assessment documents share the table; the discriminator is indexed for lists.
CREATE INDEX IF NOT EXISTS assessments_kind_recent
  ON assessments (tenant_id, (document->>'kind'), created_at DESC, id);
INSERT INTO schema_migrations(version) VALUES ('011_bitcoin') ON CONFLICT DO NOTHING;
COMMIT;
