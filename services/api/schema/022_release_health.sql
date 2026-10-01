-- Retain observations separately from one-time deployment proof. Only the
-- current, routed release is probed; history remains attached to its release.
CREATE TABLE hosting.release_health (
  release_id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  application_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'UNKNOWN' CHECK (state IN ('UNKNOWN','UP','DEGRADED','DOWN')),
  consecutive_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
  checked_at timestamptz,
  next_probe_at timestamptz NOT NULL DEFAULT now(),
  lease_token uuid,
  lease_until timestamptz,
  FOREIGN KEY (organization_id,application_id,release_id)
    REFERENCES hosting.releases(organization_id,application_id,id)
);
CREATE INDEX release_health_due_idx ON hosting.release_health(next_probe_at,release_id);
INSERT INTO hosting.release_health(release_id,organization_id,application_id)
SELECT r.id,r.organization_id,r.application_id FROM hosting.releases r
WHERE r.state='SERVING';
GRANT SELECT ON hosting.release_health TO hosting_api,hosting_worker;
GRANT INSERT,UPDATE ON hosting.release_health TO hosting_worker;
ALTER TABLE hosting.release_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.release_health FORCE ROW LEVEL SECURITY;
CREATE POLICY release_health_api_read ON hosting.release_health FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m
    WHERE m.organization_id=release_health.organization_id
      AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY release_health_worker_read ON hosting.release_health FOR SELECT TO hosting_worker USING (true);
CREATE POLICY release_health_worker_insert ON hosting.release_health FOR INSERT TO hosting_worker WITH CHECK (true);
CREATE POLICY release_health_worker_update ON hosting.release_health FOR UPDATE TO hosting_worker
  USING (true) WITH CHECK (true);
