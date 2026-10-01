-- One outage episode begins at the third failed public check. A successful
-- check, proven suspension, or replacement closes it; history stays readable.
CREATE TABLE hosting.release_health_incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  application_id uuid NOT NULL,
  release_id uuid NOT NULL,
  opened_at timestamptz NOT NULL DEFAULT now(),
  closed_at timestamptz,
  resolution text CHECK (resolution IN ('RECOVERED','SUSPENDED','SUPERSEDED')),
  CHECK ((closed_at IS NULL AND resolution IS NULL) OR
         (closed_at IS NOT NULL AND resolution IS NOT NULL AND closed_at>=opened_at)),
  FOREIGN KEY (organization_id,application_id,release_id)
    REFERENCES hosting.releases(organization_id,application_id,id)
);
CREATE UNIQUE INDEX release_health_open_incident_idx ON hosting.release_health_incidents(release_id)
  WHERE closed_at IS NULL;
CREATE INDEX release_health_incidents_app_idx ON hosting.release_health_incidents
  (organization_id,application_id,opened_at DESC,id DESC);
INSERT INTO hosting.release_health_incidents(organization_id,application_id,release_id,opened_at)
SELECT h.organization_id,h.application_id,h.release_id,h.checked_at
FROM hosting.release_health h JOIN hosting.applications a
  ON a.id=h.application_id AND a.active_release_id=h.release_id AND a.traffic_state='ACTIVE'
WHERE h.state='DOWN' AND h.checked_at IS NOT NULL;
GRANT SELECT ON hosting.release_health_incidents TO hosting_api,hosting_worker;
GRANT INSERT,UPDATE ON hosting.release_health_incidents TO hosting_worker;
ALTER TABLE hosting.release_health_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.release_health_incidents FORCE ROW LEVEL SECURITY;
CREATE POLICY health_incidents_api_read ON hosting.release_health_incidents FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m
    WHERE m.organization_id=release_health_incidents.organization_id
      AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY health_incidents_worker_read ON hosting.release_health_incidents FOR SELECT TO hosting_worker USING (true);
CREATE POLICY health_incidents_worker_insert ON hosting.release_health_incidents FOR INSERT TO hosting_worker WITH CHECK (true);
CREATE POLICY health_incidents_worker_update ON hosting.release_health_incidents FOR UPDATE TO hosting_worker
  USING (true) WITH CHECK (true);
