-- Reversible route suspension retains releases, reserved capacity and data.
ALTER TABLE hosting.applications
  ADD COLUMN traffic_state text NOT NULL DEFAULT 'ACTIVE'
    CHECK (traffic_state IN ('ACTIVE','SUSPENDING','SUSPENDED','RESUMING')),
  ADD COLUMN traffic_reason text,
  ADD COLUMN traffic_requested_by text,
  ADD COLUMN traffic_updated_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN traffic_lease_token uuid,
  ADD COLUMN traffic_lease_until timestamptz,
  ADD COLUMN traffic_next_attempt_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN traffic_last_error text;
CREATE INDEX applications_traffic_work_idx ON hosting.applications(traffic_next_attempt_at,id)
  WHERE traffic_state IN ('SUSPENDING','RESUMING');

CREATE TABLE hosting.application_traffic_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization_id uuid NOT NULL,
  application_id uuid NOT NULL,
  actor_sub text NOT NULL,
  action text NOT NULL CHECK (action IN ('suspend','resume')),
  reason text NOT NULL CHECK (length(reason) BETWEEN 3 AND 240),
  request_id uuid NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id,application_id) REFERENCES hosting.applications(organization_id,id)
);
CREATE INDEX traffic_events_app_idx ON hosting.application_traffic_events(application_id,id DESC);
GRANT SELECT,INSERT ON hosting.application_traffic_events TO hosting_api;
GRANT USAGE ON SEQUENCE hosting.application_traffic_events_id_seq TO hosting_api;
GRANT UPDATE (traffic_state,traffic_reason,traffic_requested_by,traffic_updated_at,
              traffic_next_attempt_at,traffic_last_error) ON hosting.applications TO hosting_api;
CREATE POLICY app_api_traffic_update ON hosting.applications FOR UPDATE TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=applications.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'))
  WITH CHECK (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=applications.organization_id
                     AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'));
ALTER TABLE hosting.application_traffic_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.application_traffic_events FORCE ROW LEVEL SECURITY;
CREATE POLICY traffic_events_read ON hosting.application_traffic_events FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=application_traffic_events.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY traffic_events_insert ON hosting.application_traffic_events FOR INSERT TO hosting_api
  WITH CHECK (actor_sub=current_setting('hosting.actor_sub',true) AND
              EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=application_traffic_events.organization_id
                      AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'));
