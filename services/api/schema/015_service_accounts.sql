-- Machine credentials come from the configured issuer under a distinct audience.
-- The control plane grants a specific issuer subject/client pair only one app.
CREATE TABLE hosting.service_accounts (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  application_id uuid NOT NULL,
  client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 128),
  actor_sub text NOT NULL CHECK (length(actor_sub) BETWEEN 1 AND 255),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  UNIQUE (organization_id,client_id,actor_sub),
  FOREIGN KEY (organization_id,application_id) REFERENCES hosting.applications(organization_id,id)
);
CREATE INDEX service_accounts_app_idx ON hosting.service_accounts(organization_id,application_id);
GRANT SELECT,INSERT,UPDATE (revoked_at) ON hosting.service_accounts TO hosting_api;
ALTER TABLE hosting.service_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.service_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY service_owner_read ON hosting.service_accounts FOR SELECT TO hosting_api
  USING (current_setting('hosting.auth_kind',true) IS DISTINCT FROM 'service' AND
         EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=service_accounts.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'));
CREATE POLICY service_self_read ON hosting.service_accounts FOR SELECT TO hosting_api
  USING (current_setting('hosting.auth_kind',true)='service' AND revoked_at IS NULL AND
         actor_sub=current_setting('hosting.actor_sub',true) AND
         client_id=current_setting('hosting.service_client_id',true));
CREATE POLICY service_owner_insert ON hosting.service_accounts FOR INSERT TO hosting_api
  WITH CHECK (created_by=current_setting('hosting.actor_sub',true) AND revoked_at IS NULL AND
              current_setting('hosting.auth_kind',true) IS DISTINCT FROM 'service' AND
              EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=service_accounts.organization_id
                      AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'));
CREATE POLICY service_owner_revoke ON hosting.service_accounts FOR UPDATE TO hosting_api
  USING (revoked_at IS NULL AND current_setting('hosting.auth_kind',true) IS DISTINCT FROM 'service' AND
         EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=service_accounts.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'))
  WITH CHECK (revoked_at IS NOT NULL);

-- A machine token must never inherit a human membership with a matching sub.
DROP POLICY memberships_self ON hosting.memberships;
CREATE POLICY memberships_self ON hosting.memberships FOR SELECT TO hosting_api
  USING (current_setting('hosting.auth_kind',true) IS DISTINCT FROM 'service' AND
         actor_sub=current_setting('hosting.actor_sub',true));

CREATE POLICY service_app_read ON hosting.applications FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.service_accounts s
                 WHERE s.organization_id=applications.organization_id AND s.application_id=applications.id));
CREATE POLICY service_domain_read ON hosting.domains FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.service_accounts s
                 WHERE s.organization_id=domains.organization_id AND s.application_id=domains.application_id));
CREATE POLICY service_release_read ON hosting.releases FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.service_accounts s
                 WHERE s.organization_id=releases.organization_id AND s.application_id=releases.application_id));
CREATE POLICY service_release_insert ON hosting.releases FOR INSERT TO hosting_api
  WITH CHECK (requested_by=current_setting('hosting.actor_sub',true) AND
              EXISTS (SELECT 1 FROM hosting.service_accounts s
                      WHERE s.organization_id=releases.organization_id AND s.application_id=releases.application_id));
CREATE POLICY service_job_insert ON hosting.jobs FOR INSERT TO hosting_api
  WITH CHECK (EXISTS (SELECT 1 FROM hosting.releases r JOIN hosting.service_accounts s
                      ON s.organization_id=r.organization_id AND s.application_id=r.application_id
                      WHERE r.id=jobs.release_id AND r.organization_id=jobs.organization_id
                        AND r.requested_by=current_setting('hosting.actor_sub',true)));
CREATE POLICY service_audit_read ON hosting.audit_events FOR SELECT TO hosting_api
  USING (current_setting('hosting.auth_kind',true)='service' AND
         EXISTS (SELECT 1 FROM hosting.service_accounts s WHERE s.organization_id=audit_events.organization_id));
CREATE POLICY service_audit_insert ON hosting.audit_events FOR INSERT TO hosting_api
  WITH CHECK (current_setting('hosting.auth_kind',true)='service' AND
              actor_sub=current_setting('hosting.actor_sub',true) AND action='release.queue' AND
              EXISTS (SELECT 1 FROM hosting.releases r JOIN hosting.service_accounts s
                      ON s.organization_id=r.organization_id AND s.application_id=r.application_id
                      WHERE r.id=audit_events.resource_id AND r.organization_id=audit_events.organization_id));
