-- A hostname belongs to exactly one application across every tenant.
ALTER TABLE hosting.nodes ADD COLUMN public_ipv4 inet;
ALTER TABLE hosting.nodes ADD CONSTRAINT public_ipv4_only CHECK (family(public_ipv4)=4);

CREATE TABLE hosting.domains (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  application_id uuid NOT NULL,
  hostname text NOT NULL UNIQUE CHECK (length(hostname) BETWEEN 4 AND 253),
  verification_token text NOT NULL CHECK (length(verification_token) = 43),
  verified_at timestamptz,
  challenge_expires_at timestamptz NOT NULL DEFAULT now() + interval '24 hours',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (application_id),
  FOREIGN KEY (organization_id,application_id) REFERENCES hosting.applications(organization_id,id)
);
CREATE INDEX domains_org_idx ON hosting.domains(organization_id,application_id);
GRANT SELECT,INSERT ON hosting.domains TO hosting_api;
GRANT UPDATE (verified_at) ON hosting.domains TO hosting_api;
GRANT SELECT ON hosting.domains TO hosting_worker;
ALTER TABLE hosting.domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.domains FORCE ROW LEVEL SECURITY;
CREATE POLICY domains_api_select ON hosting.domains FOR SELECT TO hosting_api USING (
  EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=domains.organization_id
          AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY domains_api_insert ON hosting.domains FOR INSERT TO hosting_api WITH CHECK (
  EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=domains.organization_id
          AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));
CREATE POLICY domains_api_update ON hosting.domains FOR UPDATE TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=domains.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')))
  WITH CHECK (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=domains.organization_id
                      AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));
CREATE POLICY domains_worker_read ON hosting.domains FOR SELECT TO hosting_worker USING (true);
