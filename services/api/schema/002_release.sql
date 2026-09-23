-- Release and job state live in PostgreSQL. Apply once as the protected migration role.
CREATE TABLE hosting.nodes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint text NOT NULL CHECK (endpoint ~ '^https://[A-Za-z0-9.-]+:[0-9]{2,5}$'),
  server_name text NOT NULL CHECK (length(server_name) BETWEEN 1 AND 255),
  enabled boolean NOT NULL DEFAULT false,
  cpu_milli integer NOT NULL CHECK (cpu_milli > 0),
  memory_mb integer NOT NULL CHECK (memory_mb > 0),
  reserved_cpu_milli integer NOT NULL DEFAULT 0 CHECK (reserved_cpu_milli >= 0),
  reserved_memory_mb integer NOT NULL DEFAULT 0 CHECK (reserved_memory_mb >= 0),
  observed_at timestamptz NOT NULL,
  CHECK (reserved_cpu_milli <= cpu_milli),
  CHECK (reserved_memory_mb <= memory_mb)
);
CREATE TABLE hosting.artifact_admissions (
  image text PRIMARY KEY CHECK (image ~ '@sha256:[a-f0-9]{64}$'),
  sbom_sha256 text NOT NULL CHECK (sbom_sha256 ~ '^[a-f0-9]{64}$'),
  source_commit text NOT NULL CHECK (source_commit ~ '^[a-f0-9]{40}$'),
  policy_revision text NOT NULL,
  verification_receipt jsonb NOT NULL,
  admitted_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE hosting.applications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
  project_id uuid NOT NULL,
  environment text NOT NULL CHECK (environment ~ '^[a-z][a-z0-9-]{0,31}$'),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  active_release_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id,id),
  UNIQUE (organization_id,project_id,environment,name),
  FOREIGN KEY (organization_id,project_id) REFERENCES hosting.projects(organization_id,id)
);
CREATE INDEX applications_project_idx ON hosting.applications(organization_id,project_id,environment);
CREATE TABLE hosting.releases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
  application_id uuid NOT NULL,
  node_id uuid NOT NULL REFERENCES hosting.nodes(id),
  requested_by text NOT NULL,
  idempotency_key uuid NOT NULL,
  image text NOT NULL REFERENCES hosting.artifact_admissions(image),
  port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
  health_path text NOT NULL CHECK (health_path ~ '^/[A-Za-z0-9/_-]{0,127}$'),
  memory_mb integer NOT NULL CHECK (memory_mb BETWEEN 64 AND 32768),
  cpu_milli integer NOT NULL CHECK (cpu_milli BETWEEN 50 AND 32000),
  state text NOT NULL DEFAULT 'QUEUED' CHECK (state IN ('QUEUED','DEPLOYING','HEALTHY_PRIVATE','SUPERSEDED','RETIRED','FAILED')),
  previous_release_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id,id),
  UNIQUE (organization_id,application_id,idempotency_key),
  FOREIGN KEY (organization_id,application_id) REFERENCES hosting.applications(organization_id,id)
);
CREATE UNIQUE INDEX releases_one_pending_per_app ON hosting.releases(application_id)
  WHERE state IN ('QUEUED','DEPLOYING');
ALTER TABLE hosting.applications ADD CONSTRAINT active_release_fk
  FOREIGN KEY (organization_id,active_release_id) REFERENCES hosting.releases(organization_id,id)
  DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX releases_app_created_idx ON hosting.releases(organization_id,application_id,created_at DESC);
CREATE TABLE hosting.jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  release_id uuid NOT NULL UNIQUE,
  state text NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING','RUNNING','COMPLETE','FAILED')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_until timestamptz,
  last_error text,
  receipt jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id,release_id) REFERENCES hosting.releases(organization_id,id)
);
CREATE INDEX jobs_claim_idx ON hosting.jobs(next_attempt_at,id)
  WHERE state IN ('PENDING','RUNNING');

GRANT SELECT ON hosting.nodes,hosting.artifact_admissions TO hosting_api;
GRANT UPDATE (reserved_cpu_milli,reserved_memory_mb) ON hosting.nodes TO hosting_api;
GRANT SELECT,INSERT ON hosting.applications,hosting.releases,hosting.jobs TO hosting_api;
GRANT SELECT ON hosting.organizations,hosting.memberships,hosting.projects,hosting.nodes,
  hosting.applications,hosting.releases,hosting.jobs TO hosting_worker;
GRANT UPDATE ON hosting.nodes,hosting.applications,hosting.releases,hosting.jobs TO hosting_worker;
GRANT SELECT,INSERT ON hosting.audit_events TO hosting_worker;
GRANT USAGE ON SCHEMA hosting TO hosting_worker;
GRANT USAGE ON SEQUENCE hosting.audit_events_id_seq TO hosting_worker;

ALTER TABLE hosting.applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.applications FORCE ROW LEVEL SECURITY;
CREATE POLICY app_api_select ON hosting.applications FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=applications.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY app_api_insert ON hosting.applications FOR INSERT TO hosting_api
  WITH CHECK (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=applications.organization_id
                     AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));
CREATE POLICY app_worker_select ON hosting.applications FOR SELECT TO hosting_worker USING (true);
CREATE POLICY app_worker_update ON hosting.applications FOR UPDATE TO hosting_worker USING (true) WITH CHECK (true);

ALTER TABLE hosting.releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.releases FORCE ROW LEVEL SECURITY;
CREATE POLICY release_api_select ON hosting.releases FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=releases.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY release_api_insert ON hosting.releases FOR INSERT TO hosting_api
  WITH CHECK (requested_by=current_setting('hosting.actor_sub',true) AND
              EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=releases.organization_id
                      AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));
CREATE POLICY release_worker_select ON hosting.releases FOR SELECT TO hosting_worker USING (true);
CREATE POLICY release_worker_update ON hosting.releases FOR UPDATE TO hosting_worker USING (true) WITH CHECK (true);

ALTER TABLE hosting.jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY job_api_select ON hosting.jobs FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=jobs.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY job_api_insert ON hosting.jobs FOR INSERT TO hosting_api
  WITH CHECK (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=jobs.organization_id
                     AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));
CREATE POLICY job_worker_select ON hosting.jobs FOR SELECT TO hosting_worker USING (true);
CREATE POLICY job_worker_update ON hosting.jobs FOR UPDATE TO hosting_worker USING (true) WITH CHECK (true);

-- Worker operations are service-side and may inspect tenant rows only for accepted jobs.
CREATE POLICY worker_membership_read ON hosting.memberships FOR SELECT TO hosting_worker USING (true);
CREATE POLICY worker_org_read ON hosting.organizations FOR SELECT TO hosting_worker USING (true);
CREATE POLICY worker_project_read ON hosting.projects FOR SELECT TO hosting_worker USING (true);
CREATE POLICY worker_audit_read ON hosting.audit_events FOR SELECT TO hosting_worker USING (true);
CREATE POLICY worker_audit_insert ON hosting.audit_events FOR INSERT TO hosting_worker WITH CHECK (true);
