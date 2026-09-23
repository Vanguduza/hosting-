-- One private, persistent Valkey cache per application. Reservations remain
-- assigned on failure so an operator can reconcile the volume before retry.
CREATE TABLE hosting.valkey_instances (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  application_id uuid NOT NULL UNIQUE,
  node_id uuid NOT NULL REFERENCES hosting.nodes(id),
  requested_by text NOT NULL,
  idempotency_key uuid NOT NULL,
  memory_mb integer NOT NULL CHECK (memory_mb BETWEEN 128 AND 16384),
  cpu_milli integer NOT NULL CHECK (cpu_milli BETWEEN 100 AND 16000),
  state text NOT NULL DEFAULT 'QUEUED' CHECK (state IN ('QUEUED','PROVISIONING','READY','FAILED')),
  secret_version integer NOT NULL DEFAULT 0 CHECK (secret_version >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id,id),
  FOREIGN KEY (organization_id,application_id) REFERENCES hosting.applications(organization_id,id)
);
CREATE TABLE hosting.valkey_jobs (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  instance_id uuid NOT NULL UNIQUE,
  state text NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING','RUNNING','COMPLETE','FAILED')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_until timestamptz,
  last_error text,
  receipt jsonb,
  FOREIGN KEY (organization_id,instance_id) REFERENCES hosting.valkey_instances(organization_id,id)
);
CREATE INDEX valkey_jobs_claim_idx ON hosting.valkey_jobs(next_attempt_at,id)
  WHERE state IN ('PENDING','RUNNING');
GRANT SELECT,INSERT ON hosting.valkey_instances,hosting.valkey_jobs TO hosting_api;
GRANT SELECT,UPDATE ON hosting.valkey_instances,hosting.valkey_jobs TO hosting_worker;
ALTER TABLE hosting.valkey_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.valkey_instances FORCE ROW LEVEL SECURITY;
CREATE POLICY vk_api_select ON hosting.valkey_instances FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=valkey_instances.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY vk_api_insert ON hosting.valkey_instances FOR INSERT TO hosting_api
  WITH CHECK (requested_by=current_setting('hosting.actor_sub',true) AND
              EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=valkey_instances.organization_id
                      AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));
CREATE POLICY vk_worker_select ON hosting.valkey_instances FOR SELECT TO hosting_worker USING (true);
CREATE POLICY vk_worker_update ON hosting.valkey_instances FOR UPDATE TO hosting_worker USING (true) WITH CHECK (true);
ALTER TABLE hosting.valkey_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.valkey_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY vk_job_api_select ON hosting.valkey_jobs FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=valkey_jobs.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY vk_job_api_insert ON hosting.valkey_jobs FOR INSERT TO hosting_api
  WITH CHECK (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=valkey_jobs.organization_id
                      AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));
CREATE POLICY vk_job_worker_select ON hosting.valkey_jobs FOR SELECT TO hosting_worker USING (true);
CREATE POLICY vk_job_worker_update ON hosting.valkey_jobs FOR UPDATE TO hosting_worker USING (true) WITH CHECK (true);
