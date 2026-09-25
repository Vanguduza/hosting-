-- A private single-node Garage S3 bucket per application. Placement and the
-- volume survive failed jobs; this is not a redundant production profile.
CREATE TABLE hosting.object_storage_instances (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  application_id uuid NOT NULL UNIQUE,
  node_id uuid NOT NULL REFERENCES hosting.nodes(id),
  requested_by text NOT NULL,
  idempotency_key uuid NOT NULL,
  memory_mb integer NOT NULL CHECK (memory_mb BETWEEN 256 AND 16384),
  cpu_milli integer NOT NULL CHECK (cpu_milli BETWEEN 100 AND 16000),
  state text NOT NULL DEFAULT 'QUEUED' CHECK (state IN ('QUEUED','PROVISIONING','READY','FAILED')),
  secret_version integer NOT NULL DEFAULT 0 CHECK (secret_version >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id,id),
  FOREIGN KEY (organization_id,application_id) REFERENCES hosting.applications(organization_id,id)
);
CREATE TABLE hosting.object_storage_jobs (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  instance_id uuid NOT NULL UNIQUE,
  state text NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING','RUNNING','COMPLETE','FAILED')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_until timestamptz,
  last_error text,
  receipt jsonb,
  FOREIGN KEY (organization_id,instance_id) REFERENCES hosting.object_storage_instances(organization_id,id)
);
CREATE INDEX object_storage_jobs_claim_idx ON hosting.object_storage_jobs(next_attempt_at,id)
  WHERE state IN ('PENDING','RUNNING');
GRANT SELECT,INSERT ON hosting.object_storage_instances,hosting.object_storage_jobs TO hosting_api;
GRANT SELECT,UPDATE ON hosting.object_storage_instances,hosting.object_storage_jobs TO hosting_worker;
ALTER TABLE hosting.object_storage_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.object_storage_instances FORCE ROW LEVEL SECURITY;
CREATE POLICY storage_api_select ON hosting.object_storage_instances FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=object_storage_instances.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY storage_api_insert ON hosting.object_storage_instances FOR INSERT TO hosting_api
  WITH CHECK (requested_by=current_setting('hosting.actor_sub',true) AND
              EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=object_storage_instances.organization_id
                      AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));
CREATE POLICY storage_worker_select ON hosting.object_storage_instances FOR SELECT TO hosting_worker USING (true);
CREATE POLICY storage_worker_update ON hosting.object_storage_instances FOR UPDATE TO hosting_worker
  USING (true) WITH CHECK (true);
ALTER TABLE hosting.object_storage_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.object_storage_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY storage_job_api_select ON hosting.object_storage_jobs FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=object_storage_jobs.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY storage_job_api_insert ON hosting.object_storage_jobs FOR INSERT TO hosting_api
  WITH CHECK (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=object_storage_jobs.organization_id
                     AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));
CREATE POLICY storage_job_worker_select ON hosting.object_storage_jobs FOR SELECT TO hosting_worker USING (true);
CREATE POLICY storage_job_worker_update ON hosting.object_storage_jobs FOR UPDATE TO hosting_worker
  USING (true) WITH CHECK (true);

-- Machine release requests need to see their application's resource placement
-- and readiness even though they cannot call a resource-management route.
CREATE POLICY service_pg_release_read ON hosting.postgres_instances FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.service_accounts s WHERE s.organization_id=postgres_instances.organization_id
                 AND s.application_id=postgres_instances.application_id));
CREATE POLICY service_vk_release_read ON hosting.valkey_instances FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.service_accounts s WHERE s.organization_id=valkey_instances.organization_id
                 AND s.application_id=valkey_instances.application_id));
CREATE POLICY service_storage_release_read ON hosting.object_storage_instances FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.service_accounts s
                 WHERE s.organization_id=object_storage_instances.organization_id
                   AND s.application_id=object_storage_instances.application_id));
