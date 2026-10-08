-- Signed GitHub push -> isolated rootless build -> admitted immutable image.
-- Registration requires the protected operator role, never the webhook role.
CREATE TABLE hosting.git_sources (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
  application_id uuid NOT NULL,
  repository_id bigint NOT NULL CHECK (repository_id > 0),
  full_name text NOT NULL CHECK (full_name ~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'),
  branch text NOT NULL CHECK (branch ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$' AND position('..' in branch)=0),
  image_repository text NOT NULL CHECK (image_repository ~ '^[a-z0-9][a-z0-9./:_-]{1,240}$' AND image_repository !~ ':[^/]+$'),
  dockerfile text NOT NULL DEFAULT 'Dockerfile' CHECK (dockerfile ~ '^[A-Za-z0-9][A-Za-z0-9_./-]{0,159}$' AND position('..' in dockerfile)=0),
  builder text NOT NULL CHECK (builder ~ '^[A-Za-z0-9_-]{1,64}$'),
  policy_revision text NOT NULL CHECK (policy_revision ~ '^[A-Za-z0-9._-]{1,64}$'),
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (repository_id,branch),
  UNIQUE (organization_id,application_id),
  FOREIGN KEY (organization_id,application_id) REFERENCES hosting.applications(organization_id,id)
);
CREATE TABLE hosting.github_builds (
  delivery_id uuid PRIMARY KEY,
  source_id uuid NOT NULL REFERENCES hosting.git_sources(id),
  source_commit text NOT NULL CHECK (source_commit ~ '^[a-f0-9]{40}$'),
  state text NOT NULL DEFAULT 'QUEUED' CHECK (state IN ('QUEUED','RUNNING','ADMITTED','FAILED')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_until timestamptz,
  image text,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX github_builds_claim_idx ON hosting.github_builds(next_attempt_at,delivery_id)
  WHERE state IN ('QUEUED','RUNNING');

GRANT USAGE ON SCHEMA hosting TO hosting_hook,hosting_buildworker;
GRANT SELECT ON hosting.git_sources TO hosting_hook,hosting_buildworker;
GRANT SELECT,INSERT ON hosting.github_builds TO hosting_hook;
GRANT SELECT,UPDATE ON hosting.github_builds TO hosting_buildworker;
GRANT SELECT ON hosting.artifact_admissions TO hosting_buildworker;
ALTER TABLE hosting.git_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.git_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY git_hook_sources ON hosting.git_sources FOR SELECT TO hosting_hook USING (enabled);
CREATE POLICY git_worker_sources ON hosting.git_sources FOR SELECT TO hosting_buildworker USING (true);
ALTER TABLE hosting.github_builds ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.github_builds FORCE ROW LEVEL SECURITY;
CREATE POLICY git_hook_builds_select ON hosting.github_builds FOR SELECT TO hosting_hook USING (true);
CREATE POLICY git_hook_builds_insert ON hosting.github_builds FOR INSERT TO hosting_hook
  WITH CHECK (state='QUEUED' AND attempts=0 AND image IS NULL AND lease_until IS NULL);
CREATE POLICY git_worker_builds_select ON hosting.github_builds FOR SELECT TO hosting_buildworker USING (true);
CREATE POLICY git_worker_builds_update ON hosting.github_builds FOR UPDATE TO hosting_buildworker
  USING (true) WITH CHECK (true);
