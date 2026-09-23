-- Run as a dedicated migration role. The serving role must not own these tables,
-- have BYPASSRLS, or be able to CREATE in the hosting schema.
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
CREATE SCHEMA IF NOT EXISTS hosting;
REVOKE ALL ON SCHEMA hosting FROM PUBLIC;

CREATE TABLE hosting.organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE hosting.memberships (
  organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
  actor_sub text NOT NULL CHECK (length(actor_sub) BETWEEN 1 AND 255),
  role text NOT NULL CHECK (role IN ('owner','admin','viewer')),
  PRIMARY KEY (organization_id, actor_sub)
);
CREATE INDEX memberships_actor_idx ON hosting.memberships(actor_sub,organization_id);
CREATE TABLE hosting.projects (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (organization_id,id),
  UNIQUE (organization_id,name)
);
CREATE INDEX projects_org_created_idx ON hosting.projects(organization_id,created_at DESC);
CREATE TABLE hosting.audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
  actor_sub text NOT NULL,
  action text NOT NULL,
  resource_id uuid NOT NULL,
  request_id uuid NOT NULL UNIQUE,
  previous_hash text NOT NULL,
  event_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_org_id_idx ON hosting.audit_events(organization_id,id DESC);

-- The API role gets no destructive, DDL or cross-schema privileges.
-- Substitute the actual pre-created non-superuser role in the next four lines.
GRANT USAGE ON SCHEMA hosting TO hosting_api;
GRANT SELECT ON hosting.organizations,hosting.memberships,hosting.projects TO hosting_api;
GRANT INSERT ON hosting.projects,hosting.audit_events TO hosting_api;
GRANT SELECT ON hosting.audit_events TO hosting_api;
GRANT USAGE ON SEQUENCE hosting.audit_events_id_seq TO hosting_api;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- This schema is private to the control plane and not exposed by PostgREST.
-- RLS adds defense in depth; the API explicitly checks membership for every route.
ALTER TABLE hosting.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.projects FORCE ROW LEVEL SECURITY;
CREATE POLICY projects_api_read ON hosting.projects FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m
                 WHERE m.organization_id=projects.organization_id AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY projects_api_insert ON hosting.projects FOR INSERT TO hosting_api
  WITH CHECK (EXISTS (SELECT 1 FROM hosting.memberships m
                      WHERE m.organization_id=projects.organization_id AND m.actor_sub=current_setting('hosting.actor_sub',true)
                      AND m.role IN ('owner','admin')));
