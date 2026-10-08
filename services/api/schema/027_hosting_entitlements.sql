-- Hosting-local operator assignments. Commercial entitlement import is separate.
CREATE TABLE hosting.entitlement_policy (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  require_assigned boolean NOT NULL DEFAULT false
);
INSERT INTO hosting.entitlement_policy DEFAULT VALUES;
CREATE TABLE hosting.entitlement_versions (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
  revision bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
  plan_ref text NOT NULL CHECK (plan_ref ~ '^plan://[a-zA-Z0-9/_-]{1,120}$'),
  evidence_ref text NOT NULL CHECK (evidence_ref ~ '^entitlement://[a-zA-Z0-9/_-]{1,120}$'),
  features text[] NOT NULL CHECK (features <@ ARRAY['release','postgres','valkey','storage','domain','domain_registration','build']::text[]
    AND array_position(features,NULL) IS NULL AND cardinality(features)<=7),
  cpu_milli_limit bigint NOT NULL CHECK (cpu_milli_limit>0),
  memory_mb_limit bigint NOT NULL CHECK (memory_mb_limit>0),
  project_limit integer NOT NULL CHECK (project_limit BETWEEN 0 AND 100000),
  application_limit integer NOT NULL CHECK (application_limit BETWEEN 0 AND 100000),
  domain_limit integer NOT NULL CHECK (domain_limit BETWEEN 0 AND 100000),
  registration_limit integer NOT NULL CHECK (registration_limit BETWEEN 0 AND 100000),
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL CHECK (valid_until>valid_from),
  issued_by text NOT NULL CHECK (issued_by ~ '^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id,id)
);
CREATE INDEX entitlement_history ON hosting.entitlement_versions(organization_id,revision DESC);
CREATE TABLE hosting.organization_entitlements (
  organization_id uuid PRIMARY KEY REFERENCES hosting.organizations(id),
  version_id uuid NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id,version_id) REFERENCES hosting.entitlement_versions(organization_id,id)
);
CREATE TABLE hosting.entitlement_policy_changes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_name text NOT NULL,
  evidence_ref text NOT NULL CHECK (evidence_ref ~ '^entitlement://[a-zA-Z0-9/_-]{1,120}$'),
  enabled_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION hosting.entitlement_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'Entitlement history is immutable'; END $$;
CREATE TRIGGER entitlement_version_immutable BEFORE UPDATE OR DELETE ON hosting.entitlement_versions
  FOR EACH ROW EXECUTE FUNCTION hosting.entitlement_immutable();
CREATE TRIGGER entitlement_policy_history_immutable BEFORE UPDATE OR DELETE ON hosting.entitlement_policy_changes
  FOR EACH ROW EXECUTE FUNCTION hosting.entitlement_immutable();

CREATE FUNCTION hosting.entitlement_usage(p_org uuid) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT jsonb_build_object(
    'projects',(SELECT count(*) FROM hosting.projects WHERE organization_id=p_org),
    'applications',(SELECT count(*) FROM hosting.applications WHERE organization_id=p_org),
    'domains',(SELECT count(*) FROM hosting.domains WHERE organization_id=p_org),
    'registrations',(SELECT count(*) FROM hosting.domain_registration_requests
      WHERE organization_id=p_org AND state NOT IN ('CANCELLED','FAILED')),
    'cpu_milli',(SELECT coalesce(sum(cpu_milli),0) FROM hosting.capacity_intervals WHERE organization_id=p_org AND ended_at IS NULL),
    'memory_mb',(SELECT coalesce(sum(memory_mb),0) FROM hosting.capacity_intervals WHERE organization_id=p_org AND ended_at IS NULL))
$$;

CREATE FUNCTION hosting.entitlement_audit(p_org uuid,p_actor text,p_action text,p_resource uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE previous text; request uuid := gen_random_uuid();
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(p_org::text,0));
  SELECT event_hash INTO previous FROM hosting.audit_events WHERE organization_id=p_org ORDER BY id DESC LIMIT 1;
  previous := coalesce(previous,'');
  INSERT INTO hosting.audit_events(organization_id,actor_sub,action,resource_id,request_id,previous_hash,event_hash)
    VALUES (p_org,p_actor,p_action,p_resource,request,previous,
      encode(public.digest(previous || p_actor || p_action || p_resource::text || request::text,'sha256'),'hex'));
END $$;

CREATE FUNCTION hosting.validate_entitlement_assignment() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v hosting.entitlement_versions; old_revision bigint; usage jsonb; actor text;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Entitlement assignment cannot be deleted'; END IF;
  actor := current_setting('hosting.entitlement_operator',true);
  IF actor IS NULL OR actor !~ '^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$' THEN
    RAISE EXCEPTION 'Protected entitlement operator required';
  END IF;
  PERFORM 1 FROM hosting.entitlement_policy WHERE singleton FOR SHARE;
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.organization_id::text,7));
  SELECT * INTO v FROM hosting.entitlement_versions WHERE organization_id=NEW.organization_id AND id=NEW.version_id;
  IF NOT FOUND OR v.valid_from>clock_timestamp() OR v.valid_until<=clock_timestamp() THEN
    RAISE EXCEPTION 'Active entitlement required';
  END IF;
  IF TG_OP='UPDATE' THEN
    IF NEW.organization_id<>OLD.organization_id THEN RAISE EXCEPTION 'Entitlement tenant cannot change'; END IF;
    SELECT revision INTO old_revision FROM hosting.entitlement_versions WHERE id=OLD.version_id;
    IF v.revision<=old_revision THEN RAISE EXCEPTION 'Entitlement revision must advance'; END IF;
  END IF;
  usage := hosting.entitlement_usage(NEW.organization_id);
  IF (usage->>'projects')::bigint>v.project_limit OR (usage->>'applications')::bigint>v.application_limit OR
     (usage->>'domains')::bigint>v.domain_limit OR (usage->>'registrations')::bigint>v.registration_limit OR
     (usage->>'cpu_milli')::numeric>v.cpu_milli_limit OR (usage->>'memory_mb')::numeric>v.memory_mb_limit THEN
    RAISE EXCEPTION 'Entitlement below existing reservations';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM hosting.organization_quotas WHERE organization_id=NEW.organization_id
    AND cpu_milli_limit=v.cpu_milli_limit AND memory_mb_limit=v.memory_mb_limit) THEN
    RAISE EXCEPTION 'Matching reservation quota required';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END $$;
CREATE TRIGGER entitlement_assignment_validate BEFORE INSERT OR UPDATE OR DELETE ON hosting.organization_entitlements
  FOR EACH ROW EXECUTE FUNCTION hosting.validate_entitlement_assignment();

CREATE FUNCTION hosting.log_entitlement_assignment() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  -- AFTER avoids duplicate audit facts from the INSERT branch of an upsert.
  PERFORM hosting.entitlement_audit(NEW.organization_id,current_setting('hosting.entitlement_operator'),
    'entitlement.assigned',NEW.version_id);
  RETURN NEW;
END $$;
CREATE TRIGGER entitlement_assignment_audit AFTER INSERT OR UPDATE ON hosting.organization_entitlements
  FOR EACH ROW EXECUTE FUNCTION hosting.log_entitlement_assignment();

CREATE FUNCTION hosting.validate_entitlement_policy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor text; evidence text; assignment record;
BEGIN
  IF TG_OP='DELETE' OR NEW.singleton<>OLD.singleton OR NOT NEW.require_assigned OR OLD.require_assigned THEN
    RAISE EXCEPTION 'Entitlement enforcement can only be enabled once';
  END IF;
  actor := current_setting('hosting.entitlement_operator',true);
  evidence := current_setting('hosting.entitlement_evidence',true);
  IF actor IS NULL OR actor !~ '^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$' OR
     evidence IS NULL OR evidence !~ '^entitlement://[a-zA-Z0-9/_-]{1,120}$' THEN
    RAISE EXCEPTION 'Protected entitlement operator and evidence required';
  END IF;
  IF EXISTS (SELECT 1 FROM hosting.organizations o LEFT JOIN hosting.organization_entitlements e ON e.organization_id=o.id
    LEFT JOIN hosting.entitlement_versions v ON (v.organization_id,v.id)=(e.organization_id,e.version_id)
    LEFT JOIN hosting.organization_quotas q ON q.organization_id=o.id
    WHERE v.id IS NULL OR v.valid_from>clock_timestamp() OR v.valid_until<=clock_timestamp() OR
      q.organization_id IS NULL OR q.cpu_milli_limit>v.cpu_milli_limit OR q.memory_mb_limit>v.memory_mb_limit) THEN
    RAISE EXCEPTION 'All tenants require active entitlements and bounded quotas';
  END IF;
  INSERT INTO hosting.entitlement_policy_changes(operator_name,evidence_ref) VALUES (actor,evidence);
  FOR assignment IN SELECT organization_id,version_id FROM hosting.organization_entitlements ORDER BY organization_id LOOP
    PERFORM hosting.entitlement_audit(assignment.organization_id,actor,'entitlement.enforcement_enabled',assignment.version_id);
  END LOOP;
  RETURN NEW;
END $$;
CREATE TRIGGER entitlement_policy_validate BEFORE UPDATE OR DELETE ON hosting.entitlement_policy
  FOR EACH ROW EXECUTE FUNCTION hosting.validate_entitlement_policy();

-- Shared policy lock precedes the tenant lock and capacity-quota lock (seed 4).
-- A successful check authorizes the transaction's admission/execution start.
CREATE FUNCTION hosting.entitlement_permits(p_org uuid,p_feature text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE required boolean; v hosting.entitlement_versions;
BEGIN
  SELECT require_assigned INTO required FROM hosting.entitlement_policy WHERE singleton FOR SHARE;
  PERFORM pg_advisory_xact_lock(hashtextextended(p_org::text,7));
  SELECT v1.* INTO v FROM hosting.organization_entitlements e JOIN hosting.entitlement_versions v1
    ON (v1.organization_id,v1.id)=(e.organization_id,e.version_id) WHERE e.organization_id=p_org;
  IF NOT FOUND THEN RETURN NOT coalesce(required,true); END IF;
  RETURN v.valid_from<=clock_timestamp() AND v.valid_until>clock_timestamp()
    AND (p_feature='' OR p_feature=ANY(v.features));
END $$;

CREATE FUNCTION hosting.entitlement_admission() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE org uuid; v hosting.entitlement_versions; used bigint; ceiling bigint;
BEGIN
  IF TG_TABLE_NAME='github_builds' THEN
    SELECT organization_id INTO org FROM hosting.git_sources WHERE id=NEW.source_id;
  ELSE org := NEW.organization_id; END IF;
  IF TG_OP='UPDATE' THEN
    IF NEW.state<>'PROCESSING' OR OLD.state='PROCESSING' THEN RETURN NEW; END IF;
  END IF;
  IF NOT hosting.entitlement_permits(org,TG_ARGV[0]) THEN
    RAISE EXCEPTION 'entitlement_unavailable' USING ERRCODE='P0001';
  END IF;
  IF TG_OP='UPDATE' OR TG_ARGV[1]='' THEN RETURN NEW; END IF;
  SELECT v1.* INTO v FROM hosting.organization_entitlements e JOIN hosting.entitlement_versions v1
    ON (v1.organization_id,v1.id)=(e.organization_id,e.version_id) WHERE e.organization_id=org;
  IF NOT FOUND THEN RETURN NEW; END IF;
  CASE TG_ARGV[1]
    WHEN 'projects' THEN SELECT count(*) INTO used FROM hosting.projects WHERE organization_id=org; ceiling := v.project_limit;
    WHEN 'applications' THEN SELECT count(*) INTO used FROM hosting.applications WHERE organization_id=org; ceiling := v.application_limit;
    WHEN 'domains' THEN SELECT count(*) INTO used FROM hosting.domains WHERE organization_id=org; ceiling := v.domain_limit;
    WHEN 'registrations' THEN
      SELECT count(*) INTO used FROM hosting.domain_registration_requests WHERE organization_id=org AND state NOT IN ('CANCELLED','FAILED');
      ceiling := v.registration_limit;
  END CASE;
  IF used>=ceiling THEN RAISE EXCEPTION 'entitlement_limit_exceeded' USING ERRCODE='P0001'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER entitlement_project BEFORE INSERT ON hosting.projects FOR EACH ROW EXECUTE FUNCTION hosting.entitlement_admission('','projects');
CREATE TRIGGER entitlement_application BEFORE INSERT ON hosting.applications FOR EACH ROW EXECUTE FUNCTION hosting.entitlement_admission('','applications');
CREATE TRIGGER entitlement_domain BEFORE INSERT ON hosting.domains FOR EACH ROW EXECUTE FUNCTION hosting.entitlement_admission('domain','domains');
CREATE TRIGGER entitlement_registration BEFORE INSERT OR UPDATE OF state ON hosting.domain_registration_requests
  FOR EACH ROW EXECUTE FUNCTION hosting.entitlement_admission('domain_registration','registrations');
CREATE TRIGGER entitlement_release BEFORE INSERT ON hosting.releases FOR EACH ROW EXECUTE FUNCTION hosting.entitlement_admission('release','');
CREATE TRIGGER entitlement_postgres BEFORE INSERT ON hosting.postgres_instances FOR EACH ROW EXECUTE FUNCTION hosting.entitlement_admission('postgres','');
CREATE TRIGGER entitlement_valkey BEFORE INSERT ON hosting.valkey_instances FOR EACH ROW EXECUTE FUNCTION hosting.entitlement_admission('valkey','');
CREATE TRIGGER entitlement_storage BEFORE INSERT ON hosting.object_storage_instances FOR EACH ROW EXECUTE FUNCTION hosting.entitlement_admission('storage','');
CREATE TRIGGER entitlement_build BEFORE INSERT ON hosting.github_builds FOR EACH ROW EXECUTE FUNCTION hosting.entitlement_admission('build','');

CREATE FUNCTION hosting.entitlement_capacity() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v hosting.entitlement_versions; cpu numeric; memory numeric;
BEGIN
  IF NOT hosting.entitlement_permits(NEW.organization_id,NEW.resource_type) THEN
    RAISE EXCEPTION 'entitlement_unavailable' USING ERRCODE='P0001';
  END IF;
  SELECT v1.* INTO v FROM hosting.organization_entitlements e JOIN hosting.entitlement_versions v1
    ON (v1.organization_id,v1.id)=(e.organization_id,e.version_id) WHERE e.organization_id=NEW.organization_id;
  IF NOT FOUND THEN RETURN NEW; END IF;
  SELECT coalesce(sum(cpu_milli),0),coalesce(sum(memory_mb),0) INTO cpu,memory
    FROM hosting.capacity_intervals WHERE organization_id=NEW.organization_id AND ended_at IS NULL;
  IF cpu+NEW.cpu_milli>v.cpu_milli_limit OR memory+NEW.memory_mb>v.memory_mb_limit THEN
    RAISE EXCEPTION 'entitlement_limit_exceeded' USING ERRCODE='P0001';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER a_entitlement_capacity BEFORE INSERT ON hosting.capacity_intervals
  FOR EACH ROW EXECUTE FUNCTION hosting.entitlement_capacity();

CREATE FUNCTION hosting.entitlement_readback(p_org uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v hosting.entitlement_versions; status text; version jsonb; usage jsonb;
BEGIN
  IF current_setting('hosting.auth_kind',true) IS DISTINCT FROM 'human' OR NOT EXISTS (
    SELECT 1 FROM hosting.memberships WHERE organization_id=p_org AND actor_sub=current_setting('hosting.actor_sub',true)) THEN
    RETURN NULL;
  END IF;
  SELECT v1.* INTO v FROM hosting.organization_entitlements e JOIN hosting.entitlement_versions v1
    ON (v1.organization_id,v1.id)=(e.organization_id,e.version_id) WHERE e.organization_id=p_org;
  status := CASE WHEN NOT FOUND THEN 'UNCONFIGURED' WHEN v.valid_from<=clock_timestamp() AND v.valid_until>clock_timestamp()
    THEN 'ACTIVE' ELSE 'EXPIRED' END;
  IF status<>'UNCONFIGURED' THEN
    version := jsonb_build_object('id',v.id,'plan_ref',v.plan_ref,'features',v.features,
      'valid_from',v.valid_from,'valid_until',v.valid_until,'cpu_milli_limit',v.cpu_milli_limit::text,'memory_mb_limit',v.memory_mb_limit::text,
      'project_limit',v.project_limit,'application_limit',v.application_limit,'domain_limit',v.domain_limit,'registration_limit',v.registration_limit);
  END IF;
  usage := hosting.entitlement_usage(p_org);
  RETURN jsonb_build_object('authority','OPERATOR_ASSIGNED','status',status,'version',version,
    'requires_assignment',(SELECT require_assigned FROM hosting.entitlement_policy WHERE singleton),
    'usage',usage || jsonb_build_object('cpu_milli',usage->>'cpu_milli','memory_mb',usage->>'memory_mb'));
END $$;

REVOKE ALL ON FUNCTION hosting.entitlement_immutable(),hosting.entitlement_usage(uuid),
  hosting.entitlement_audit(uuid,text,text,uuid),hosting.validate_entitlement_assignment(),hosting.log_entitlement_assignment(),hosting.validate_entitlement_policy(),
  hosting.entitlement_permits(uuid,text),hosting.entitlement_admission(),hosting.entitlement_capacity(),hosting.entitlement_readback(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hosting.entitlement_permits(uuid,text) TO hosting_worker,hosting_buildworker;
GRANT EXECUTE ON FUNCTION hosting.entitlement_readback(uuid) TO hosting_api;
-- Runtime roles have no table privileges, even if a SQL client is compromised.
ALTER TABLE hosting.entitlement_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.entitlement_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE hosting.organization_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.organization_entitlements FORCE ROW LEVEL SECURITY;
