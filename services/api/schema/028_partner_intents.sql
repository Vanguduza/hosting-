-- Durable, tenant-scoped desired state and immutable readback receipts.
-- Recording an intent grants no commercial or provisioning authority.
CREATE FUNCTION hosting.intent_canonical(value jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE result text;
BEGIN
  CASE jsonb_typeof(value)
    WHEN 'object' THEN
      SELECT '{'||coalesce(string_agg(to_jsonb(key)::text||':'||hosting.intent_canonical(v),',' ORDER BY key COLLATE "C"),'')||'}'
        INTO result FROM jsonb_each(value) AS x(key,v);
    WHEN 'array' THEN
      SELECT '['||coalesce(string_agg(hosting.intent_canonical(v),',' ORDER BY ordinal),'')||']'
        INTO result FROM jsonb_array_elements(value) WITH ORDINALITY AS x(v,ordinal);
    ELSE result := value::text;
  END CASE;
  RETURN result;
END $$;

CREATE FUNCTION hosting.intent_valid(p jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE k text; v jsonb; s text; keys text[] := ARRAY[
  'schema_version','partner_id','dial_business_account_id','project_id','template_id','template_version',
  'environment_profile','runtime_class','domain_intent','database_profile','storage_profile','backup_profile',
  'observability_profile','resource_budget','release_artifact_ref','secret_refs','tenant_admin_refs',
  'commercial_entitlement_ref','requested_by','request_id'];
BEGIN
  IF jsonb_typeof(p)<>'object' OR octet_length(p::text)>65536 THEN RETURN false; END IF;
  IF NOT p ?& keys OR (SELECT count(*) FROM jsonb_object_keys(p))<>20 THEN RETURN false; END IF;
  FOREACH k IN ARRAY ARRAY['partner_id','dial_business_account_id','template_id','template_version',
                          'commercial_entitlement_ref','requested_by'] LOOP
    s := p->>k;
    IF jsonb_typeof(p->k)<>'string' OR s !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$' OR
       s ~ '[[:space:]]' OR octet_length(s)<>length(s) THEN RETURN false; END IF;
  END LOOP;
  FOREACH k IN ARRAY ARRAY['project_id','request_id'] LOOP
    IF jsonb_typeof(p->k)<>'string' OR (p->>k) !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
       (p->>k) ~ '[[:space:]]' THEN RETURN false; END IF;
  END LOOP;
  FOREACH k IN ARRAY ARRAY['schema_version','environment_profile','runtime_class','database_profile',
                          'storage_profile','backup_profile','observability_profile','release_artifact_ref'] LOOP
    IF jsonb_typeof(p->k)<>'string' THEN RETURN false; END IF;
  END LOOP;
  IF p->>'schema_version'<>'1.0' OR p->>'runtime_class'<>'docker-http-v1' OR
     p->>'environment_profile' NOT IN ('development','staging','production') OR
     p->>'database_profile' NOT IN ('none','postgres-private-v1','supabase-unqualified') OR
     p->>'storage_profile' NOT IN ('none','garage-development-v1','s3-redundant-unqualified') OR
     p->>'backup_profile'<>'encrypted-offhost-v1' OR p->>'observability_profile'<>'release-health-v1' THEN RETURN false; END IF;
  s := p->>'release_artifact_ref';
  IF s !~ '^[a-z0-9][a-z0-9./:_-]{1,240}@sha256:[a-f0-9]{64}$' OR s ~ '[[:space:]]' THEN RETURN false; END IF;
  IF jsonb_typeof(p->'domain_intent')<>'object' THEN RETURN false; END IF;
  IF NOT (p->'domain_intent') ? 'hostname' OR (SELECT count(*) FROM jsonb_object_keys(p->'domain_intent'))<>1 OR
     jsonb_typeof(p->'domain_intent'->'hostname')<>'string' THEN RETURN false; END IF;
  s := p->'domain_intent'->>'hostname';
  IF length(s)>253 OR s !~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])$' OR
     s ~ '[[:space:]]' OR s ~ '\.(local|internal)$' THEN RETURN false; END IF;
  IF jsonb_typeof(p->'resource_budget')<>'object' THEN RETURN false; END IF;
  IF NOT (p->'resource_budget') ?& ARRAY['cpu_milli','memory_mb'] OR
     (SELECT count(*) FROM jsonb_object_keys(p->'resource_budget'))<>2 THEN RETURN false; END IF;
  FOREACH k IN ARRAY ARRAY['cpu_milli','memory_mb'] LOOP
    v := p->'resource_budget'->k;
    IF jsonb_typeof(v)<>'number' OR v::text !~ '^[0-9]+$' THEN RETURN false; END IF;
  END LOOP;
  IF (p->'resource_budget'->>'cpu_milli')::numeric NOT BETWEEN 50 AND 32000 OR
     (p->'resource_budget'->>'memory_mb')::numeric NOT BETWEEN 64 AND 32768 THEN RETURN false; END IF;
  FOREACH k IN ARRAY ARRAY['secret_refs','tenant_admin_refs'] LOOP
    IF jsonb_typeof(p->k)<>'array' THEN RETURN false; END IF;
    IF jsonb_array_length(p->k)>(CASE k WHEN 'secret_refs' THEN 64 ELSE 32 END) OR
       (k='tenant_admin_refs' AND jsonb_array_length(p->k)=0) OR
       (SELECT count(DISTINCT item) FROM jsonb_array_elements(p->k) AS x(item))<>jsonb_array_length(p->k) THEN RETURN false; END IF;
    FOR v IN SELECT item FROM jsonb_array_elements(p->k) AS x(item) LOOP
      IF jsonb_typeof(v)<>'string' THEN RETURN false; END IF;
      s := v #>> '{}';
      IF s ~ '[[:space:]]' OR octet_length(s)<>length(s) THEN RETURN false; END IF;
      IF k='secret_refs' THEN
        IF length(s)>256 OR s !~ '^secret://[a-z0-9][a-z0-9/_-]{0,190}#[1-9][0-9]{0,8}$' THEN RETURN false; END IF;
      ELSIF s !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$' THEN RETURN false; END IF;
    END LOOP;
  END LOOP;
  RETURN true;
END $$;

CREATE TABLE hosting.partner_intents (
  organization_id uuid NOT NULL,
  application_id uuid NOT NULL,
  id uuid NOT NULL,
  payload jsonb NOT NULL CHECK (hosting.intent_valid(payload)),
  intent_sha256 text GENERATED ALWAYS AS (encode(public.digest(hosting.intent_canonical(payload),'sha256'),'hex')) STORED,
  submitted_by text NOT NULL CHECK (length(submitted_by) BETWEEN 1 AND 255),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id,id),
  UNIQUE (organization_id,application_id,id),
  FOREIGN KEY (organization_id,application_id) REFERENCES hosting.applications(organization_id,id),
  CHECK (payload->>'request_id'=id::text)
);
CREATE INDEX partner_intent_app_history ON hosting.partner_intents(organization_id,application_id,created_at DESC,id);
CREATE FUNCTION hosting.intent_receipt_valid(p jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE v jsonb; seen text[] := ARRAY[]::text[]; required text[] := ARRAY['intake','commercial_authority',
  'profile_qualification','tenant_admin_bindings','secret_bindings','backups','tenant_project_environment',
  'hosting_plan','artifact_admission','runtime_placement','domain_ownership','route_tls','postgres','storage',
  'resource_budget','release_health','observability'];
BEGIN
  IF jsonb_typeof(p)<>'object' OR NOT p ?& ARRAY['controller_version','request_id','intent_sha256','state',
    'observed_at','resource_mutations_performed','transformations','stages'] OR
    (SELECT count(*) FROM jsonb_object_keys(p))<>8 THEN RETURN false; END IF;
  IF NOT p @> '{"controller_version":"hosting-readback-v1","state":"NOT_QUALIFIED","resource_mutations_performed":false}'::jsonb OR
    p->'transformations'<>'[]'::jsonb OR jsonb_typeof(p->'stages')<>'array' THEN RETURN false; END IF;
  IF jsonb_typeof(p->'request_id')<>'string' OR (p->>'request_id') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
    jsonb_typeof(p->'intent_sha256')<>'string' OR (p->>'intent_sha256') !~ '^[a-f0-9]{64}$' OR
    jsonb_typeof(p->'observed_at')<>'string' OR (p->>'observed_at') !~ '(Z|[+-][0-9]{2}:[0-9]{2})$' THEN RETURN false; END IF;
  PERFORM (p->>'observed_at')::timestamptz;
  FOR v IN SELECT item FROM jsonb_array_elements(p->'stages') AS x(item) LOOP
    IF jsonb_typeof(v)<>'object' OR NOT v ?& ARRAY['stage','state','reason'] OR
      (SELECT count(*) FROM jsonb_object_keys(v))<>3 OR
      jsonb_typeof(v->'stage')<>'string' OR NOT (v->>'stage')=ANY(required) OR
      (v->>'stage')=ANY(seen) OR jsonb_typeof(v->'state')<>'string' OR
      (v->>'state') NOT IN ('RECORDED','MATCHED','OBSERVED','OBSERVED_HEALTHY','BLOCKED','NOT_REQUESTED') OR
      jsonb_typeof(v->'reason')<>'string' OR length(v->>'reason') NOT BETWEEN 1 AND 500 THEN RETURN false; END IF;
    seen := array_append(seen,v->>'stage');
  END LOOP;
  RETURN seen=required;
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN RETURN false;
END $$;
CREATE TABLE hosting.partner_intent_evaluations (
  organization_id uuid NOT NULL,
  application_id uuid NOT NULL,
  intent_id uuid NOT NULL,
  id uuid NOT NULL,
  revision bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
  receipt jsonb NOT NULL CHECK (hosting.intent_receipt_valid(receipt)),
  evaluated_by text NOT NULL CHECK (length(evaluated_by) BETWEEN 1 AND 255),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id,id),
  FOREIGN KEY (organization_id,application_id,intent_id) REFERENCES hosting.partner_intents(organization_id,application_id,id),
  CHECK (receipt->>'request_id'=intent_id::text)
);
CREATE INDEX partner_intent_evaluation_history ON hosting.partner_intent_evaluations(organization_id,intent_id,revision DESC);

CREATE FUNCTION hosting.partner_intent_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'Partner intent history is immutable'; END $$;
CREATE TRIGGER partner_intent_immutable BEFORE UPDATE OR DELETE ON hosting.partner_intents
  FOR EACH ROW EXECUTE FUNCTION hosting.partner_intent_immutable();
CREATE TRIGGER partner_intent_evaluation_immutable BEFORE UPDATE OR DELETE ON hosting.partner_intent_evaluations
  FOR EACH ROW EXECUTE FUNCTION hosting.partner_intent_immutable();

CREATE FUNCTION hosting.partner_intent_binding() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE app record; digest text;
BEGIN
  IF TG_TABLE_NAME='partner_intents' THEN
    SELECT project_id,environment INTO app FROM hosting.applications WHERE (organization_id,id)=(NEW.organization_id,NEW.application_id);
    IF NOT FOUND OR app.project_id::text IS DISTINCT FROM NEW.payload->>'project_id' OR
       app.environment IS DISTINCT FROM NEW.payload->>'environment_profile' THEN
      RAISE EXCEPTION 'intent_binding_conflict' USING ERRCODE='P0001';
    END IF;
  ELSE
    SELECT intent_sha256 INTO digest FROM hosting.partner_intents
      WHERE (organization_id,application_id,id)=(NEW.organization_id,NEW.application_id,NEW.intent_id);
    IF NOT FOUND OR digest IS DISTINCT FROM NEW.receipt->>'intent_sha256' THEN
      RAISE EXCEPTION 'intent_binding_conflict' USING ERRCODE='P0001';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER partner_intent_binding BEFORE INSERT ON hosting.partner_intents FOR EACH ROW EXECUTE FUNCTION hosting.partner_intent_binding();
CREATE TRIGGER partner_intent_evaluation_binding BEFORE INSERT ON hosting.partner_intent_evaluations FOR EACH ROW EXECUTE FUNCTION hosting.partner_intent_binding();

CREATE FUNCTION hosting.partner_intent_audit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor text; action text;
BEGIN
  IF TG_TABLE_NAME='partner_intents' THEN actor := NEW.submitted_by; action := 'intent.recorded';
  ELSE actor := NEW.evaluated_by; action := 'intent.reconciled'; END IF;
  PERFORM hosting.entitlement_audit(NEW.organization_id,actor,action,NEW.id);
  RETURN NEW;
END $$;
CREATE TRIGGER partner_intent_audit AFTER INSERT ON hosting.partner_intents FOR EACH ROW EXECUTE FUNCTION hosting.partner_intent_audit();
CREATE TRIGGER partner_intent_evaluation_audit AFTER INSERT ON hosting.partner_intent_evaluations FOR EACH ROW EXECUTE FUNCTION hosting.partner_intent_audit();

GRANT SELECT ON hosting.partner_intents,hosting.partner_intent_evaluations TO hosting_api;
GRANT INSERT (organization_id,application_id,id,payload,submitted_by) ON hosting.partner_intents TO hosting_api;
GRANT INSERT (organization_id,application_id,intent_id,id,receipt,evaluated_by) ON hosting.partner_intent_evaluations TO hosting_api;
GRANT USAGE ON SEQUENCE hosting.partner_intent_evaluations_revision_seq TO hosting_api;
ALTER TABLE hosting.partner_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.partner_intents FORCE ROW LEVEL SECURITY;
ALTER TABLE hosting.partner_intent_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.partner_intent_evaluations FORCE ROW LEVEL SECURITY;
CREATE POLICY partner_intent_read ON hosting.partner_intents FOR SELECT TO hosting_api USING (
  current_setting('hosting.auth_kind',true)='human' AND EXISTS (SELECT 1 FROM hosting.memberships m
  WHERE m.organization_id=partner_intents.organization_id AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));
CREATE POLICY partner_intent_insert ON hosting.partner_intents FOR INSERT TO hosting_api WITH CHECK (
  submitted_by=current_setting('hosting.actor_sub',true) AND current_setting('hosting.auth_kind',true)='human' AND EXISTS (
  SELECT 1 FROM hosting.memberships m WHERE m.organization_id=partner_intents.organization_id
    AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));
CREATE POLICY partner_intent_evaluation_read ON hosting.partner_intent_evaluations FOR SELECT TO hosting_api USING (
  current_setting('hosting.auth_kind',true)='human' AND EXISTS (SELECT 1 FROM hosting.memberships m
  WHERE m.organization_id=partner_intent_evaluations.organization_id AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));
CREATE POLICY partner_intent_evaluation_insert ON hosting.partner_intent_evaluations FOR INSERT TO hosting_api WITH CHECK (
  evaluated_by=current_setting('hosting.actor_sub',true) AND current_setting('hosting.auth_kind',true)='human' AND EXISTS (
  SELECT 1 FROM hosting.memberships m WHERE m.organization_id=partner_intent_evaluations.organization_id
    AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')));

-- One statement snapshot, with authorization checked before any tenant evidence.
CREATE FUNCTION hosting.partner_intent_evidence(p_org uuid,p_app uuid,p_id uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
  WITH requested AS (
    SELECT i.payload FROM hosting.partner_intents i WHERE (i.organization_id,i.application_id,i.id)=(p_org,p_app,p_id)
      AND current_setting('hosting.auth_kind',true)='human' AND EXISTS (SELECT 1 FROM hosting.memberships m
        WHERE m.organization_id=p_org AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role IN ('owner','admin')))
  SELECT jsonb_build_object('observed_at',statement_timestamp(),
    'application',jsonb_build_object('id',a.id,'project_id',a.project_id,'environment',a.environment,'traffic_state',a.traffic_state),
    'release',CASE WHEN r.id IS NULL THEN NULL ELSE jsonb_build_object('id',r.id,'image',r.image,'state',r.state,'node_id',r.node_id,'cpu_milli',r.cpu_milli,'memory_mb',r.memory_mb) END,
    'node',CASE WHEN n.id IS NULL THEN NULL ELSE jsonb_build_object('id',n.id,'enabled',n.enabled,'observed_at',n.observed_at) END,
    'health',CASE WHEN h.release_id IS NULL THEN NULL ELSE jsonb_build_object('release_id',h.release_id,'state',h.state,'checked_at',h.checked_at) END,
    'domain',CASE WHEN d.id IS NULL THEN NULL ELSE jsonb_build_object('hostname',d.hostname,'verified_at',d.verified_at) END,
    'postgres',CASE WHEN pg.id IS NULL THEN NULL ELSE jsonb_build_object('id',pg.id,'state',pg.state,'node_id',pg.node_id) END,
    'storage',CASE WHEN s.id IS NULL THEN NULL ELSE jsonb_build_object('id',s.id,'state',s.state,'node_id',s.node_id) END,
    'artifact_admitted',EXISTS (SELECT 1 FROM hosting.artifact_admissions WHERE image=requested.payload->>'release_artifact_ref'),
    'reservations',(SELECT jsonb_build_object('cpu_milli',coalesce(sum(cpu_milli),0)::text,'memory_mb',coalesce(sum(memory_mb),0)::text)
      FROM hosting.capacity_intervals WHERE organization_id=p_org AND application_id=p_app AND ended_at IS NULL),
    'organization_reserved',(SELECT jsonb_build_object('cpu_milli',coalesce(sum(cpu_milli),0)::text,'memory_mb',coalesce(sum(memory_mb),0)::text)
      FROM hosting.capacity_intervals WHERE organization_id=p_org AND ended_at IS NULL),
    'plan',CASE WHEN v.id IS NULL THEN NULL ELSE jsonb_build_object('id',v.id,'features',v.features,'valid_from',v.valid_from,'valid_until',v.valid_until,
      'cpu_milli_limit',v.cpu_milli_limit::text,'memory_mb_limit',v.memory_mb_limit::text) END,
    'quota',CASE WHEN q.organization_id IS NULL THEN NULL ELSE jsonb_build_object('cpu_milli_limit',q.cpu_milli_limit::text,'memory_mb_limit',q.memory_mb_limit::text) END)
  FROM requested JOIN hosting.applications a ON (a.organization_id,a.id)=(p_org,p_app)
  LEFT JOIN hosting.releases r ON (r.organization_id,r.application_id,r.id)=(p_org,p_app,a.active_release_id)
  LEFT JOIN hosting.nodes n ON n.id=r.node_id
  LEFT JOIN hosting.release_health h ON (h.organization_id,h.application_id,h.release_id)=(p_org,p_app,r.id)
  LEFT JOIN hosting.domains d ON (d.organization_id,d.application_id)=(p_org,p_app)
  LEFT JOIN hosting.postgres_instances pg ON (pg.organization_id,pg.application_id)=(p_org,p_app)
  LEFT JOIN hosting.object_storage_instances s ON (s.organization_id,s.application_id)=(p_org,p_app)
  LEFT JOIN hosting.organization_entitlements e ON e.organization_id=p_org
  LEFT JOIN hosting.entitlement_versions v ON (v.organization_id,v.id)=(e.organization_id,e.version_id)
  LEFT JOIN hosting.organization_quotas q ON q.organization_id=p_org
$$;
REVOKE ALL ON FUNCTION hosting.intent_canonical(jsonb),hosting.intent_valid(jsonb),hosting.intent_receipt_valid(jsonb),hosting.partner_intent_immutable(),
  hosting.partner_intent_binding(),hosting.partner_intent_audit(),hosting.partner_intent_evidence(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hosting.intent_canonical(jsonb),hosting.intent_valid(jsonb),hosting.intent_receipt_valid(jsonb),hosting.partner_intent_evidence(uuid,uuid,uuid) TO hosting_api;
