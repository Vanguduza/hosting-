-- Reviewed profile attestations are imported only by a protected operator.
-- Matching this registry does not certify the estate or authorize execution.
CREATE FUNCTION hosting.execution_profile_valid(p jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE k text; v jsonb; s text; seen text[]:=ARRAY[]::text[]; keys text[]:=ARRAY[
 'schema_version','id','organization_id','template_id','template_version','environment_profile','runtime_class',
 'release_artifact_ref','database_profile','storage_profile','backup_profile','observability_profile',
 'resource_ceiling','node_bindings','enabled','valid_from','valid_until','qualification_refs'];
BEGIN
 IF p IS NULL OR jsonb_typeof(p)<>'object' OR octet_length(p::text)>65536 OR NOT p ?& keys OR
    (SELECT count(*) FROM jsonb_object_keys(p))<>18 THEN RETURN false; END IF;
 IF NOT hosting.authority_uuid(p->'id') OR NOT hosting.authority_uuid(p->'organization_id') OR
    NOT p @> '{"schema_version":"1.0","runtime_class":"docker-http-v1","backup_profile":"encrypted-offhost-v1","observability_profile":"release-health-v1"}'::jsonb OR
    jsonb_typeof(p->'enabled')<>'boolean' THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['template_id','template_version','environment_profile','release_artifact_ref','database_profile','storage_profile'] LOOP
   IF jsonb_typeof(p->k)<>'string' OR (p->>k) ~ '[[:space:]]' OR octet_length(p->>k)<>length(p->>k) THEN RETURN false; END IF;
 END LOOP;
 IF (p->>'template_id') !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$' OR
    (p->>'template_version') !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$' OR
    p->>'environment_profile' NOT IN ('development','staging','production') OR
    (p->>'release_artifact_ref') !~ '^[a-z0-9][a-z0-9./:_-]{1,240}@sha256:[a-f0-9]{64}$' OR
    p->>'database_profile' NOT IN ('none','postgres-private-v1') OR p->>'storage_profile' NOT IN ('none','garage-development-v1') OR
    (p->>'storage_profile'='garage-development-v1' AND p->>'environment_profile'<>'development') THEN RETURN false; END IF;
 IF jsonb_typeof(p->'resource_ceiling')<>'object' OR NOT (p->'resource_ceiling') ?& ARRAY['cpu_milli','memory_mb'] OR
    (SELECT count(*) FROM jsonb_object_keys(p->'resource_ceiling'))<>2 THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['cpu_milli','memory_mb'] LOOP
   v:=p->'resource_ceiling'->k;
   IF jsonb_typeof(v)<>'number' OR v::text !~ '^[0-9]+$' THEN RETURN false; END IF;
 END LOOP;
 IF (p->'resource_ceiling'->>'cpu_milli')::numeric NOT BETWEEN 50 AND 32000 OR
    (p->'resource_ceiling'->>'memory_mb')::numeric NOT BETWEEN 64 AND 32768 THEN RETURN false; END IF;
 IF jsonb_typeof(p->'node_bindings')<>'array' OR jsonb_array_length(p->'node_bindings') NOT BETWEEN 1 AND 32 THEN RETURN false; END IF;
 FOR v IN SELECT item FROM jsonb_array_elements(p->'node_bindings') AS x(item) LOOP
   IF jsonb_typeof(v)<>'object' OR NOT v ?& ARRAY['node_id','configuration_sha256'] OR (SELECT count(*) FROM jsonb_object_keys(v))<>2 OR
      NOT hosting.authority_uuid(v->'node_id') OR jsonb_typeof(v->'configuration_sha256')<>'string' OR
      (v->>'configuration_sha256') !~ '^[a-f0-9]{64}$' OR (v->>'node_id')=ANY(seen) THEN RETURN false; END IF;
   seen:=array_append(seen,v->>'node_id');
 END LOOP;
 FOREACH k IN ARRAY ARRAY['valid_from','valid_until'] LOOP
   IF jsonb_typeof(p->k)<>'string' OR (p->>k) ~ '[[:space:]]' OR
      (p->>k) !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,6})?(Z|[+-](0[0-9]|1[0-5]):[0-5][0-9])$' THEN RETURN false; END IF;
   PERFORM (p->>k)::timestamptz;
 END LOOP;
 IF NOT (p->>'valid_from')::timestamptz<(p->>'valid_until')::timestamptz OR
    (p->>'valid_until')::timestamptz>(p->>'valid_from')::timestamptz+interval '2160 hours' THEN RETURN false; END IF;
 IF jsonb_typeof(p->'qualification_refs')<>'object' OR NOT (p->'qualification_refs') ?& ARRAY['template','runtime','estate','compatibility'] OR
    (SELECT count(*) FROM jsonb_object_keys(p->'qualification_refs'))<>4 THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['template','runtime','estate','compatibility'] LOOP
   s:=p->'qualification_refs'->>k;
   IF jsonb_typeof(p->'qualification_refs'->k)<>'string' OR s ~ '[[:space:]]' OR s !~ ('^'||k||'-proof://[A-Za-z0-9/_-]{1,120}$') THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END $$;

-- Bind identity, measured capacity and lifecycle revision, not changing reservations/heartbeat.
CREATE FUNCTION hosting.execution_node_fingerprint(p_node uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT encode(public.digest(hosting.intent_canonical(jsonb_build_object('id',n.id,'endpoint',n.endpoint,
   'server_name',n.server_name,'public_ipv4',host(n.public_ipv4),'cpu_milli',n.cpu_milli,'memory_mb',n.memory_mb,
   'state_revision',coalesce((SELECT max(id) FROM hosting.node_state_changes WHERE node_id=n.id),0)::text)),'sha256'),'hex')
 FROM hosting.nodes n WHERE n.id=p_node
$$;
CREATE FUNCTION hosting.execution_node_eligible(p_node uuid,p_digest text,cpu integer,memory integer,p_asof timestamptz DEFAULT statement_timestamp()) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT coalesce((SELECT n.enabled AND n.public_ipv4 IS NOT NULL AND n.cpu_milli>=cpu AND n.memory_mb>=memory AND
    n.observed_at BETWEEN p_asof-interval '5 minutes' AND p_asof AND
    hosting.execution_node_fingerprint(n.id)=p_digest FROM hosting.nodes n WHERE n.id=p_node),false)
$$;

CREATE TABLE hosting.execution_profile_versions (
 id uuid PRIMARY KEY,
 organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
 revision bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 payload jsonb NOT NULL CHECK (hosting.execution_profile_valid(payload)),
 payload_sha256 text GENERATED ALWAYS AS (encode(public.digest(hosting.intent_canonical(payload),'sha256'),'hex')) STORED,
 issued_by text NOT NULL CHECK (issued_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK (payload->>'id'=id::text AND payload->>'organization_id'=organization_id::text)
);
CREATE INDEX execution_profile_current ON hosting.execution_profile_versions(organization_id,
 (payload->>'template_id'),(payload->>'template_version'),(payload->>'environment_profile'),revision DESC);
ALTER TABLE hosting.execution_profile_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.execution_profile_versions FORCE ROW LEVEL SECURITY;
-- No API table privileges or policies. Protected functions return redacted bounded summaries.
CREATE TRIGGER execution_profile_immutable BEFORE UPDATE OR DELETE ON hosting.execution_profile_versions
 FOR EACH ROW EXECUTE FUNCTION hosting.partner_intent_immutable();
CREATE FUNCTION hosting.execution_profile_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE b jsonb; now_at timestamptz;
BEGIN
 IF current_user IN ('hosting_api','hosting_worker','hosting_admitter','hosting_hook','hosting_buildworker') OR
    NEW.issued_by IS DISTINCT FROM current_setting('hosting.entitlement_operator',true) THEN RAISE EXCEPTION 'Protected profile import required'; END IF;
 IF NOT hosting.execution_profile_valid(NEW.payload) THEN RAISE EXCEPTION 'Invalid reviewed profile'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.id::text,13));
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.organization_id::text,12));
 IF NEW.payload->'enabled'='true'::jsonb THEN
   IF NOT EXISTS (SELECT 1 FROM hosting.artifact_admissions WHERE image=NEW.payload->>'release_artifact_ref') THEN RAISE EXCEPTION 'Profile artifact is not admitted'; END IF;
   -- Lock all bound nodes in a stable order before checking a reviewed snapshot.
   PERFORM 1 FROM hosting.nodes WHERE id IN (SELECT (item->>'node_id')::uuid FROM jsonb_array_elements(NEW.payload->'node_bindings') AS x(item)) ORDER BY id FOR SHARE;
   now_at:=clock_timestamp();
   FOR b IN SELECT item FROM jsonb_array_elements(NEW.payload->'node_bindings') AS x(item) LOOP
     IF NOT hosting.execution_node_eligible((b->>'node_id')::uuid,b->>'configuration_sha256',
         (NEW.payload->'resource_ceiling'->>'cpu_milli')::integer,(NEW.payload->'resource_ceiling'->>'memory_mb')::integer,now_at) THEN
       RAISE EXCEPTION 'Reviewed node configuration or fresh capacity evidence differs';
     END IF;
   END LOOP;
 END IF;
 -- Effective version ordering follows serialization, including protected SQL imports.
 NEW.revision:=nextval('hosting.execution_profile_versions_revision_seq'::regclass);
 RETURN NEW;
END $$;
CREATE TRIGGER execution_profile_insert BEFORE INSERT ON hosting.execution_profile_versions FOR EACH ROW EXECUTE FUNCTION hosting.execution_profile_insert();
CREATE FUNCTION hosting.execution_profile_audit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM hosting.entitlement_audit(NEW.organization_id,NEW.issued_by,'profile.review_recorded',NEW.id);
 RETURN NEW;
END $$;
CREATE TRIGGER execution_profile_audit AFTER INSERT ON hosting.execution_profile_versions FOR EACH ROW EXECUTE FUNCTION hosting.execution_profile_audit();

CREATE FUNCTION hosting.execution_profile_readback(p_org uuid,p_app uuid,p_intent uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 WITH requested AS (
 SELECT i.payload,i.intent_sha256 FROM hosting.partner_intents i WHERE (i.organization_id,i.application_id,i.id)=(p_org,p_app,p_intent)
 AND current_setting('hosting.auth_kind',true)='human' AND EXISTS (SELECT 1 FROM hosting.memberships
 WHERE organization_id=p_org AND actor_sub=current_setting('hosting.actor_sub',true) AND role IN ('owner','admin'))),
 observed AS (
 SELECT p.id,p.payload_sha256,p.payload,r.intent_sha256,
 CASE WHEN p.id IS NULL THEN 'UNCONFIGURED'
      WHEN p.payload->'enabled'<>'true'::jsonb THEN 'DISABLED'
      WHEN (p.payload->>'valid_from')::timestamptz>statement_timestamp() THEN 'NOT_YET_VALID'
      WHEN (p.payload->>'valid_until')::timestamptz<=statement_timestamp() THEN 'EXPIRED'
      WHEN EXISTS (SELECT 1 FROM unnest(ARRAY['runtime_class','release_artifact_ref','database_profile','storage_profile','backup_profile','observability_profile']) AS k(key)
        WHERE p.payload->key IS DISTINCT FROM r.payload->key) THEN 'PROFILE_MISMATCH'
      WHEN NOT EXISTS (SELECT 1 FROM hosting.artifact_admissions WHERE image=r.payload->>'release_artifact_ref') THEN 'ARTIFACT_UNADMITTED'
      WHEN (r.payload->'resource_budget'->>'cpu_milli')::int>(p.payload->'resource_ceiling'->>'cpu_milli')::int OR
           (r.payload->'resource_budget'->>'memory_mb')::int>(p.payload->'resource_ceiling'->>'memory_mb')::int THEN 'BUDGET_EXCEEDED'
      WHEN NOT EXISTS (SELECT 1 FROM jsonb_array_elements(p.payload->'node_bindings') AS x(b) WHERE
        hosting.execution_node_eligible((b->>'node_id')::uuid,b->>'configuration_sha256',
          (p.payload->'resource_ceiling'->>'cpu_milli')::int,(p.payload->'resource_ceiling'->>'memory_mb')::int)) THEN 'NO_ELIGIBLE_NODE'
      WHEN active.id IS NOT NULL AND active.state='SERVING' AND active.image=r.payload->>'release_artifact_ref' AND
        NOT EXISTS (SELECT 1 FROM jsonb_array_elements(p.payload->'node_bindings') AS x(b) WHERE
          (b->>'node_id')::uuid=active.node_id AND hosting.execution_node_eligible(active.node_id,b->>'configuration_sha256',
            (p.payload->'resource_ceiling'->>'cpu_milli')::int,(p.payload->'resource_ceiling'->>'memory_mb')::int)) THEN 'PLACEMENT_MISMATCH'
      ELSE 'MATCHED' END AS state
 FROM requested r LEFT JOIN LATERAL (SELECT * FROM hosting.execution_profile_versions WHERE organization_id=p_org AND
    payload->>'template_id'=r.payload->>'template_id' AND payload->>'template_version'=r.payload->>'template_version' AND
    payload->>'environment_profile'=r.payload->>'environment_profile' ORDER BY revision DESC LIMIT 1) p ON true
 JOIN hosting.applications a ON (a.organization_id,a.id)=(p_org,p_app)
 LEFT JOIN hosting.releases active ON (active.organization_id,active.application_id,active.id)=(p_org,p_app,a.active_release_id))
 SELECT jsonb_build_object('organization_id',p_org,'application_id',p_app,'intent_id',p_intent,'intent_sha256',intent_sha256,
   'observed_at',statement_timestamp(),'state',state,'profile_version_id',id,'profile_sha256',payload_sha256,
   'valid_from',payload->'valid_from','valid_until',payload->'valid_until') FROM observed
$$;
-- Add profile evidence to the same outer statement snapshot as all earlier authority/runtime checks.
ALTER FUNCTION hosting.partner_intent_evidence(uuid,uuid,uuid) RENAME TO partner_intent_authority_evidence_v1;
REVOKE ALL ON FUNCTION hosting.partner_intent_authority_evidence_v1(uuid,uuid,uuid) FROM hosting_api;
CREATE FUNCTION hosting.partner_intent_evidence(p_org uuid,p_app uuid,p_id uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT evidence||jsonb_build_object('execution_profile',hosting.execution_profile_readback(p_org,p_app,p_id))
 FROM (SELECT hosting.partner_intent_authority_evidence_v1(p_org,p_app,p_id) AS evidence) e WHERE evidence IS NOT NULL
$$;
REVOKE ALL ON FUNCTION hosting.execution_profile_valid(jsonb),hosting.execution_node_fingerprint(uuid),hosting.execution_node_eligible(uuid,text,integer,integer,timestamptz),
 hosting.execution_profile_insert(),hosting.execution_profile_audit(),hosting.execution_profile_readback(uuid,uuid,uuid),hosting.partner_intent_evidence(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hosting.execution_profile_readback(uuid,uuid,uuid),hosting.partner_intent_evidence(uuid,uuid,uuid) TO hosting_api;
