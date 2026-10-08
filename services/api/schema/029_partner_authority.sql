-- Hosting consumes a deliberately registered external publisher's assertions.
-- It never grants memberships or mutates business records or resources.
CREATE FUNCTION hosting.authority_uuid(v jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT coalesce(jsonb_typeof(v)='string' AND (v#>>'{}') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND (v#>>'{}') !~ '[[:space:]]',false)
$$;
CREATE FUNCTION hosting.authority_subject(v jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT coalesce(jsonb_typeof(v)='string' AND length(v#>>'{}') BETWEEN 1 AND 255 AND (v#>>'{}') !~ '[[:cntrl:]]',false)
$$;
CREATE FUNCTION hosting.authority_valid(p jsonb,is_source boolean) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE k text; v jsonb; seen text[]:=ARRAY[]::text[]; keys text[];
BEGIN
 IF p IS NULL OR jsonb_typeof(p)<>'object' OR octet_length(p::text)>65536 THEN RETURN false; END IF;
 keys:=CASE WHEN is_source THEN ARRAY['id','organization_id','purpose','name','issuer','client_id','actor_sub','enabled','max_validity_seconds','evidence_ref']
 ELSE ARRAY['schema_version','purpose','id','source_version_id','intent_sha256','sequence','disposition','hosting_entitlement_version_id','admin_bindings','issued_at','valid_until','evidence_ref'] END;
 IF NOT p ?& keys OR (SELECT count(*) FROM jsonb_object_keys(p))<>cardinality(keys) OR
    NOT p @> '{"purpose":"partner-commercial-bindings-v1"}'::jsonb OR NOT hosting.authority_uuid(p->'id') THEN RETURN false; END IF;
 IF is_source THEN
   IF NOT hosting.authority_uuid(p->'organization_id') OR NOT hosting.authority_subject(p->'actor_sub') OR
      jsonb_typeof(p->'enabled')<>'boolean' OR jsonb_typeof(p->'max_validity_seconds')<>'number' OR
      (p->'max_validity_seconds')::text !~ '^[0-9]+$' OR (p->>'max_validity_seconds')::numeric NOT BETWEEN 30 AND 3600 THEN RETURN false; END IF;
   FOREACH k IN ARRAY ARRAY['name','issuer','client_id','evidence_ref'] LOOP
     IF jsonb_typeof(p->k)<>'string' OR (p->>k) ~ '[[:space:]]' OR octet_length(p->>k)<>length(p->>k) THEN RETURN false; END IF;
   END LOOP;
   RETURN (p->>'name') ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$' AND
     length(p->>'issuer')<=512 AND (p->>'issuer') ~ '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$' AND
     (p->>'client_id') ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$' AND
     (p->>'evidence_ref') ~ '^authority://[A-Za-z0-9/_-]{1,120}$';
 END IF;
 IF NOT p @> '{"schema_version":"1.0"}'::jsonb OR NOT hosting.authority_uuid(p->'source_version_id') OR
    jsonb_typeof(p->'sequence')<>'number' OR (p->'sequence')::text !~ '^[0-9]+$' OR
    (p->>'sequence')::numeric NOT BETWEEN 1 AND 9223372036854775807 OR
    jsonb_typeof(p->'intent_sha256')<>'string' OR (p->>'intent_sha256') !~ '^[a-f0-9]{64}$' OR
    jsonb_typeof(p->'evidence_ref')<>'string' OR (p->>'evidence_ref') !~ '^partner-proof://[A-Za-z0-9/_-]{1,120}$' OR
    (p->>'evidence_ref') ~ '[[:space:]]' OR jsonb_typeof(p->'admin_bindings')<>'array' OR
    jsonb_array_length(p->'admin_bindings')>32 THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['issued_at','valid_until'] LOOP
   IF k='valid_until' AND p->k='null'::jsonb THEN CONTINUE; END IF;
   IF jsonb_typeof(p->k)<>'string' OR (p->>k) !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})$' OR
      (p->>k) ~ '[[:space:]]' THEN RETURN false; END IF;
   PERFORM (p->>k)::timestamptz;
 END LOOP;
 IF p->>'disposition'='REVOKE' THEN
   RETURN p->'hosting_entitlement_version_id'='null'::jsonb AND p->'valid_until'='null'::jsonb AND p->'admin_bindings'='[]'::jsonb;
 ELSIF p->>'disposition'<>'AUTHORIZE' OR jsonb_typeof(p->'disposition')<>'string' OR
       NOT hosting.authority_uuid(p->'hosting_entitlement_version_id') OR p->'valid_until'='null'::jsonb OR
       (p->>'valid_until')::timestamptz<=(p->>'issued_at')::timestamptz OR jsonb_array_length(p->'admin_bindings')=0 THEN RETURN false;
 END IF;
 FOR v IN SELECT item FROM jsonb_array_elements(p->'admin_bindings') AS x(item) LOOP
   IF jsonb_typeof(v)<>'object' OR NOT v ?& ARRAY['ref','actor_sub'] OR (SELECT count(*) FROM jsonb_object_keys(v))<>2 OR
      NOT hosting.authority_subject(v->'actor_sub') OR jsonb_typeof(v->'ref')<>'string' OR
      (v->>'ref') !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$' OR (v->>'ref') ~ '[[:space:]]' OR
      (v->>'ref')=ANY(seen) THEN RETURN false; END IF;
   seen:=array_append(seen,v->>'ref');
 END LOOP;
 RETURN true;
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END $$;

CREATE TABLE hosting.partner_authority_sources (
 id uuid PRIMARY KEY,
 organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
 revision bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 payload jsonb NOT NULL CHECK (hosting.authority_valid(payload,true)),
 payload_sha256 text GENERATED ALWAYS AS (encode(public.digest(hosting.intent_canonical(payload),'sha256'),'hex')) STORED,
 issued_by text NOT NULL CHECK (issued_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE (organization_id,id),
 CHECK (payload->>'id'=id::text AND payload->>'organization_id'=organization_id::text)
);
CREATE INDEX partner_authority_source_current ON hosting.partner_authority_sources(organization_id,revision DESC);
CREATE TABLE hosting.partner_authority_receipts (
 organization_id uuid NOT NULL,
 application_id uuid NOT NULL,
 intent_id uuid NOT NULL,
 id uuid NOT NULL,
 source_version_id uuid NOT NULL,
 sequence bigint NOT NULL CHECK (sequence>0),
 payload jsonb NOT NULL CHECK (hosting.authority_valid(payload,false)),
 payload_sha256 text GENERATED ALWAYS AS (encode(public.digest(hosting.intent_canonical(payload),'sha256'),'hex')) STORED,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (organization_id,id),
 UNIQUE (organization_id,intent_id,sequence),
 FOREIGN KEY (organization_id,application_id,intent_id) REFERENCES hosting.partner_intents(organization_id,application_id,id),
 FOREIGN KEY (organization_id,source_version_id) REFERENCES hosting.partner_authority_sources(organization_id,id),
 CHECK (payload->>'id'=id::text AND payload->>'source_version_id'=source_version_id::text AND (payload->>'sequence')::bigint=sequence)
);
CREATE INDEX partner_authority_current ON hosting.partner_authority_receipts(organization_id,intent_id,sequence DESC);
ALTER TABLE hosting.partner_authority_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.partner_authority_sources FORCE ROW LEVEL SECURITY;
ALTER TABLE hosting.partner_authority_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.partner_authority_receipts FORCE ROW LEVEL SECURITY;
-- No API table privileges or policies: private data is accessed only through bounded functions.
CREATE TRIGGER partner_authority_source_immutable BEFORE UPDATE OR DELETE ON hosting.partner_authority_sources
 FOR EACH ROW EXECUTE FUNCTION hosting.partner_intent_immutable();
CREATE TRIGGER partner_authority_receipt_immutable BEFORE UPDATE OR DELETE ON hosting.partner_authority_receipts
 FOR EACH ROW EXECUTE FUNCTION hosting.partner_intent_immutable();
CREATE FUNCTION hosting.authority_source_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF current_user IN ('hosting_api','hosting_worker','hosting_admitter','hosting_hook','hosting_buildworker') OR
    NEW.issued_by IS DISTINCT FROM current_setting('hosting.entitlement_operator',true) THEN
   RAISE EXCEPTION 'Protected publisher registration required';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.organization_id::text,10));
 -- Assign effective ordering after serialization, including protected SQL imports.
 NEW.revision:=nextval('hosting.partner_authority_sources_revision_seq'::regclass);
 RETURN NEW;
END $$;
CREATE TRIGGER authority_source_insert BEFORE INSERT ON hosting.partner_authority_sources FOR EACH ROW EXECUTE FUNCTION hosting.authority_source_insert();

CREATE FUNCTION hosting.authority_admin_bound(p_org uuid,desired jsonb,bindings jsonb) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT (SELECT jsonb_agg(item->'ref' ORDER BY item->>'ref' COLLATE "C") FROM jsonb_array_elements(bindings) AS x(item)) =
        (SELECT jsonb_agg(item ORDER BY item#>>'{}' COLLATE "C") FROM jsonb_array_elements(desired->'tenant_admin_refs') AS x(item))
 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(bindings) AS x(item) WHERE NOT EXISTS (
   SELECT 1 FROM hosting.memberships WHERE organization_id=p_org AND actor_sub=item->>'actor_sub' AND role IN ('owner','admin')))
$$;
CREATE FUNCTION hosting.authority_receipt_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE source hosting.partner_authority_sources; intent hosting.partner_intents; plan hosting.entitlement_versions; now_at timestamptz:=statement_timestamp();
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.organization_id::text,10));
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.organization_id::text||':'||NEW.id::text,11));
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.organization_id::text||':'||NEW.intent_id::text,8));
 now_at:=clock_timestamp();
 SELECT * INTO source FROM hosting.partner_authority_sources WHERE organization_id=NEW.organization_id ORDER BY revision DESC LIMIT 1;
 IF NOT FOUND OR source.payload->'enabled'<>'true'::jsonb OR
    current_setting('hosting.auth_kind',true) IS DISTINCT FROM 'service' OR
    source.payload->>'issuer' IS DISTINCT FROM current_setting('hosting.token_issuer',true) OR
    source.payload->>'client_id' IS DISTINCT FROM current_setting('hosting.service_client_id',true) OR
    source.payload->>'actor_sub' IS DISTINCT FROM current_setting('hosting.actor_sub',true) THEN RAISE EXCEPTION 'authority_binding_conflict'; END IF;
 IF source.id<>NEW.source_version_id THEN RAISE EXCEPTION 'authority_source_changed'; END IF;
 SELECT * INTO intent FROM hosting.partner_intents WHERE (organization_id,application_id,id)=(NEW.organization_id,NEW.application_id,NEW.intent_id);
 IF NOT FOUND OR intent.intent_sha256 IS DISTINCT FROM NEW.payload->>'intent_sha256' THEN RAISE EXCEPTION 'authority_binding_conflict'; END IF;
 IF NEW.sequence <= coalesce((SELECT max(sequence) FROM hosting.partner_authority_receipts WHERE organization_id=NEW.organization_id AND intent_id=NEW.intent_id),0) THEN
   RAISE EXCEPTION 'authority_revision_conflict'; END IF;
 IF (NEW.payload->>'issued_at')::timestamptz>now_at OR
    (NEW.payload->>'issued_at')::timestamptz<now_at-make_interval(secs=>(source.payload->>'max_validity_seconds')::int) THEN RAISE EXCEPTION 'authority_expired'; END IF;
 IF NEW.payload->>'disposition'='AUTHORIZE' THEN
   IF (NEW.payload->>'valid_until')::timestamptz<=now_at OR
      (NEW.payload->>'valid_until')::timestamptz>(NEW.payload->>'issued_at')::timestamptz+make_interval(secs=>(source.payload->>'max_validity_seconds')::int) THEN RAISE EXCEPTION 'authority_expired'; END IF;
   SELECT v.* INTO plan FROM hosting.organization_entitlements e JOIN hosting.entitlement_versions v ON (v.organization_id,v.id)=(e.organization_id,e.version_id)
     WHERE e.organization_id=NEW.organization_id;
   IF NOT FOUND OR plan.id::text IS DISTINCT FROM NEW.payload->>'hosting_entitlement_version_id' OR
      NOT (plan.valid_from<=now_at AND now_at<plan.valid_until) OR
      NOT hosting.authority_admin_bound(NEW.organization_id,intent.payload,NEW.payload->'admin_bindings') THEN RAISE EXCEPTION 'authority_binding_conflict'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER authority_receipt_insert BEFORE INSERT ON hosting.partner_authority_receipts FOR EACH ROW EXECUTE FUNCTION hosting.authority_receipt_insert();
CREATE FUNCTION hosting.authority_audit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='partner_authority_sources' THEN
   PERFORM hosting.entitlement_audit(NEW.organization_id,NEW.issued_by,'partner.publisher_registered',NEW.id);
 ELSE
   PERFORM hosting.entitlement_audit(NEW.organization_id,current_setting('hosting.actor_sub'),'partner.authority_recorded',NEW.id);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER authority_source_audit AFTER INSERT ON hosting.partner_authority_sources FOR EACH ROW EXECUTE FUNCTION hosting.authority_audit();
CREATE TRIGGER authority_receipt_audit AFTER INSERT ON hosting.partner_authority_receipts FOR EACH ROW EXECUTE FUNCTION hosting.authority_audit();

CREATE FUNCTION hosting.publish_partner_authority(p_org uuid,p_app uuid,p_intent uuid,p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE source hosting.partner_authority_sources; previous hosting.partner_authority_receipts; original hosting.partner_authority_sources;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(p_org::text,10));
 SELECT * INTO source FROM hosting.partner_authority_sources WHERE organization_id=p_org ORDER BY revision DESC LIMIT 1;
 IF NOT FOUND OR source.payload->'enabled'<>'true'::jsonb OR current_setting('hosting.auth_kind',true) IS DISTINCT FROM 'service' OR
    source.payload->>'issuer' IS DISTINCT FROM current_setting('hosting.token_issuer',true) OR
    source.payload->>'client_id' IS DISTINCT FROM current_setting('hosting.service_client_id',true) OR
    source.payload->>'actor_sub' IS DISTINCT FROM current_setting('hosting.actor_sub',true) THEN RETURN NULL; END IF;
 IF NOT hosting.authority_valid(p,false) THEN RAISE EXCEPTION 'authority_binding_conflict'; END IF;
 IF NOT EXISTS (SELECT 1 FROM hosting.partner_intents WHERE (organization_id,application_id,id)=(p_org,p_app,p_intent)) THEN RETURN NULL; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_org::text||':'||(p->>'id'),11));
 PERFORM pg_advisory_xact_lock(hashtextextended(p_org::text||':'||p_intent::text,8));
 SELECT * INTO previous FROM hosting.partner_authority_receipts WHERE organization_id=p_org AND id=(p->>'id')::uuid;
 IF FOUND THEN
   SELECT * INTO original FROM hosting.partner_authority_sources WHERE id=previous.source_version_id;
   IF previous.application_id<>p_app OR previous.intent_id<>p_intent OR previous.payload<>p OR
      original.payload->>'issuer' IS DISTINCT FROM source.payload->>'issuer' OR
      original.payload->>'client_id' IS DISTINCT FROM source.payload->>'client_id' OR
      original.payload->>'actor_sub' IS DISTINCT FROM source.payload->>'actor_sub' THEN RAISE EXCEPTION 'authority_binding_conflict'; END IF;
   RETURN jsonb_build_object('id',previous.id,'state','RECORDED','sequence',previous.sequence::text,'replayed',true);
 END IF;
 INSERT INTO hosting.partner_authority_receipts(organization_id,application_id,intent_id,id,source_version_id,sequence,payload)
 VALUES(p_org,p_app,p_intent,(p->>'id')::uuid,(p->>'source_version_id')::uuid,(p->>'sequence')::bigint,p);
 RETURN jsonb_build_object('id',p->>'id','state','RECORDED','sequence',p->>'sequence','replayed',false);
END $$;

CREATE FUNCTION hosting.partner_authority_readback(p_org uuid,p_app uuid,p_intent uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 WITH requested AS (
 SELECT payload FROM hosting.partner_intents WHERE (organization_id,application_id,id)=(p_org,p_app,p_intent)
 AND current_setting('hosting.auth_kind',true)='human' AND EXISTS (SELECT 1 FROM hosting.memberships
 WHERE organization_id=p_org AND actor_sub=current_setting('hosting.actor_sub',true) AND role IN ('owner','admin'))),
 observed AS (
 SELECT s.id AS source_id,r.id AS receipt_id,r.sequence,r.created_at,r.payload AS receipt,v.id AS plan_id,
 CASE WHEN s.id IS NULL THEN 'UNCONFIGURED'
      WHEN s.payload->'enabled'<>'true'::jsonb THEN 'SOURCE_DISABLED'
      WHEN r.id IS NULL THEN 'AWAITING_RECEIPT'
      WHEN r.payload->>'disposition'='REVOKE' THEN 'REVOKED'
      WHEN r.source_version_id<>s.id THEN 'SOURCE_CHANGED'
      WHEN (r.payload->>'issued_at')::timestamptz>statement_timestamp() OR (r.payload->>'valid_until')::timestamptz<=statement_timestamp() THEN 'EXPIRED'
      WHEN v.id IS NULL OR NOT (v.valid_from<=statement_timestamp() AND statement_timestamp()<v.valid_until) THEN 'PLAN_UNAVAILABLE'
      WHEN v.id::text<>r.payload->>'hosting_entitlement_version_id' THEN 'PLAN_CHANGED'
      WHEN NOT hosting.authority_admin_bound(p_org,requested.payload,r.payload->'admin_bindings') THEN 'ADMIN_UNBOUND'
      ELSE 'ACTIVE' END AS state
 FROM requested LEFT JOIN LATERAL (SELECT * FROM hosting.partner_authority_sources WHERE organization_id=p_org ORDER BY revision DESC LIMIT 1) s ON true
 LEFT JOIN LATERAL (SELECT * FROM hosting.partner_authority_receipts WHERE organization_id=p_org AND intent_id=p_intent ORDER BY sequence DESC LIMIT 1) r ON true
 LEFT JOIN hosting.organization_entitlements e ON e.organization_id=p_org
 LEFT JOIN hosting.entitlement_versions v ON (v.organization_id,v.id)=(e.organization_id,e.version_id))
 SELECT jsonb_build_object('organization_id',p_org,'application_id',p_app,'intent_id',p_intent,'observed_at',statement_timestamp(),
   'state',state,'source_version_id',source_id,'receipt_id',receipt_id,'sequence',sequence::text,
   'issued_at',receipt->'issued_at','valid_until',receipt->'valid_until','hosting_entitlement_version_id',receipt->'hosting_entitlement_version_id') FROM observed
$$;
-- Both STABLE helpers see the outer statement's snapshot, including memberships and plans.
ALTER FUNCTION hosting.partner_intent_evidence(uuid,uuid,uuid) RENAME TO partner_intent_base_evidence_v1;
REVOKE ALL ON FUNCTION hosting.partner_intent_base_evidence_v1(uuid,uuid,uuid) FROM hosting_api;
CREATE FUNCTION hosting.partner_intent_evidence(p_org uuid,p_app uuid,p_id uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT evidence||jsonb_build_object('partner_authority',hosting.partner_authority_readback(p_org,p_app,p_id))
 FROM (SELECT hosting.partner_intent_base_evidence_v1(p_org,p_app,p_id) AS evidence) e WHERE evidence IS NOT NULL
$$;
REVOKE ALL ON FUNCTION hosting.authority_uuid(jsonb),hosting.authority_subject(jsonb),hosting.authority_valid(jsonb,boolean),
 hosting.authority_source_insert(),hosting.authority_admin_bound(uuid,jsonb,jsonb),hosting.authority_receipt_insert(),hosting.authority_audit(),
 hosting.publish_partner_authority(uuid,uuid,uuid,jsonb),hosting.partner_authority_readback(uuid,uuid,uuid),hosting.partner_intent_evidence(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hosting.publish_partner_authority(uuid,uuid,uuid,jsonb),hosting.partner_authority_readback(uuid,uuid,uuid),hosting.partner_intent_evidence(uuid,uuid,uuid) TO hosting_api;
