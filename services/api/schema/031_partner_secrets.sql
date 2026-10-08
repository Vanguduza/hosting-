-- Operator-reviewed reference authority and short-lived exact-version availability.
-- No values or value hashes are stored, and API identities cannot import or probe secrets.
CREATE FUNCTION hosting.partner_secret_binding_valid(p jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE k text; port text; keys text[]:=ARRAY['schema_version','id','organization_id','application_id','secret_ref',
 'bao_address','bao_mount','resource_id','kv_version','value_key','enabled','valid_from','valid_until','authorization_ref'];
BEGIN
 IF p IS NULL OR jsonb_typeof(p)<>'object' OR octet_length(p::text)>16384 OR NOT p ?& keys OR
    (SELECT count(*) FROM jsonb_object_keys(p))<>14 THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['id','organization_id','application_id','resource_id'] LOOP
   IF NOT hosting.authority_uuid(p->k) THEN RETURN false; END IF;
 END LOOP;
 IF NOT p @> '{"schema_version":"1.0"}'::jsonb OR jsonb_typeof(p->'enabled')<>'boolean' OR
    jsonb_typeof(p->'kv_version')<>'number' OR (p->'kv_version')::text !~ '^[1-9][0-9]{0,8}$' THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['secret_ref','bao_address','bao_mount','value_key','authorization_ref','valid_from','valid_until'] LOOP
   IF jsonb_typeof(p->k)<>'string' OR (p->>k) ~ '[[:space:]]' OR octet_length(p->>k)<>length(p->>k) THEN RETURN false; END IF;
 END LOOP;
 IF p->>'secret_ref' !~ '^secret://[a-z0-9][a-z0-9/_-]{0,190}#[1-9][0-9]{0,8}$' OR
    split_part(p->>'secret_ref','#',2) IS DISTINCT FROM p->>'kv_version' OR
    length(p->>'bao_address')>270 OR p->>'bao_address' !~ '^https://[a-z0-9][a-z0-9.-]{0,252}(:[1-9][0-9]{0,4})?$' OR
    p->>'bao_mount' !~ '^[a-z][a-z0-9_-]{0,31}$' OR p->>'value_key' !~ '^[a-z][a-z0-9_]{0,63}$' OR
    p->>'authorization_ref' !~ '^secret-proof://[A-Za-z0-9/_-]{1,120}$' THEN RETURN false; END IF;
 port:=substring(p->>'bao_address' FROM ':([0-9]+)$');
 IF port IS NOT NULL AND port::int NOT BETWEEN 1 AND 65535 THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['valid_from','valid_until'] LOOP
   IF p->>k !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,6})?(Z|[+-](0[0-9]|1[0-5]):[0-5][0-9])$' THEN RETURN false; END IF;
   PERFORM (p->>k)::timestamptz;
 END LOOP;
 RETURN (p->>'valid_from')::timestamptz<(p->>'valid_until')::timestamptz AND
        (p->>'valid_until')::timestamptz<=(p->>'valid_from')::timestamptz+interval '2160 hours';
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END $$;

CREATE TABLE hosting.partner_secret_bindings (
 id uuid PRIMARY KEY,
 organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
 application_id uuid NOT NULL REFERENCES hosting.applications(id),
 revision bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 payload jsonb NOT NULL CHECK (hosting.partner_secret_binding_valid(payload)),
 issued_by text NOT NULL CHECK (issued_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE (organization_id,application_id,id),
 FOREIGN KEY (organization_id,application_id) REFERENCES hosting.applications(organization_id,id),
 CHECK (payload->>'id'=id::text AND payload->>'organization_id'=organization_id::text AND payload->>'application_id'=application_id::text)
);
CREATE INDEX partner_secret_binding_current ON hosting.partner_secret_bindings(organization_id,application_id,(payload->>'secret_ref'),revision DESC);
CREATE TABLE hosting.partner_secret_checks (
 id uuid PRIMARY KEY,
 organization_id uuid NOT NULL,
 application_id uuid NOT NULL,
 binding_id uuid NOT NULL,
 revision bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 state text NOT NULL CHECK (state IN ('AVAILABLE','UNAVAILABLE')),
 issued_by text NOT NULL CHECK (issued_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$'),
 checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY (organization_id,application_id,binding_id) REFERENCES hosting.partner_secret_bindings(organization_id,application_id,id)
);
CREATE INDEX partner_secret_check_current ON hosting.partner_secret_checks(binding_id,revision DESC);
ALTER TABLE hosting.partner_secret_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.partner_secret_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE hosting.partner_secret_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.partner_secret_checks FORCE ROW LEVEL SECURITY;
CREATE TRIGGER partner_secret_binding_immutable BEFORE UPDATE OR DELETE ON hosting.partner_secret_bindings
 FOR EACH ROW EXECUTE FUNCTION hosting.partner_intent_immutable();
CREATE TRIGGER partner_secret_check_immutable BEFORE UPDATE OR DELETE ON hosting.partner_secret_checks
 FOR EACH ROW EXECUTE FUNCTION hosting.partner_intent_immutable();

CREATE FUNCTION hosting.partner_secret_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE b hosting.partner_secret_bindings; latest uuid; now_at timestamptz;
BEGIN
 IF current_user IN ('hosting_api','hosting_worker','hosting_admitter','hosting_hook','hosting_buildworker') OR
    NEW.issued_by IS DISTINCT FROM current_setting('hosting.entitlement_operator',true) THEN RAISE EXCEPTION 'Protected secret operation required'; END IF;
 IF TG_TABLE_NAME='partner_secret_bindings' THEN
   IF NOT hosting.partner_secret_binding_valid(NEW.payload) OR NOT EXISTS (SELECT 1 FROM hosting.applications
      WHERE (organization_id,id)=(NEW.organization_id,NEW.application_id)) THEN RAISE EXCEPTION 'Invalid scoped secret binding'; END IF;
   PERFORM pg_advisory_xact_lock(hashtextextended(NEW.id::text,15));
   PERFORM pg_advisory_xact_lock(hashtextextended(NEW.organization_id::text||':'||NEW.application_id::text||':'||(NEW.payload->>'secret_ref'),14));
   NEW.revision:=nextval('hosting.partner_secret_bindings_revision_seq'::regclass);
   NEW.created_at:=clock_timestamp();
 ELSE
   PERFORM pg_advisory_xact_lock(hashtextextended(NEW.id::text,16));
   SELECT * INTO b FROM hosting.partner_secret_bindings WHERE (organization_id,application_id,id)=(NEW.organization_id,NEW.application_id,NEW.binding_id);
   IF NOT FOUND THEN RAISE EXCEPTION 'Unknown scoped binding'; END IF;
   PERFORM pg_advisory_xact_lock(hashtextextended(b.organization_id::text||':'||b.application_id::text||':'||(b.payload->>'secret_ref'),14));
   SELECT id INTO latest FROM hosting.partner_secret_bindings WHERE organization_id=b.organization_id AND application_id=b.application_id
       AND payload->>'secret_ref'=b.payload->>'secret_ref' ORDER BY revision DESC LIMIT 1;
   now_at:=clock_timestamp();
   IF latest<>b.id OR b.payload->'enabled'<>'true'::jsonb OR (b.payload->>'valid_from')::timestamptz>now_at OR
      (b.payload->>'valid_until')::timestamptz<=now_at THEN RAISE EXCEPTION 'Binding is not current and active'; END IF;
   NEW.revision:=nextval('hosting.partner_secret_checks_revision_seq'::regclass);
   -- A caller-supplied time cannot extend availability freshness.
   NEW.checked_at:=now_at;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER partner_secret_binding_insert BEFORE INSERT ON hosting.partner_secret_bindings FOR EACH ROW EXECUTE FUNCTION hosting.partner_secret_insert();
CREATE TRIGGER partner_secret_check_insert BEFORE INSERT ON hosting.partner_secret_checks FOR EACH ROW EXECUTE FUNCTION hosting.partner_secret_insert();
CREATE FUNCTION hosting.partner_secret_audit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM hosting.entitlement_audit(NEW.organization_id,NEW.issued_by,
   CASE WHEN TG_TABLE_NAME='partner_secret_bindings' THEN 'secret.binding_recorded' ELSE 'secret.availability_checked' END,NEW.id);
 RETURN NEW;
END $$;
CREATE TRIGGER partner_secret_binding_audit AFTER INSERT ON hosting.partner_secret_bindings FOR EACH ROW EXECUTE FUNCTION hosting.partner_secret_audit();
CREATE TRIGGER partner_secret_check_audit AFTER INSERT ON hosting.partner_secret_checks FOR EACH ROW EXECUTE FUNCTION hosting.partner_secret_audit();

CREATE FUNCTION hosting.partner_secret_readback(p_org uuid,p_app uuid,p_intent uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 WITH requested AS (
 SELECT i.payload,i.intent_sha256 FROM hosting.partner_intents i WHERE (i.organization_id,i.application_id,i.id)=(p_org,p_app,p_intent)
 AND current_setting('hosting.auth_kind',true)='human' AND EXISTS (SELECT 1 FROM hosting.memberships
 WHERE organization_id=p_org AND actor_sub=current_setting('hosting.actor_sub',true) AND role IN ('owner','admin'))),
 refs AS (SELECT value AS ref FROM requested r CROSS JOIN LATERAL jsonb_array_elements_text(r.payload->'secret_refs')),
 observed AS (
 SELECT CASE WHEN b.id IS NULL THEN 'UNCONFIGURED'
      WHEN b.payload->'enabled'<>'true'::jsonb THEN 'BINDING_DISABLED'
      WHEN (b.payload->>'valid_from')::timestamptz>statement_timestamp() THEN 'NOT_YET_VALID'
      WHEN (b.payload->>'valid_until')::timestamptz<=statement_timestamp() THEN 'EXPIRED'
      WHEN c.id IS NULL OR c.checked_at<=statement_timestamp()-interval '5 minutes' OR c.checked_at>statement_timestamp() THEN 'CHECK_REQUIRED'
      WHEN c.state<>'AVAILABLE' THEN 'CHECK_FAILED' ELSE 'MATCHED' END AS state,
      c.checked_at,least(c.checked_at+interval '5 minutes',(b.payload->>'valid_until')::timestamptz) AS valid_until
 FROM refs r LEFT JOIN LATERAL (SELECT * FROM hosting.partner_secret_bindings WHERE organization_id=p_org AND application_id=p_app
   AND payload->>'secret_ref'=r.ref ORDER BY revision DESC LIMIT 1) b ON true
 LEFT JOIN LATERAL (SELECT * FROM hosting.partner_secret_checks WHERE binding_id=b.id ORDER BY revision DESC LIMIT 1) c ON true),
 summary AS (SELECT count(*)::int AS requested_count,count(*) FILTER (WHERE state='MATCHED')::int AS matched_count,
    CASE WHEN count(*)=0 THEN 'NOT_REQUESTED' WHEN bool_and(state='MATCHED') THEN 'MATCHED'
      ELSE (array_agg(state ORDER BY array_position(ARRAY['BINDING_DISABLED','EXPIRED','NOT_YET_VALID','UNCONFIGURED','CHECK_FAILED','CHECK_REQUIRED','MATCHED'],state)))[1] END AS state,
    CASE WHEN count(*)>0 AND bool_and(state='MATCHED') THEN min(checked_at) END AS oldest_checked_at,
    CASE WHEN count(*)>0 AND bool_and(state='MATCHED') THEN min(valid_until) END AS valid_until FROM observed)
 SELECT jsonb_build_object('organization_id',p_org,'application_id',p_app,'intent_id',p_intent,'intent_sha256',r.intent_sha256,
   'observed_at',statement_timestamp(),'state',s.state,'requested_count',s.requested_count,'matched_count',s.matched_count,
   'oldest_checked_at',s.oldest_checked_at,'valid_until',s.valid_until) FROM requested r CROSS JOIN summary s
$$;
ALTER FUNCTION hosting.partner_intent_evidence(uuid,uuid,uuid) RENAME TO partner_intent_profile_evidence_v1;
REVOKE ALL ON FUNCTION hosting.partner_intent_profile_evidence_v1(uuid,uuid,uuid) FROM hosting_api;
CREATE FUNCTION hosting.partner_intent_evidence(p_org uuid,p_app uuid,p_id uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT evidence||jsonb_build_object('partner_secrets',hosting.partner_secret_readback(p_org,p_app,p_id))
 FROM (SELECT hosting.partner_intent_profile_evidence_v1(p_org,p_app,p_id) AS evidence) e WHERE evidence IS NOT NULL
$$;
REVOKE ALL ON FUNCTION hosting.partner_secret_binding_valid(jsonb),hosting.partner_secret_insert(),hosting.partner_secret_audit(),
 hosting.partner_secret_readback(uuid,uuid,uuid),hosting.partner_intent_evidence(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hosting.partner_secret_readback(uuid,uuid,uuid),hosting.partner_intent_evidence(uuid,uuid,uuid) TO hosting_api;
