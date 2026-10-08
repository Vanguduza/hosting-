-- Registrar orders are distinct from domain ownership proof and routing.
CREATE TABLE hosting.domain_registration_requests (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
  idempotency_key uuid NOT NULL,
  hostname text NOT NULL CHECK (hostname ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.(com|co\.zw)$'),
  term_years integer NOT NULL CHECK (term_years BETWEEN 1 AND 5),
  registrant_ref text NOT NULL CHECK (registrant_ref ~ '^registrant://[a-z0-9/_-]{1,120}$'),
  requested_by text NOT NULL,
  state text NOT NULL DEFAULT 'REQUESTED' CHECK (state IN
    ('REQUESTED','QUOTED','APPROVED','PROCESSING','FULFILLMENT_RECORDED','CANCELLED','FAILED')),
  current_quote_id uuid,
  approved_by text,
  approved_at timestamptz,
  cancelled_by text,
  payment_evidence_ref text,
  operation_id uuid UNIQUE,
  failure_evidence_ref text,
  provider_order_ref text,
  receipt_sha256 text CHECK (receipt_sha256 ~ '^[a-f0-9]{64}$'),
  fulfilled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id,id),
  UNIQUE (organization_id,idempotency_key),
  CHECK (hostname NOT LIKE '%.co.zw' OR term_years=1),
  CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
  CHECK (state NOT IN ('QUOTED','APPROVED','PROCESSING','FULFILLMENT_RECORDED','FAILED') OR current_quote_id IS NOT NULL),
  CHECK (state NOT IN ('APPROVED','PROCESSING','FULFILLMENT_RECORDED','FAILED') OR approved_at IS NOT NULL),
  CHECK (state NOT IN ('PROCESSING','FULFILLMENT_RECORDED','FAILED') OR
    (payment_evidence_ref IS NOT NULL AND operation_id IS NOT NULL)),
  CHECK (state <> 'FAILED' OR failure_evidence_ref IS NOT NULL),
  CHECK (state <> 'FULFILLMENT_RECORDED' OR
    (provider_order_ref IS NOT NULL AND receipt_sha256 IS NOT NULL AND fulfilled_at IS NOT NULL))
);
CREATE INDEX registration_tenant_read ON hosting.domain_registration_requests(organization_id,created_at DESC,id);
CREATE UNIQUE INDEX registration_tenant_open_name ON hosting.domain_registration_requests(organization_id,hostname)
  WHERE state NOT IN ('CANCELLED','FAILED');
-- This is internal purchase exclusion, not a registrar reservation.
CREATE UNIQUE INDEX registration_purchase_name ON hosting.domain_registration_requests(hostname)
  WHERE state IN ('APPROVED','PROCESSING','FULFILLMENT_RECORDED');

CREATE TABLE hosting.domain_registration_quotes (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  registration_id uuid NOT NULL,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  expires_at timestamptz NOT NULL,
  quote_sha256 text GENERATED ALWAYS AS (encode(public.digest(payload::text,'sha256'),'hex')) STORED,
  issued_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id,registration_id,id),
  FOREIGN KEY (organization_id,registration_id) REFERENCES hosting.domain_registration_requests(organization_id,id)
);
CREATE INDEX registration_quote_history ON hosting.domain_registration_quotes(organization_id,registration_id,created_at DESC);
ALTER TABLE hosting.domain_registration_requests ADD FOREIGN KEY (organization_id,id,current_quote_id)
  REFERENCES hosting.domain_registration_quotes(organization_id,registration_id,id);

GRANT SELECT ON hosting.domain_registration_requests,hosting.domain_registration_quotes TO hosting_api;
GRANT INSERT (id,organization_id,idempotency_key,hostname,term_years,registrant_ref,requested_by)
  ON hosting.domain_registration_requests TO hosting_api;
ALTER TABLE hosting.domain_registration_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.domain_registration_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE hosting.domain_registration_quotes ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.domain_registration_quotes FORCE ROW LEVEL SECURITY;
CREATE POLICY registration_owner_read ON hosting.domain_registration_requests FOR SELECT TO hosting_api
  USING (current_setting('hosting.auth_kind',true)='human' AND EXISTS (
    SELECT 1 FROM hosting.memberships m WHERE m.organization_id=domain_registration_requests.organization_id
    AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'));
CREATE POLICY registration_owner_insert ON hosting.domain_registration_requests FOR INSERT TO hosting_api
  WITH CHECK (requested_by=current_setting('hosting.actor_sub',true) AND
    current_setting('hosting.auth_kind',true)='human' AND EXISTS (
      SELECT 1 FROM hosting.memberships m WHERE m.organization_id=domain_registration_requests.organization_id
      AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'));
CREATE POLICY registration_quote_owner_read ON hosting.domain_registration_quotes FOR SELECT TO hosting_api
  USING (current_setting('hosting.auth_kind',true)='human' AND EXISTS (
    SELECT 1 FROM hosting.memberships m WHERE m.organization_id=domain_registration_quotes.organization_id
    AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'));

CREATE FUNCTION hosting.registration_audit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor text; action text; resource uuid; previous text; request uuid := gen_random_uuid();
BEGIN
  IF TG_TABLE_NAME='domain_registration_quotes' THEN
    actor := NEW.issued_by; action := 'registration.quote'; resource := NEW.id;
  ELSE
    IF TG_OP='UPDATE' AND NEW.state=OLD.state AND NEW.current_quote_id IS NOT DISTINCT FROM OLD.current_quote_id THEN
      RETURN NEW;
    END IF;
    resource := NEW.id; action := 'registration.' || lower(NEW.state);
    actor := CASE WHEN TG_OP='INSERT' THEN NEW.requested_by
      WHEN NEW.state='APPROVED' THEN NEW.approved_by WHEN NEW.state='CANCELLED' THEN NEW.cancelled_by
      ELSE current_setting('hosting.registration_operator',true) END;
  END IF;
  IF coalesce(length(actor),0) NOT BETWEEN 1 AND 255 THEN RAISE EXCEPTION 'Registration audit actor required'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.organization_id::text,0));
  SELECT a.event_hash INTO previous FROM hosting.audit_events a WHERE a.organization_id=NEW.organization_id
    ORDER BY a.id DESC LIMIT 1;
  previous := coalesce(previous,'');
  INSERT INTO hosting.audit_events(organization_id,actor_sub,action,resource_id,request_id,previous_hash,event_hash)
    VALUES (NEW.organization_id,actor,action,resource,request,previous,
      encode(public.digest(previous || actor || action || resource::text || request::text,'sha256'),'hex'));
  RETURN NEW;
END $$;
CREATE TRIGGER registration_audit AFTER INSERT OR UPDATE ON hosting.domain_registration_requests
  FOR EACH ROW EXECUTE FUNCTION hosting.registration_audit();
CREATE TRIGGER registration_quote_audit AFTER INSERT ON hosting.domain_registration_quotes
  FOR EACH ROW EXECUTE FUNCTION hosting.registration_audit();
CREATE FUNCTION hosting.registration_quote_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'Registration quotes are immutable'; END $$;
CREATE TRIGGER registration_quote_immutable BEFORE UPDATE OR DELETE ON hosting.domain_registration_quotes
  FOR EACH ROW EXECUTE FUNCTION hosting.registration_quote_immutable();

CREATE TABLE hosting.domain_registration_consents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  registration_id uuid NOT NULL,
  quote_id uuid NOT NULL UNIQUE,
  actor_sub text NOT NULL,
  approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id,registration_id,quote_id)
    REFERENCES hosting.domain_registration_quotes(organization_id,registration_id,id)
);
CREATE INDEX registration_consent_history ON hosting.domain_registration_consents(organization_id,registration_id,approved_at DESC);
CREATE TRIGGER registration_consent_immutable BEFORE UPDATE OR DELETE ON hosting.domain_registration_consents
  FOR EACH ROW EXECUTE FUNCTION hosting.registration_quote_immutable();
ALTER TABLE hosting.domain_registration_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.domain_registration_consents FORCE ROW LEVEL SECURITY;
GRANT SELECT ON hosting.domain_registration_consents TO hosting_api;
CREATE POLICY registration_consent_owner_read ON hosting.domain_registration_consents FOR SELECT TO hosting_api
  USING (current_setting('hosting.auth_kind',true)='human' AND EXISTS (
    SELECT 1 FROM hosting.memberships m WHERE m.organization_id=domain_registration_consents.organization_id
    AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'));

CREATE FUNCTION hosting.registration_consent(p_org uuid,p_id uuid,p_quote uuid,p_hash text,p_cancel boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r hosting.domain_registration_requests%ROWTYPE; q hosting.domain_registration_quotes%ROWTYPE;
  actor text := current_setting('hosting.actor_sub',true);
BEGIN
  IF current_setting('hosting.auth_kind',true) IS DISTINCT FROM 'human' OR NOT EXISTS (
    SELECT 1 FROM hosting.memberships m WHERE m.organization_id=p_org AND m.actor_sub=actor AND m.role='owner')
    THEN RETURN NULL; END IF;
  SELECT * INTO r FROM hosting.domain_registration_requests d WHERE d.organization_id=p_org AND d.id=p_id FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF p_cancel THEN
    IF r.state='CANCELLED' THEN RETURN jsonb_build_object('id',r.id,'state',r.state,'replayed',true); END IF;
    IF r.state NOT IN ('REQUESTED','QUOTED','APPROVED') THEN RETURN NULL; END IF;
    UPDATE hosting.domain_registration_requests d SET state='CANCELLED',cancelled_by=actor,updated_at=clock_timestamp()
      WHERE d.id=r.id;
    RETURN jsonb_build_object('id',r.id,'state','CANCELLED','replayed',false);
  END IF;
  SELECT * INTO q FROM hosting.domain_registration_quotes d WHERE d.organization_id=p_org AND d.registration_id=p_id
    AND d.id=r.current_quote_id;
  IF NOT FOUND OR q.id IS DISTINCT FROM p_quote OR q.quote_sha256 IS DISTINCT FROM p_hash THEN RETURN NULL; END IF;
  IF r.state IN ('APPROVED','PROCESSING','FULFILLMENT_RECORDED') THEN
    RETURN jsonb_build_object('id',r.id,'state',r.state,'replayed',true);
  END IF;
  IF r.state <> 'QUOTED' OR q.expires_at<=clock_timestamp() THEN RETURN NULL; END IF;
  INSERT INTO hosting.domain_registration_consents(organization_id,registration_id,quote_id,actor_sub)
    VALUES (p_org,p_id,q.id,actor);
  UPDATE hosting.domain_registration_requests d SET state='APPROVED',approved_by=actor,
    approved_at=clock_timestamp(),updated_at=clock_timestamp() WHERE d.id=r.id;
  RETURN jsonb_build_object('id',r.id,'state','APPROVED','replayed',false);
END $$;
REVOKE ALL ON FUNCTION hosting.registration_audit(),hosting.registration_quote_immutable(),
  hosting.registration_consent(uuid,uuid,uuid,text,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hosting.registration_consent(uuid,uuid,uuid,text,boolean) TO hosting_api;
