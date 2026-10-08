-- Every committed audit fact has exactly one durable delivery record. The
-- trigger executes in the same transaction as the originating state change.
CREATE TABLE hosting.event_outbox (
  audit_event_id bigint PRIMARY KEY REFERENCES hosting.audit_events(id),
  organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
  state text NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING','DELIVERED','DEAD')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_token uuid,
  lease_until timestamptz,
  delivered_at timestamptz,
  last_error text,
  CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
  CHECK ((state = 'DELIVERED') = (delivered_at IS NOT NULL)),
  CHECK (state = 'PENDING' OR lease_token IS NULL)
);
CREATE INDEX event_outbox_claim_idx ON hosting.event_outbox(next_attempt_at,audit_event_id)
  WHERE state = 'PENDING';
CREATE INDEX event_outbox_org_order_idx ON hosting.event_outbox(organization_id,audit_event_id)
  WHERE state <> 'DELIVERED';
CREATE TABLE hosting.event_replays (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  audit_event_id bigint NOT NULL REFERENCES hosting.event_outbox(audit_event_id),
  operator_name text NOT NULL CHECK (length(operator_name) BETWEEN 1 AND 128),
  reason text NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION hosting.enqueue_audit_event() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = hosting, pg_temp AS $$
BEGIN
  INSERT INTO hosting.event_outbox(audit_event_id,organization_id)
  VALUES (NEW.id,NEW.organization_id);
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION hosting.enqueue_audit_event() FROM PUBLIC;
CREATE TRIGGER audit_to_outbox AFTER INSERT ON hosting.audit_events
  FOR EACH ROW EXECUTE FUNCTION hosting.enqueue_audit_event();
-- Older committed audit facts also enter the stream, in original ID order.
INSERT INTO hosting.event_outbox(audit_event_id,organization_id)
SELECT id,organization_id FROM hosting.audit_events ORDER BY id;

GRANT SELECT,UPDATE (state,attempts,next_attempt_at,lease_token,lease_until,delivered_at,last_error)
  ON hosting.event_outbox TO hosting_worker;
GRANT SELECT ON hosting.audit_events TO hosting_worker;
ALTER TABLE hosting.event_outbox ENABLE ROW LEVEL SECURITY;
-- The SECURITY DEFINER trigger runs as the table owner to insert rows; the
-- restricted worker remains subject to the policies below.
CREATE POLICY event_worker_read ON hosting.event_outbox FOR SELECT TO hosting_worker USING (true);
CREATE POLICY event_worker_update ON hosting.event_outbox FOR UPDATE TO hosting_worker
  USING (true) WITH CHECK (true);
