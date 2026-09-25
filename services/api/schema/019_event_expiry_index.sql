-- Bounded scan for final-attempt leases left behind by a crashed sender.
CREATE INDEX event_outbox_expired_idx ON hosting.event_outbox(lease_until,audit_event_id)
  WHERE state='PENDING' AND attempts=10;
