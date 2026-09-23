-- A failed release retains its capacity reservation until the node confirms
-- that its container has stopped. This prevents leaked workloads from being
-- counted as free capacity when a worker crashes during compensation.
ALTER TABLE hosting.releases ADD COLUMN cleanup_at timestamptz;
CREATE INDEX releases_failed_cleanup_idx ON hosting.releases(created_at)
  WHERE state='FAILED' AND cleanup_at IS NULL;
