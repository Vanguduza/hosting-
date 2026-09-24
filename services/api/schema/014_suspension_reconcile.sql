-- Bound the worker scan when suspended applications need periodic rechecks.
CREATE INDEX applications_suspended_recheck_idx
  ON hosting.applications(traffic_next_attempt_at,id)
  WHERE traffic_state='SUSPENDED';
