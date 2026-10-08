-- The admission trigger sums open intervals under a per-tenant lock.
CREATE INDEX capacity_active_org_idx ON hosting.capacity_intervals(organization_id)
  WHERE ended_at IS NULL;

-- Removing a row would silently turn an enforced ceiling into UNBOUNDED.
-- A protected migration can deliberately change this rule if required.
CREATE FUNCTION hosting.reject_quota_delete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = hosting, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'Quota deletion prohibited; set a reviewed ceiling instead';
END;
$$;
REVOKE ALL ON FUNCTION hosting.reject_quota_delete() FROM PUBLIC;
CREATE TRIGGER quota_no_delete BEFORE DELETE ON hosting.organization_quotas
  FOR EACH ROW EXECUTE FUNCTION hosting.reject_quota_delete();
