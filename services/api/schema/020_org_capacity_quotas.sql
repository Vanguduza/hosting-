-- Operator-assigned ceilings for active CPU and memory reservations.
-- No row means uncapped at the tenant layer; production requires an explicit row.
CREATE TABLE hosting.organization_quotas (
  organization_id uuid PRIMARY KEY REFERENCES hosting.organizations(id),
  cpu_milli_limit bigint NOT NULL CHECK (cpu_milli_limit > 0),
  memory_mb_limit bigint NOT NULL CHECK (memory_mb_limit > 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE hosting.quota_changes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
  operator_name text NOT NULL CHECK (length(operator_name) BETWEEN 1 AND 128),
  reason text NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
  cpu_milli_limit bigint NOT NULL,
  memory_mb_limit bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION hosting.enforce_capacity_quota() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = hosting, pg_temp AS $$
DECLARE limits record; current_cpu bigint; current_memory bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.organization_id::text,4));
  SELECT cpu_milli_limit,memory_mb_limit INTO limits FROM hosting.organization_quotas
    WHERE organization_id=NEW.organization_id;
  IF NOT FOUND THEN RETURN NEW; END IF;
  SELECT coalesce(sum(cpu_milli),0),coalesce(sum(memory_mb),0)
    INTO current_cpu,current_memory FROM hosting.capacity_intervals
    WHERE organization_id=NEW.organization_id AND ended_at IS NULL;
  IF current_cpu + NEW.cpu_milli > limits.cpu_milli_limit OR
     current_memory + NEW.memory_mb > limits.memory_mb_limit THEN
    RAISE EXCEPTION 'quota_exceeded' USING ERRCODE='P0001';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER enforce_capacity_quota BEFORE INSERT ON hosting.capacity_intervals
  FOR EACH ROW EXECUTE FUNCTION hosting.enforce_capacity_quota();

CREATE FUNCTION hosting.validate_quota_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = hosting, pg_temp AS $$
DECLARE current_cpu bigint; current_memory bigint;
BEGIN
  IF coalesce(current_setting('hosting.quota_operator',true),'') = '' OR
     coalesce(length(current_setting('hosting.quota_reason',true)),0) NOT BETWEEN 10 AND 500 THEN
    RAISE EXCEPTION 'Operator and reason required for quota changes';
  END IF;
  IF TG_OP='UPDATE' AND NEW.organization_id <> OLD.organization_id THEN
    RAISE EXCEPTION 'Quota tenant cannot change';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.organization_id::text,4));
  SELECT coalesce(sum(cpu_milli),0),coalesce(sum(memory_mb),0)
    INTO current_cpu,current_memory FROM hosting.capacity_intervals
    WHERE organization_id=NEW.organization_id AND ended_at IS NULL;
  IF current_cpu > NEW.cpu_milli_limit OR current_memory > NEW.memory_mb_limit THEN
    RAISE EXCEPTION 'Quota below existing reservations';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;
CREATE TRIGGER quota_validate BEFORE INSERT OR UPDATE ON hosting.organization_quotas
  FOR EACH ROW EXECUTE FUNCTION hosting.validate_quota_change();
CREATE FUNCTION hosting.log_quota_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = hosting, pg_temp AS $$
BEGIN
  INSERT INTO hosting.quota_changes(organization_id,operator_name,reason,cpu_milli_limit,memory_mb_limit)
  VALUES (NEW.organization_id,current_setting('hosting.quota_operator'),
          current_setting('hosting.quota_reason'),NEW.cpu_milli_limit,NEW.memory_mb_limit);
  RETURN NEW;
END;
$$;
CREATE TRIGGER quota_log AFTER INSERT OR UPDATE ON hosting.organization_quotas
  FOR EACH ROW EXECUTE FUNCTION hosting.log_quota_change();
REVOKE ALL ON FUNCTION hosting.enforce_capacity_quota(),hosting.validate_quota_change(),
  hosting.log_quota_change() FROM PUBLIC;
GRANT SELECT ON hosting.organization_quotas TO hosting_api;
ALTER TABLE hosting.organization_quotas ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_quota_read ON hosting.organization_quotas FOR SELECT TO hosting_api
  USING (current_setting('hosting.auth_kind',true)='human' AND EXISTS (
    SELECT 1 FROM hosting.memberships m WHERE m.organization_id=organization_quotas.organization_id
    AND m.actor_sub=current_setting('hosting.actor_sub',true)));
