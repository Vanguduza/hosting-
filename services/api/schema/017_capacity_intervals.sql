-- Durable reservation intervals. The migration begins coverage at its own
-- clock time; existing rows are backfilled from this instant, never billed
-- retroactively from their created_at timestamp.
CREATE TABLE hosting.capacity_metering_epoch (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  started_at timestamptz NOT NULL
);
INSERT INTO hosting.capacity_metering_epoch(singleton,started_at) VALUES (true,clock_timestamp());
CREATE TABLE hosting.capacity_intervals (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
  application_id uuid NOT NULL,
  resource_type text NOT NULL CHECK (resource_type IN ('release','postgres','valkey','storage')),
  resource_id uuid NOT NULL,
  node_id uuid NOT NULL,
  cpu_milli integer NOT NULL CHECK (cpu_milli > 0),
  memory_mb integer NOT NULL CHECK (memory_mb > 0),
  started_at timestamptz NOT NULL,
  ended_at timestamptz,
  source text NOT NULL CHECK (source IN ('NEW','BACKFILL')),
  UNIQUE(resource_type,resource_id),
  CHECK (ended_at IS NULL OR ended_at >= started_at)
);
CREATE INDEX capacity_interval_lookup_idx ON hosting.capacity_intervals(organization_id,started_at,ended_at);

CREATE FUNCTION hosting.record_capacity_interval() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = hosting, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO hosting.capacity_intervals(organization_id,application_id,resource_type,resource_id,
                                           node_id,cpu_milli,memory_mb,started_at,source)
    VALUES (NEW.organization_id,NEW.application_id,TG_ARGV[0],NEW.id,
            NEW.node_id,NEW.cpu_milli,NEW.memory_mb,clock_timestamp(),'NEW');
  ELSIF TG_OP = 'UPDATE' AND TG_ARGV[0] = 'release' AND
        (NEW.state = 'RETIRED' OR (NEW.state = 'FAILED' AND NEW.cleanup_at IS NOT NULL)) THEN
    UPDATE hosting.capacity_intervals SET ended_at=GREATEST(started_at,clock_timestamp())
    WHERE resource_type='release' AND resource_id=NEW.id AND ended_at IS NULL;
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION hosting.record_capacity_interval() FROM PUBLIC;
CREATE TRIGGER meter_release_insert AFTER INSERT ON hosting.releases
  FOR EACH ROW EXECUTE FUNCTION hosting.record_capacity_interval('release');
CREATE TRIGGER meter_release_close AFTER UPDATE OF state,cleanup_at ON hosting.releases
  FOR EACH ROW EXECUTE FUNCTION hosting.record_capacity_interval('release');
CREATE TRIGGER meter_postgres_insert AFTER INSERT ON hosting.postgres_instances
  FOR EACH ROW EXECUTE FUNCTION hosting.record_capacity_interval('postgres');
CREATE TRIGGER meter_valkey_insert AFTER INSERT ON hosting.valkey_instances
  FOR EACH ROW EXECUTE FUNCTION hosting.record_capacity_interval('valkey');
CREATE TRIGGER meter_storage_insert AFTER INSERT ON hosting.object_storage_instances
  FOR EACH ROW EXECUTE FUNCTION hosting.record_capacity_interval('storage');

INSERT INTO hosting.capacity_intervals(organization_id,application_id,resource_type,resource_id,
                                       node_id,cpu_milli,memory_mb,started_at,source)
SELECT r.organization_id,r.application_id,'release',r.id,r.node_id,r.cpu_milli,r.memory_mb,
       (SELECT started_at FROM hosting.capacity_metering_epoch),'BACKFILL'
FROM hosting.releases r WHERE r.state <> 'RETIRED' AND (r.state <> 'FAILED' OR r.cleanup_at IS NULL);
INSERT INTO hosting.capacity_intervals(organization_id,application_id,resource_type,resource_id,
                                       node_id,cpu_milli,memory_mb,started_at,source)
SELECT p.organization_id,p.application_id,'postgres',p.id,p.node_id,p.cpu_milli,p.memory_mb,
       (SELECT started_at FROM hosting.capacity_metering_epoch),'BACKFILL'
FROM hosting.postgres_instances p;
INSERT INTO hosting.capacity_intervals(organization_id,application_id,resource_type,resource_id,
                                       node_id,cpu_milli,memory_mb,started_at,source)
SELECT v.organization_id,v.application_id,'valkey',v.id,v.node_id,v.cpu_milli,v.memory_mb,
       (SELECT started_at FROM hosting.capacity_metering_epoch),'BACKFILL'
FROM hosting.valkey_instances v;
INSERT INTO hosting.capacity_intervals(organization_id,application_id,resource_type,resource_id,
                                       node_id,cpu_milli,memory_mb,started_at,source)
SELECT s.organization_id,s.application_id,'storage',s.id,s.node_id,s.cpu_milli,s.memory_mb,
       (SELECT started_at FROM hosting.capacity_metering_epoch),'BACKFILL'
FROM hosting.object_storage_instances s;

GRANT SELECT ON hosting.capacity_intervals,hosting.capacity_metering_epoch TO hosting_api;
ALTER TABLE hosting.capacity_intervals ENABLE ROW LEVEL SECURITY;
-- The migration owner executes the SECURITY DEFINER trigger. It bypasses
-- RLS as table owner; neither serving role receives INSERT/UPDATE grants.
CREATE POLICY capacity_tenant_read ON hosting.capacity_intervals FOR SELECT TO hosting_api
  USING (current_setting('hosting.auth_kind',true)='human' AND EXISTS (
    SELECT 1 FROM hosting.memberships m WHERE m.organization_id=capacity_intervals.organization_id
    AND m.actor_sub=current_setting('hosting.actor_sub',true)));
