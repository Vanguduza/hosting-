-- A physical ingress or private node endpoint must not appear twice in the
-- scheduler's capacity inventory. Refuse migration if an existing inventory
-- already contains duplicates; an operator must reconcile it first.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM hosting.nodes GROUP BY endpoint HAVING count(*)>1) OR
     EXISTS (SELECT 1 FROM hosting.nodes WHERE public_ipv4 IS NOT NULL
             GROUP BY public_ipv4 HAVING count(*)>1) THEN
    RAISE EXCEPTION 'Duplicate node identity in capacity inventory';
  END IF;
END;
$$;
ALTER TABLE hosting.nodes ADD CONSTRAINT public_ipv4_host_mask
  CHECK (public_ipv4 IS NULL OR masklen(public_ipv4)=32);
CREATE UNIQUE INDEX nodes_endpoint_unique ON hosting.nodes(endpoint);
CREATE UNIQUE INDEX nodes_public_ipv4_unique ON hosting.nodes(public_ipv4)
  WHERE public_ipv4 IS NOT NULL;
