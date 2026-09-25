-- Keep operator node placement decisions separate from tenant audit events.
CREATE TABLE hosting.node_state_changes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES hosting.nodes(id),
  enabled boolean NOT NULL,
  operator text NOT NULL CHECK (length(operator) BETWEEN 2 AND 120),
  reason text NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX node_state_changes_node_idx ON hosting.node_state_changes(node_id,id DESC);
