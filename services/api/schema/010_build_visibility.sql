-- Expose immutable build status through tenant-scoped read-only API policies.
GRANT SELECT ON hosting.git_sources,hosting.github_builds TO hosting_api;
CREATE POLICY git_api_sources ON hosting.git_sources FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m
                 WHERE m.organization_id=git_sources.organization_id
                   AND m.actor_sub=current_setting('hosting.actor_sub',true)));
CREATE POLICY git_api_builds ON hosting.github_builds FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.git_sources s
                 WHERE s.id=github_builds.source_id));
CREATE INDEX github_builds_source_recent_idx ON hosting.github_builds(source_id,created_at DESC,delivery_id DESC);
