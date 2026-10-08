-- GitHub-produced digests belong to their registered application. Operator-
-- admitted artifacts without a GitHub build retain the existing shared path.
-- The definer sees all build rows even when the API's tenant RLS hides another
-- application's build; the caller receives only a boolean admission decision.
-- FORCE RLS still applies to a nonsuperuser migration owner, so grant its
-- security-definer identity an explicit read policy on both lookup tables.
CREATE POLICY git_owner_sources ON hosting.git_sources FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY git_owner_builds ON hosting.github_builds FOR SELECT TO CURRENT_USER USING (true);
CREATE FUNCTION hosting.release_image_admitted(target_image text, target_org uuid, target_app uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = hosting, pg_catalog AS $$
  SELECT EXISTS (SELECT 1 FROM hosting.artifact_admissions a WHERE a.image=target_image)
     AND (NOT EXISTS (SELECT 1 FROM hosting.github_builds b
                       WHERE b.image=target_image AND b.state='ADMITTED')
          OR EXISTS (SELECT 1 FROM hosting.github_builds b
                     JOIN hosting.git_sources s ON s.id=b.source_id
                     WHERE b.image=target_image AND b.state='ADMITTED'
                       AND s.organization_id=target_org AND s.application_id=target_app));
$$;
REVOKE ALL ON FUNCTION hosting.release_image_admitted(text,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hosting.release_image_admitted(text,uuid,uuid) TO hosting_api;
