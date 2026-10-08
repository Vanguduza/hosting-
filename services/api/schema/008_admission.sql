-- Dedicated image-admission identity for the isolated rootless builder.
-- The builder never receives the migration or control API database credential.
GRANT USAGE ON SCHEMA hosting TO hosting_admitter;
GRANT SELECT,INSERT ON hosting.artifact_admissions TO hosting_admitter;
