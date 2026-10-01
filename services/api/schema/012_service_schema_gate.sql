-- Each serving identity can inspect only the migration history. It cannot
-- modify the ledger, own the schema, or apply a migration.
GRANT SELECT ON hosting.schema_migrations TO hosting_api,hosting_worker,hosting_hook,hosting_buildworker;
