"""Recheck plan authorization at the durable worker execution boundary."""


def permits(conn, organization_id, feature):
    return conn.execute('SELECT hosting.entitlement_permits(%s,%s) AS allowed',
                        (organization_id, feature)).fetchone()['allowed']


def hold(conn, table, identifier, *, build=False):
    # Identifiers are fixed source constants, never input or database values.
    if table not in ('jobs', 'postgres_jobs', 'valkey_jobs', 'object_storage_jobs', 'github_builds'):
        raise ValueError('Unknown entitlement job table')
    conn.execute('UPDATE hosting.' + table + " SET state=%s,lease_until=NULL,last_error='entitlement_unavailable',"
                 "next_attempt_at=now()+interval '60 seconds' WHERE " + ('delivery_id' if build else 'id') + '=%s',
                 ('QUEUED' if build else 'PENDING', identifier))
