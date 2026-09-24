# Committed event delivery

Migration 018 mirrors every committed `hosting.audit_events` insert into `hosting.event_outbox` in the same PostgreSQL transaction. It also queues older committed facts when first installed. Rollbacks leave neither event nor delivery record. The immutable audit ID is the receiver's idempotency key; the body includes the organization, action, resource, actor, request ID, timestamp, and hash-chain links. This stream consists of control-plane audit facts, including worker state changes recorded by `record()`. It does not represent arbitrary application telemetry or a complete usage meter.

The dedicated process `python -m hosting_api.event_worker` uses the restricted `hosting_worker` database role. Configure its fixed `EVENT_SINK_URL` as an HTTPS URL with an explicit path, and `EVENT_SINK_SECRET_FILE` as an owner-protected file containing 32–4096 random bytes. For the development Compose profile, create `.secrets/event_sink` under the private `.secrets` directory and start with:

```bash
EVENT_SINK_URL=https://events.example.org/ingest docker compose \
  -f deploy/control/compose.yaml -f deploy/control/event-worker.compose.yaml \
  --env-file deploy/control/.env up --build -d event-worker
```

The receiver must authenticate the sender, check `X-Dial-Event-Timestamp` within a short replay window, and compare `X-Dial-Event-Signature` in constant time. The signature is `v1=` followed by lowercase hex HMAC-SHA256 over the ASCII timestamp, a literal period, and the exact UTF-8 request body, using the raw secret file bytes. Deduplicate persistently on `X-Dial-Event-Id` before side effects, then return any 2xx response. No redirect is followed. The receiver must durably process or enqueue an event before returning 2xx. Rotate the shared secret with a receiver overlap window and restart the worker after installing the new file.

The worker leases the oldest outstanding fact per organization for 60 seconds, sends it over verified HTTPS with a 10-second timeout, and records 2xx acknowledgment. A crash after the receiver accepts and before database acknowledgment causes a duplicate; receiver deduplication is mandatory. Errors retry with exponential backoff up to 300 seconds. After ten attempts the record becomes `DEAD` and blocks subsequent events for that tenant, preserving order; other tenants continue. Monitor `state`, `last_error`, `attempts` and the age of the oldest non-delivered row. Never delete the outbox to clear a backlog.

After repairing the receiver, a protected database operator can requeue a `DEAD` or `DELIVERED` event. The replay transaction records operator and reason in `hosting.event_replays`. Use `DB_HOST`, `DB_NAME`, `DB_USER` and `DB_PASSWORD_FILE` for a protected operator role with schema access, and run:

```bash
python tools/replay_event.py 123 --operator operator-name \
  --reason 'Receiver restored and idempotency ledger verified' --confirm replay_event
```

A targeted replay of a delivered event does not replay later delivered facts. Tenant-facing roles cannot read the outbox or reset its delivery state. This is one operator-configured sink; it is not the full JetStream event fabric, fan-out subscriptions, notification gateway, or production alerting specified in the blueprint. Its external receiver and incident runbook must be deployed and certified before production qualification.
