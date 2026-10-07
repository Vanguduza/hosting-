import test from 'node:test';
import assert from 'node:assert/strict';
import {ControlClient, MutationKeys, ApiError, canManage, canManageAccess, AuditPages,
  invitationState, visibleReceipt} from '../services/api/hosting_api/portal/portal.mjs';

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: {'Content-Type': 'application/json'},
});

test('authentication is in the bearer header; requests omit cookies and refuse redirects', async () => {
  const calls = [];
  const client = new ControlClient(async (...args) => { calls.push(args); return json({organizations: []}); });
  client.connect('private.jwt');
  await client.request('/v1/organizations');
  const [path, options] = calls[0];
  assert.equal(path, '/v1/organizations');
  assert.equal(options.headers.Authorization, 'Bearer private.jwt');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.redirect, 'error');
  assert.equal(options.cache, 'no-store');
  assert.equal(options.method, 'GET');
  assert.equal(options.body, undefined);
});

test('client refuses cross-origin and malformed paths before passing the token to fetch', async () => {
  let calls = 0;
  const client = new ControlClient(() => { calls++; }); client.connect('private.jwt');
  for (const path of ['https://other.test/v1/organizations','//other.test/v1/organizations',
    '/v1/../portal','/v1/organizations?token=x','/v1//organizations','/portal']) {
    await assert.rejects(client.request(path), /Invalid control API path/);
  }
  assert.equal(calls, 0);
});

test('invalid and disconnected credentials never reach fetch', async () => {
  let calls = 0;
  const client = new ControlClient(() => { calls++; });
  for (const token of ['', 'a b', 'a\nb', 'x'.repeat(16385), null]) {
    assert.throws(() => client.connect(token), /valid control API token/);
  }
  await assert.rejects(client.request('/v1/organizations'), /Connect/);
  assert.equal(calls, 0);
});

test('a disconnected in-flight response cannot repopulate the next session', async () => {
  let finish, signal;
  const client = new ControlClient((path, options) => {
    signal = options.signal;
    return new Promise(resolve => { finish = resolve; });
  });
  client.connect('old.jwt');
  const pending = client.request('/v1/organizations');
  client.disconnect(); client.connect('new.jwt');
  assert.equal(signal.aborted, true);
  finish(json({organizations: [{id: 'old-tenant'}]}));
  await assert.rejects(pending, error => error.name === 'AbortError');
});

test('401 clears authentication and exposes only a bounded typed error', async () => {
  let calls = 0;
  const client = new ControlClient(async () => { calls++; return json({error: 'unauthorized'}, 401); });
  client.connect('private.jwt');
  await assert.rejects(client.request('/v1/organizations'), error => error instanceof ApiError && error.status === 401);
  await assert.rejects(client.request('/v1/organizations'), /Connect/);
  assert.equal(calls, 1);
});

test('transport and arbitrary server errors do not leak token or response diagnostics', async () => {
  const client = new ControlClient(async () => { throw new Error('private.jwt'); }); client.connect('private.jwt');
  await assert.rejects(client.request('/v1/organizations'), error => !error.message.includes('private.jwt'));
  const server = new ControlClient(async () => json({error: '<script>private.jwt</script>'}, 503)); server.connect('private.jwt');
  await assert.rejects(server.request('/v1/organizations'), /request_failed/);
});

test('malformed and oversized readback fails closed', async () => {
  for (const body of ['not json','[]','null','"text"', 'x'.repeat(1048577)]) {
    const client = new ControlClient(async () => new Response(body)); client.connect('private.jwt');
    await assert.rejects(client.request('/v1/organizations'));
  }
});

test('POST sends the explicit change and preserves the caller idempotency key', async () => {
  let payload;
  const client = new ControlClient(async (path, options) => { payload = options; return json({state: 'QUEUED'}, 202); });
  client.connect('private.jwt');
  await client.request('/v1/organizations/a/applications/b/releases', {idempotency_key: 'stable-key', image: 'image'});
  assert.equal(payload.method, 'POST');
  assert.equal(payload.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(payload.body), {idempotency_key: 'stable-key', image: 'image'});
});

test('retry keys survive identical changes and separate tenants, applications and specifications', () => {
  let counter = 0;
  const keys = new MutationKeys(() => `key-${++counter}`);
  const key = keys.forRequest('/tenant/a/app/x/releases', {image: 'one', memory_mb: 256});
  assert.equal(keys.forRequest('/tenant/a/app/x/releases', {memory_mb: 256, image: 'one'}), key);
  assert.notEqual(keys.forRequest('/tenant/b/app/x/releases', {image: 'one', memory_mb: 256}), key);
  assert.notEqual(keys.forRequest('/tenant/a/app/y/releases', {image: 'one', memory_mb: 256}), key);
  assert.notEqual(keys.forRequest('/tenant/a/app/x/releases', {image: 'two', memory_mb: 256}), key);
  keys.clear();
  assert.notEqual(keys.forRequest('/tenant/a/app/x/releases', {image: 'one', memory_mb: 256}), key);
});

test('viewer and unknown roles receive no mutation affordance', () => {
  assert.equal(canManage('owner'), true); assert.equal(canManage('admin'), true);
  for (const role of ['viewer','OWNER','service',null,undefined]) assert.equal(canManage(role), false);
});

test('only owners can manage team and machine access; invitations expire conservatively', () => {
  assert.equal(canManageAccess('owner'), true);
  for (const role of ['admin','viewer','OWNER','service',null]) assert.equal(canManageAccess(role), false);
  const now = Date.parse('2026-10-07T00:00:00Z');
  assert.equal(invitationState({expires_at: '2026-10-08T00:00:00Z'}, now), 'PENDING');
  assert.equal(invitationState({expires_at: '2026-10-07T00:00:00Z'}, now), 'EXPIRED');
  assert.equal(invitationState({expires_at: 'bad'}, now), 'EXPIRED');
  assert.equal(invitationState({accepted_at: '2026-10-06', expires_at: '2026-10-06'}, now), 'ACCEPTED');
  assert.equal(invitationState({revoked_at: '2026-10-06', expires_at: '2026-10-08'}, now), 'REVOKED');
});

test('one-time invitation secrets stay out of generic operation receipts', () => {
  const source = {id: 'invitation', token: 'private-invitation', role: 'viewer'};
  assert.equal(visibleReceipt(source).token, '[shown separately once]');
  assert.equal(source.token, 'private-invitation');
  assert.equal(JSON.stringify(visibleReceipt(source)).includes('private-invitation'), false);
  assert.deepEqual(visibleReceipt({state: 'JOINED'}), {state: 'JOINED'});
});

test('deliberately starting another request rotates only that route retry keys', () => {
  let counter = 0;
  const keys = new MutationKeys(() => `key-${++counter}`);
  const first = keys.forRequest('/tenant/a/releases', {image: 'one'});
  const service = keys.forRequest('/tenant/a/postgres', {memory_mb: 256});
  const otherTenant = keys.forRequest('/tenant/b/releases', {image: 'one'});
  keys.resetRoute('/tenant/a/releases');
  assert.notEqual(keys.forRequest('/tenant/a/releases', {image: 'one'}), first);
  assert.equal(keys.forRequest('/tenant/a/postgres', {memory_mb: 256}), service);
  assert.equal(keys.forRequest('/tenant/b/releases', {image: 'one'}), otherTenant);
});

test('401 ends authentication even when the unauthorized body is invalid', async () => {
  const client = new ControlClient(async () => new Response('not-json', {status: 401})); client.connect('private.jwt');
  await assert.rejects(client.request('/v1/organizations'), error => error.status === 401);
  await assert.rejects(client.request('/v1/organizations'), /Connect/);
});

test('unresponsive unauthorized body cancellation cannot hold the session open', async () => {
  const stream = new ReadableStream({cancel() { return new Promise(() => {}); }});
  const client = new ControlClient(async () => new Response(stream, {status: 401})); client.connect('private.jwt');
  let timer;
  try {
    await assert.rejects(Promise.race([client.request('/v1/organizations'),
      new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error('Authentication stalled')), 100); })]),
      error => error.status === 401);
    await assert.rejects(client.request('/v1/organizations'), /Connect/);
  } finally { clearTimeout(timer); }
});

test('response stream failures are sanitized and empty success bodies are rejected', async () => {
  const stream = new ReadableStream({start(controller) { controller.error(new Error('private.jwt')); }});
  const client = new ControlClient(async () => new Response(stream)); client.connect('private.jwt');
  await assert.rejects(client.request('/v1/organizations'), error => !error.message.includes('private.jwt') && error.message.includes('interrupted'));
  const empty = new ControlClient(async () => new Response(null, {status: 204})); empty.connect('private.jwt');
  await assert.rejects(empty.request('/v1/organizations'), /invalid response/);
});

const org = '11111111-1111-4111-8111-111111111111';
const otherOrg = '22222222-2222-4222-8222-222222222222';
const event = (id, previous_hash = '', event_hash = 'a'.repeat(64)) => ({
  id, previous_hash, event_hash, actor_sub: 'owner-subject', action: 'project.create',
  resource_id: org, request_id: otherOrg, created_at: '2026-10-07T00:00:00Z',
});

test('audit pagination accepts strictly ordered global IDs with gaps and tenant-bound cursors', async () => {
  const calls = [];
  const client = {request: async path => { calls.push(path); return calls.length === 1
    ? {events: [event(2)], next_after: 2, has_more: true}
    : {events: [event(7, 'a'.repeat(64), 'b'.repeat(64))], next_after: 7, has_more: false}; }};
  const pages = new AuditPages(); pages.reset(org);
  await pages.load(client); await pages.load(client);
  assert.deepEqual(pages.events.map(row => row.id), [2,7]);
  assert.equal(pages.after, 7); assert.equal(pages.hasMore, false);
  assert.deepEqual(calls, [`/v1/organizations/${org}/audit?after=0`, `/v1/organizations/${org}/audit?after=2`]);
  pages.reset(otherOrg); assert.equal(pages.after, 0); assert.deepEqual(pages.events, []);
});

test('audit rejects duplicate or reversed IDs, unsafe integer cursors and broken chain boundaries atomically', async () => {
  for (const response of [
    {events: [event(1),event(1,'a'.repeat(64))], next_after: 1, has_more: false},
    {events: [event(2),event(1,'a'.repeat(64))], next_after: 1, has_more: false},
    {events: [event(9007199254740992)], next_after: 9007199254740992, has_more: false},
    {events: [event(1,'b'.repeat(64))], next_after: 1, has_more: false},
    {events: [event(1)], next_after: 2, has_more: false},
    {events: [], next_after: 0, has_more: true},
    {events: [], next_after: 0, has_more: 'false'},
  ]) {
    const pages = new AuditPages(); pages.reset(org);
    await assert.rejects(pages.load({request: async () => response}), /audit/i);
    assert.equal(pages.after, 0); assert.deepEqual(pages.events, []);
  }
  const pages = new AuditPages(); pages.reset(org);
  await pages.load({request: async () => ({events: [event(1)], next_after: 1, has_more: true})});
  await assert.rejects(pages.load({request: async () => ({events: [event(3)], next_after: 3, has_more: false})}), /continuity/);
  assert.equal(pages.after, 1); assert.equal(pages.events.length, 1);
});

test('late audit pages cannot cross a tenant switch or overwrite a newer request', async () => {
  const pages = new AuditPages(); pages.reset(org);
  let finish;
  const pending = pages.load({request: () => new Promise(resolve => { finish = resolve; })});
  pages.reset(otherOrg);
  finish({events: [event(1)], next_after: 1, has_more: false});
  await assert.rejects(pending, error => error.name === 'AbortError');
  assert.deepEqual(pages.events, []); assert.equal(pages.organization, otherOrg);
  const first = pages.load({request: () => new Promise(resolve => { finish = resolve; })});
  await pages.load({request: async () => ({events: [event(2)], next_after: 2, has_more: false})});
  finish({events: [event(1)], next_after: 1, has_more: false});
  await assert.rejects(first, error => error.name === 'AbortError');
  assert.deepEqual(pages.events.map(row => row.id), [2]);
});

test('the client permits only the exact read-only audit cursor query', async () => {
  const calls = [];
  const client = new ControlClient(async path => { calls.push(path); return json({events: []}); }); client.connect('private.jwt');
  await client.request(`/v1/organizations/${org}/audit?after=42`);
  for (const path of [`/v1/organizations/${org}/audit?after=-1`, `/v1/organizations/${org}/audit?after=01`,
    `/v1/organizations/${org}/audit?after=42&token=secret`, `/v1/organizations/${org}/audit?after=0#fragment`,
    `/v1/organizations/${org}/projects?after=0`]) await assert.rejects(client.request(path), /Invalid/);
  await assert.rejects(client.request(`/v1/organizations/${org}/audit?after=0`, {}), /Invalid/);
  assert.equal(calls.length, 1);
});
