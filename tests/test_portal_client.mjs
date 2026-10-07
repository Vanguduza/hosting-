import test from 'node:test';
import assert from 'node:assert/strict';
import {ControlClient, MutationKeys, ApiError, canManage} from '../services/api/hosting_api/portal/portal.mjs';

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
