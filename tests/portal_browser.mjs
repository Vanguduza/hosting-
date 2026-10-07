// Browser contract proof with intercepted control API responses; no live estate.
import assert from 'node:assert/strict';
import {readFile, mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const require = createRequire(process.env.PORTAL_PLAYWRIGHT_ROOT
  ? path.join(process.env.PORTAL_PLAYWRIGHT_ROOT, 'package.json') : import.meta.url);
const {chromium} = require('playwright');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const assets = path.join(root, 'services/api/hosting_api/portal');
const orgA = '11111111-1111-4111-8111-111111111111';
const orgB = '22222222-2222-4222-8222-222222222222';
const project = '33333333-3333-4333-8333-333333333333';
const app = '44444444-4444-4444-8444-444444444444';
const previousRelease = '55555555-5555-4555-8555-555555555555';
const invitation = '66666666-6666-4666-8666-666666666666';
const grant = '77777777-7777-4777-8777-777777777777';
const privateInvitation = 't'.repeat(43);
const invitationKeys = new Set();
const writes = [], errors = [];
let role = 'admin', unavailable = false, expired = false, removedMember = false, revokedInvite = false, revokedGrant = false;
const auditEvent = (id, previous_hash, event_hash) => ({id, previous_hash, event_hash,
  actor_sub: 'owner-subject', action: 'project.create', resource_id: project,
  request_id: orgA, created_at: '2026-10-07T00:00:00Z'});
const browser = await chromium.launch({headless: true,
  ...(process.env.PORTAL_CHROMIUM ? {executablePath: process.env.PORTAL_CHROMIUM} : {})});
try {
  const page = await browser.newPage({viewport: {width: 1280, height: 900}});
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', msg => { if (msg.type() === 'error' && !msg.text().includes('status of 503') && !msg.text().includes('status of 401')) errors.push(msg.text()); });
  await page.route('https://portal.example.test/**', async route => {
    const request = route.request(), url = new URL(request.url()), pathname = url.pathname;
    if (pathname.startsWith('/portal')) {
      const filename = {'/portal':'index.html','/portal/portal.css':'portal.css','/portal/portal.mjs':'portal.mjs'}[pathname];
      assert.ok(filename, 'Only listed static assets may be loaded');
      return route.fulfill({status: 200, body: await readFile(path.join(assets, filename)), headers: {
        'Content-Type': filename.endsWith('.html') ? 'text/html' : filename.endsWith('.css') ? 'text/css' : 'text/javascript',
        'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
      }});
    }
    assert.ok(pathname.startsWith('/v1/'));
    assert.equal(request.headers().authorization, 'Bearer disposable-browser-test');
    assert.equal(request.headers().cookie, undefined);
    let body = {}, status = 200;
    if (request.method() === 'POST') {
      const payload = request.postDataJSON();
      writes.push({path: pathname, body: payload});
      status = 202; body = {id: app, state: 'QUEUED', request_id: orgA};
      if (pathname.endsWith('/team/invitations')) {
        const replayed = invitationKeys.has(payload.idempotency_key);
        invitationKeys.add(payload.idempotency_key);
        status = replayed ? 200 : 201;
        body = {id: invitation, expires_at: '2099-10-08T00:00:00Z',
          ...(replayed ? {replayed: true} : {token: privateInvitation, role: payload.role})};
      } else if (pathname.endsWith('/team/members/remove')) {
        assert.equal(payload.confirm, 'remove_member'); assert.equal(payload.actor_sub, 'viewer-subject');
        removedMember = true; body = {state: 'REMOVED'};
      } else if (pathname.endsWith('/team/invitations/revoke')) {
        assert.equal(payload.invitation_id, invitation); revokedInvite = true; body = {state: 'REVOKED'};
      } else if (pathname.endsWith('/service-accounts/revoke')) {
        assert.equal(payload.confirm, 'revoke_service_account'); assert.equal(payload.id, grant);
        revokedGrant = true; body = {state: 'REVOKED'};
      } else if (pathname.endsWith('/service-accounts')) {
        assert.equal(payload.application_id, app); body = {id: grant, application_id: app}; status = 201;
      } else if (pathname === '/v1/team/invitations/accept') {
        assert.equal(payload.token, privateInvitation); body = {organization_id: orgA, role: 'viewer', state: 'JOINED'};
      }
    } else if (expired) { status = 401; body = {error: 'unauthorized'}; }
    else if (pathname === '/v1/organizations') body = {organizations: [
      {id: orgA, name: 'First workspace', role}, {id: orgB, name: 'Second workspace', role},
    ]};
    else if (pathname.endsWith('/projects')) body = {projects: [{id: project, name: '<img src=x onerror=alert(1)>'}]};
    else if (pathname.endsWith('/applications')) body = {applications: [{id: app, name: 'Partner storefront', environment: 'production', active_release_id: app}]};
    else if (pathname.endsWith('/audit')) body = url.searchParams.get('after') === '0'
      ? {events: [auditEvent(1, '', 'a'.repeat(64))], next_after: 1, has_more: true}
      : {events: [auditEvent(3, 'a'.repeat(64), 'b'.repeat(64))], next_after: 3, has_more: false};
    else if (pathname.endsWith('/team/members')) body = {members: [
      {actor_sub: 'owner-subject', role: 'owner'}, ...(!removedMember ? [{actor_sub: 'viewer-subject', role: 'viewer'}] : []),
    ]};
    else if (pathname.endsWith('/team/invitations')) body = {invitations: [{id: invitation,
      role: 'viewer', expires_at: '2099-10-08T00:00:00Z', accepted_at: null, revoked_at: revokedInvite ? '2026-10-07T00:00:00Z' : null}]};
    else if (pathname.endsWith('/service-accounts')) body = {service_accounts: [{id: grant, application_id: app,
      client_id: 'factory-client', actor_sub: 'factory-subject', revoked_at: revokedGrant ? '2026-10-07T00:00:00Z' : null}]};
    else if (pathname.endsWith('/quotas')) body = {reserved: {cpu_milli: 250, memory_mb: 256}, quota: null};
    else if (pathname.endsWith('/health/incidents')) body = {incidents: []};
    else if (pathname.endsWith('/health')) {
      body = {state: 'UP', checked_at: '2026-10-07T00:00:00Z'};
      if (unavailable) { status = 503; body = {error: 'unavailable'}; }
    } else if (pathname.endsWith('/releases')) body = {releases: [
      {id: app, state: 'SERVING', image: 'registry.test/web@sha256:'+'a'.repeat(64), created_at: '2026-10-07T00:00:00Z'},
      {id: previousRelease, state: 'SUPERSEDED', image: 'registry.test/web@sha256:'+'b'.repeat(64), created_at: '2026-10-06T00:00:00Z'},
    ]};
    else if (pathname.endsWith('/domain')) body = {domain: {hostname: 'app.example.test', verified_at: '2026-10-07T00:00:00Z'}};
    else if (pathname.endsWith('/traffic')) body = {traffic: {traffic_state: 'ACTIVE'}};
    else for (const kind of ['postgres','valkey','storage']) if (pathname.endsWith('/'+kind)) body = {[kind]: null};
    return route.fulfill({status, contentType: 'application/json', body: JSON.stringify(body)});
  });
  await page.goto('https://portal.example.test/portal');
  async function connect() {
    await page.locator('#token').fill('disposable-browser-test');
    await page.locator('#connect-form button').click();
    await page.locator('#health .badge').waitFor();
    await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  }
  await connect();
  assert.equal(await page.locator('#token').inputValue(), '');
  assert.equal(await page.locator('#health .badge').textContent(), 'UP');
  assert.equal(await page.locator('#projects option').textContent(), '<img src=x onerror=alert(1)>');
  assert.equal(await page.locator('img').count(), 0);
  assert.equal(await page.locator('#access-panel').isVisible(), false);
  assert.equal(await page.locator('#audit-events tr').count(), 1);
  await page.locator('#audit-more').click();
  await page.waitForFunction(() => document.querySelectorAll('#audit-events tr').length === 2);
  assert.equal(await page.locator('#audit-more').isVisible(), false);
  assert.equal(await page.locator('#rollback-target').inputValue(), previousRelease);
  await page.locator('#organizations').selectOption(orgB);
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  await page.locator('#release-form input[name=image]').fill('registry.test/web@sha256:'+'b'.repeat(64));
  await page.locator('#release-form button').click();
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  await page.locator('#release-form button').click();
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  assert.equal(writes.length, 2);
  assert.ok(writes[0].path.includes(orgB));
  assert.equal(writes[0].body.idempotency_key, writes[1].body.idempotency_key);
  assert.equal(writes[0].body.memory_mb, 256);
  assert.match(await page.locator('#receipt').textContent(), /QUEUED/);
  await page.locator('#new-release').click();
  await page.locator('#release-form button').click();
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  assert.notEqual(writes[2].body.idempotency_key, writes[0].body.idempotency_key);
  await page.locator('#rollback-form button').click();
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  assert.equal(writes.at(-1).body.target_release_id, previousRelease);
  assert.ok(writes.at(-1).path.endsWith('/rollback'));
  unavailable = true;
  await page.locator('#refresh').click();
  await page.waitForFunction(() => document.getElementById('message').textContent.includes('readbacks are unavailable'));
  assert.equal(await page.locator('#health .badge').count(), 0);
  assert.match(await page.locator('#health').textContent(), /unavailable/);
  unavailable = false;
  await page.locator('#disconnect').click();
  assert.equal(await page.locator('#workspace').isVisible(), false);
  assert.equal(await page.locator('#receipt').textContent(), 'No changes requested in this session.');
  assert.equal(await page.locator('#health').textContent(), '');
  role = 'viewer';
  await connect();
  assert.equal(await page.locator('#create-panel').isVisible(), false);
  assert.equal(await page.locator('#manage-panel').isVisible(), false);
  assert.equal(await page.locator('#access-panel').isVisible(), false);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  await page.setViewportSize({width: 390, height: 844});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  if (process.env.PORTAL_SCREENSHOT_DIR) {
    await mkdir(process.env.PORTAL_SCREENSHOT_DIR, {recursive: true});
    await page.screenshot({path: path.join(process.env.PORTAL_SCREENSHOT_DIR, 'portal-mobile.png'), fullPage: true});
  }
  await page.locator('#disconnect').click();
  role = 'owner';
  await page.setViewportSize({width: 1280, height: 900});
  await connect();
  assert.equal(await page.locator('#access-panel').isVisible(), true);
  assert.equal(await page.locator('#remove-member-target option').count(), 1);
  assert.equal(await page.locator('#remove-member-target').inputValue(), 'viewer-subject');
  await page.locator('#invitation-form button[type=submit], #invitation-form button:not([type])').click();
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  assert.equal(await page.locator('#invitation-token').textContent(), privateInvitation);
  assert.equal((await page.locator('#receipt').textContent()).includes(privateInvitation), false);
  await page.locator('#service-form input[name=client_id]').fill('previous-tenant-client');
  await page.locator('#service-form input[name=actor_sub]').fill('previous-tenant-subject');
  await page.locator('#organizations').selectOption(orgB);
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  assert.equal(await page.locator('#invitation-token').textContent(), '');
  assert.equal(await page.locator('#invitation-secret').isVisible(), false);
  assert.equal(await page.locator('#service-form input[name=client_id]').inputValue(), '');
  assert.equal(await page.locator('#service-form input[name=actor_sub]').inputValue(), '');
  await page.locator('#new-invitation').click();
  await page.locator('#invitation-form button:not([type])').click();
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  assert.equal(writes.at(-1).body.confirm, 'invite_viewer');
  await page.locator('#clear-invitation').click();
  assert.equal(await page.locator('#invitation-token').textContent(), '');
  await page.locator('#remove-member-form button').click();
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  assert.equal(await page.locator('#remove-member-form button').isDisabled(), true);
  await page.locator('#revoke-invitation-form button').click();
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  assert.equal(await page.locator('#revoke-invitation-form button').isDisabled(), true);
  await page.locator('#service-form input[name=client_id]').fill('factory-client');
  await page.locator('#service-form input[name=actor_sub]').fill('factory-subject');
  await page.locator('#service-form button').click();
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  await page.locator('#revoke-service-form button').click();
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  assert.equal(await page.locator('#revoke-service-form button').isDisabled(), true);
  await page.locator('#accept-form input').fill(privateInvitation);
  await page.locator('#accept-form button').click();
  await page.waitForFunction(() => document.getElementById('message').textContent === 'Readback updated.');
  assert.equal(await page.locator('#accept-form input').inputValue(), '');
  assert.match(await page.locator('#receipt').textContent(), /JOINED/);
  expired = true;
  await page.locator('#refresh').click();
  await page.locator('#connect-panel').waitFor();
  assert.match(await page.locator('#message').textContent(), /expired or is invalid/);
  assert.deepEqual(errors, []);
  console.log('Portal browser contracts: PASS (roles, audit pagination, owner access, private invitation handling, rollback, tenant switch, retry, stale readback, disconnect, mobile and expired token)');
} finally { await browser.close(); }
