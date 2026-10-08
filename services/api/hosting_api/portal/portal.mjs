import {IssuerLogin} from './login.mjs';

export class ApiError extends Error {
  constructor(status, code) {
    super(`Request failed (${status}): ${code}`);
    this.status = status;
  }
}

export class ControlClient {
  #token = '';
  #session = new AbortController();
  constructor(fetcher = (...args) => fetch(...args)) { this.fetcher = fetcher; }
  connect(token) {
    if (typeof token !== 'string' || !token || token.length > 16384 || /\s/.test(token)) {
      throw new Error('Enter a valid control API token.');
    }
    this.disconnect();
    this.#token = token;
  }
  disconnect() {
    this.#token = '';
    this.#session.abort();
    this.#session = new AbortController();
  }
  renew(token) {
    if (!this.#token || typeof token !== 'string' || !token || token.length > 16384 || /\s/.test(token)) throw new Error('Session renewal failed.');
    this.#token = token;
  }
  async request(path, body) {
    const auditCursor = /^\/v1\/organizations\/[0-9a-f-]{36}\/audit\?after=(0|[1-9][0-9]{0,18})$/.test(path);
    if ((!/^\/v1\/[a-z0-9/-]+$/.test(path) && !(auditCursor && body === undefined)) || path.includes('//')) {
      throw new Error('Invalid control API path.');
    }
    if (!this.#token) throw new Error('Connect to your workspace first.');
    const session = this.#session;
    if (this.beforeRequest) await this.beforeRequest();
    if (session.signal.aborted) throw new DOMException('Session ended', 'AbortError');
    const headers = {Authorization: `Bearer ${this.#token}`, Accept: 'application/json'};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let response;
    try {
      response = await this.fetcher(path, {
        method: body === undefined ? 'GET' : 'POST', headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: 'omit', redirect: 'error', cache: 'no-store',
        signal: AbortSignal.any([session.signal, AbortSignal.timeout(15000)]),
      });
    } catch (error) {
      if (session.signal.aborted) throw new DOMException('Session ended', 'AbortError');
      throw new Error('Connection interrupted. Refresh readback before retrying a change.');
    }
    if (session.signal.aborted) throw new DOMException('Session ended', 'AbortError');
    if (response.status === 401) {
      this.disconnect();
      try { response.body?.cancel().catch(() => {}); } catch { /* Authentication is already cleared. */ }
      throw new ApiError(401, 'unauthorized');
    }
    if (!response.body) throw new Error('Control API returned an invalid response.');
    // Bound memory even when a proxy returns an unexpectedly large body.
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 1048576) throw new Error('Control API response is too large.');
        chunks.push(value);
      }
    } catch {
      if (session.signal.aborted) throw new DOMException('Session ended', 'AbortError');
      throw new Error(size > 1048576 ? 'Control API response is too large.' : 'Connection interrupted while reading control API response.');
    } finally {
      try { reader.cancel().catch(() => {}); } catch { /* Do not expose transport diagnostics. */ }
    }
    if (session.signal.aborted) throw new DOMException('Session ended', 'AbortError');
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    let result;
    try { result = JSON.parse(new TextDecoder().decode(bytes)); }
    catch { throw new Error('Control API returned an invalid response.'); }
    if (!result || Array.isArray(result) || typeof result !== 'object') {
      throw new Error('Control API returned an invalid response.');
    }
    if (!response.ok) {
      const code = typeof result.error === 'string' && /^[a-z_]{1,80}$/.test(result.error)
        ? result.error : 'request_failed';
      throw new ApiError(response.status, code);
    }
    return result;
  }
}

export class MutationKeys {
  #keys = new Map();
  constructor(generate = () => crypto.randomUUID()) { this.generate = generate; }
  forRequest(path, body) {
    const sorted = Object.fromEntries(Object.entries(body).sort(([a], [b]) => a.localeCompare(b)));
    const identity = JSON.stringify([path, sorted]);
    if (!this.#keys.has(identity)) this.#keys.set(identity, this.generate());
    return this.#keys.get(identity);
  }
  clear() { this.#keys.clear(); }
  resetRoute(path) {
    for (const identity of this.#keys.keys()) if (JSON.parse(identity)[0] === path) this.#keys.delete(identity);
  }
}

export function canManage(role) { return role === 'owner' || role === 'admin'; }
export function canManageAccess(role) { return role === 'owner'; }

export function entitlementView(data) {
  const features = ['release','postgres','valkey','storage','domain','domain_registration','build'];
  const decimal = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,18})$/.test(value);
  if (!data || data.authority !== 'OPERATOR_ASSIGNED' || typeof data.requires_assignment !== 'boolean' ||
      !['UNCONFIGURED','ACTIVE','EXPIRED'].includes(data.status) || !data.usage ||
      !decimal(data.usage.cpu_milli) || !decimal(data.usage.memory_mb) ||
      ['projects','applications','domains','registrations'].some(name => !Number.isSafeInteger(data.usage[name]) || data.usage[name]<0)) {
    throw new Error('Hosting plan readback is invalid.');
  }
  const v = data.version;
  if (data.status === 'UNCONFIGURED') {
    if (v !== null) throw new Error('Hosting plan readback is invalid.');
  } else if (!v || !CANONICAL_UUID.test(v.id) || typeof v.plan_ref !== 'string' || !/^plan:\/\/[a-zA-Z0-9/_-]{1,120}$/.test(v.plan_ref) ||
      !Array.isArray(v.features) || v.features.some(feature => !features.includes(feature)) || new Set(v.features).size !== v.features.length ||
      !decimal(v.cpu_milli_limit) || BigInt(v.cpu_milli_limit)<1n || BigInt(v.cpu_milli_limit)>9223372036854775807n ||
      !decimal(v.memory_mb_limit) || BigInt(v.memory_mb_limit)<1n || BigInt(v.memory_mb_limit)>9223372036854775807n ||
      ['project_limit','application_limit','domain_limit','registration_limit'].some(name => !Number.isInteger(v[name]) || v[name]<0 || v[name]>100000) ||
      !Number.isFinite(Date.parse(v.valid_from)) || !Number.isFinite(Date.parse(v.valid_until)) || Date.parse(v.valid_until)<=Date.parse(v.valid_from)) {
    throw new Error('Hosting plan readback is invalid.');
  }
  return data;
}

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function invitationState(invitation, now = Date.now()) {
  if (invitation.revoked_at) return 'REVOKED';
  if (invitation.accepted_at) return 'ACCEPTED';
  const expiry = Date.parse(invitation.expires_at);
  return !Number.isFinite(expiry) || expiry <= now ? 'EXPIRED' : 'PENDING';
}

export function visibleReceipt(receipt) {
  const result = {...receipt};
  if (Object.hasOwn(result, 'token')) result.token = '[shown separately once]';
  return result;
}

export class AuditPages {
  #revision = 0;
  constructor() { this.reset(); }
  reset(organization = '') {
    this.#revision++;
    this.organization = organization; this.events = []; this.after = 0;
    this.hasMore = false; this.loaded = false;
  }
  async load(client) {
    if (!CANONICAL_UUID.test(this.organization)) throw new Error('Select an organization first.');
    const revision = ++this.#revision, after = this.after;
    const result = await client.request(`/v1/organizations/${this.organization}/audit?after=${after}`);
    if (revision !== this.#revision) throw new DOMException('Workspace changed', 'AbortError');
    if (!Array.isArray(result.events) || result.events.length > 100 || typeof result.has_more !== 'boolean' ||
        !Number.isSafeInteger(result.next_after) || result.next_after < after ||
        (result.has_more && !result.events.length)) throw new Error('Invalid audit pagination response.');
    let cursor = after;
    let previous = this.events.length ? this.events.at(-1).event_hash : '';
    for (const event of result.events) {
      if (!event || !Number.isSafeInteger(event.id) || event.id <= cursor ||
          typeof event.actor_sub !== 'string' || typeof event.action !== 'string' ||
          !CANONICAL_UUID.test(event.resource_id) || !CANONICAL_UUID.test(event.request_id) ||
          typeof event.created_at !== 'string' || !Number.isFinite(Date.parse(event.created_at)) ||
          !/^[0-9a-f]{64}$/.test(event.event_hash) || event.previous_hash !== previous) {
        throw new Error('Invalid audit event or broken page continuity.');
      }
      cursor = event.id; previous = event.event_hash;
    }
    if (result.next_after !== cursor) throw new Error('Invalid audit pagination cursor.');
    // Publish the new page atomically; rejected pages do not change the cursor.
    this.events.push(...result.events); this.after = cursor;
    this.hasMore = result.has_more; this.loaded = true;
    return result.events;
  }
}

export function registrationQuote(request, now = Date.now()) {
  const quote = request?.quote, payload = quote?.payload;
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  if (request?.state !== 'QUOTED' || !uuid.test(request.id) || !uuid.test(quote?.id) ||
      !/^[a-f0-9]{64}$/.test(quote?.sha256) || !payload || payload.quote_id !== quote.id ||
      payload.hostname !== request.hostname || payload.registrant_ref !== request.registrant_ref ||
      !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|co\.zw)$/.test(payload.hostname) ||
      /\s/.test(payload.hostname) || !/^registrant:\/\/[a-z0-9/_-]{1,120}$/.test(payload.registrant_ref) ||
      /\s/.test(payload.registrant_ref) ||
      payload.term_years !== request.term_years || !Number.isInteger(payload.term_years) ||
      payload.term_years < 1 || payload.term_years > 5 ||
      (payload.hostname.endsWith('.co.zw') && payload.term_years !== 1) || payload.renewal_term_years !== 1 ||
      !Number.isSafeInteger(payload.initial_amount_minor) || payload.initial_amount_minor < 1 || payload.initial_amount_minor > 2147483647 ||
      !Number.isSafeInteger(payload.renewal_amount_minor) || payload.renewal_amount_minor < 0 || payload.renewal_amount_minor > 2147483647 ||
      !['USD','ZAR','ZWG'].includes(payload.currency) || payload.fulfillment_mode !== 'MANUAL' ||
      payload.provider !== (payload.hostname.endsWith('.co.zw') ? 'ZISPA_MEMBER' : 'OPENSRS') ||
      typeof payload.registrar !== 'string' || payload.registrar.length < 1 || payload.registrar.length > 128 ||
      typeof payload.terms_text !== 'string' || payload.terms_text.length < 10 || payload.terms_text.length > 4000 ||
      !Number.isFinite(Date.parse(payload.expires_at)) || Date.parse(payload.expires_at) <= now) return null;
  return quote;
}

export function intentObservation(row, appId) {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const evaluation = row?.evaluation, receipt = evaluation?.receipt;
  const stages = ['intake','commercial_authority','profile_qualification','tenant_admin_bindings','secret_bindings',
    'backups','tenant_project_environment','hosting_plan','artifact_admission','runtime_placement','domain_ownership',
    'route_tls','postgres','storage','resource_budget','release_health','observability'];
  if (!uuid.test(row?.id) || row.application_id !== appId || row.state !== 'RECORDED' ||
      !/^[a-f0-9]{64}$/.test(row.intent_sha256) || typeof row.desired?.template_id !== 'string' ||
      typeof row.desired?.template_version !== 'string' || typeof row.desired?.domain_intent?.hostname !== 'string' ||
      !uuid.test(evaluation?.id) || !Number.isSafeInteger(evaluation.revision) || evaluation.revision < 1 ||
      receipt?.request_id !== row.id || receipt.intent_sha256 !== row.intent_sha256 ||
      receipt.controller_version !== 'hosting-readback-v1' || receipt.state !== 'NOT_QUALIFIED' ||
      receipt.resource_mutations_performed !== false || !Array.isArray(receipt.transformations) || receipt.transformations.length ||
      typeof receipt.observed_at !== 'string' || !/([+-][0-9]{2}:[0-9]{2}|Z)$/.test(receipt.observed_at) || !Number.isFinite(Date.parse(receipt.observed_at)) ||
      !Array.isArray(receipt.stages) || receipt.stages.length !== stages.length ||
      receipt.stages.some((stage, index) => stage?.stage !== stages[index] ||
        !['RECORDED','MATCHED','OBSERVED','OBSERVED_HEALTHY','BLOCKED','NOT_REQUESTED'].includes(stage.state) ||
        typeof stage.reason !== 'string' || !stage.reason || stage.reason.length > 500)) {
    throw new Error('Hosting request observation is unavailable.');
  }
  return receipt;
}

export function authorityView(data, orgId, appId, intentId) {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const date = value => typeof value === 'string' && /([+-][0-9]{2}:[0-9]{2}|Z)$/.test(value) && Number.isFinite(Date.parse(value));
  const fields = ['organization_id','application_id','intent_id','observed_at','state','source_version_id',
    'receipt_id','sequence','issued_at','valid_until','hosting_entitlement_version_id'];
  if (!data || Object.keys(data).length !== fields.length || fields.some(key => !Object.hasOwn(data,key)) ||
      data.organization_id !== orgId || data.application_id !== appId || data.intent_id !== intentId ||
      !date(data.observed_at) || !['UNCONFIGURED','SOURCE_DISABLED','AWAITING_RECEIPT','REVOKED','SOURCE_CHANGED',
        'EXPIRED','PLAN_UNAVAILABLE','PLAN_CHANGED','ADMIN_UNBOUND','ACTIVE'].includes(data.state) ||
      ['source_version_id','receipt_id','hosting_entitlement_version_id'].some(key => data[key] !== null && !uuid.test(data[key])) ||
      (data.sequence !== null && (typeof data.sequence !== 'string' || !/^[1-9][0-9]{0,18}$/.test(data.sequence) || BigInt(data.sequence) > 9223372036854775807n)) ||
      ['issued_at','valid_until'].some(key => data[key] !== null && !date(data[key])) ||
      (data.receipt_id === null && ['sequence','issued_at','valid_until','hosting_entitlement_version_id'].some(key => data[key] !== null)) ||
      (data.receipt_id !== null && (data.sequence === null || data.issued_at === null)) ||
      (data.state === 'ACTIVE' && (!data.source_version_id || !data.receipt_id || !data.hosting_entitlement_version_id ||
        !date(data.valid_until) || Date.parse(data.valid_until) <= Date.parse(data.observed_at) || Date.parse(data.issued_at) > Date.parse(data.observed_at)))) {
    throw new Error('Partner approval readback is unavailable.');
  }
  return data;
}

export function profileView(data, orgId, appId, intentId, intentHash) {
  const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const digest=value => typeof value==='string' && /^[a-f0-9]{64}$/.test(value);
  const date=value => typeof value==='string' && /([+-][0-9]{2}:[0-9]{2}|Z)$/.test(value) && Number.isFinite(Date.parse(value));
  const fields=['organization_id','application_id','intent_id','intent_sha256','observed_at','state',
    'profile_version_id','profile_sha256','valid_from','valid_until'];
  if (!data || Object.keys(data).length!==fields.length || fields.some(key => !Object.hasOwn(data,key)) ||
      data.organization_id!==orgId || data.application_id!==appId || data.intent_id!==intentId ||
      !digest(data.intent_sha256) || data.intent_sha256!==intentHash || !date(data.observed_at) ||
      !['UNCONFIGURED','DISABLED','NOT_YET_VALID','EXPIRED','PROFILE_MISMATCH','ARTIFACT_UNADMITTED',
        'BUDGET_EXCEEDED','NO_ELIGIBLE_NODE','PLACEMENT_MISMATCH','MATCHED'].includes(data.state) ||
      (data.state==='UNCONFIGURED' && fields.slice(6).some(key => data[key]!==null)) ||
      (data.state!=='UNCONFIGURED' && (!uuid.test(data.profile_version_id) || !digest(data.profile_sha256) ||
        !date(data.valid_from) || !date(data.valid_until) || Date.parse(data.valid_until)<=Date.parse(data.valid_from))) ||
      (data.state==='MATCHED' && (Date.parse(data.valid_from)>Date.parse(data.observed_at) || Date.parse(data.valid_until)<=Date.parse(data.observed_at)))) {
    throw new Error('Reviewed setup readback is unavailable.');
  }
  return data;
}

export function secretView(data,orgId,appId,intentId,intentHash) {
  const date=value => typeof value==='string' && /([+-][0-9]{2}:[0-9]{2}|Z)$/.test(value) && Number.isFinite(Date.parse(value));
  const fields=['organization_id','application_id','intent_id','intent_sha256','observed_at','state',
    'requested_count','matched_count','oldest_checked_at','valid_until'];
  if (!data || Object.keys(data).length!==fields.length || fields.some(key => !Object.hasOwn(data,key)) ||
      data.organization_id!==orgId || data.application_id!==appId || data.intent_id!==intentId ||
      typeof data.intent_sha256!=='string' || !/^[a-f0-9]{64}$/.test(data.intent_sha256) || data.intent_sha256!==intentHash || !date(data.observed_at) ||
      !['NOT_REQUESTED','UNCONFIGURED','BINDING_DISABLED','NOT_YET_VALID','EXPIRED','CHECK_REQUIRED','CHECK_FAILED','MATCHED'].includes(data.state) ||
      ['requested_count','matched_count'].some(key => !Number.isInteger(data[key]) || data[key]<0 || data[key]>64) ||
      data.matched_count>data.requested_count || (data.state==='NOT_REQUESTED')!==(data.requested_count===0) ||
      (data.state==='MATCHED' && (data.requested_count===0 || data.matched_count!==data.requested_count ||
        !date(data.oldest_checked_at) || !date(data.valid_until) || Date.parse(data.oldest_checked_at)>Date.parse(data.observed_at) ||
        Date.parse(data.oldest_checked_at)<Date.parse(data.observed_at)-300000 || Date.parse(data.valid_until)<=Date.parse(data.observed_at) ||
        Date.parse(data.valid_until)>Date.parse(data.oldest_checked_at)+300000)) ||
      (data.state!=='MATCHED' && (data.oldest_checked_at!==null || data.valid_until!==null ||
        (data.requested_count>0 && data.matched_count===data.requested_count)))) {
    throw new Error('Application secret readback is unavailable.');
  }
  return data;
}

function bootstrap() {
  const $ = id => document.getElementById(id);
  const client = new ControlClient();
  const login = new IssuerLogin({onToken: (token, renewal) => renewal ? client.renew(token) : client.connect(token),
    onExpired: () => { disconnect(); message('Your sign-in session ended. Sign in again to continue.', 'error'); }});
  client.beforeRequest = () => login.ensureFresh();
  let loginConfig = null, signingIn = false;
  const keys = new MutationKeys();
  const audit = new AuditPages();
  let organizations = [], projects = [], applications = [];
  let members = [], invitations = [], grants = [];
  let registrations = [], intents = [];
  let authorityGeneration = 0;
  let generation = 0, busy = false;
  const element = (tag, text = '', className = '') => {
    const node = document.createElement(tag); node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  const badge = state => { const node = element('span', state || 'UNKNOWN', 'badge'); node.dataset.state = state || 'UNKNOWN'; return node; };
  const date = value => value ? new Date(value).toLocaleString() : 'No observation';
  const list = (data, key) => { if (!Array.isArray(data[key])) throw new Error('Control API returned an invalid list.'); return data[key]; };
  const orgPath = () => `/v1/organizations/${$('organizations').value}`;
  const appPath = () => `${orgPath()}/applications/${$('applications').value}`;
  const selectedRole = () => organizations.find(org => org.id === $('organizations').value)?.role;
  const message = (text, kind = '') => { $('message').textContent = text; $('message').dataset.kind = kind; };
  function connected(value) {
    $('workspace').hidden = !value; $('connect-panel').hidden = value; $('disconnect').hidden = !value;
  }
  function options(id, values, label, preferred) {
    const select = $(id), previous = preferred || select.value;
    select.replaceChildren();
    if (!values.length) {
      const option = element('option', 'None available'); option.value = ''; select.append(option);
    } else for (const value of values) {
      const option = element('option', label(value)); option.value = value.id; select.append(option);
    }
    if (values.some(value => value.id === previous)) select.value = previous;
  }
  function clearDetails() {
    for (const id of ['quota','entitlements','health','resources','domain','traffic','incidents','releases','dns-proof','intents','intent-target','intent-stages']) $(id).replaceChildren();
    intents = []; $('intent-observed').textContent = 'No recorded observation selected.';
    authorityGeneration++; $('intent-authority').textContent = 'No approval check selected.';
    $('intent-profile').textContent = 'No reviewed setup check selected.';
    $('intent-secrets').textContent = 'No application secret check selected.';
    $('release-count').textContent = ''; $('dns-proof').hidden = true;
    $('rollback-target').replaceChildren();
  }
  function clearPrivateReceipt() {
    $('receipt').textContent = 'No changes requested for this selection.';
    $('invitation-token').textContent = ''; $('invitation-secret').hidden = true;
    for (const id of ['project-form','application-form','release-form','domain-form','resource-form','service-form','invitation-form','accept-form','registration-form','registration-approve-form','registration-cancel-form','intent-form']) $(id).reset();
    showRegistrationQuote();
  }
  function clearOrganizationViews() {
    audit.reset($('organizations').value);
    members = []; invitations = []; grants = [];
    clearRegistrations();
    for (const id of ['audit-events','members','invitations','service-accounts','remove-member-target','revoke-invitation-target','revoke-service-target']) $(id).replaceChildren();
    $('audit-state').textContent = 'Audit readback not loaded.';
    $('audit-more').hidden = true;
  }
  function disconnect({preserveTransaction = false} = {}) {
    generation++; login.disconnect({preserveTransaction}); client.disconnect(); keys.clear(); connected(false); clearDetails(); clearOrganizationViews();
    clearPrivateReceipt();
    organizations = []; projects = []; applications = [];
    for (const id of ['organizations','projects','applications']) $(id).replaceChildren();
    $('receipt').textContent = 'No changes requested in this session.';
    for (const form of document.querySelectorAll('form')) form.reset();
    message('Disconnected.');
  }
  async function run(operation) {
    if (busy) return;
    busy = true; const current = generation;
    for (const control of document.querySelectorAll('button,select')) if (control.id !== 'disconnect') control.disabled = true;
    message('Loading…');
    try { await operation(); if (current === generation) message('Readback updated.', 'success'); }
    catch (error) {
      if (error instanceof ApiError && error.status === 401) { disconnect(); message('Your access token has expired or is invalid. Reconnect to continue.', 'error'); }
      else if (current === generation && error.name !== 'AbortError') message(error.message, 'error');
    } finally {
      busy = false;
      for (const control of document.querySelectorAll('button,select')) control.disabled = false;
      updateActions();
    }
  }
  function updateActions() {
    const manage = canManage(selectedRole());
    $('create-panel').hidden = !manage || !$('organizations').value;
    $('manage-panel').hidden = !manage || !$('applications').value;
    $('rollback-panel').hidden = !manage || !$('applications').value;
    $('intent-panel').hidden = !manage || !$('applications').value;
    $('intent-form').querySelector('button').disabled = !intents.some(row => row.id === $('intent-target').value);
    $('application-form').querySelector('button').disabled = !projects.length;
    const owner = canManageAccess(selectedRole()) && Boolean($('organizations').value);
    $('access-panel').hidden = !owner;
    $('registration-panel').hidden = !owner;
    $('registration-approve-form').querySelector('button').disabled = !registrations.some(row => row.id === $('registration-quote-target').value && registrationQuote(row));
    $('registration-cancel-form').querySelector('button').disabled = !$('registration-cancel-target').value;
    $('service-form').querySelector('button').disabled = !$('applications').value;
    $('remove-member-form').querySelector('button').disabled = !members.some(member => ['admin','viewer'].includes(member.role));
    $('revoke-invitation-form').querySelector('button').disabled = !invitations.some(invite => invitationState(invite) === 'PENDING');
    $('revoke-service-form').querySelector('button').disabled = !grants.some(grant => !grant.revoked_at);
    $('rollback-form').querySelector('button').disabled = !$('rollback-target').value;
  }
  async function loadOrganizations(preferred) {
    const previous = $('organizations').value;
    organizations = list(await client.request('/v1/organizations'), 'organizations');
    options('organizations', organizations, org => `${org.name} · ${org.role}`, preferred);
    if ($('organizations').value !== previous) clearPrivateReceipt();
    if (!canManageAccess(selectedRole())) {
      $('invitation-token').textContent = ''; $('invitation-secret').hidden = true;
    }
    connected(true); await loadProjects();
  }
  async function loadProjects(preferred) {
    clearOrganizationViews();
    clearDetails(); applications = []; options('applications', [], () => '');
    projects = $('organizations').value ? list(await client.request(`${orgPath()}/projects`), 'projects') : [];
    options('projects', projects, project => project.name, preferred);
    const results = await Promise.allSettled([loadApplications(), loadOrganizationViews()]);
    const failures = results.filter(result => result.status === 'rejected');
    const authFailure = failures.find(result => result.reason instanceof ApiError && result.reason.status === 401);
    if (failures.length) throw (authFailure || failures[0]).reason;
  }
  async function loadApplications(preferred) {
    clearDetails();
    applications = $('projects').value ? list(await client.request(`${orgPath()}/projects/${$('projects').value}/applications`), 'applications') : [];
    options('applications', applications, app => `${app.name} · ${app.environment}`, preferred);
    await loadDetails();
  }
  function showRows(id, rows, columns, empty) {
    $(id).replaceChildren();
    if (!rows.length) { const row = element('tr'), cell = element('td', empty); cell.colSpan = columns.length; row.append(cell); $(id).append(row); return; }
    for (const item of rows) {
      const row = element('tr');
      for (const column of columns) row.append(element('td', String(column(item) ?? '—'), 'details'));
      $(id).append(row);
    }
  }
  async function loadAudit() {
    try {
      await audit.load(client);
      showRows('audit-events', audit.events, [event => event.id, event => event.action, event => event.actor_sub,
        event => date(event.created_at), event => event.resource_id], 'No committed events.');
      $('audit-state').textContent = `${audit.events.length} committed events shown. Integrity checked by the control API.`;
      $('audit-more').hidden = !audit.hasMore;
    } catch (error) {
      if (error.name !== 'AbortError') $('audit-state').textContent = 'Audit readback unavailable. Refresh or retry the current page.';
      throw error;
    }
  }
  async function loadAccess() {
    if (!canManageAccess(selectedRole()) || !$('organizations').value) return;
    const jobs = [['members','team/members'],['invitations','team/invitations'],['service-accounts','service-accounts']];
    const revision = generation;
    const results = await Promise.allSettled(jobs.map(async ([id, suffix]) => [id, await client.request(`${orgPath()}/${suffix}`)]));
    if (revision !== generation) return;
    let failure;
    for (let index = 0; index < results.length; index++) {
      const result = results[index], id = jobs[index][0];
      if (result.status === 'rejected') {
        if (id === 'members') { members = []; $('remove-member-target').replaceChildren(); }
        if (id === 'invitations') { invitations = []; $('revoke-invitation-target').replaceChildren(); }
        if (id === 'service-accounts') { grants = []; $('revoke-service-target').replaceChildren(); }
        showRows(id, [], [value => value], 'Readback unavailable.');
        if (!failure || result.reason.status === 401) failure = result.reason;
        continue;
      }
      const [, data] = result.value;
      if (id === 'members') {
        members = list(data, 'members');
        showRows(id, members, [member => member.actor_sub, member => member.role], 'No team members.');
        options('remove-member-target', members.filter(member => ['admin','viewer'].includes(member.role)).map(member => ({...member, id: member.actor_sub})), member => `${member.actor_sub} · ${member.role}`);
      } else if (id === 'invitations') {
        invitations = list(data, 'invitations');
        showRows(id, invitations, [invite => invite.role, invite => invitationState(invite), invite => date(invite.expires_at), invite => invite.id], 'No invitations.');
        options('revoke-invitation-target', invitations.filter(invite => invitationState(invite) === 'PENDING'), invite => `${invite.role} · ${invite.id}`);
      } else {
        grants = list(data, 'service_accounts');
        showRows(id, grants, [grant => grant.client_id, grant => grant.actor_sub, grant => grant.application_id, grant => grant.revoked_at ? 'REVOKED' : 'ACTIVE'], 'No service grants.');
        options('revoke-service-target', grants.filter(grant => !grant.revoked_at), grant => `${grant.client_id} · ${grant.application_id}`);
      }
    }
    if (failure) throw failure;
  }
  async function loadOrganizationViews() {
    if (!$('organizations').value) return;
    const results = await Promise.allSettled([loadAudit(), loadAccess(), loadRegistrations()]);
    const failures = results.filter(result => result.status === 'rejected');
    const authFailure = failures.find(result => result.reason instanceof ApiError && result.reason.status === 401);
    if (failures.length) throw (authFailure || failures[0]).reason;
  }
  function money(payload, field = 'initial_amount_minor') {
    return `${payload.currency} ${(payload[field] / 100).toFixed(2)}`;
  }
  function clearRegistrations() {
    registrations = [];
    for (const id of ['registrations','registration-quote-target','registration-cancel-target']) $(id).replaceChildren();
    $('registration-quote-details').textContent = 'No current quote selected.';
    $('registration-consent').checked = false;
  }
  function showRegistrationQuote() {
    $('registration-consent').checked = false;
    const row = registrations.find(item => item.id === $('registration-quote-target').value);
    const quote = registrationQuote(row);
    if (!quote) { $('registration-quote-details').textContent = 'No current quote selected.'; updateActions(); return; }
    const p = quote.payload;
    $('registration-quote-details').textContent = `Domain: ${p.hostname}\nRegistrant: ${p.registrant_ref}\nTerm: ${p.term_years} year(s)\nRegistrar: ${p.registrar}\nInitial total: ${money(p)}\nRenewal (1 year): ${money(p, 'renewal_amount_minor')}\nExpires: ${date(p.expires_at)}\nTerms:\n${p.terms_text}`;
    updateActions();
  }
  async function loadRegistrations() {
    if (!canManageAccess(selectedRole()) || !$('organizations').value) { clearRegistrations(); return; }
    const organization = $('organizations').value, revision = generation;
    try {
      const data = await client.request(`${orgPath()}/domain-registrations`);
      if (revision !== generation || organization !== $('organizations').value || !canManageAccess(selectedRole())) return;
      registrations = list(data, 'registrations');
      showRows('registrations', registrations, [row => row.hostname, row => row.state,
        row => registrationQuote(row) ? money(row.quote.payload) : '—', row => date(row.updated_at)], 'No registration requests.');
      options('registration-quote-target', registrations.filter(row => registrationQuote(row)), row => `${row.hostname} · ${money(row.quote.payload)}`);
      options('registration-cancel-target', registrations.filter(row => ['REQUESTED','QUOTED','APPROVED'].includes(row.state)), row => `${row.hostname} · ${row.state}`);
      showRegistrationQuote();
    } catch (error) {
      if (organization === $('organizations').value) {
        clearRegistrations(); showRows('registrations', [], [row => row], 'Registration readback unavailable.');
      }
      throw error;
    }
  }
  function showIntent() {
    authorityGeneration++; $('intent-authority').textContent = 'No approval check selected.';
    $('intent-profile').textContent = 'No reviewed setup check selected.';
    $('intent-secrets').textContent = 'No application secret check selected.';
    $('intent-stages').replaceChildren();
    const row = intents.find(item => item.id === $('intent-target').value);
    if (!row) { $('intent-observed').textContent = 'No recorded observation selected.'; updateActions(); return; }
    const receipt = intentObservation(row, $('applications').value);
    $('intent-observed').textContent = `Recorded observation: ${date(receipt.observed_at)} · ${receipt.state}. Refresh and recheck to observe again.`;
    for (const stage of receipt.stages) {
      const line = element('tr'), state = element('td'); state.append(badge(stage.state));
      const labels = {intake:'Request',commercial_authority:'Commercial approval',profile_qualification:'Supported setup',
        tenant_admin_bindings:'Administrator access',secret_bindings:'Application secrets',backups:'Backups',
        tenant_project_environment:'Project and environment',hosting_plan:'Hosting plan',artifact_admission:'Application version',
        runtime_placement:'Server placement',domain_ownership:'Domain ownership',route_tls:'Secure domain access',
        postgres:'Database',storage:'File storage',resource_budget:'Capacity budget',release_health:'Application health',observability:'Monitoring'};
      line.append(element('td', labels[stage.stage]), state, element('td', stage.reason));
      $('intent-stages').append(line);
    }
    updateActions();
    void showAuthority(row);
    void showProfile(row);
    void showSecrets(row);
  }
  async function showAuthority(row) {
    const current = generation, ticket = authorityGeneration;
    const org = $('organizations').value, app = $('applications').value;
    const selected = () => current === generation && ticket === authorityGeneration &&
      org === $('organizations').value && app === $('applications').value && row.id === $('intent-target').value;
    $('intent-authority').textContent = 'Checking Partner approval…';
    try {
      const data = authorityView(await client.request(`${appPath()}/intents/${row.id}/authority`),org,app,row.id);
      if (!selected()) return;
      const labels = {UNCONFIGURED:'Publisher setup is pending',SOURCE_DISABLED:'Publisher is disabled',
        AWAITING_RECEIPT:'Awaiting Partner approval',REVOKED:'Approval was revoked',SOURCE_CHANGED:'Publisher changed; a new approval is required',
        EXPIRED:'Approval expired',PLAN_UNAVAILABLE:'Hosting plan is unavailable',PLAN_CHANGED:'Hosting plan changed; a new approval is required',
        ADMIN_UNBOUND:'Administrator access changed; approval is unavailable',ACTIVE:'Approval was valid at this check'};
      $('intent-authority').textContent = `Latest approval check: ${date(data.observed_at)} · ${labels[data.state]}.` +
        (data.state === 'ACTIVE' ? ` Valid until ${date(data.valid_until)}. Recheck the request to record a new observation.` : '');
    } catch (error) {
      if (!selected()) return;
      if (error instanceof ApiError && error.status === 401) { disconnect(); message('Your session ended. Sign in again.', 'error'); return; }
      $('intent-authority').textContent = 'Partner approval readback is unavailable.';
    }
  }
  async function showProfile(row) {
    const current=generation,ticket=authorityGeneration;
    const org=$('organizations').value,app=$('applications').value;
    const selected=() => current===generation && ticket===authorityGeneration && org===$('organizations').value &&
      app===$('applications').value && row.id===$('intent-target').value;
    $('intent-profile').textContent='Checking reviewed setup…';
    try {
      const data=profileView(await client.request(`${appPath()}/intents/${row.id}/profile`),org,app,row.id,row.intent_sha256);
      if (!selected()) return;
      const labels={UNCONFIGURED:'Setup review is pending',DISABLED:'Reviewed setup was withdrawn',NOT_YET_VALID:'Review is not yet active',
        EXPIRED:'Setup review expired',PROFILE_MISMATCH:'Requested setup differs from the review',ARTIFACT_UNADMITTED:'Application version is no longer admitted',
        BUDGET_EXCEEDED:'Requested capacity exceeds the reviewed limit',NO_ELIGIBLE_NODE:'Reviewed server evidence is unavailable',
        PLACEMENT_MISMATCH:'The application uses a server outside this review',MATCHED:'Requested setup matched its review at this check'};
      $('intent-profile').textContent=`Latest setup check: ${date(data.observed_at)} · ${labels[data.state]}.` +
        (data.state==='MATCHED' ? ` Review valid until ${date(data.valid_until)}. Recheck the request to record a new observation.` : '');
    } catch (error) {
      if (!selected()) return;
      if (error instanceof ApiError && error.status===401) { disconnect();message('Your session ended. Sign in again.','error');return; }
      $('intent-profile').textContent='Reviewed setup readback is unavailable.';
    }
  }
  async function showSecrets(row) {
    const current=generation,ticket=authorityGeneration;
    const org=$('organizations').value,app=$('applications').value;
    const selected=() => current===generation && ticket===authorityGeneration && org===$('organizations').value &&
      app===$('applications').value && row.id===$('intent-target').value;
    $('intent-secrets').textContent='Checking application secrets…';
    try {
      const data=secretView(await client.request(`${appPath()}/intents/${row.id}/secrets`),org,app,row.id,row.intent_sha256);
      if (!selected()) return;
      const labels={NOT_REQUESTED:'No application secrets requested',UNCONFIGURED:'Secret setup is pending',BINDING_DISABLED:'Secret access was withdrawn',
        NOT_YET_VALID:'Secret access is not yet active',EXPIRED:'Secret access expired',CHECK_REQUIRED:'A fresh secret availability check is required',
        CHECK_FAILED:'The latest secret availability check failed',MATCHED:'All requested secrets were available at this check'};
      $('intent-secrets').textContent=`Latest secret check: ${date(data.observed_at)} · ${labels[data.state]}.` +
        (data.state==='MATCHED' ? ` Availability valid until ${date(data.valid_until)}. Recheck the request to record a new observation.` : '');
    } catch (error) {
      if (!selected()) return;
      if (error instanceof ApiError && error.status===401) { disconnect();message('Your session ended. Sign in again.','error');return; }
      $('intent-secrets').textContent='Application secret readback is unavailable.';
    }
  }
  async function loadDetails() {
    clearDetails(); const current = generation;
    const jobs = [];
    if ($('organizations').value) jobs.push(['quota', `${orgPath()}/quotas`], ['entitlements', `${orgPath()}/entitlements`]);
    if ($('applications').value) for (const [id, suffix] of [
      ['health','health'], ['releases','releases'], ['domain','domain'], ['traffic','traffic'],
      ['postgres','postgres'], ['valkey','valkey'], ['storage','storage'], ['incidents','health/incidents']
    ]) jobs.push([id, `${appPath()}/${suffix}`]);
    if ($('applications').value && canManage(selectedRole())) jobs.push(['intents', `${appPath()}/intents`]);
    const results = await Promise.allSettled(jobs.map(async ([id, path]) => [id, await client.request(path)]));
    if (current !== generation) return;
    const authFailure = results.find(result => result.status === 'rejected' && result.reason instanceof ApiError && result.reason.status === 401);
    if (authFailure) throw authFailure.reason;
    let failures = 0;
    for (let index = 0; index < results.length; index++) {
      const result = results[index], id = jobs[index][0];
      if (result.status === 'rejected') {
        failures++; const target = ['postgres','valkey','storage'].includes(id) ? 'resources' : id;
        $(target).append(element('p', `${id}: readback unavailable`, 'hint')); continue;
      }
      const [, data] = result.value;
      if (id === 'intents') {
        try {
          const rows = list(data, 'intents');
          if (rows.length > 50 || new Set(rows.map(row => row.id)).size !== rows.length) throw new Error();
          for (const row of rows) intentObservation(row, $('applications').value);
          intents = rows;
        } catch { failures++; $('intents').append(element('p', 'Hosting requests: readback unavailable', 'hint')); continue; }
        options('intent-target', intents, row => `${row.desired.template_id} ${row.desired.template_version} · ${row.desired.domain_intent.hostname}`);
        if (!intents.length) {
          const row = element('tr'), cell = element('td', 'No hosting requests recorded.'); cell.colSpan = 4; row.append(cell); $('intents').append(row);
        }
        for (const intent of intents) {
          const row = element('tr'), state = element('td'); state.append(badge(intent.evaluation.receipt.state));
          row.append(element('td', `${intent.desired.template_id} ${intent.desired.template_version}`), element('td', intent.desired.domain_intent.hostname), state, element('td', date(intent.evaluation.receipt.observed_at)));
          $('intents').append(row);
        }
        showIntent();
      } else if (id === 'quota') {
        const reserved = data.reserved;
        $('quota').append(element('div', `${reserved.memory_mb} MB / ${reserved.cpu_milli} millicores`, 'stat'),
          element('p', data.quota ? `Ceiling: ${data.quota.memory_mb_limit} MB / ${data.quota.cpu_milli_limit} millicores` : 'No tenant reservation ceiling configured.', 'hint'));
      } else if (id === 'entitlements') {
        let plan;
        try { plan = entitlementView(data); }
        catch { failures++; $('entitlements').append(element('p', 'Hosting plan readback unavailable.', 'hint')); continue; }
        $('entitlements').append(badge(plan.status));
        const v = plan.version;
        if (!v) $('entitlements').append(element('p', plan.requires_assignment
          ? 'A hosting plan is required before new work can start.' : 'No hosting plan is assigned. Contact your operator before launch.', 'hint'));
        else {
          $('entitlements').append(element('p', v.plan_ref, 'details'), element('p', `Valid until: ${date(v.valid_until)}`, 'hint'),
            element('p', `Features: ${v.features.join(', ') || 'None'}`, 'details'));
          for (const [name, ceiling] of [['projects','project_limit'],['applications','application_limit'],['domains','domain_limit'],['registrations','registration_limit']]) {
            $('entitlements').append(element('p', `${name}: ${plan.usage[name]} / ${v[ceiling]}`, 'hint'));
          }
          if (plan.status === 'EXPIRED') $('entitlements').append(element('p', 'New work is blocked. Queued work waits for renewal.', 'hint'));
        }
      } else if (id === 'health') {
        $('health').append(badge(data.state), element('p', `Last checked: ${date(data.checked_at)}`, 'hint'));
      } else if (id === 'releases') {
        const rows = list(data, 'releases'); $('release-count').textContent = `${rows.length} recent releases`;
        const active = applications.find(app => app.id === $('applications').value)?.active_release_id;
        options('rollback-target', rows.filter(release => ['SERVING','SUPERSEDED','RETIRED'].includes(release.state) && release.id !== active), release => `${date(release.created_at)} · ${release.id}`);
        if (!rows.length) { const row = element('tr'); const cell = element('td', 'No releases yet.'); cell.colSpan = 4; row.append(cell); $('releases').append(row); }
        for (const release of rows) {
          const row = element('tr'), state = element('td'); state.append(badge(release.state));
          row.append(state, element('td', release.image, 'digest'), element('td', date(release.created_at)), element('td', release.id, 'digest')); $('releases').append(row);
        }
      } else if (['postgres','valkey','storage'].includes(id)) {
        const resource = data[id], row = element('div', '', 'resource-row');
        row.append(element('span', id === 'storage' ? 'Development S3' : id), badge(resource?.state || 'NOT_PROVISIONED'));
        $('resources').append(row);
      } else if (id === 'domain') {
        const domain = data.domain;
        $('domain').append(element('p', domain ? domain.hostname : 'No domain registered.', 'details'));
        if (domain) $('domain').append(badge(domain.verified_at ? 'VERIFIED' : 'PROOF_PENDING'));
        if (domain?.txt_name) {
          $('dns-proof').hidden = false;
          $('dns-proof').append(element('pre', `TXT name: ${domain.txt_name}\nTXT value: ${domain.txt_value}\nExpires: ${date(domain.challenge_expires_at)}`));
        }
      } else if (id === 'traffic') {
        $('traffic').append(element('p', 'Traffic', 'hint'), badge(data.traffic?.traffic_state));
      } else if (id === 'incidents') {
        const incidents = list(data, 'incidents');
        if (!incidents.length) $('incidents').append(element('p', 'No recorded outage episodes.', 'hint'));
        for (const incident of incidents) $('incidents').append(element('p', `${date(incident.opened_at)} → ${incident.closed_at ? date(incident.closed_at) : 'Open'} · ${incident.resolution || 'Unresolved'}`, 'details'));
      }
    }
    if (!$('applications').value) $('health').append(element('p', 'Select or create an application.', 'hint'));
    if (failures) throw new Error(`${failures} readbacks are unavailable. Refresh to check again.`);
  }
  async function mutate(path, body, idempotent = false, ownerOnly = false) {
    if (ownerOnly ? !canManageAccess(selectedRole()) : !canManage(selectedRole())) throw new Error(ownerOnly ? 'Only an organization owner can change access.' : 'Your workspace role allows read access.');
    if (idempotent) body = {...body, idempotency_key: keys.forRequest(path, body)};
    const data = await client.request(path, body);
    $('receipt').textContent = JSON.stringify(visibleReceipt(data), null, 2);
    return data;
  }
  const values = form => Object.fromEntries(new FormData(form));
  const bind = (id, action) => $(id).addEventListener('submit', event => {
    event.preventDefault(); const body = values(event.currentTarget); run(() => action(body));
  });
  $('connect-form').addEventListener('submit', event => {
    event.preventDefault(); const token = $('token').value; $('token').value = '';
    run(async () => { login.disconnect(); client.connect(token); await loadOrganizations(); });
  });
  $('sign-in').addEventListener('click', () => run(async () => {
    if (!loginConfig) throw new Error('Sign-in is unavailable.');
    const target = await login.begin(loginConfig);
    signingIn = true; window.location.assign(target);
  }));
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') login.ensureFresh().catch(() => {});
  });
  window.addEventListener('pagehide', () => disconnect({preserveTransaction: signingIn}));
  $('disconnect').addEventListener('click', disconnect);
  $('refresh').addEventListener('click', () => run(loadOrganizations));
  $('organizations').addEventListener('change', () => { clearPrivateReceipt(); projects = []; options('projects', [], () => ''); run(loadProjects); });
  $('projects').addEventListener('change', () => { clearPrivateReceipt(); applications = []; options('applications', [], () => ''); run(loadApplications); });
  $('applications').addEventListener('change', () => { clearPrivateReceipt(); run(loadDetails); });
  bind('project-form', async body => { const result = await mutate(`${orgPath()}/projects`, body); $('project-form').reset(); await loadProjects(result.id); });
  bind('application-form', async body => { const result = await mutate(`${orgPath()}/projects/${$('projects').value}/applications`, body); $('application-form').reset(); await loadApplications(result.id); });
  bind('release-form', async body => {
    for (const field of ['port','memory_mb','cpu_milli']) body[field] = Number(body[field]);
    await mutate(`${appPath()}/releases`, body, true); await loadDetails();
  });
  $('intent-target').addEventListener('change', showIntent);
  bind('intent-form', async body => {
    const row = intents.find(item => item.id === body.intent_id);
    if (!row) throw new Error('Select a recorded hosting request.');
    const path = `${appPath()}/intents/${body.intent_id}/reconcile`;
    const key = keys.forRequest(path, {});
    const data = await mutate(path, {}, true);
    if (typeof data.replayed !== 'boolean' || data.evaluation?.id !== key) throw new Error('Hosting request observation is unavailable.');
    intentObservation({...row,evaluation:data.evaluation}, $('applications').value);
    keys.resetRoute(path);
    await loadDetails();
  });
  bind('domain-form', async body => { await mutate(`${appPath()}/domain`, body); await loadDetails(); });
  bind('registration-form', async body => {
    await mutate(`${orgPath()}/domain-registrations`, {...body, term_years: Number(body.term_years)}, true, true);
    $('registration-form').reset(); await loadRegistrations();
  });
  $('new-registration').addEventListener('click', () => {
    keys.resetRoute(`${orgPath()}/domain-registrations`);
    message('New registration request prepared. Inspect existing requests before submitting again.');
  });
  $('registration-quote-target').addEventListener('change', showRegistrationQuote);
  bind('registration-approve-form', async body => {
    const row = registrations.find(item => item.id === body.registration_id), quote = registrationQuote(row);
    if (!quote || !$('registration-consent').checked) throw new Error('Select a current quote and approve its displayed terms.');
    await mutate(`${orgPath()}/domain-registrations/${row.id}/approve`, {quote_id: quote.id,
      quote_sha256: quote.sha256, confirm: 'approve_registration_quote'}, false, true);
    await loadRegistrations();
  });
  bind('registration-cancel-form', async body => {
    await mutate(`${orgPath()}/domain-registrations/${body.registration_id}/cancel`, {confirm: 'cancel_registration'}, false, true);
    await loadRegistrations();
  });
  $('verify-domain').addEventListener('click', () => run(async () => { await mutate(`${appPath()}/domain/verify`, {}); await loadDetails(); }));
  bind('resource-form', async ({kind, memory_mb, cpu_milli}) => {
    await mutate(`${appPath()}/${kind}`, {memory_mb: Number(memory_mb), cpu_milli: Number(cpu_milli)}, true); await loadDetails();
  });
  bind('rollback-form', async body => { await mutate(`${appPath()}/rollback`, body, true); await loadDetails(); });
  $('new-release').addEventListener('click', () => {
    keys.resetRoute(`${appPath()}/releases`);
    message('New release request prepared. Submitting will use a new retry key.');
  });
  $('audit-more').addEventListener('click', () => run(loadAudit));
  $('audit-refresh').addEventListener('click', () => run(async () => {
    audit.reset($('organizations').value); $('audit-events').replaceChildren(); $('audit-more').hidden = true;
    await loadAudit();
  }));
  bind('invitation-form', async ({role, expires_hours}) => {
    const data = await mutate(`${orgPath()}/team/invitations`, {role, expires_hours: Number(expires_hours), confirm: `invite_${role}`}, true, true);
    if (typeof data.token === 'string') {
      $('invitation-token').textContent = data.token; $('invitation-secret').hidden = false;
    }
    await loadAccess();
  });
  $('new-invitation').addEventListener('click', () => {
    keys.resetRoute(`${orgPath()}/team/invitations`);
    $('invitation-token').textContent = ''; $('invitation-secret').hidden = true;
    message('New invitation request prepared. Existing invitations remain active until revoked or expired.');
  });
  $('clear-invitation').addEventListener('click', () => { $('invitation-token').textContent = ''; $('invitation-secret').hidden = true; });
  bind('remove-member-form', async body => {
    await mutate(`${orgPath()}/team/members/remove`, {...body, confirm: 'remove_member'}, false, true);
    await loadAccess();
  });
  bind('revoke-invitation-form', async body => { await mutate(`${orgPath()}/team/invitations/revoke`, body, false, true); await loadAccess(); });
  bind('service-form', async body => {
    await mutate(`${orgPath()}/service-accounts`, {...body, application_id: $('applications').value}, false, true);
    $('service-form').reset(); await loadAccess();
  });
  bind('revoke-service-form', async body => {
    await mutate(`${orgPath()}/service-accounts/revoke`, {...body, confirm: 'revoke_service_account'}, false, true);
    await loadAccess();
  });
  bind('accept-form', async body => {
    $('accept-form').reset();
    const data = await client.request('/v1/team/invitations/accept', body);
    await loadOrganizations(data.organization_id);
    $('receipt').textContent = JSON.stringify(visibleReceipt(data), null, 2);
  });
  connected(false);
  const callbackURL = window.location.href;
  const callback = Boolean(new URL(callbackURL).hash) || ['code','state','error','iss'].some(name => new URL(callbackURL).searchParams.has(name));
  if (callback) window.history.replaceState(null, '', '/portal');
  (async () => {
    try {
      loginConfig = await login.configuration(window.location.origin);
      $('sign-in').hidden = !loginConfig;
      $('token-connection').open = !loginConfig;
      if (callback) await run(async () => {
        if (!loginConfig) { login.disconnect(); throw new Error('Sign-in is unavailable. Start again after it is configured.'); }
        await login.complete(callbackURL, loginConfig); await loadOrganizations();
      });
    } catch (error) {
      if (callback && error.name !== 'AbortError') { login.disconnect(); message('Sign-in could not be completed. Start sign-in again.', 'error'); }
    }
  })();
}

if (typeof document !== 'undefined') bootstrap();
