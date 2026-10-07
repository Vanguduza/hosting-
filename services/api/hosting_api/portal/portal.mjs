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
  async request(path, body) {
    if (!/^\/v1\/[a-z0-9/-]+$/.test(path) || path.includes('//')) {
      throw new Error('Invalid control API path.');
    }
    if (!this.#token) throw new Error('Connect to your workspace first.');
    const session = this.#session;
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
    } finally { await reader.cancel(); }
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
      if (response.status === 401) this.disconnect();
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
}

export function canManage(role) { return role === 'owner' || role === 'admin'; }

function bootstrap() {
  const $ = id => document.getElementById(id);
  const client = new ControlClient();
  const keys = new MutationKeys();
  let organizations = [], projects = [], applications = [];
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
    for (const id of ['quota','health','resources','domain','traffic','incidents','releases','dns-proof']) $(id).replaceChildren();
    $('release-count').textContent = ''; $('dns-proof').hidden = true;
  }
  function disconnect() {
    generation++; client.disconnect(); keys.clear(); connected(false); clearDetails();
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
    $('application-form').querySelector('button').disabled = !projects.length;
  }
  async function loadOrganizations() {
    organizations = list(await client.request('/v1/organizations'), 'organizations');
    options('organizations', organizations, org => `${org.name} · ${org.role}`);
    connected(true); await loadProjects();
  }
  async function loadProjects(preferred) {
    clearDetails(); applications = []; options('applications', [], () => '');
    projects = $('organizations').value ? list(await client.request(`${orgPath()}/projects`), 'projects') : [];
    options('projects', projects, project => project.name, preferred); await loadApplications();
  }
  async function loadApplications(preferred) {
    clearDetails();
    applications = $('projects').value ? list(await client.request(`${orgPath()}/projects/${$('projects').value}/applications`), 'applications') : [];
    options('applications', applications, app => `${app.name} · ${app.environment}`, preferred);
    await loadDetails();
  }
  async function loadDetails() {
    clearDetails(); const current = generation;
    const jobs = [];
    if ($('organizations').value) jobs.push(['quota', `${orgPath()}/quotas`]);
    if ($('applications').value) for (const [id, suffix] of [
      ['health','health'], ['releases','releases'], ['domain','domain'], ['traffic','traffic'],
      ['postgres','postgres'], ['valkey','valkey'], ['storage','storage'], ['incidents','health/incidents']
    ]) jobs.push([id, `${appPath()}/${suffix}`]);
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
      if (id === 'quota') {
        const reserved = data.reserved;
        $('quota').append(element('div', `${reserved.memory_mb} MB / ${reserved.cpu_milli} millicores`, 'stat'),
          element('p', data.quota ? `Ceiling: ${data.quota.memory_mb_limit} MB / ${data.quota.cpu_milli_limit} millicores` : 'No tenant reservation ceiling configured.', 'hint'));
      } else if (id === 'health') {
        $('health').append(badge(data.state), element('p', `Last checked: ${date(data.checked_at)}`, 'hint'));
      } else if (id === 'releases') {
        const rows = list(data, 'releases'); $('release-count').textContent = `${rows.length} recent releases`;
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
  async function mutate(path, body, idempotent = false) {
    if (!canManage(selectedRole())) throw new Error('Your workspace role allows read access.');
    if (idempotent) body = {...body, idempotency_key: keys.forRequest(path, body)};
    const data = await client.request(path, body);
    $('receipt').textContent = JSON.stringify(data, null, 2);
    return data;
  }
  const values = form => Object.fromEntries(new FormData(form));
  const bind = (id, action) => $(id).addEventListener('submit', event => {
    event.preventDefault(); const body = values(event.currentTarget); run(() => action(body));
  });
  $('connect-form').addEventListener('submit', event => {
    event.preventDefault(); const token = $('token').value; $('token').value = '';
    run(async () => { client.connect(token); await loadOrganizations(); });
  });
  $('disconnect').addEventListener('click', disconnect);
  $('refresh').addEventListener('click', () => run(loadOrganizations));
  $('organizations').addEventListener('change', () => { projects = []; options('projects', [], () => ''); run(loadProjects); });
  $('projects').addEventListener('change', () => { applications = []; options('applications', [], () => ''); run(loadApplications); });
  $('applications').addEventListener('change', () => run(loadDetails));
  bind('project-form', async body => { const result = await mutate(`${orgPath()}/projects`, body); $('project-form').reset(); await loadProjects(result.id); });
  bind('application-form', async body => { const result = await mutate(`${orgPath()}/projects/${$('projects').value}/applications`, body); $('application-form').reset(); await loadApplications(result.id); });
  bind('release-form', async body => {
    for (const field of ['port','memory_mb','cpu_milli']) body[field] = Number(body[field]);
    await mutate(`${appPath()}/releases`, body, true); await loadDetails();
  });
  bind('domain-form', async body => { await mutate(`${appPath()}/domain`, body); await loadDetails(); });
  $('verify-domain').addEventListener('click', () => run(async () => { await mutate(`${appPath()}/domain/verify`, {}); await loadDetails(); }));
  bind('resource-form', async ({kind, memory_mb, cpu_milli}) => {
    await mutate(`${appPath()}/${kind}`, {memory_mb: Number(memory_mb), cpu_milli: Number(cpu_milli)}, true); await loadDetails();
  });
  connected(false);
}

if (typeof document !== 'undefined') bootstrap();
