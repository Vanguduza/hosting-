// Public-client PKCE transaction; access and refresh tokens never enter storage.
export const LOGIN_TRANSACTION = 'dial.hosting.pkce.v1';
const randomPattern = /^[A-Za-z0-9_-]{43,128}$/;
const tokenPattern = /^[^\s\x00-\x1f\x7f]{1,16384}$/;
const loginError = () => new Error('Sign-in could not be completed. Start sign-in again.');
const ended = () => new DOMException('Session ended', 'AbortError');

function httpsURL(value, loopback = false) {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || /[\s\\\x00-\x1f\x7f]/.test(value) ||
      (url.protocol !== 'https:' && !(loopback && url.protocol === 'http:' && ['127.0.0.1','[::1]'].includes(url.hostname)))) throw loginError();
  return url;
}

export function loginConfiguration(data, pageOrigin) {
  if (data?.enabled === false) return null;
  if (data?.enabled !== true || typeof data.client_id !== 'string' || !/^[A-Za-z0-9._:/-]{1,128}$/.test(data.client_id) ||
      !Array.isArray(data.scopes) || !data.scopes.includes('openid') || data.scopes.length > 12 ||
      new Set(data.scopes).size !== data.scopes.length || data.scopes.some(scope => typeof scope !== 'string' || !/^[A-Za-z0-9:._/-]{1,200}$/.test(scope))) throw loginError();
  const issuer = httpsURL(data.issuer), authorize = httpsURL(data.authorization_url), callback = httpsURL(data.redirect_uri, true);
  if (issuer.origin !== authorize.origin || callback.origin !== pageOrigin || callback.pathname !== '/portal') throw loginError();
  return {issuer: data.issuer, client_id: data.client_id, authorization_url: data.authorization_url,
    redirect_uri: data.redirect_uri, scopes: [...data.scopes]};
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
}

export class IssuerLogin {
  #session = new AbortController();
  #revision = 0;
  #credentials = null;
  #timer;
  #renewing = null;
  constructor({fetcher = (...args) => fetch(...args), storage = globalThis.sessionStorage,
    cryptoProvider = globalThis.crypto, now = () => Date.now(), schedule = (callback, delay) => globalThis.setTimeout(callback, delay),
    unschedule = timer => globalThis.clearTimeout(timer), onToken = () => {}, onExpired = () => {}} = {}) {
    Object.assign(this, {fetcher, storage, cryptoProvider, now, schedule, unschedule, onToken, onExpired});
  }
  disconnect({preserveTransaction = false} = {}) {
    this.#revision++;
    this.#credentials = null;
    this.#session.abort(); this.#session = new AbortController();
    this.unschedule(this.#timer); this.#timer = undefined; this.#renewing = null;
    if (!preserveTransaction) {
      try { this.storage?.removeItem(LOGIN_TRANSACTION); } catch { /* Nothing is retained in memory. */ }
    }
  }
  async request(path, body) {
    if (!(path === '/v1/auth/config' && body === undefined ||
          ['/v1/auth/exchange','/v1/auth/refresh'].includes(path) && body && typeof body === 'object' && !Array.isArray(body))) throw loginError();
    const session = this.#session;
    let response, reader;
    try {
      response = await this.fetcher(path, {method: body === undefined ? 'GET' : 'POST',
        headers: body === undefined ? {Accept: 'application/json'} : {Accept: 'application/json', 'Content-Type': 'application/json'},
        body: body === undefined ? undefined : JSON.stringify(body), credentials: 'omit', redirect: 'error', cache: 'no-store',
        signal: AbortSignal.any([session.signal, AbortSignal.timeout(15000)])});
      if (session.signal.aborted) throw ended();
      if (!response.ok || !response.body) throw loginError();
      reader = response.body.getReader();
      const chunks = []; let size = 0;
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 65536) throw loginError();
        chunks.push(value);
      }
      if (session.signal.aborted) throw ended();
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      const data = JSON.parse(new TextDecoder().decode(bytes));
      if (!data || Array.isArray(data) || typeof data !== 'object') throw loginError();
      return data;
    } catch {
      if (session.signal.aborted) throw ended();
      throw loginError();
    } finally {
      try { (reader ? reader.cancel() : response?.body?.cancel())?.catch(() => {}); } catch { /* No transport details in UI. */ }
    }
  }
  async configuration(pageOrigin) {
    return loginConfiguration(await this.request('/v1/auth/config'), pageOrigin);
  }
  async begin(config) {
    this.disconnect();
    const revision = this.#revision;
    const random = () => base64url(this.cryptoProvider.getRandomValues(new Uint8Array(32)));
    const verifier = random(), state = random(), nonce = random();
    const challenge = base64url(new Uint8Array(await this.cryptoProvider.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
    if (revision !== this.#revision) throw ended();
    try { this.storage.setItem(LOGIN_TRANSACTION, JSON.stringify({config, verifier, state, nonce, created_at: this.now()})); }
    catch { throw new Error('Sign-in needs temporary storage in this browser tab.'); }
    const url = new URL(config.authorization_url);
    for (const [name, value] of Object.entries({response_type: 'code', client_id: config.client_id,
      redirect_uri: config.redirect_uri, scope: config.scopes.join(' '), state, nonce,
      code_challenge: challenge, code_challenge_method: 'S256'})) url.searchParams.set(name, value);
    return url.href;
  }
  async complete(callbackURL, config) {
    const revision = this.#revision;
    let transaction;
    try {
      const raw = this.storage.getItem(LOGIN_TRANSACTION);
      this.storage.removeItem(LOGIN_TRANSACTION); // Consume before any exchange, including rejected callbacks.
      if (!raw || raw.length > 8192) throw loginError();
      transaction = JSON.parse(raw);
    } catch { throw loginError(); }
    const callback = new URL(callbackURL), expected = new URL(config.redirect_uri), params = callback.searchParams;
    if (callback.origin !== expected.origin || callback.pathname !== expected.pathname || callback.hash ||
        params.has('error') || params.getAll('code').length !== 1 || params.getAll('state').length !== 1 ||
        params.getAll('iss').length > 1 || (params.has('iss') && params.get('iss') !== config.issuer) ||
        typeof params.get('code') !== 'string' || !/^[!-~]{1,2048}$/.test(params.get('code')) ||
        !transaction || JSON.stringify(transaction.config) !== JSON.stringify(config) ||
        !Number.isSafeInteger(transaction.created_at) || this.now() < transaction.created_at || this.now() - transaction.created_at > 600000 ||
        !randomPattern.test(transaction.state) || params.get('state') !== transaction.state ||
        !randomPattern.test(transaction.verifier) || !randomPattern.test(transaction.nonce)) throw loginError();
    const data = await this.request('/v1/auth/exchange', {code: params.get('code'), code_verifier: transaction.verifier, nonce: transaction.nonce});
    if (revision !== this.#revision) throw ended();
    this.#accept(data, transaction.nonce, false);
  }
  #accept(data, nonce, renewal) {
    if (typeof data.access_token !== 'string' || !tokenPattern.test(data.access_token) ||
        !(data.refresh_token === null || typeof data.refresh_token === 'string' && tokenPattern.test(data.refresh_token)) ||
        !Number.isSafeInteger(data.expires_at) || data.expires_at * 1000 <= this.now() + 5000 ||
        typeof data.subject !== 'string' || !data.subject || data.subject.length > 255 ||
        renewal && data.subject !== this.#credentials?.subject) throw loginError();
    this.onToken(data.access_token, renewal);
    this.#credentials = {refresh_token: data.refresh_token, nonce, subject: data.subject, expires_at: data.expires_at};
    this.unschedule(this.#timer);
    const delay = Math.max(1000, data.expires_at * 1000 - this.now() - (data.refresh_token ? 30000 : 0));
    this.#timer = this.schedule(() => { this.ensureFresh(true).catch(() => {}); }, delay);
  }
  async ensureFresh(force = false) {
    if (!this.#credentials) return;
    if (!force && this.#credentials.expires_at * 1000 > this.now() + (this.#credentials.refresh_token ? 30000 : 0)) return;
    if (this.#renewing) return this.#renewing;
    const revision = this.#revision, credentials = this.#credentials;
    this.#renewing = (async () => {
      try {
        if (!credentials.refresh_token) throw loginError();
        const data = await this.request('/v1/auth/refresh', {refresh_token: credentials.refresh_token,
          nonce: credentials.nonce, subject: credentials.subject});
        if (revision !== this.#revision) throw ended();
        this.#accept(data, credentials.nonce, true);
      } catch (error) {
        if (revision !== this.#revision) throw ended();
        this.disconnect(); this.onExpired(); throw loginError();
      } finally { if (revision === this.#revision) this.#renewing = null; }
    })();
    return this.#renewing;
  }
}
