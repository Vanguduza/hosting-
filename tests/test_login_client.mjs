import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {IssuerLogin, LOGIN_TRANSACTION, loginConfiguration} from '../services/api/hosting_api/portal/login.mjs';

const config = {issuer: 'https://iam.example.test', client_id: 'portal-client', authorization_url: 'https://iam.example.test/authorize',
  redirect_uri: 'https://portal.example.test/portal', scopes: ['openid','offline_access']};
const json = (data, status = 200) => new Response(JSON.stringify(data), {status, headers: {'Content-Type':'application/json'}});
const storage = () => {
  const values = new Map();
  return {getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key,value), removeItem: key => values.delete(key), values};
};
function fixture(fetcher, overrides = {}) {
  let now = Date.now();
  const tab = storage(), timers = [], tokens = [], expired = [];
  const login = new IssuerLogin({fetcher, storage:tab, cryptoProvider:webcrypto, now:()=>now,
    schedule:(callback,delay) => { const item = {callback,delay}; timers.push(item); return item; }, unschedule:()=>{},
    onToken:(token,renewal)=>tokens.push({token,renewal}), onExpired:()=>expired.push(true), ...overrides});
  return {login,tab,timers,tokens,expired,advance:ms=>{now+=ms;},receipt:patch=>({access_token:'private-access',refresh_token:'private-refresh',expires_at:Math.floor(now/1000)+120,subject:'human-1',...patch})};
}
const callback = state => config.redirect_uri + '?code=private-code&state=' + state + '&iss=' + encodeURIComponent(config.issuer);

test('login configuration binds HTTPS issuer, callback origin and exact public client', () => {
  assert.deepEqual(loginConfiguration({enabled:true,...config}, 'https://portal.example.test'), config);
  assert.equal(loginConfiguration({enabled:false}, 'https://portal.example.test'), null);
  for (const change of [{authorization_url:'https://other.example.test/authorize'}, {redirect_uri:'https://attacker.example.test/portal'},
    {redirect_uri:config.redirect_uri+'?target=bad'}, {issuer:'http://iam.example.test'}, {scopes:['profile']}, {client_id:'client\n'}]) {
    assert.throws(()=>loginConfiguration({enabled:true,...config,...change}, 'https://portal.example.test'));
  }
});

test('PKCE persists only a short-lived tab transaction and survives issuer navigation', async () => {
  const calls = [];
  const f = fixture(async(path,options)=>{calls.push({path,options});return json(f.receipt());});
  const url = new URL(await f.login.begin(config)), transaction = JSON.parse(f.tab.getItem(LOGIN_TRANSACTION));
  assert.equal(url.origin, 'https://iam.example.test');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  const challenge = Buffer.from(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(transaction.verifier))).toString('base64url');
  assert.equal(url.searchParams.get('code_challenge'), challenge);
  assert.notEqual(transaction.state, transaction.nonce);
  assert.equal(url.searchParams.get('nonce'), transaction.nonce);
  assert.equal(url.searchParams.get('redirect_uri'), config.redirect_uri);
  f.login.disconnect({preserveTransaction:true});
  await f.login.complete(callback(transaction.state), config);
  assert.equal(f.tab.values.size,0);
  assert.deepEqual(f.tokens,[{token:'private-access',renewal:false}]);
  assert.equal(calls[0].path,'/v1/auth/exchange');
  assert.deepEqual(JSON.parse(calls[0].options.body),{code:'private-code',code_verifier:transaction.verifier,nonce:transaction.nonce});
  assert.equal(calls[0].options.credentials,'omit'); assert.equal(calls[0].options.redirect,'error');
  assert.equal(calls[0].options.headers.Authorization,undefined);
  assert.ok(f.timers[0].delay>=88000 && f.timers[0].delay<=90000);
  f.login.disconnect();
});

test('state, issuer, callback duplication, expiry and replay fail before exchange', async () => {
  let calls = 0;
  const f = fixture(async()=>{calls++; return json(f.receipt());});
  const variants = [state=>callback('wrong-state'),state=>callback(state)+'&state='+state,
    state=>callback(state).replace(encodeURIComponent(config.issuer),encodeURIComponent('https://attacker.example.test')),
    state=>callback(state)+'#access_token=private-implicit',state=>callback(state)+'&error=access_denied'];
  for (const make of variants) {
    const state = new URL(await f.login.begin(config)).searchParams.get('state');
    await assert.rejects(()=>f.login.complete(make(state),config));
    assert.equal(f.tab.values.size,0);
  }
  const state = new URL(await f.login.begin(config)).searchParams.get('state');
  f.advance(600001);
  await assert.rejects(()=>f.login.complete(callback(state),config));
  assert.equal(calls,0);
  const fresh = new URL(await f.login.begin(config)).searchParams.get('state');
  await f.login.complete(callback(fresh),config);
  await assert.rejects(()=>f.login.complete(callback(fresh),config));
  assert.equal(calls,1);
});

test('changed public configuration invalidates a pending login transaction', async () => {
  const f = fixture(async()=>{throw new Error('must not contact issuer');});
  const state = new URL(await f.login.begin(config)).searchParams.get('state');
  await assert.rejects(()=>f.login.complete(callback(state),{...config,client_id:'replacement-client'}));
  assert.equal(f.tab.values.size,0);
});

test('refreshes serialize, rotate in memory and cannot switch identity', async () => {
  const bodies = [];
  const f = fixture(async(path,options)=>{
    if(path==='/v1/auth/exchange') return json(f.receipt());
    bodies.push(JSON.parse(options.body));
    return json(f.receipt({access_token:'renewed-access',refresh_token:'rotated-refresh'}));
  });
  const state = new URL(await f.login.begin(config)).searchParams.get('state');
  await f.login.complete(callback(state),config);
  await Promise.all([f.login.ensureFresh(true),f.login.ensureFresh(true),f.login.ensureFresh(true)]);
  assert.equal(bodies.length,1);
  assert.equal(bodies[0].refresh_token,'private-refresh');
  await f.login.ensureFresh(true);
  assert.equal(bodies[1].refresh_token,'rotated-refresh');
  assert.equal(f.tab.values.size,0);
  assert.deepEqual(f.tokens.at(-1),{token:'renewed-access',renewal:true});
  f.login.fetcher=async()=>json(f.receipt({subject:'other-human'}));
  await assert.rejects(()=>f.login.ensureFresh(true));
  assert.equal(f.expired.length,1);
  assert.equal(f.tokens.length,3);
});

test('late code and refresh replies cannot reconnect after disconnect', async () => {
  let resolve;
  const f = fixture(()=>new Promise(done=>{resolve=done;}));
  const state = new URL(await f.login.begin(config)).searchParams.get('state');
  const pending = f.login.complete(callback(state),config);
  f.login.disconnect(); resolve(json(f.receipt()));
  await assert.rejects(pending,{name:'AbortError'});
  assert.equal(f.tokens.length,0); assert.equal(f.tab.values.size,0);
  f.login.fetcher=async()=>json(f.receipt());
  const newState = new URL(await f.login.begin(config)).searchParams.get('state');
  await f.login.complete(callback(newState),config);
  f.login.fetcher=()=>new Promise(done=>{resolve=done;});
  const refreshing = f.login.ensureFresh(true);
  f.login.disconnect(); resolve(json(f.receipt()));
  await assert.rejects(refreshing,{name:'AbortError'});
  assert.equal(f.tokens.length,1); assert.equal(f.expired.length,0);
});

test('expiry without refresh clears credentials and renewal failures hide diagnostics', async () => {
  const f = fixture(async()=>json(f.receipt({refresh_token:null})));
  const state = new URL(await f.login.begin(config)).searchParams.get('state');
  await f.login.complete(callback(state),config);
  f.advance(100000); await f.login.ensureFresh();
  assert.equal(f.expired.length,0);
  f.advance(21000); await assert.rejects(()=>f.login.ensureFresh());
  assert.equal(f.expired.length,1);
  const g=fixture(async()=>{throw new Error('private diagnostic refresh=secret');});
  const otherState=new URL(await g.login.begin(config)).searchParams.get('state');
  await assert.rejects(()=>g.login.complete(callback(otherState),config),error=>!error.message.includes('private diagnostic'));
});

test('login response bodies are bounded and private transaction storage must work', async () => {
  const f=fixture(async()=>new Response('x'.repeat(65537)));
  await assert.rejects(()=>f.login.configuration('https://portal.example.test'));
  await assert.rejects(()=>f.login.request('https://attacker.example.test/steal',{refresh_token:'private-refresh'}));
  const g=fixture(async()=>json({enabled:false}),{storage:{removeItem(){},setItem(){throw new Error('private storage detail');}}});
  await assert.rejects(()=>g.login.begin(config),error=>error.message.includes('temporary storage') && !error.message.includes('private storage detail'));
});
