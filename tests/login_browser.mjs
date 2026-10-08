// Full PKCE issuer navigation and renewal against intercepted contracts.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const require = createRequire(process.env.PORTAL_PLAYWRIGHT_ROOT
  ? path.join(process.env.PORTAL_PLAYWRIGHT_ROOT,'package.json') : import.meta.url);
const {chromium} = require('playwright');
const assets = path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../services/api/hosting_api/portal');
const config = {enabled:true,issuer:'https://iam.example.test',client_id:'portal-client',
  authorization_url:'https://iam.example.test/authorize',redirect_uri:'https://portal.example.test/portal',scopes:['openid','offline_access']};
const browser = await chromium.launch({headless:true,...(process.env.PORTAL_CHROMIUM ? {executablePath:process.env.PORTAL_CHROMIUM} : {})});
try {
  const page=await browser.newPage();
  const errors=[], bearerTokens=[];
  let authorization, exchangeCount=0, refreshCount=0, failRefresh=false;
  page.on('pageerror',error=>errors.push(error.message));
  await page.route('https://iam.example.test/**', async route=>{
    const request=route.request();
    authorization=new URL(request.url()).searchParams;
    assert.equal(request.headers().referer,undefined);
    assert.equal(authorization.get('client_id'),'portal-client');
    assert.equal(authorization.get('code_challenge_method'),'S256');
    assert.equal(authorization.get('response_type'),'code');
    const state=authorization.get('state');
    assert.match(state,/^[A-Za-z0-9_-]{43}$/);
    // Playwright 1.55 intercepts only the initial request in an HTTP redirect
    // chain. A hosted-login page performs a new navigation so both fixture
    // origins stay intercepted; the portal still traverses the issuer origin.
    const callback=config.redirect_uri+'?code=private-code&state='+state+'&iss='+encodeURIComponent(config.issuer);
    return route.fulfill({status:200,contentType:'text/html',body:'<!doctype html><title>Issuer fixture</title><script>location.replace('+JSON.stringify(callback)+');</script>'});
  });
  await page.route('https://portal.example.test/**',async route=>{
    const request=route.request(),url=new URL(request.url()),pathname=url.pathname;
    assert.equal(request.headers().cookie,undefined);
    if(pathname.startsWith('/portal')) {
      const filename={'/portal':'index.html','/portal/portal.mjs':'portal.mjs','/portal/login.mjs':'login.mjs','/portal/portal.css':'portal.css'}[pathname];
      assert.ok(filename);
      return route.fulfill({status:200,body:await readFile(path.join(assets,filename)),headers:{
        'Content-Type':filename.endsWith('.html')?'text/html':filename.endsWith('.css')?'text/css':'text/javascript',
        'Referrer-Policy':'no-referrer','Cache-Control':'no-store',
        'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"}});
    }
    if(pathname.startsWith('/v1/auth/')) {
      assert.equal(request.headers().authorization,undefined);
      if(pathname==='/v1/auth/config') return route.fulfill({status:200,json:config});
      const body=request.postDataJSON();
      if(pathname==='/v1/auth/exchange') {
        exchangeCount++;
        assert.equal(body.code,'private-code');
        assert.equal(body.nonce,authorization.get('nonce'));
        assert.equal(createHash('sha256').update(body.code_verifier).digest('base64url'),authorization.get('code_challenge'));
        return route.fulfill({status:200,json:{access_token:'initial-private-access',refresh_token:'initial-private-refresh',
          expires_at:Math.floor(Date.now()/1000)+32,subject:'human-1'}});
      }
      assert.equal(pathname,'/v1/auth/refresh'); refreshCount++;
      assert.equal(body.subject,'human-1'); assert.equal(body.nonce,authorization.get('nonce'));
      assert.equal(body.refresh_token,refreshCount===1?'initial-private-refresh':'rotated-private-refresh');
      if(failRefresh) return route.fulfill({status:401,json:{error:'login_rejected'}});
      return route.fulfill({status:200,json:{access_token:'renewed-private-access',refresh_token:'rotated-private-refresh',
        expires_at:Math.floor(Date.now()/1000)+3600,subject:'human-1'}});
    }
    assert.equal(pathname,'/v1/organizations');
    bearerTokens.push(request.headers().authorization);
    return route.fulfill({status:200,json:{organizations:[]}});
  });
  await page.goto(config.redirect_uri);
  await page.locator('#sign-in').waitFor({state:'visible'});
  await page.locator('#sign-in').click();
  try { await page.locator('#workspace').waitFor({state:'visible'}); }
  catch (error) {
    const url = new URL(page.url());
    console.error(JSON.stringify({page:url.origin+url.pathname,message:await page.locator('#message').textContent({timeout:1000}).catch(()=>null),errors}));
    throw error;
  }
  assert.equal(exchangeCount,1);
  assert.equal(page.url(),config.redirect_uri);
  assert.deepEqual(await page.evaluate(()=>({session:Object.keys(sessionStorage),local:Object.keys(localStorage)})),{session:[],local:[]});
  await page.waitForFunction(()=>document.querySelector('#workspace').hidden===false);
  for(let attempt=0;attempt<40 && refreshCount===0;attempt++) await page.waitForTimeout(100);
  assert.equal(refreshCount,1);
  await page.locator('#refresh').click();
  await page.waitForFunction(()=>document.querySelector('#message').textContent==='Readback updated.');
  assert.equal(bearerTokens.at(-1),'Bearer renewed-private-access');
  for(const privateValue of ['initial-private-access','initial-private-refresh','renewed-private-access','rotated-private-refresh','private-code']) {
    assert.ok(!(await page.locator('body').textContent()).includes(privateValue));
  }
  failRefresh=true;
  await page.evaluate(()=>{const now=Date.now();Date.now=()=>now+3600000;});
  await page.locator('#refresh').click();
  await page.locator('#connect-panel').waitFor({state:'visible'});
  assert.match(await page.locator('#message').textContent(),/session ended/);
  assert.equal(refreshCount,2);
  await page.goto(config.redirect_uri+'?code=forged-code&state=forged-state');
  await page.waitForFunction(()=>document.querySelector('#message').textContent.includes('Sign-in could not'));
  assert.equal(exchangeCount,1); assert.equal(page.url(),config.redirect_uri);
  assert.equal(await page.locator('#workspace').isVisible(),false);
  assert.deepEqual(errors,[]);
  console.log('Issuer login browser: PASS (PKCE redirect, callback clearing, in-memory renewal, rotated credentials, failed renewal and forged callback)');
} finally { await browser.close(); }
