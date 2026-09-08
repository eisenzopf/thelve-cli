// Disposable qualification only: completes the test admin's required password
// change through Keycloak's admin API, then uses the real browser SDK for PKCE,
// DPoP token exchange, ID-token verification, and an authenticated API request.
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
const [directory, source, email] = process.argv.slice(2);
const receipt = JSON.parse(await readFile(`${directory}/launch-receipt.json`, 'utf8'));
assert(receipt.name.endsWith('-verification'), 'Use only a disposable *-verification appliance');
const origin = receipt.app_url;
const base = `${origin}/sso`;
const password = await readFile(`${directory}/initial-admin-password`, 'utf8');
const bootstrap = await readFile(`${directory}/secrets/keycloak-bootstrap-admin-password`, 'utf8');
async function checked(url, init) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(30000) });
  assert(response.ok, `HTTP ${response.status} at ${new URL(url).pathname}`);
  return response;
}
const token = await (await checked(`${base}/realms/master/protocol/openid-connect/token`, {
  method: 'POST', body: new URLSearchParams({grant_type:'password',client_id:'admin-cli',username:'thelve-bootstrap',password:bootstrap}),
})).json();
const headers = {authorization:`Bearer ${token.access_token}`,'content-type':'application/json'};
const users = await (await checked(`${base}/admin/realms/thelve/users?exact=true&username=${encodeURIComponent(email)}`, {headers})).json();
assert.equal(users.length, 1);
await checked(`${base}/admin/realms/thelve/users/${users[0].id}`, {method:'PUT',headers,body:JSON.stringify({...users[0],firstName:'CLI',lastName:'Verification',requiredActions:[]})});
await checked(`${base}/admin/realms/thelve/users/${users[0].id}/reset-password`, {method:'PUT',headers,body:JSON.stringify({type:'password',value:password,temporary:false})});
const {BrowserOidcClient,WebCryptoDpopKey,ThelveClient} = await import(pathToFileURL(`${source}/packages/sdk/dist/index.js`));
const key = await WebCryptoDpopKey.generate();
const oidc = new BrowserOidcClient();
const transaction = await oidc.prepare({issuer:`${base}/realms/thelve`,clientId:'thelve-desk',redirectUri:`${origin}/auth/callback`,scopes:['openid','profile','email']},key);
const cookies = new Map();
async function page(url, init={}) {
  assert.equal(new URL(url).origin, origin);
  const result = await fetch(url,{...init,redirect:'manual',headers:{...init.headers,cookie:[...cookies].map(([k,v])=>`${k}=${v}`).join('; ')},signal:AbortSignal.timeout(30000)});
  for(const cookie of result.headers.getSetCookie()) {const part=cookie.split(';')[0]; const at=part.indexOf('=');cookies.set(part.slice(0,at),part.slice(at+1));}
  return result;
}
let response = await page(transaction.authorizationUrl);
const html = await response.text();
const action = html.match(/<form[^>]*\baction="([^"]+)"/i)?.[1].replaceAll('&amp;','&');
assert(action,'Login form missing');
response = await page(action,{method:'POST',body:new URLSearchParams({username:email,password,credentialId:''})});
const callback = response.headers.get('location');
assert(callback?.startsWith(`${origin}/auth/callback`), `Expected callback after sign-in, got HTTP ${response.status}`);
const credential = await oidc.complete(callback,transaction,key);
assert.equal(credential.tokenType,'DPoP');
const configuration = await (await checked(`${origin}/api/runtime-config`)).json();
const client = new ThelveClient({baseUrl:configuration.apiBaseUrl,accessToken:()=>credential.accessToken,dpopProof:key.createProof});
await client.request('/api/v1/crm/contacts?limit=1');
const workspace = await client.request('/api/v1/workspace/bootstrap');
assert.equal(workspace.actor.name, 'CLI Verification', 'Sign-in profile did not reach the workspace actor');
assert(workspace.capabilities.includes('tenancy.actors.list'), 'Initial administrator cannot access account administration');
console.log('PASS: real browser SDK PKCE/DPoP login, ID-token verification, and authenticated contacts API');

// Exercise the exact application-initiated action used by the desk's account menu.
const actionKey = await WebCryptoDpopKey.generate();
const actionTransaction = await oidc.prepare({issuer:`${base}/realms/thelve`,clientId:'thelve-desk',redirectUri:`${origin}/auth/callback`,scopes:['openid','profile','email']}, actionKey);
const passwordUrl = new URL(actionTransaction.authorizationUrl);
passwordUrl.searchParams.set('kc_action','UPDATE_PASSWORD');
response = await page(passwordUrl.toString());
for (let hop = 0; hop < 5 && response.status === 302; hop++) {
  response = await page(new URL(response.headers.get('location'), origin).toString());
}
const passwordPage = await response.text();
assert(passwordPage.includes('Choose your Thelve password'), 'Branded account password action missing');
assert(passwordPage.includes('/thelve/css/thelve.css'), 'Account action lost Thelve theme');
const passwordAction = passwordPage.match(/<form[^>]*\baction="([^"]+)"/i)?.[1].replaceAll('&amp;','&');
assert(passwordAction, 'Password update form missing');
const newPassword = `Thelve!${crypto.randomUUID()}a7`;
response = await page(passwordAction,{method:'POST',body:new URLSearchParams({'password-new':newPassword,'password-confirm':newPassword})});
const passwordCallback = response.headers.get('location');
assert(passwordCallback?.startsWith(`${origin}/auth/callback`), `Password change did not return to Thelve: ${response.status}`);
const refreshed = await oidc.complete(passwordCallback, actionTransaction, actionKey);
const refreshedClient = new ThelveClient({baseUrl:configuration.apiBaseUrl,accessToken:()=>refreshed.accessToken,dpopProof:actionKey.createProof});
await refreshedClient.request('/api/v1/crm/contacts?limit=1');
console.log('PASS: Thelve password screen, real password update, secure callback, and continued API access');
