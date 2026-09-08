import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import ts from 'typescript';
import * as boundary from '../src/message-boundary.ts';
import { sessionStorageAdapter } from '../src/session-storage.ts';

const source = (await readFile(new URL('../src/background.ts', import.meta.url), 'utf8'))
  .replaceAll('import.meta.env.VITE_SUPABASE_URL', JSON.stringify('https://wkkmyacbhqloubtwvjom.supabase.co'))
  .replaceAll('import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY', JSON.stringify('sb_publishable_synthetic'));
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
const id = 'egkaneajfcaomheahcmopioiemmplebg';
const storageKey = 'passkeyXSession';
function harness({ initial = {}, signOutFails = false, rejectUser = false, requireMfa = false, sessionMismatch = false } = {}) {
  const values = structuredClone(initial), events = {}, calls = [];
  let current = null, options;
  const sessionArea = { async get(key) { return { [key]:values[key] }; }, async set(record) { Object.assign(values,record); }, async remove(key) { delete values[key]; } };
  const add = name => ({ addListener(callback) { events[name] = callback; } });
  const auth = {
    mfa: { async getAuthenticatorAssuranceLevel() { return { data: { currentLevel: 'aal1', nextLevel: requireMfa ? 'aal2' : 'aal1' }, error: null }; } },
    async getSession() { return { data:{session:current ?? JSON.parse(values[storageKey] ?? 'null')},error:null }; },
    async getUser(token) { calls.push(['getUser',token]); return {data:{user:rejectUser ? null : {id:'synthetic-user',email:'test@example.invalid'}},error:rejectUser ? new Error('Invalid token') : null}; },
    async setSession(tokens) { current = {...tokens,user:{id:sessionMismatch ? 'another-user' : 'synthetic-user',email:'test@example.invalid'}}; await options.auth.storage.setItem(storageKey,JSON.stringify(current)); return {data:{session:current,user:current.user},error:null}; },
    async signOut(arg) { calls.push(['signOut',arg.scope]); if(signOutFails) return {error:new Error('Offline')}; current=null; await options.auth.storage.removeItem(storageKey); events.auth?.('SIGNED_OUT',null); return {error:null}; },
    onAuthStateChange(callback) { events.auth=callback; },
  };
  const chrome = {
    runtime:{id,getURL:path=>'chrome-extension://'+id+'/'+path,onMessage:add('message'),onMessageExternal:add('external'),onSuspend:add('suspend')},
    storage:{session:sessionArea,local:{ async get(){return {};},async set(){throw new Error('Unexpected persistent write');} }},
    tabs:{async create({url}){calls.push(['tab',url]);return{id:7};},onRemoved:add('removed'),onUpdated:add('updated')},
    commands:{onCommand:add('command')},
  };
  vm.runInNewContext(compiled,{exports:{},require:name=>{
    if(name==='./message-boundary')return boundary;
    if(name==='./session-storage')return {sessionStorageAdapter};
    if(name==='@supabase/supabase-js')return {createClient:(_url,_key,config)=>{options=config;return{auth};}};
    if(name==='hash-wasm')return {};
    throw new Error('Unexpected import '+name);
  },chrome,crypto:webcrypto,TextEncoder,TextDecoder,URL,Uint8Array,Map,Set,Date,Error,Number,String,Boolean,JSON,clearTimeout,setTimeout:(callback,ms)=>{const timer=setTimeout(callback,ms);timer.unref();return timer;}});
  const send = (name,message,sender) => new Promise(resolve=>events[name](message,sender,resolve));
  return {values,calls,options,events,send,command:message=>send('message',message,{id,url:'chrome-extension://'+id+'/popup.html'})};
}
async function pair(h) {
  assert.equal((await h.command({type:'PX_CONNECT'})).ok,true);
  const pending=h.values.passkeyXPendingPairing;
  const payload={type:'PX_PAIR_SESSION',extensionId:id,nonce:pending.nonce,accessToken:'synthetic-access',refreshToken:'synthetic-refresh'};
  const sender={url:'https://passkey-x.com/extension/connect?extension_id='+id,frameId:0,tab:{id:7}};
  return {payload,sender,result:await h.send('external',payload,sender)};
}

test('session adapter writes only to the supplied browser-session area',async()=>{
  const values={},area={async get(k){return{[k]:values[k]};},async set(v){Object.assign(values,v);},async remove(k){delete values[k];}};
  const adapter=sessionStorageAdapter(area);
  assert.equal(await adapter.getItem('session'),null);
  await adapter.setItem('session','synthetic-token');assert.equal(await adapter.getItem('session'),'synthetic-token');
  await adapter.removeItem('session');assert.equal(await adapter.getItem('session'),null);
});
test('pairing consumes the request once, verifies the user, and rejects replay',async()=>{
  const h=harness();const {payload,sender,result}=await pair(h);
  assert.equal(result.ok,true);assert.equal(h.values.passkeyXPendingPairing,undefined);
  assert.equal(h.calls.filter(c=>c[0]==='getUser').length,1);
  assert.equal((await h.send('external',payload,sender)).ok,false);
  assert.equal(h.calls.filter(c=>c[0]==='getUser').length,1);
  assert.equal((await h.command({type:'PX_STATUS'})).connected,true);
  const url=new URL(h.calls.find(c=>c[0]==='tab')[1]);assert.equal(url.searchParams.has('accessToken'),false);assert.equal(url.hash.length,65);
});
test('untrusted or invalid sessions are never persisted',async()=>{
  const h=harness({rejectUser:true});assert.equal((await pair(h)).result.ok,false);assert.equal(h.values[storageKey],undefined);
  const fresh=harness();assert.equal((await fresh.send('external',{type:'PX_PAIR_SESSION'},{url:'https://evil.invalid'})).ok,false);assert.equal(fresh.values[storageKey],undefined);
});
test('lock and worker restart preserve the account but never an unlocked vault',async()=>{
  const h=harness();await pair(h);assert.equal((await h.command({type:'PX_LOCK'})).connected,true);
  h.events.suspend();const restarted=harness({initial:h.values});const status=await restarted.command({type:'PX_STATUS'});
  assert.equal(status.connected,true);assert.equal(status.unlocked,false);
  assert.equal((await harness().command({type:'PX_STATUS'})).connected,false);
});
test('disconnect revokes only this session and local removal remains effective offline',async()=>{
  for(const signOutFails of [false,true]) {
    const h=harness({signOutFails});await pair(h);await h.command({type:'PX_DISCONNECT'});
    assert.equal(h.values[storageKey],undefined);assert.equal((await h.command({type:'PX_STATUS'})).connected,false);
    assert.equal(h.calls.find(c=>c[0]==='signOut')[1],'local');
  }
});
test('locked extension ignores login candidates',async()=>{
  const h=harness();await pair(h);
  const result=await h.send('message',{type:'PX_CANDIDATE',origin:'https://example.invalid',url:'https://example.invalid/login',username:'synthetic',secret:'synthetic'}, {id,url:'https://example.invalid/login',frameId:0,tab:{id:9,url:'https://example.invalid/login'}});
  assert.equal(result.ignored,true);
});

test('pairing rejects incomplete MFA and removes an inconsistent accepted session',async()=>{
  for (const options of [{requireMfa:true},{sessionMismatch:true}]) {
    const h=harness(options); assert.equal((await pair(h)).result.ok,false);
    assert.equal(h.values[storageKey],undefined);
    assert.equal((await h.command({type:'PX_STATUS'})).connected,false);
  }
});
