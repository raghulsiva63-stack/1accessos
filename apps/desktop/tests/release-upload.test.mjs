import assert from 'node:assert/strict';
import test from 'node:test';
import { handleReleaseUpload, sha256, BUCKET } from '../../../supabase/functions/publish-desktop-release/handler.ts';

const bytes = new TextEncoder().encode('synthetic installer');
const token = 'a'.repeat(64);
const filename = 'passkey-x-desktop-0.2.0-windows-x64.exe';
const config = { token_sha256: await sha256(new TextEncoder().encode(token)), expires_at: Date.now() + 60000, files: [{filename, sha256: await sha256(bytes), bytes: bytes.length, objectPath: 'desktop/0.2.0/' + filename}] };
function harness() {
  const calls = [];
  const storage = {
    async getBucket(id) { calls.push(['bucket', id]); return {data:{public:true},error:null}; },
    async createBucket() { throw new Error('Unexpected create'); },
    from(id) { return { async upload(path, body, options) { calls.push(['upload', id, path, Array.from(body), options]); return {error:null}; } }; },
  };
  const request = ({file=filename, secret=token, data=bytes, length=data.length}={}) => new Request('https://release.example.test?file='+encodeURIComponent(file), {method:'POST',headers:{'x-release-token':secret,'content-length':String(length)},body:data});
  return {calls,storage,request};
}
test('release uploader requires a live scoped token before touching storage',async()=>{
  const h=harness();
  assert.equal((await handleReleaseUpload(h.request(),{...config,expires_at:0},h.storage)).status,410);
  assert.equal((await handleReleaseUpload(h.request({secret:'b'.repeat(64)}),config,h.storage)).status,401);
  assert.equal(h.calls.length,0);
});
test('only the exact reviewed filename, size and installer bytes can be published',async()=>{
  const h=harness();
  for(const options of [{file:'../../vault.json'},{length:1},{data:new Uint8Array(bytes.length)}]) assert.equal((await handleReleaseUpload(h.request(options),config,h.storage)).status,400);
  assert.equal(h.calls.length,0);
  assert.equal((await handleReleaseUpload(h.request(),config,h.storage)).status,201);
  const upload=h.calls.find(c=>c[0]==='upload'); assert.equal(upload[1],BUCKET); assert.deepEqual(upload[3],Array.from(bytes)); assert.equal(upload[4].upsert,false);
});
