export type ReleaseConfig = { token_sha256: string; expires_at: number; files: { filename: string; sha256: string; bytes: number; objectPath: string }[] };
export const BUCKET = "passkey-x-client-releases";
type Storage = {
  getBucket(id: string): Promise<{ data: { public: boolean } | null; error: unknown }>;
  createBucket(id: string, options: { public: boolean; fileSizeLimit: number; allowedMimeTypes: string[] }): Promise<{ error: unknown }>;
  from(id: string): { upload(path: string, body: Uint8Array, options: { upsert: boolean; contentType: string; cacheControl: string }): Promise<{ error: unknown }> };
};
export async function sha256(bytes: BufferSource) {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), byte => byte.toString(16).padStart(2, "0")).join("");
}
const response = (status: number, message: string) => new Response(JSON.stringify({ message }), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });

/** Deployment-time upload capability. The checked-in configuration is closed.
 * An enabled deployment accepts only a short-lived token and pre-reviewed hashes.
 * It cannot change existing objects, publish arbitrary bytes or access vault data. */
export async function handleReleaseUpload(request: Request, config: ReleaseConfig, storage: Storage): Promise<Response> {
  if (!/^[a-f0-9]{64}$/.test(config.token_sha256) || config.expires_at <= Date.now()) return response(410, "Release publishing is closed.");
  if (request.method !== "POST") return response(405, "POST required.");
  const token = request.headers.get("x-release-token") ?? "";
  if (!/^[a-f0-9]{64}$/.test(token)) return response(401, "Release authorization required.");
  const actualTokenHash = await sha256(new TextEncoder().encode(token));
  let difference = 0;
  for (let i = 0; i < 64; i++) difference |= actualTokenHash.charCodeAt(i) ^ config.token_sha256.charCodeAt(i);
  if (difference) return response(401, "Release authorization required.");
  const filename = new URL(request.url).searchParams.get("file");
  const file = config.files.find(entry => entry.filename === filename);
  if (!file || !/^passkey-x-desktop-[0-9.]+-(windows-x64\.exe|macos-universal\.dmg|linux-x64\.deb)(\.sha256)?$/.test(file.filename)
    || !/^desktop\/[0-9.]+\/passkey-x-desktop-[a-zA-Z0-9.-]+$/.test(file.objectPath)
    || !Number.isSafeInteger(file.bytes) || file.bytes <= 0 || file.bytes > 50_000_000 || !/^[a-f0-9]{64}$/.test(file.sha256)) return response(400, "Unknown release file.");
  if (Number(request.headers.get("content-length")) !== file.bytes || !request.body) return response(400, "Unexpected release size.");
  const body = new Uint8Array(file.bytes);
  const reader = request.body.getReader();
  let offset = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      if (offset + chunk.value.byteLength > body.length) { await reader.cancel(); return response(413, "Release is too large."); }
      body.set(chunk.value, offset); offset += chunk.value.byteLength;
    }
    if (offset !== file.bytes || await sha256(body) !== file.sha256) return response(400, "Release checksum mismatch.");
    const bucket = await storage.getBucket(BUCKET);
    if (bucket.data && !bucket.data.public) return response(409, "Release bucket configuration differs.");
    if (!bucket.data) {
      const created = await storage.createBucket(BUCKET, { public: true, fileSizeLimit: 50_000_000, allowedMimeTypes: ["application/octet-stream"] });
      if (created.error) return response(503, "Unable to prepare release storage.");
    }
    const uploaded = await storage.from(BUCKET).upload(file.objectPath, body, { upsert: false, contentType: "application/octet-stream", cacheControl: "31536000" });
    return uploaded.error ? response(409, "File exists or upload was rejected.") : response(201, "Verified release published.");
  } catch { return response(503, "Release upload failed."); }
  finally { body.fill(0); }
}
