// Lets Node's test runner import apps/web/lib TypeScript modules the way Next.js resolves them:
// extensionless relative imports ("./domains") and the "@/..." alias. Type-only imports are
// removed by Node's type stripping, so only runtime imports reach this hook.
import { existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

const webRoot = new URL("../../apps/web/", import.meta.url);

// The Supabase browser client needs node_modules; tests get a stub whose client they can set
// with globalThis.__pxSupabase.
const SUPABASE_STUB = "data:text/javascript," + encodeURIComponent(
  "export const supabase = new Proxy({}, { get: (_t, key) => globalThis.__pxSupabase?.[key] }); export const passkeysEnabled = false; export const phoneMfaEnabled = false;");

export async function resolve(specifier, context, next) {
  if (specifier === "@/lib/supabase/client") return { url: SUPABASE_STUB, shortCircuit: true };
  if (specifier === "hash-wasm") return { url: "data:text/javascript," + encodeURIComponent("export async function argon2id() { throw new Error('argon2id is not available in tests'); }"), shortCircuit: true };
  let candidate = null;
  if (specifier.startsWith("@/")) candidate = new URL(specifier.slice(2), webRoot);
  else if ((specifier.startsWith("./") || specifier.startsWith("../")) && context.parentURL?.includes("/apps/web/")) candidate = new URL(specifier, context.parentURL);
  if (candidate && !/\.[cm]?[jt]sx?$/u.test(candidate.pathname)) {
    for (const extension of [".ts", ".tsx", "/index.ts"]) {
      const path = fileURLToPath(candidate) + extension;
      if (existsSync(path)) return next(pathToFileURL(path).href, context);
    }
  }
  return next(specifier, context);
}
