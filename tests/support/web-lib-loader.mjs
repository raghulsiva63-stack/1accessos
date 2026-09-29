// Lets Node's test runner import apps/web/lib TypeScript modules the way Next.js resolves them:
// extensionless relative imports ("./domains") and the "@/..." alias. Type-only imports are
// removed by Node's type stripping, so only runtime imports reach this hook.
import { existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

const webRoot = new URL("../../apps/web/", import.meta.url);

export async function resolve(specifier, context, next) {
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
