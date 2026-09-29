import { readdir, readFile } from "node:fs/promises";

/**
 * The web app shell used to live in apps/web/app/page.tsx. It is now split into
 * apps/web/components/app/shell/*.tsx; static checks read all of it as one source.
 */
export async function readAppShell() {
  const dir = "apps/web/components/app/shell";
  const files = (await readdir(dir)).filter((name) => name.endsWith(".tsx")).sort();
  const parts = [await readFile("apps/web/app/page.tsx", "utf8")];
  for (const name of files) parts.push(await readFile(`${dir}/${name}`, "utf8"));
  return parts.join("\n");
}
