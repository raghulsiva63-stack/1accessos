#!/usr/bin/env node

import path from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_API_URL = "https://egqgzkirazabocqwdlfp.supabase.co/functions/v1/v1";
const COMMANDS = new Set(["health", "item-types", "workspaces", "members", "items", "sync", "missions", "requests", "grants"]);

export function parseArguments(argv) {
  const [command = "help", ...rest] = argv;
  const options = {};
  for (let index = 0; index < rest.length; index += 1) {
    const value = rest[index];
    if (!value.startsWith("--")) throw new Error(`Unexpected argument: ${value}`);
    const name = value.slice(2);
    const next = rest[index + 1];
    if (!next || next.startsWith("--")) throw new Error(`Missing value for --${name}`);
    options[name] = next;
    index += 1;
  }
  return { command, options };
}

export function commandPath(command, options = {}) {
  const workspace = options.workspace;
  if (["members", "items", "sync", "missions", "requests", "grants"].includes(command) && !workspace) {
    throw new Error(`--workspace is required for ${command}`);
  }
  const encoded = workspace ? encodeURIComponent(workspace) : "";
  if (command === "health") return "/health";
  if (command === "item-types") return "/item-types";
  if (command === "workspaces") return "/workspaces";
  if (command === "members") return `/workspaces/${encoded}/members`;
  if (command === "items") return `/vault-items?workspace_id=${encoded}`;
  if (command === "sync") return `/sync/changes?workspace_id=${encoded}&cursor=${encodeURIComponent(options.cursor ?? "0")}`;
  if (command === "missions") return `/missions?workspace_id=${encoded}`;
  if (command === "requests") return `/access-requests?workspace_id=${encoded}`;
  if (command === "grants") return `/access-grants?workspace_id=${encoded}`;
  throw new Error(`Unknown command: ${command}`);
}

export function usage() {
  return `Passkey-X ciphertext-only CLI

Usage:
  passkey-x health
  passkey-x item-types
  passkey-x workspaces
  passkey-x members --workspace <uuid>
  passkey-x items --workspace <uuid>
  passkey-x sync --workspace <uuid> [--cursor <sequence>]
  passkey-x missions --workspace <uuid>
  passkey-x requests --workspace <uuid>
  passkey-x grants --workspace <uuid>

Environment:
  PASSKEY_X_API_URL       API base URL (development default is built in)
  PASSKEY_X_ACCESS_TOKEN  Short-lived user access token; never pass it as an argument

The CLI returns authorization metadata and encrypted envelopes only. It never accepts
or prints a vault password, recovery key, item plaintext, or service-role key.`;
}

export async function run(argv, environment = process.env, fetcher = fetch) {
  const { command, options } = parseArguments(argv);
  if (command === "help" || command === "--help" || command === "-h") return { exitCode: 0, output: usage() };
  if (!COMMANDS.has(command)) throw new Error(`Unknown command: ${command}\n\n${usage()}`);
  const token = environment.PASSKEY_X_ACCESS_TOKEN;
  if (command !== "health" && !token) throw new Error("PASSKEY_X_ACCESS_TOKEN is required for authenticated commands.");
  const baseUrl = (environment.PASSKEY_X_API_URL || DEFAULT_API_URL).replace(/\/$/u, "");
  const result = await fetcher(`${baseUrl}${commandPath(command, options)}`, {
    headers: {
      accept: "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
  });
  const payload = await result.json().catch(() => ({ error: { code: "invalid_response", message: "The API did not return JSON." } }));
  if (!result.ok) {
    const detail = payload?.error?.message ?? `API request failed with ${result.status}`;
    throw new Error(detail);
  }
  return { exitCode: 0, output: JSON.stringify(payload, null, 2) };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  run(process.argv.slice(2)).then(({ exitCode, output }) => {
    process.stdout.write(`${output}\n`);
    process.exitCode = exitCode;
  }).catch((error) => {
    process.stderr.write(`Passkey-X CLI: ${error instanceof Error ? error.message : "request failed"}\n`);
    process.exitCode = 1;
  });
}
