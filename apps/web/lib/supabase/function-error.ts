/**
 * Supabase `functions.invoke` returns a generic FunctionsHttpError for any non-2xx
 * response. Our edge functions put a stable `{ error: "<code>" }` in that body,
 * so read it back to show the right message.
 */
export async function functionErrorCode(error: unknown, fallback = "service_unavailable"): Promise<string> {
  const context = (error as { context?: unknown } | null)?.context;
  if (context instanceof Response) {
    try {
      const body = await context.clone().json() as { error?: unknown };
      if (typeof body?.error === "string" && /^[a-z0-9_]{2,64}$/u.test(body.error)) return body.error;
    } catch { /* not JSON */ }
  }
  return fallback;
}
