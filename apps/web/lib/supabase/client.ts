import { createClient } from "@supabase/supabase-js";
import type { Database } from "@/lib/supabase/database.types";
import { desktopAuthStorage, isDesktopApp } from "@/lib/desktop/bridge";

const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
const publishableKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
export const passkeysEnabled = process.env.NEXT_PUBLIC_PASSKEYS_ENABLED === "true";
export const phoneMfaEnabled = process.env.NEXT_PUBLIC_PHONE_MFA_ENABLED === "true";
export const captchaSiteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY?.trim() ?? "";
export const captchaEnabled = Boolean(captchaSiteKey);
export const isSupabaseConfigured = Boolean(url && publishableKey);
// Web: the session lasts for the browser tab. Desktop: it is kept in the system keychain.
function authStorage() {
  if (typeof window === "undefined") return undefined;
  return isDesktopApp() ? desktopAuthStorage() : window.sessionStorage;
}

export const supabase = isSupabaseConfigured
  ? createClient<Database>(url!, publishableKey!, { auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, experimental: { passkey: passkeysEnabled }, storage: authStorage() } })
  : null;
