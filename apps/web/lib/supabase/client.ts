import { createClient } from "@supabase/supabase-js";
import type { Database } from "@/lib/supabase/database.types";

const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
const publishableKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
export const passkeysEnabled = process.env.NEXT_PUBLIC_PASSKEYS_ENABLED === "true";
export const phoneMfaEnabled = process.env.NEXT_PUBLIC_PHONE_MFA_ENABLED === "true";
export const captchaSiteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY?.trim() ?? "";
export const captchaEnabled = Boolean(captchaSiteKey);
export const isSupabaseConfigured = Boolean(url && publishableKey);
export const supabase = isSupabaseConfigured
  ? createClient<Database>(url!, publishableKey!, { auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, experimental: { passkey: passkeysEnabled }, storage: typeof window === "undefined" ? undefined : window.sessionStorage } })
  : null;
