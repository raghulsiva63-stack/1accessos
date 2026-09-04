import { createClient } from "@supabase/supabase-js";
import type { Database } from "@/lib/supabase/database.types";

const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
const publishableKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
export const isSupabaseConfigured = Boolean(url && publishableKey);
export const supabase = isSupabaseConfigured
  ? createClient<Database>(url!, publishableKey!, { auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, storage: typeof window === "undefined" ? undefined : window.sessionStorage } })
  : null;

