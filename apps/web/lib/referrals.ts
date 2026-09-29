import type { SupabaseClient } from "@supabase/supabase-js";
import type { ClaimStatus, ReferralSummary } from "@/lib/referral-codes";
import { supabase } from "@/lib/supabase/client";

// The referral RPCs are newer than the generated database types.
function db() {
  if (!supabase) throw new Error("unavailable");
  return supabase as unknown as SupabaseClient;
}

export async function claimReferral(code: string): Promise<ClaimStatus> {
  const { data, error } = await db().rpc("claim_referral", { p_code: code });
  if (error) throw error;
  return data as ClaimStatus;
}

export async function loadReferralSummary(): Promise<ReferralSummary> {
  const { data, error } = await db().rpc("my_referral_summary");
  if (error) throw error;
  return data as ReferralSummary;
}
