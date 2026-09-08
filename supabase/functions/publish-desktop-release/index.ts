import { createClient } from "npm:@supabase/supabase-js@2.115.0";
import config from "./release-config.json" with { type: "json" };
import { handleReleaseUpload } from "./handler.ts";

Deno.serve(request => {
  const client = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false, autoRefreshToken: false } });
  return handleReleaseUpload(request, config, client.storage);
});
