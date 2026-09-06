"use client";

import { Turnstile } from "@marsidev/react-turnstile";
import { captchaSiteKey } from "@/lib/supabase/client";

type TurnstileCheckProps = {
  action: "auth-signin" | "auth-signup";
  resetKey: number;
  onProblem: () => void;
  onToken: (token: string | null) => void;
};

export function TurnstileCheck({ action, resetKey, onProblem, onToken }: TurnstileCheckProps) {
  if (!captchaSiteKey) return null;

  return (
    <div className="captcha-check">
      <Turnstile
        key={`${action}:${resetKey}`}
        siteKey={captchaSiteKey}
        onSuccess={(token) => onToken(token)}
        onExpire={() => onToken(null)}
        onTimeout={() => onToken(null)}
        onUnsupported={() => { onToken(null); onProblem(); }}
        onError={() => { onToken(null); onProblem(); }}
        options={{ action, size: "flexible", theme: "auto" }}
        scriptOptions={{ defer: true }}
      />
      <p className="field-hint">Protected by Cloudflare Turnstile. Complete this check before continuing.</p>
    </div>
  );
}
