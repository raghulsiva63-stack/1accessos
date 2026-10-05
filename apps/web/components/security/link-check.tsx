"use client";

import { useEffect, useEffectEvent, useState } from "react";
import { Flag, Link2, LoaderCircle, ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { checkLink, reportPhishingLink, takePendingLink, type LinkCheckResult } from "@/lib/security/link-check";

/** Security Center › Check a link (web, desktop and the Android share sheet). */
export function LinkCheckCard({ savedUrls = [] }: { savedUrls?: string[] }) {
  const [value, setValue] = useState("");
  const [result, setResult] = useState<LinkCheckResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function run(input: string) {
    setBusy(true); setMessage(""); setResult(null);
    try {
      const checked = await checkLink(input, savedUrls);
      if (!checked) setMessage("That doesn't look like a web link. Paste the full address, for example https://example.com/login.");
      setResult(checked);
    } catch { setMessage("The link couldn't be checked. Try again."); }
    finally { setBusy(false); }
  }
  const runShared = useEffectEvent(() => {
    const shared = takePendingLink();
    if (shared) { setValue(shared); void run(shared); document.getElementById("link-check")?.scrollIntoView({ block: "start" }); }
  });
  useEffect(() => {
    const timer = setTimeout(() => runShared(), 0);
    const listener = () => runShared();
    window.addEventListener("passkey-x:check-link", listener);
    return () => { clearTimeout(timer); window.removeEventListener("passkey-x:check-link", listener); };
  }, []);

  async function report() {
    if (!result) return;
    setMessage(await reportPhishingLink(result.url) ? "Thanks. The link was reported to your IT team." : "The link couldn't be reported. Sign in and try again.");
  }

  const level = result?.verdict.level;
  return <Card id="link-check">
    <CardHeader>
      <CardTitle>Check a link</CardTitle>
      <CardDescription>Got a link in an email, text or chat that looks odd? Check it before you open it. {"On Android, share any link to “Check link with Passkey-X”."}</CardDescription>
    </CardHeader>
    <CardContent className="si-stack">
      <form className="link-check-form" onSubmit={(event) => { event.preventDefault(); void run(value); }}>
        <Label htmlFor="link-check-input" className="sr-only">Link</Label>
        <Input id="link-check-input" inputMode="url" autoComplete="off" spellCheck={false} placeholder="https://…" value={value} onChange={(event) => setValue(event.target.value)} />
        <Button disabled={busy || !value.trim()}>{busy ? <LoaderCircle className="spin" /> : <Link2 />} Check</Button>
      </form>
      {result && <div className={`guard-summary ${level === "dangerous" ? "bad" : level === "suspicious" ? "warn" : "good"}`} role="status">
        {level === "dangerous" ? <ShieldAlert /> : level === "suspicious" ? <TriangleAlert /> : <ShieldCheck />}
        <div>
          <strong>{level === "dangerous" ? "Don't open this link" : level === "suspicious" ? "Be careful with this link" : result.title}: {result.host}</strong>
          {result.reasons.length > 0 ? <small>{result.reasons.join(" ")}</small>
            : <small>{result.checkedLists ? "Not on any threat list and not a look-alike of a known site." : "Not a look-alike of a known site. Sign in to also check threat lists."} New scam sites appear every day; if in doubt, go to the site by typing its address.</small>}
        </div>
      </div>}
      {result && <div className="inline-actions"><Button variant="outline" size="sm" onClick={() => void report()}><Flag /> Report as phishing</Button></div>}
      {message && <p className="form-message" role="status">{message}</p>}
    </CardContent>
  </Card>;
}
