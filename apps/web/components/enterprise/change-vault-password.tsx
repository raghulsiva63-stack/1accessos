"use client";

import { useState } from "react";
import type { SupabaseClient } from "@supabase/supabase-js";
import { KeyRound, LoaderCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useEnterprise } from "@/components/enterprise/policy-context";
import {
  deriveMasterKey, fromBase64Url, randomBytes, toBase64Url, toPostgresBytea, unwrapKey,
  WEB_KDF_PROFILE, wrapKey,
} from "@/lib/crypto/vault";
import { estimateStrength, STRENGTH_LABELS } from "@/lib/enterprise/health";
import { supabase } from "@/lib/supabase/client";

export type RotatableProfile = {
  identity_id: string;
  salt: string;
  kdf_parameters: { memoryKib: number; iterations: number; parallelism: number; hashLength: 32 };
  master_nonce: string;
  master_wrapped_root: string;
};

function bytea(value: string) {
  return value.startsWith("\\x") ? Uint8Array.from(value.slice(2).match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16)) : fromBase64Url(value);
}

/**
 * Re-wraps the account root key under a new vault password. The current password
 * is verified locally by unwrapping the root; only the new wrap reaches the server.
 */
export function ChangeVaultPasswordCard<T extends RotatableProfile>({
  profile, onProfileChange, onPasswordChanged,
}: {
  profile: T;
  onProfileChange: (profile: T) => void;
  onPasswordChanged?: (facts: { length: number; strength: number }) => void;
}) {
  const { policy } = useEnterprise();
  const [open, setOpen] = useState(false);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const strength = estimateStrength(next);
  const minLength = Math.max(12, policy.minVaultPasswordLength);
  const meetsPolicy = next.length >= minLength && strength.score >= policy.minVaultPasswordStrength;

  function reset() { setCurrent(""); setNext(""); setConfirm(""); }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setMessage("");
    if (next !== confirm) { setMessage("The new vault passwords do not match."); return; }
    if (!meetsPolicy) { setMessage(`Use at least ${minLength} characters${policy.minVaultPasswordStrength ? ` with ${STRENGTH_LABELS[policy.minVaultPasswordStrength].toLowerCase()} strength` : ""}.`); return; }
    if (next === current) { setMessage("Choose a password you have not used for this vault."); return; }
    if (!supabase) return;
    setBusy(true);
    let oldMaster: Uint8Array | null = null; let root: Uint8Array | null = null; let newMaster: Uint8Array | null = null;
    try {
      oldMaster = await deriveMasterKey(current, bytea(profile.salt), { algorithm: "ARGON2ID", ...profile.kdf_parameters });
      root = await unwrapKey(oldMaster, { algorithm: "AES-256-GCM", nonce: toBase64Url(bytea(profile.master_nonce)), ciphertext: toBase64Url(bytea(profile.master_wrapped_root)) }, "1accessos:account-root:v1");
      const salt = randomBytes(16);
      newMaster = await deriveMasterKey(next, salt, WEB_KDF_PROFILE);
      const wrapped = await wrapKey(newMaster, root, "1accessos:account-root:v1");
      const { error } = await (supabase as unknown as SupabaseClient).rpc("rotate_master_with_session", {
        p_expected_master_nonce: toPostgresBytea(bytea(profile.master_nonce)),
        p_salt: toPostgresBytea(salt),
        p_kdf_parameters: WEB_KDF_PROFILE,
        p_master_nonce: toPostgresBytea(fromBase64Url(wrapped.nonce)),
        p_master_wrapped_root: toPostgresBytea(fromBase64Url(wrapped.ciphertext)),
      });
      if (error) throw error;
      onProfileChange({ ...profile, salt: toBase64Url(salt), kdf_parameters: WEB_KDF_PROFILE, master_nonce: wrapped.nonce, master_wrapped_root: wrapped.ciphertext });
      onPasswordChanged?.({ length: next.length, strength: strength.score });
      reset(); setOpen(false);
      setMessage("Vault password changed. Use the new password next time you unlock. Your recovery key still works.");
    } catch (reason) {
      const detail = reason instanceof Error ? reason.message : String((reason as { message?: string })?.message ?? "");
      setMessage(/incorrect|changed/iu.test(detail) && !/another device/iu.test(detail) ? "The current vault password is incorrect." : /another device/iu.test(detail) ? "Your vault password was changed on another device. Lock and unlock again." : /sign in again/iu.test(detail) ? "Sign in again, then change your vault password." : "The vault password could not be changed.");
    } finally {
      oldMaster?.fill(0); root?.fill(0); newMaster?.fill(0); setBusy(false);
    }
  }

  return <Card>
    <CardHeader><CardTitle>Vault password</CardTitle><CardDescription>Changing it re-encrypts your account key on this device. Items and your recovery key are unaffected.</CardDescription></CardHeader>
    <CardContent>
      {!open ? <Button variant="outline" onClick={() => { setOpen(true); setMessage(""); }}><KeyRound /> Change vault password</Button> :
        <form className="form-stack" onSubmit={submit}>
          <div><Label htmlFor="current-vault-password">Current vault password</Label><Input id="current-vault-password" type="password" autoComplete="current-password" required value={current} onChange={(event) => setCurrent(event.target.value)} /></div>
          <div><Label htmlFor="next-vault-password">New vault password</Label><Input id="next-vault-password" type="password" autoComplete="new-password" required minLength={minLength} value={next} onChange={(event) => setNext(event.target.value)} />
            {next && <div className={`strength-meter s${strength.score}`} aria-live="polite"><i style={{ width: `${(strength.score + 1) * 20}%` }} /><span>{STRENGTH_LABELS[strength.score]} · {next.length}/{minLength}+ characters</span></div>}
          </div>
          <div><Label htmlFor="confirm-vault-password">Confirm new vault password</Label><Input id="confirm-vault-password" type="password" autoComplete="new-password" required value={confirm} onChange={(event) => setConfirm(event.target.value)} /></div>
          <div className="inline-actions"><Button disabled={busy || !meetsPolicy}>{busy ? <LoaderCircle className="spin" /> : <KeyRound />} Change password</Button><Button type="button" variant="ghost" onClick={() => { reset(); setOpen(false); }} disabled={busy}>Cancel</Button></div>
        </form>}
      {message && <p className="form-message" role="status">{message}</p>}
    </CardContent>
  </Card>;
}
