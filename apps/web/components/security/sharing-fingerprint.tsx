"use client";

import { useEffect, useState } from "react";
import { Fingerprint } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { myFingerprint } from "@/lib/enterprise/key-sharing";

/** Shows the fingerprint administrators compare before sharing workspace keys directly. */
export function SharingFingerprintCard() {
  const { identityId, isOrganization } = useEnterprise();
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    if (!identityId) return () => { active = false; };
    void myFingerprint(identityId).then((value) => { if (active) setFingerprint(value); }, () => undefined);
    return () => { active = false; };
  }, [identityId]);
  if (!fingerprint || !isOrganization) return null;
  return <Card>
    <CardHeader><CardTitle><Fingerprint /> Sharing key fingerprint</CardTitle>
      <CardDescription>Your organization encrypts team workspace keys to this key. If an administrator asks you to confirm it, read these characters to them — never your password.</CardDescription></CardHeader>
    <CardContent><code className="sharing-fingerprint">{fingerprint}</code></CardContent>
  </Card>;
}
