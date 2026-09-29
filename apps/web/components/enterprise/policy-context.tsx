"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { recordVaultActivity, type VaultActivity } from "@/lib/enterprise/audit";
import { DEFAULT_POLICY, exportAllowed, loadMyPolicy, LOADING_POLICY, type EnterprisePolicy } from "@/lib/enterprise/policies";
import { passkeysEnabled, supabase } from "@/lib/supabase/client";

export type Compliance = {
  checked: boolean;
  hasPasskey: boolean | null;
  hasMfa: boolean;
};

type EnterpriseContextValue = {
  /** The signed-in person's identity (empty when outside the vault). */
  identityId: string;
  policy: EnterprisePolicy;
  tenantRole: string | null;
  tenantKind: string | null;
  isOrganization: boolean;
  isTenantAdmin: boolean;
  loading: boolean;
  compliance: Compliance;
  canExport: boolean;
  record: (action: VaultActivity, itemId?: string | null) => void;
  refresh: () => void;
  refreshCompliance: () => void;
};

const fallback: EnterpriseContextValue = {
  identityId: "",
  policy: DEFAULT_POLICY,
  tenantRole: null,
  tenantKind: null,
  isOrganization: false,
  isTenantAdmin: false,
  loading: false,
  compliance: { checked: false, hasPasskey: null, hasMfa: false },
  canExport: true,
  record: () => undefined,
  refresh: () => undefined,
  refreshCompliance: () => undefined,
};

const EnterpriseContext = createContext<EnterpriseContextValue>(fallback);

export function EnterpriseProvider({
  tenantId, identityId, workspaceId, currentItemId, children,
}: {
  tenantId: string | null;
  identityId: string;
  workspaceId: string | null;
  currentItemId?: string | null;
  children: ReactNode;
}) {
  const [policy, setPolicy] = useState<EnterprisePolicy>(DEFAULT_POLICY);
  const [tenantRole, setTenantRole] = useState<string | null>(null);
  const [tenantKind, setTenantKind] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [version, setVersion] = useState(0);
  const [complianceVersion, setComplianceVersion] = useState(0);
  const [compliance, setCompliance] = useState<Compliance>({ checked: false, hasPasskey: null, hasMfa: false });

  useEffect(() => {
    let current = true;
    if (!tenantId) return () => { current = false; };
    void Promise.resolve().then(() => {
      if (!current) return;
      setLoading(true); setPolicy(LOADING_POLICY); setTenantRole(null); setTenantKind(null);
    })
      .then(() => loadMyPolicy(tenantId, identityId))
      .then((state) => {
        if (!current) return;
        setPolicy(state.policy); setTenantRole(state.tenantRole); setTenantKind(state.kind);
      }, () => {
        if (current) { setPolicy(LOADING_POLICY); setTenantRole(null); setTenantKind(null); }
      })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [identityId, tenantId, version]);

  useEffect(() => {
    let current = true;
    const client = supabase;
    if (!client) return () => { current = false; };
    void (async () => {
      const [factors, passkeys] = await Promise.all([
        client.auth.mfa.listFactors().catch(() => null),
        passkeysEnabled ? client.auth.passkey.list().catch(() => null) : Promise.resolve(null),
      ]);
      if (!current) return;
      const verified = factors?.data?.all?.filter((factor) => factor.status === "verified") ?? [];
      const passkeyList = passkeys && "data" in passkeys && Array.isArray(passkeys.data) ? passkeys.data : null;
      setCompliance({
        checked: true,
        hasMfa: verified.length > 0,
        hasPasskey: passkeyList ? passkeyList.length > 0 : null,
      });
    })();
    return () => { current = false; };
  }, [complianceVersion]);

  const record = useCallback((action: VaultActivity, itemId?: string | null) => {
    if (!tenantId || !workspaceId) return;
    recordVaultActivity(tenantId, workspaceId, itemId === undefined ? currentItemId ?? null : itemId, action);
  }, [currentItemId, tenantId, workspaceId]);

  const value = useMemo<EnterpriseContextValue>(() => ({
    identityId,
    policy,
    tenantRole,
    tenantKind,
    isOrganization: tenantKind === "organization",
    isTenantAdmin: tenantRole === "owner" || tenantRole === "admin",
    loading,
    compliance,
    canExport: exportAllowed(policy, tenantRole),
    record,
    refresh: () => setVersion((value) => value + 1),
    refreshCompliance: () => setComplianceVersion((value) => value + 1),
  }), [compliance, identityId, loading, policy, record, tenantKind, tenantRole]);

  return <EnterpriseContext.Provider value={value}>{children}</EnterpriseContext.Provider>;
}

export function useEnterprise() {
  return useContext(EnterpriseContext);
}
