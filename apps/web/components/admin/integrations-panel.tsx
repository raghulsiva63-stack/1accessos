"use client";

import { useEnterprise } from "@/components/enterprise/policy-context";
import { ApiKeysCard } from "@/components/admin/integrations/api-keys";
import { AuditStreamingCard } from "@/components/admin/integrations/audit-streaming";
import { ChatChannelsCard } from "@/components/admin/integrations/chat-channels";
import type { WorkspaceVault } from "@/lib/vault/items";

/**
 * Admin console → Integrations: audit streaming to SIEMs and HTTPS webhooks, Slack / Microsoft Teams
 * alert channels and organization API keys. Only organization admins can change anything; everyone
 * else with access to the console sees read-only lists.
 */
export function IntegrationsPanel({ vault }: { vault: WorkspaceVault }) {
  const { isTenantAdmin } = useEnterprise();
  return <div className="integrations-panel cx-panel">
    {!isTenantAdmin && <p className="form-message neutral-message" role="status">Only organization owners and admins can add or change integrations.</p>}
    <AuditStreamingCard tenantId={vault.tenantId} isAdmin={isTenantAdmin} />
    <ChatChannelsCard tenantId={vault.tenantId} isAdmin={isTenantAdmin} />
    <ApiKeysCard tenantId={vault.tenantId} isAdmin={isTenantAdmin} />
  </div>;
}
