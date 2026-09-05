export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.5"
  }
  public: {
    Tables: {
      access_capsules: {
        Row: {
          accepted_at: string | null
          accepted_by: string | null
          created_at: string
          created_by: string
          expires_at: string
          id: string
          invite_key_aad_hash: string
          invite_key_nonce: string
          invite_wrapped_key: string
          item_id: string
          max_uses: number
          not_before: string
          payload_aad_hash: string
          payload_ciphertext: string
          payload_nonce: string
          purpose_code: string
          recipient_email_hash: string
          recipient_key_aad_hash: string | null
          recipient_key_nonce: string | null
          recipient_wrapped_key: string | null
          requires_approval: boolean
          reveal_policy: string
          revoked_at: string | null
          status: string
          tenant_id: string
          token_hash: string | null
          updated_at: string
          use_count: number
          workspace_id: string
        }
        Insert: {
          accepted_at?: string | null
          accepted_by?: string | null
          created_at?: string
          created_by: string
          expires_at: string
          id: string
          invite_key_aad_hash: string
          invite_key_nonce: string
          invite_wrapped_key: string
          item_id: string
          max_uses?: number
          not_before?: string
          payload_aad_hash: string
          payload_ciphertext: string
          payload_nonce: string
          purpose_code?: string
          recipient_email_hash: string
          recipient_key_aad_hash?: string | null
          recipient_key_nonce?: string | null
          recipient_wrapped_key?: string | null
          requires_approval?: boolean
          reveal_policy: string
          revoked_at?: string | null
          status?: string
          tenant_id: string
          token_hash?: string | null
          updated_at?: string
          use_count?: number
          workspace_id: string
        }
        Update: {
          accepted_at?: string | null
          accepted_by?: string | null
          created_at?: string
          created_by?: string
          expires_at?: string
          id?: string
          invite_key_aad_hash?: string
          invite_key_nonce?: string
          invite_wrapped_key?: string
          item_id?: string
          max_uses?: number
          not_before?: string
          payload_aad_hash?: string
          payload_ciphertext?: string
          payload_nonce?: string
          purpose_code?: string
          recipient_email_hash?: string
          recipient_key_aad_hash?: string | null
          recipient_key_nonce?: string | null
          recipient_wrapped_key?: string | null
          requires_approval?: boolean
          reveal_policy?: string
          revoked_at?: string | null
          status?: string
          tenant_id?: string
          token_hash?: string | null
          updated_at?: string
          use_count?: number
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "access_capsules_accepted_by_fkey"
            columns: ["accepted_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "access_capsules_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "access_capsules_tenant_id_item_id_fkey"
            columns: ["tenant_id", "item_id"]
            isOneToOne: false
            referencedRelation: "vault_items"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "access_capsules_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      access_grants: {
        Row: {
          created_at: string
          created_by: string
          expires_at: string
          id: string
          item_id: string | null
          revoked_at: string | null
          scope: string
          source_request_id: string | null
          starts_at: string
          status: string
          subject_identity_id: string
          tenant_id: string
          workspace_id: string
        }
        Insert: {
          created_at?: string
          created_by: string
          expires_at: string
          id?: string
          item_id?: string | null
          revoked_at?: string | null
          scope: string
          source_request_id?: string | null
          starts_at?: string
          status?: string
          subject_identity_id: string
          tenant_id: string
          workspace_id: string
        }
        Update: {
          created_at?: string
          created_by?: string
          expires_at?: string
          id?: string
          item_id?: string | null
          revoked_at?: string | null
          scope?: string
          source_request_id?: string | null
          starts_at?: string
          status?: string
          subject_identity_id?: string
          tenant_id?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "access_grants_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "access_grants_source_request_id_fkey"
            columns: ["source_request_id"]
            isOneToOne: false
            referencedRelation: "access_requests"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "access_grants_subject_identity_id_fkey"
            columns: ["subject_identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "access_grants_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "access_grants_tenant_id_item_id_fkey"
            columns: ["tenant_id", "item_id"]
            isOneToOne: false
            referencedRelation: "vault_items"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "access_grants_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      access_requests: {
        Row: {
          created_at: string
          decided_at: string | null
          encrypted_purpose: string
          expires_at: string
          id: string
          item_id: string | null
          purpose_aad_hash: string
          purpose_nonce: string
          requested_duration_minutes: number
          requested_scope: string
          requester_identity_id: string
          status: string
          tenant_id: string
          updated_at: string
          workspace_id: string
        }
        Insert: {
          created_at?: string
          decided_at?: string | null
          encrypted_purpose: string
          expires_at: string
          id: string
          item_id?: string | null
          purpose_aad_hash: string
          purpose_nonce: string
          requested_duration_minutes: number
          requested_scope: string
          requester_identity_id: string
          status?: string
          tenant_id: string
          updated_at?: string
          workspace_id: string
        }
        Update: {
          created_at?: string
          decided_at?: string | null
          encrypted_purpose?: string
          expires_at?: string
          id?: string
          item_id?: string | null
          purpose_aad_hash?: string
          purpose_nonce?: string
          requested_duration_minutes?: number
          requested_scope?: string
          requester_identity_id?: string
          status?: string
          tenant_id?: string
          updated_at?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "access_requests_requester_identity_id_fkey"
            columns: ["requester_identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "access_requests_tenant_id_item_id_fkey"
            columns: ["tenant_id", "item_id"]
            isOneToOne: false
            referencedRelation: "vault_items"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "access_requests_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      account_crypto_profiles: {
        Row: {
          created_at: string
          identity_id: string
          kdf_parameters: Json
          master_nonce: string
          master_wrapped_root: string
          recovery_nonce: string
          recovery_verifier: string | null
          recovery_wrapped_root: string
          salt: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          identity_id: string
          kdf_parameters: Json
          master_nonce: string
          master_wrapped_root: string
          recovery_nonce: string
          recovery_verifier?: string | null
          recovery_wrapped_root: string
          salt: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          identity_id?: string
          kdf_parameters?: Json
          master_nonce?: string
          master_wrapped_root?: string
          recovery_nonce?: string
          recovery_verifier?: string | null
          recovery_wrapped_root?: string
          salt?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "account_crypto_profiles_identity_id_fkey"
            columns: ["identity_id"]
            isOneToOne: true
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
        ]
      }
      account_entitlements: {
        Row: {
          ai_credits_remaining: number
          automation_runs_remaining: number
          identity_id: string
          period_ends_at: string
          period_started_at: string
          phase2_preview_enabled: boolean
          plan_code: string
          updated_at: string
        }
        Insert: {
          ai_credits_remaining?: number
          automation_runs_remaining?: number
          identity_id: string
          period_ends_at?: string
          period_started_at?: string
          phase2_preview_enabled?: boolean
          plan_code?: string
          updated_at?: string
        }
        Update: {
          ai_credits_remaining?: number
          automation_runs_remaining?: number
          identity_id?: string
          period_ends_at?: string
          period_started_at?: string
          phase2_preview_enabled?: boolean
          plan_code?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "account_entitlements_identity_id_fkey"
            columns: ["identity_id"]
            isOneToOne: true
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
        ]
      }
      api_tokens: {
        Row: {
          created_at: string
          expires_at: string | null
          id: string
          identity_id: string
          last_used_at: string | null
          revoked_at: string | null
          scopes: string[]
          token_hash: string
          token_prefix: string
        }
        Insert: {
          created_at?: string
          expires_at?: string | null
          id?: string
          identity_id: string
          last_used_at?: string | null
          revoked_at?: string | null
          scopes?: string[]
          token_hash: string
          token_prefix: string
        }
        Update: {
          created_at?: string
          expires_at?: string | null
          id?: string
          identity_id?: string
          last_used_at?: string | null
          revoked_at?: string | null
          scopes?: string[]
          token_hash?: string
          token_prefix?: string
        }
        Relationships: [
          {
            foreignKeyName: "api_tokens_identity_id_fkey"
            columns: ["identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
        ]
      }
      approvals: {
        Row: {
          approver_identity_id: string
          created_at: string
          decision: string
          id: string
          request_id: string
          tenant_id: string
          workspace_id: string
        }
        Insert: {
          approver_identity_id: string
          created_at?: string
          decision: string
          id?: string
          request_id: string
          tenant_id: string
          workspace_id: string
        }
        Update: {
          approver_identity_id?: string
          created_at?: string
          decision?: string
          id?: string
          request_id?: string
          tenant_id?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "approvals_approver_identity_id_fkey"
            columns: ["approver_identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "approvals_request_id_fkey"
            columns: ["request_id"]
            isOneToOne: false
            referencedRelation: "access_requests"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "approvals_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "approvals_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      attachment_versions: {
        Row: {
          aad_hash: string | null
          attachment_id: string
          ciphertext_sha256: string
          ciphertext_size: number
          created_at: string
          key_version: number
          nonce: string | null
          storage_path: string
          version: number
        }
        Insert: {
          aad_hash?: string | null
          attachment_id: string
          ciphertext_sha256: string
          ciphertext_size: number
          created_at?: string
          key_version: number
          nonce?: string | null
          storage_path: string
          version: number
        }
        Update: {
          aad_hash?: string | null
          attachment_id?: string
          ciphertext_sha256?: string
          ciphertext_size?: number
          created_at?: string
          key_version?: number
          nonce?: string | null
          storage_path?: string
          version?: number
        }
        Relationships: [
          {
            foreignKeyName: "attachment_versions_attachment_id_fkey"
            columns: ["attachment_id"]
            isOneToOne: false
            referencedRelation: "attachments"
            referencedColumns: ["id"]
          },
        ]
      }
      attachments: {
        Row: {
          created_at: string
          created_by: string
          deleted_at: string | null
          encrypted_metadata: string
          head_version: number
          id: string
          item_id: string
          metadata_aad_hash: string | null
          metadata_nonce: string | null
          tenant_id: string
          workspace_id: string
        }
        Insert: {
          created_at?: string
          created_by: string
          deleted_at?: string | null
          encrypted_metadata: string
          head_version?: number
          id?: string
          item_id: string
          metadata_aad_hash?: string | null
          metadata_nonce?: string | null
          tenant_id: string
          workspace_id: string
        }
        Update: {
          created_at?: string
          created_by?: string
          deleted_at?: string | null
          encrypted_metadata?: string
          head_version?: number
          id?: string
          item_id?: string
          metadata_aad_hash?: string | null
          metadata_nonce?: string | null
          tenant_id?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "attachments_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "attachments_tenant_id_item_id_fkey"
            columns: ["tenant_id", "item_id"]
            isOneToOne: false
            referencedRelation: "vault_items"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "attachments_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      audit_events: {
        Row: {
          action: string
          actor_identity_id: string | null
          event_hash: string
          metadata: Json
          occurred_at: string
          previous_hash: string | null
          sequence: number
          target_id: string | null
          target_type: string
          tenant_id: string
        }
        Insert: {
          action: string
          actor_identity_id?: string | null
          event_hash: string
          metadata?: Json
          occurred_at?: string
          previous_hash?: string | null
          sequence?: never
          target_id?: string | null
          target_type: string
          tenant_id: string
        }
        Update: {
          action?: string
          actor_identity_id?: string | null
          event_hash?: string
          metadata?: Json
          occurred_at?: string
          previous_hash?: string | null
          sequence?: never
          target_id?: string | null
          target_type?: string
          tenant_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "audit_events_actor_identity_id_fkey"
            columns: ["actor_identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "audit_events_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      billing_customers: {
        Row: {
          created_at: string
          livemode: boolean
          provider: string
          stripe_customer_id: string
          tenant_id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          livemode: boolean
          provider?: string
          stripe_customer_id: string
          tenant_id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          livemode?: boolean
          provider?: string
          stripe_customer_id?: string
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "billing_customers_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: true
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      billing_events: {
        Row: {
          delivery_count: number
          event_type: string
          livemode: boolean
          outcome: string
          payload_sha256: string
          processed_at: string | null
          received_at: string
          stripe_api_version: string | null
          stripe_event_id: string
          tenant_id: string | null
        }
        Insert: {
          delivery_count?: number
          event_type: string
          livemode: boolean
          outcome?: string
          payload_sha256: string
          processed_at?: string | null
          received_at?: string
          stripe_api_version?: string | null
          stripe_event_id: string
          tenant_id?: string | null
        }
        Update: {
          delivery_count?: number
          event_type?: string
          livemode?: boolean
          outcome?: string
          payload_sha256?: string
          processed_at?: string | null
          received_at?: string
          stripe_api_version?: string | null
          stripe_event_id?: string
          tenant_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "billing_events_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      billing_subscriptions: {
        Row: {
          billing_interval: string
          cancel_at_period_end: boolean
          canceled_at: string | null
          created_at: string
          currency: string
          current_period_ends_at: string | null
          current_period_started_at: string | null
          livemode: boolean
          plan_code: string
          quantity: number
          status: string
          stripe_price_id: string
          stripe_product_id: string
          stripe_subscription_id: string
          tenant_id: string
          updated_at: string
        }
        Insert: {
          billing_interval: string
          cancel_at_period_end?: boolean
          canceled_at?: string | null
          created_at?: string
          currency: string
          current_period_ends_at?: string | null
          current_period_started_at?: string | null
          livemode: boolean
          plan_code: string
          quantity?: number
          status: string
          stripe_price_id: string
          stripe_product_id: string
          stripe_subscription_id: string
          tenant_id: string
          updated_at?: string
        }
        Update: {
          billing_interval?: string
          cancel_at_period_end?: boolean
          canceled_at?: string | null
          created_at?: string
          currency?: string
          current_period_ends_at?: string | null
          current_period_started_at?: string | null
          livemode?: boolean
          plan_code?: string
          quantity?: number
          status?: string
          stripe_price_id?: string
          stripe_product_id?: string
          stripe_subscription_id?: string
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "billing_subscriptions_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: true
            referencedRelation: "billing_customers"
            referencedColumns: ["tenant_id"]
          },
          {
            foreignKeyName: "billing_subscriptions_tenant_mode_fkey"
            columns: ["tenant_id", "livemode"]
            isOneToOne: false
            referencedRelation: "billing_customers"
            referencedColumns: ["tenant_id", "livemode"]
          },
        ]
      }
      conflicts: {
        Row: {
          base_revision: number
          created_at: string
          created_by: string
          encrypted_proposal: string
          id: string
          item_id: string
          proposed_revision: number
          resolved_at: string | null
          tenant_id: string
          workspace_id: string
        }
        Insert: {
          base_revision: number
          created_at?: string
          created_by: string
          encrypted_proposal: string
          id?: string
          item_id: string
          proposed_revision: number
          resolved_at?: string | null
          tenant_id: string
          workspace_id: string
        }
        Update: {
          base_revision?: number
          created_at?: string
          created_by?: string
          encrypted_proposal?: string
          id?: string
          item_id?: string
          proposed_revision?: number
          resolved_at?: string | null
          tenant_id?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "conflicts_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "conflicts_tenant_id_item_id_fkey"
            columns: ["tenant_id", "item_id"]
            isOneToOne: false
            referencedRelation: "vault_items"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "conflicts_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      connector_catalog: {
        Row: {
          adapter_stage: string
          auth_scheme: string
          capabilities: string[]
          category: string
          certification_version: string | null
          connector_key: string
          created_at: string
          display_name: string
          documentation_url: string | null
          minimum_scopes: string[]
          phase5_target: boolean
          published: boolean
          quality_label: string
          updated_at: string
        }
        Insert: {
          adapter_stage?: string
          auth_scheme: string
          capabilities: string[]
          category: string
          certification_version?: string | null
          connector_key: string
          created_at?: string
          display_name: string
          documentation_url?: string | null
          minimum_scopes: string[]
          phase5_target?: boolean
          published?: boolean
          quality_label?: string
          updated_at?: string
        }
        Update: {
          adapter_stage?: string
          auth_scheme?: string
          capabilities?: string[]
          category?: string
          certification_version?: string | null
          connector_key?: string
          created_at?: string
          display_name?: string
          documentation_url?: string | null
          minimum_scopes?: string[]
          phase5_target?: boolean
          published?: boolean
          quality_label?: string
          updated_at?: string
        }
        Relationships: []
      }
      connector_certifications: {
        Row: {
          adapter_version: string
          certified_at: string
          checks: Json
          connector_key: string
          evidence_sha256: string
          expires_at: string | null
          id: string
          result: string
          suite_version: string
        }
        Insert: {
          adapter_version: string
          certified_at?: string
          checks?: Json
          connector_key: string
          evidence_sha256: string
          expires_at?: string | null
          id?: string
          result: string
          suite_version: string
        }
        Update: {
          adapter_version?: string
          certified_at?: string
          checks?: Json
          connector_key?: string
          evidence_sha256?: string
          expires_at?: string | null
          id?: string
          result?: string
          suite_version?: string
        }
        Relationships: [
          {
            foreignKeyName: "connector_certifications_connector_key_fkey"
            columns: ["connector_key"]
            isOneToOne: false
            referencedRelation: "connector_catalog"
            referencedColumns: ["connector_key"]
          },
        ]
      }
      connector_credentials: {
        Row: {
          ciphertext_sha256: string
          connector_id: string
          created_at: string
          encrypted_token_ref: string
          envelope_algorithm: string
          key_version: number
          revoked_at: string | null
          rotated_at: string | null
          tenant_id: string
        }
        Insert: {
          ciphertext_sha256: string
          connector_id: string
          created_at?: string
          encrypted_token_ref: string
          envelope_algorithm?: string
          key_version: number
          revoked_at?: string | null
          rotated_at?: string | null
          tenant_id: string
        }
        Update: {
          ciphertext_sha256?: string
          connector_id?: string
          created_at?: string
          encrypted_token_ref?: string
          envelope_algorithm?: string
          key_version?: number
          revoked_at?: string | null
          rotated_at?: string | null
          tenant_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "connector_credentials_connector_id_fkey"
            columns: ["connector_id"]
            isOneToOne: true
            referencedRelation: "tenant_connectors"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "connector_credentials_tenant_id_connector_id_fkey"
            columns: ["tenant_id", "connector_id"]
            isOneToOne: false
            referencedRelation: "tenant_connectors"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "connector_credentials_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      devices: {
        Row: {
          created_at: string
          encrypted_label: string | null
          id: string
          identity_id: string
          last_seen_at: string | null
          public_key: string
          revoked_at: string | null
          status: string
        }
        Insert: {
          created_at?: string
          encrypted_label?: string | null
          id?: string
          identity_id: string
          last_seen_at?: string | null
          public_key: string
          revoked_at?: string | null
          status?: string
        }
        Update: {
          created_at?: string
          encrypted_label?: string | null
          id?: string
          identity_id?: string
          last_seen_at?: string | null
          public_key?: string
          revoked_at?: string | null
          status?: string
        }
        Relationships: [
          {
            foreignKeyName: "devices_identity_id_fkey"
            columns: ["identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
        ]
      }
      feature_catalog: {
        Row: {
          catalog_version: string
          category: string
          created_at: string
          description: string
          display_name: string
          feature_key: string
          security_class: string
          sort_order: number
          status: string
        }
        Insert: {
          catalog_version: string
          category: string
          created_at?: string
          description: string
          display_name: string
          feature_key: string
          security_class: string
          sort_order: number
          status: string
        }
        Update: {
          catalog_version?: string
          category?: string
          created_at?: string
          description?: string
          display_name?: string
          feature_key?: string
          security_class?: string
          sort_order?: number
          status?: string
        }
        Relationships: []
      }
      idempotency_records: {
        Row: {
          created_at: string
          expires_at: string
          idempotency_key: string
          identity_id: string
          request_hash: string
          response_body: Json | null
          response_status: number | null
        }
        Insert: {
          created_at?: string
          expires_at: string
          idempotency_key: string
          identity_id: string
          request_hash: string
          response_body?: Json | null
          response_status?: number | null
        }
        Update: {
          created_at?: string
          expires_at?: string
          idempotency_key?: string
          identity_id?: string
          request_hash?: string
          response_body?: Json | null
          response_status?: number | null
        }
        Relationships: [
          {
            foreignKeyName: "idempotency_records_identity_id_fkey"
            columns: ["identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
        ]
      }
      identities: {
        Row: {
          auth_user_id: string | null
          created_at: string
          id: string
          kind: string
          status: string
          updated_at: string
        }
        Insert: {
          auth_user_id?: string | null
          created_at?: string
          id?: string
          kind: string
          status?: string
          updated_at?: string
        }
        Update: {
          auth_user_id?: string | null
          created_at?: string
          id?: string
          kind?: string
          status?: string
          updated_at?: string
        }
        Relationships: []
      }
      identity_lifecycle_events: {
        Row: {
          actor_identity_id: string
          event_type: string
          from_department_id: string | null
          from_team_id: string | null
          id: string
          occurred_at: string
          reason_code: string | null
          subject_identity_id: string
          tenant_id: string
          to_department_id: string | null
          to_team_id: string | null
        }
        Insert: {
          actor_identity_id: string
          event_type: string
          from_department_id?: string | null
          from_team_id?: string | null
          id?: string
          occurred_at?: string
          reason_code?: string | null
          subject_identity_id: string
          tenant_id: string
          to_department_id?: string | null
          to_team_id?: string | null
        }
        Update: {
          actor_identity_id?: string
          event_type?: string
          from_department_id?: string | null
          from_team_id?: string | null
          id?: string
          occurred_at?: string
          reason_code?: string | null
          subject_identity_id?: string
          tenant_id?: string
          to_department_id?: string | null
          to_team_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "identity_lifecycle_events_actor_identity_id_fkey"
            columns: ["actor_identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "identity_lifecycle_events_subject_identity_id_fkey"
            columns: ["subject_identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "identity_lifecycle_events_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "identity_lifecycle_events_tenant_id_from_department_id_fkey"
            columns: ["tenant_id", "from_department_id"]
            isOneToOne: false
            referencedRelation: "organization_departments"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "identity_lifecycle_events_tenant_id_from_team_id_fkey"
            columns: ["tenant_id", "from_team_id"]
            isOneToOne: false
            referencedRelation: "organization_teams"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "identity_lifecycle_events_tenant_id_subject_identity_id_fkey"
            columns: ["tenant_id", "subject_identity_id"]
            isOneToOne: false
            referencedRelation: "tenant_memberships"
            referencedColumns: ["tenant_id", "identity_id"]
          },
          {
            foreignKeyName: "identity_lifecycle_events_tenant_id_to_department_id_fkey"
            columns: ["tenant_id", "to_department_id"]
            isOneToOne: false
            referencedRelation: "organization_departments"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "identity_lifecycle_events_tenant_id_to_team_id_fkey"
            columns: ["tenant_id", "to_team_id"]
            isOneToOne: false
            referencedRelation: "organization_teams"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      key_envelopes: {
        Row: {
          algorithm: string
          created_at: string
          id: string
          key_kind: string
          key_version: number
          nonce: string
          recipient_device_id: string | null
          recipient_identity_id: string | null
          revoked_at: string | null
          tenant_id: string
          workspace_id: string | null
          wrapped_key: string
        }
        Insert: {
          algorithm: string
          created_at?: string
          id?: string
          key_kind: string
          key_version: number
          nonce: string
          recipient_device_id?: string | null
          recipient_identity_id?: string | null
          revoked_at?: string | null
          tenant_id: string
          workspace_id?: string | null
          wrapped_key: string
        }
        Update: {
          algorithm?: string
          created_at?: string
          id?: string
          key_kind?: string
          key_version?: number
          nonce?: string
          recipient_device_id?: string | null
          recipient_identity_id?: string | null
          revoked_at?: string | null
          tenant_id?: string
          workspace_id?: string | null
          wrapped_key?: string
        }
        Relationships: [
          {
            foreignKeyName: "key_envelopes_recipient_device_id_fkey"
            columns: ["recipient_device_id"]
            isOneToOne: false
            referencedRelation: "devices"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "key_envelopes_recipient_identity_id_fkey"
            columns: ["recipient_identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "key_envelopes_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "key_envelopes_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      lifecycle_workflow_runs: {
        Row: {
          created_at: string
          finished_at: string | null
          id: string
          idempotency_key: string
          result_summary: Json
          started_at: string | null
          status: string
          tenant_id: string
          trigger_ref_hash: string
          workflow_id: string
        }
        Insert: {
          created_at?: string
          finished_at?: string | null
          id?: string
          idempotency_key: string
          result_summary?: Json
          started_at?: string | null
          status?: string
          tenant_id: string
          trigger_ref_hash: string
          workflow_id: string
        }
        Update: {
          created_at?: string
          finished_at?: string | null
          id?: string
          idempotency_key?: string
          result_summary?: Json
          started_at?: string | null
          status?: string
          tenant_id?: string
          trigger_ref_hash?: string
          workflow_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "lifecycle_workflow_runs_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "lifecycle_workflow_runs_tenant_id_workflow_id_fkey"
            columns: ["tenant_id", "workflow_id"]
            isOneToOne: false
            referencedRelation: "lifecycle_workflows"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      lifecycle_workflows: {
        Row: {
          action_type: string
          approval_required: boolean
          created_at: string
          created_by: string
          definition: Json
          destructive_action: boolean
          display_name: string
          enabled: boolean
          execution_mode: string
          id: string
          tenant_id: string
          trigger_type: string
          updated_at: string
          version: number
        }
        Insert: {
          action_type: string
          approval_required?: boolean
          created_at?: string
          created_by: string
          definition?: Json
          destructive_action?: boolean
          display_name: string
          enabled?: boolean
          execution_mode?: string
          id?: string
          tenant_id: string
          trigger_type: string
          updated_at?: string
          version?: number
        }
        Update: {
          action_type?: string
          approval_required?: boolean
          created_at?: string
          created_by?: string
          definition?: Json
          destructive_action?: boolean
          display_name?: string
          enabled?: boolean
          execution_mode?: string
          id?: string
          tenant_id?: string
          trigger_type?: string
          updated_at?: string
          version?: number
        }
        Relationships: [
          {
            foreignKeyName: "lifecycle_workflows_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "lifecycle_workflows_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      mission_items: {
        Row: {
          item_id: string
          mission_id: string
          sort_order: number
          tenant_id: string
          workspace_id: string
        }
        Insert: {
          item_id: string
          mission_id: string
          sort_order?: number
          tenant_id: string
          workspace_id: string
        }
        Update: {
          item_id?: string
          mission_id?: string
          sort_order?: number
          tenant_id?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "mission_items_mission_id_fkey"
            columns: ["mission_id"]
            isOneToOne: false
            referencedRelation: "missions"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "mission_items_tenant_id_item_id_fkey"
            columns: ["tenant_id", "item_id"]
            isOneToOne: false
            referencedRelation: "vault_items"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "mission_items_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      mission_runs: {
        Row: {
          expires_at: string
          finished_at: string | null
          id: string
          mission_id: string
          started_at: string
          started_by: string
          status: string
          tenant_id: string
          workspace_id: string
        }
        Insert: {
          expires_at: string
          finished_at?: string | null
          id?: string
          mission_id: string
          started_at?: string
          started_by: string
          status?: string
          tenant_id: string
          workspace_id: string
        }
        Update: {
          expires_at?: string
          finished_at?: string | null
          id?: string
          mission_id?: string
          started_at?: string
          started_by?: string
          status?: string
          tenant_id?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "mission_runs_mission_id_fkey"
            columns: ["mission_id"]
            isOneToOne: false
            referencedRelation: "missions"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "mission_runs_started_by_fkey"
            columns: ["started_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "mission_runs_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      missions: {
        Row: {
          created_at: string
          created_by: string
          definition_aad_hash: string
          definition_nonce: string
          encrypted_definition: string
          id: string
          status: string
          tenant_id: string
          updated_at: string
          workspace_id: string
        }
        Insert: {
          created_at?: string
          created_by: string
          definition_aad_hash: string
          definition_nonce: string
          encrypted_definition: string
          id: string
          status?: string
          tenant_id: string
          updated_at?: string
          workspace_id: string
        }
        Update: {
          created_at?: string
          created_by?: string
          definition_aad_hash?: string
          definition_nonce?: string
          encrypted_definition?: string
          id?: string
          status?: string
          tenant_id?: string
          updated_at?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "missions_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "missions_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      msp_tenant_access: {
        Row: {
          approved_at: string | null
          approved_by: string | null
          created_at: string
          created_by: string
          customer_tenant_id: string
          id: string
          permission: string
          provider_tenant_id: string
          revoked_at: string | null
          status: string
          updated_at: string
        }
        Insert: {
          approved_at?: string | null
          approved_by?: string | null
          created_at?: string
          created_by: string
          customer_tenant_id: string
          id?: string
          permission?: string
          provider_tenant_id: string
          revoked_at?: string | null
          status?: string
          updated_at?: string
        }
        Update: {
          approved_at?: string | null
          approved_by?: string | null
          created_at?: string
          created_by?: string
          customer_tenant_id?: string
          id?: string
          permission?: string
          provider_tenant_id?: string
          revoked_at?: string | null
          status?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "msp_tenant_access_approved_by_fkey"
            columns: ["approved_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "msp_tenant_access_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "msp_tenant_access_customer_tenant_id_fkey"
            columns: ["customer_tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "msp_tenant_access_provider_tenant_id_fkey"
            columns: ["provider_tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      organization_admin_assignments: {
        Row: {
          assigned_by: string
          created_at: string
          id: string
          identity_id: string
          role: string
          scope_id: string | null
          scope_type: string
          status: string
          tenant_id: string
          updated_at: string
        }
        Insert: {
          assigned_by: string
          created_at?: string
          id?: string
          identity_id: string
          role: string
          scope_id?: string | null
          scope_type: string
          status?: string
          tenant_id: string
          updated_at?: string
        }
        Update: {
          assigned_by?: string
          created_at?: string
          id?: string
          identity_id?: string
          role?: string
          scope_id?: string | null
          scope_type?: string
          status?: string
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_admin_assignments_assigned_by_fkey"
            columns: ["assigned_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_admin_assignments_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_admin_assignments_tenant_id_identity_id_fkey"
            columns: ["tenant_id", "identity_id"]
            isOneToOne: false
            referencedRelation: "organization_profiles"
            referencedColumns: ["tenant_id", "identity_id"]
          },
        ]
      }
      organization_departments: {
        Row: {
          created_at: string
          created_by: string
          display_name: string
          id: string
          parent_department_id: string | null
          slug: string
          status: string
          tenant_id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          created_by: string
          display_name: string
          id?: string
          parent_department_id?: string | null
          slug: string
          status?: string
          tenant_id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          created_by?: string
          display_name?: string
          id?: string
          parent_department_id?: string | null
          slug?: string
          status?: string
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_departments_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_departments_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_departments_tenant_id_parent_department_id_fkey"
            columns: ["tenant_id", "parent_department_id"]
            isOneToOne: false
            referencedRelation: "organization_departments"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      organization_device_posture_reports: {
        Row: {
          created_at: string
          created_by: string
          device_id: string
          disk_encrypted: boolean | null
          endpoint_protection: boolean | null
          evaluation: string
          evidence_hash: string | null
          id: string
          identity_id: string
          observed_at: string
          os_family: string
          screen_lock: boolean | null
          security_patch_current: boolean | null
          source: string
          tenant_id: string
          valid_until: string
          verification_status: string
        }
        Insert: {
          created_at?: string
          created_by: string
          device_id: string
          disk_encrypted?: boolean | null
          endpoint_protection?: boolean | null
          evaluation?: string
          evidence_hash?: string | null
          id?: string
          identity_id: string
          observed_at?: string
          os_family?: string
          screen_lock?: boolean | null
          security_patch_current?: boolean | null
          source: string
          tenant_id: string
          valid_until: string
          verification_status?: string
        }
        Update: {
          created_at?: string
          created_by?: string
          device_id?: string
          disk_encrypted?: boolean | null
          endpoint_protection?: boolean | null
          evaluation?: string
          evidence_hash?: string | null
          id?: string
          identity_id?: string
          observed_at?: string
          os_family?: string
          screen_lock?: boolean | null
          security_patch_current?: boolean | null
          source?: string
          tenant_id?: string
          valid_until?: string
          verification_status?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_device_posture_reports_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_device_posture_reports_device_id_fkey"
            columns: ["device_id"]
            isOneToOne: false
            referencedRelation: "devices"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_device_posture_reports_identity_id_fkey"
            columns: ["identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_device_posture_reports_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_device_posture_reports_tenant_id_identity_id_fkey"
            columns: ["tenant_id", "identity_id"]
            isOneToOne: false
            referencedRelation: "tenant_memberships"
            referencedColumns: ["tenant_id", "identity_id"]
          },
        ]
      }
      organization_group_memberships: {
        Row: {
          assigned_by: string
          created_at: string
          group_id: string
          identity_id: string
          tenant_id: string
        }
        Insert: {
          assigned_by: string
          created_at?: string
          group_id: string
          identity_id: string
          tenant_id: string
        }
        Update: {
          assigned_by?: string
          created_at?: string
          group_id?: string
          identity_id?: string
          tenant_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_group_memberships_assigned_by_fkey"
            columns: ["assigned_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_group_memberships_tenant_id_group_id_fkey"
            columns: ["tenant_id", "group_id"]
            isOneToOne: false
            referencedRelation: "organization_groups"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "organization_group_memberships_tenant_id_identity_id_fkey"
            columns: ["tenant_id", "identity_id"]
            isOneToOne: false
            referencedRelation: "organization_profiles"
            referencedColumns: ["tenant_id", "identity_id"]
          },
        ]
      }
      organization_groups: {
        Row: {
          created_at: string
          created_by: string
          description: string | null
          display_name: string
          id: string
          slug: string
          status: string
          tenant_id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          created_by: string
          description?: string | null
          display_name: string
          id?: string
          slug: string
          status?: string
          tenant_id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          created_by?: string
          description?: string | null
          display_name?: string
          id?: string
          slug?: string
          status?: string
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_groups_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_groups_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      organization_invitations: {
        Row: {
          accepted_at: string | null
          accepted_by: string | null
          created_at: string
          created_by: string
          department_id: string | null
          display_name: string
          expires_at: string
          id: string
          job_title: string | null
          recipient_email_hash: string
          revoked_at: string | null
          status: string
          team_id: string | null
          team_role: string
          tenant_id: string
          token_hash: string
          updated_at: string
        }
        Insert: {
          accepted_at?: string | null
          accepted_by?: string | null
          created_at?: string
          created_by: string
          department_id?: string | null
          display_name: string
          expires_at: string
          id: string
          job_title?: string | null
          recipient_email_hash: string
          revoked_at?: string | null
          status?: string
          team_id?: string | null
          team_role?: string
          tenant_id: string
          token_hash: string
          updated_at?: string
        }
        Update: {
          accepted_at?: string | null
          accepted_by?: string | null
          created_at?: string
          created_by?: string
          department_id?: string | null
          display_name?: string
          expires_at?: string
          id?: string
          job_title?: string | null
          recipient_email_hash?: string
          revoked_at?: string | null
          status?: string
          team_id?: string | null
          team_role?: string
          tenant_id?: string
          token_hash?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_invitations_accepted_by_fkey"
            columns: ["accepted_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_invitations_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_invitations_tenant_id_department_id_fkey"
            columns: ["tenant_id", "department_id"]
            isOneToOne: false
            referencedRelation: "organization_departments"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "organization_invitations_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_invitations_tenant_id_team_id_fkey"
            columns: ["tenant_id", "team_id"]
            isOneToOne: false
            referencedRelation: "organization_teams"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      organization_policies: {
        Row: {
          configuration: Json
          created_at: string
          created_by: string
          enforced: boolean
          id: string
          policy_type: string
          priority: number
          scope_id: string | null
          scope_type: string
          tenant_id: string
          updated_at: string
          version: number
        }
        Insert: {
          configuration?: Json
          created_at?: string
          created_by: string
          enforced?: boolean
          id?: string
          policy_type: string
          priority?: number
          scope_id?: string | null
          scope_type: string
          tenant_id: string
          updated_at?: string
          version?: number
        }
        Update: {
          configuration?: Json
          created_at?: string
          created_by?: string
          enforced?: boolean
          id?: string
          policy_type?: string
          priority?: number
          scope_id?: string | null
          scope_type?: string
          tenant_id?: string
          updated_at?: string
          version?: number
        }
        Relationships: [
          {
            foreignKeyName: "organization_policies_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_policies_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      organization_profiles: {
        Row: {
          created_at: string
          department_id: string | null
          display_name: string
          employee_ref_hash: string | null
          identity_id: string
          job_title: string | null
          joined_on: string | null
          lifecycle_status: string
          manager_identity_id: string | null
          tenant_id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          department_id?: string | null
          display_name: string
          employee_ref_hash?: string | null
          identity_id: string
          job_title?: string | null
          joined_on?: string | null
          lifecycle_status?: string
          manager_identity_id?: string | null
          tenant_id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          department_id?: string | null
          display_name?: string
          employee_ref_hash?: string | null
          identity_id?: string
          job_title?: string | null
          joined_on?: string | null
          lifecycle_status?: string
          manager_identity_id?: string | null
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_profiles_tenant_id_department_id_fkey"
            columns: ["tenant_id", "department_id"]
            isOneToOne: false
            referencedRelation: "organization_departments"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "organization_profiles_tenant_id_identity_id_fkey"
            columns: ["tenant_id", "identity_id"]
            isOneToOne: true
            referencedRelation: "tenant_memberships"
            referencedColumns: ["tenant_id", "identity_id"]
          },
          {
            foreignKeyName: "organization_profiles_tenant_id_manager_identity_id_fkey"
            columns: ["tenant_id", "manager_identity_id"]
            isOneToOne: false
            referencedRelation: "organization_profiles"
            referencedColumns: ["tenant_id", "identity_id"]
          },
        ]
      }
      organization_team_memberships: {
        Row: {
          assigned_by: string
          created_at: string
          identity_id: string
          role: string
          status: string
          team_id: string
          tenant_id: string
          updated_at: string
        }
        Insert: {
          assigned_by: string
          created_at?: string
          identity_id: string
          role?: string
          status?: string
          team_id: string
          tenant_id: string
          updated_at?: string
        }
        Update: {
          assigned_by?: string
          created_at?: string
          identity_id?: string
          role?: string
          status?: string
          team_id?: string
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_team_memberships_assigned_by_fkey"
            columns: ["assigned_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_team_memberships_tenant_id_identity_id_fkey"
            columns: ["tenant_id", "identity_id"]
            isOneToOne: false
            referencedRelation: "organization_profiles"
            referencedColumns: ["tenant_id", "identity_id"]
          },
          {
            foreignKeyName: "organization_team_memberships_tenant_id_team_id_fkey"
            columns: ["tenant_id", "team_id"]
            isOneToOne: false
            referencedRelation: "organization_teams"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      organization_teams: {
        Row: {
          created_at: string
          created_by: string
          department_id: string | null
          display_name: string
          id: string
          slug: string
          status: string
          tenant_id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          created_by: string
          department_id?: string | null
          display_name: string
          id?: string
          slug: string
          status?: string
          tenant_id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          created_by?: string
          department_id?: string | null
          display_name?: string
          id?: string
          slug?: string
          status?: string
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_teams_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "organization_teams_tenant_id_department_id_fkey"
            columns: ["tenant_id", "department_id"]
            isOneToOne: false
            referencedRelation: "organization_departments"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "organization_teams_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      outbox_events: {
        Row: {
          attempts: number
          created_at: string
          event_type: string
          id: string
          payload: Json
          published_at: string | null
          tenant_id: string | null
        }
        Insert: {
          attempts?: number
          created_at?: string
          event_type: string
          id?: string
          payload: Json
          published_at?: string | null
          tenant_id?: string | null
        }
        Update: {
          attempts?: number
          created_at?: string
          event_type?: string
          id?: string
          payload?: Json
          published_at?: string | null
          tenant_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "outbox_events_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      plan_catalog: {
        Row: {
          audience: string
          billing_model: string
          catalog_version: string
          commercial_status: string
          created_at: string
          display_name: string
          is_featured: boolean
          max_seats: number | null
          min_seats: number | null
          plan_code: string
          sort_order: number
          status: string
          summary: string
          trial_days: number
        }
        Insert: {
          audience: string
          billing_model: string
          catalog_version: string
          commercial_status?: string
          created_at?: string
          display_name: string
          is_featured?: boolean
          max_seats?: number | null
          min_seats?: number | null
          plan_code: string
          sort_order: number
          status: string
          summary: string
          trial_days?: number
        }
        Update: {
          audience?: string
          billing_model?: string
          catalog_version?: string
          commercial_status?: string
          created_at?: string
          display_name?: string
          is_featured?: boolean
          max_seats?: number | null
          min_seats?: number | null
          plan_code?: string
          sort_order?: number
          status?: string
          summary?: string
          trial_days?: number
        }
        Relationships: []
      }
      plan_entitlements: {
        Row: {
          catalog_version: string
          created_at: string
          display_order: number
          display_text: string
          entitlement_value: Json
          feature_key: string
          plan_code: string
        }
        Insert: {
          catalog_version: string
          created_at?: string
          display_order: number
          display_text: string
          entitlement_value: Json
          feature_key: string
          plan_code: string
        }
        Update: {
          catalog_version?: string
          created_at?: string
          display_order?: number
          display_text?: string
          entitlement_value?: Json
          feature_key?: string
          plan_code?: string
        }
        Relationships: [
          {
            foreignKeyName: "plan_entitlements_catalog_version_feature_key_fkey"
            columns: ["catalog_version", "feature_key"]
            isOneToOne: false
            referencedRelation: "feature_catalog"
            referencedColumns: ["catalog_version", "feature_key"]
          },
          {
            foreignKeyName: "plan_entitlements_catalog_version_plan_code_fkey"
            columns: ["catalog_version", "plan_code"]
            isOneToOne: false
            referencedRelation: "plan_catalog"
            referencedColumns: ["catalog_version", "plan_code"]
          },
        ]
      }
      plan_prices: {
        Row: {
          billing_interval: string
          catalog_version: string
          created_at: string
          currency: string
          plan_code: string
          price_scope: string
          stripe_price_id: string | null
          unit_amount_minor: number
        }
        Insert: {
          billing_interval: string
          catalog_version: string
          created_at?: string
          currency: string
          plan_code: string
          price_scope: string
          stripe_price_id?: string | null
          unit_amount_minor: number
        }
        Update: {
          billing_interval?: string
          catalog_version?: string
          created_at?: string
          currency?: string
          plan_code?: string
          price_scope?: string
          stripe_price_id?: string | null
          unit_amount_minor?: number
        }
        Relationships: [
          {
            foreignKeyName: "plan_prices_catalog_version_plan_code_fkey"
            columns: ["catalog_version", "plan_code"]
            isOneToOne: false
            referencedRelation: "plan_catalog"
            referencedColumns: ["catalog_version", "plan_code"]
          },
        ]
      }
      saas_applications: {
        Row: {
          app_key: string
          category: string
          confidence: number | null
          connector_id: string | null
          created_at: string
          data_risk: string
          discovery_source: string
          display_name: string
          external_ref_hash: string | null
          first_seen_at: string
          id: string
          last_seen_at: string
          owner_identity_id: string | null
          sanctioned_state: string
          tenant_id: string
          updated_at: string
        }
        Insert: {
          app_key: string
          category: string
          confidence?: number | null
          connector_id?: string | null
          created_at?: string
          data_risk?: string
          discovery_source: string
          display_name: string
          external_ref_hash?: string | null
          first_seen_at?: string
          id?: string
          last_seen_at?: string
          owner_identity_id?: string | null
          sanctioned_state?: string
          tenant_id: string
          updated_at?: string
        }
        Update: {
          app_key?: string
          category?: string
          confidence?: number | null
          connector_id?: string | null
          created_at?: string
          data_risk?: string
          discovery_source?: string
          display_name?: string
          external_ref_hash?: string | null
          first_seen_at?: string
          id?: string
          last_seen_at?: string
          owner_identity_id?: string | null
          sanctioned_state?: string
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "saas_applications_owner_identity_id_fkey"
            columns: ["owner_identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "saas_applications_tenant_id_connector_id_fkey"
            columns: ["tenant_id", "connector_id"]
            isOneToOne: false
            referencedRelation: "tenant_connectors"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "saas_applications_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      saas_contracts: {
        Row: {
          application_id: string
          billing_interval: string
          created_at: string
          currency: string
          id: string
          notice_days: number
          purchased_seats: number
          renewal_at: string | null
          sku: string
          source: string
          tenant_id: string
          unit_cost_minor: number
          updated_at: string
        }
        Insert: {
          application_id: string
          billing_interval: string
          created_at?: string
          currency: string
          id?: string
          notice_days?: number
          purchased_seats: number
          renewal_at?: string | null
          sku: string
          source: string
          tenant_id: string
          unit_cost_minor: number
          updated_at?: string
        }
        Update: {
          application_id?: string
          billing_interval?: string
          created_at?: string
          currency?: string
          id?: string
          notice_days?: number
          purchased_seats?: number
          renewal_at?: string | null
          sku?: string
          source?: string
          tenant_id?: string
          unit_cost_minor?: number
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "saas_contracts_tenant_id_application_id_fkey"
            columns: ["tenant_id", "application_id"]
            isOneToOne: false
            referencedRelation: "saas_applications"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "saas_contracts_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      saas_identity_accounts: {
        Row: {
          account_ref_hash: string
          account_status: string
          application_id: string
          created_at: string
          first_seen_at: string
          id: string
          identity_id: string | null
          last_activity_bucket: string | null
          last_seen_at: string
          owner_state: string
          privilege_tier: string
          tenant_id: string
        }
        Insert: {
          account_ref_hash: string
          account_status?: string
          application_id: string
          created_at?: string
          first_seen_at?: string
          id?: string
          identity_id?: string | null
          last_activity_bucket?: string | null
          last_seen_at?: string
          owner_state?: string
          privilege_tier?: string
          tenant_id: string
        }
        Update: {
          account_ref_hash?: string
          account_status?: string
          application_id?: string
          created_at?: string
          first_seen_at?: string
          id?: string
          identity_id?: string | null
          last_activity_bucket?: string | null
          last_seen_at?: string
          owner_state?: string
          privilege_tier?: string
          tenant_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "saas_identity_accounts_identity_id_fkey"
            columns: ["identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "saas_identity_accounts_tenant_id_application_id_fkey"
            columns: ["tenant_id", "application_id"]
            isOneToOne: false
            referencedRelation: "saas_applications"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "saas_identity_accounts_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      saas_licenses: {
        Row: {
          account_id: string | null
          assigned_at: string | null
          assigned_identity_id: string | null
          contract_id: string
          created_at: string
          id: string
          last_used_on: string | null
          status: string
          tenant_id: string
          updated_at: string
        }
        Insert: {
          account_id?: string | null
          assigned_at?: string | null
          assigned_identity_id?: string | null
          contract_id: string
          created_at?: string
          id?: string
          last_used_on?: string | null
          status?: string
          tenant_id: string
          updated_at?: string
        }
        Update: {
          account_id?: string | null
          assigned_at?: string | null
          assigned_identity_id?: string | null
          contract_id?: string
          created_at?: string
          id?: string
          last_used_on?: string | null
          status?: string
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "saas_licenses_assigned_identity_id_fkey"
            columns: ["assigned_identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "saas_licenses_tenant_id_account_id_fkey"
            columns: ["tenant_id", "account_id"]
            isOneToOne: false
            referencedRelation: "saas_identity_accounts"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "saas_licenses_tenant_id_contract_id_fkey"
            columns: ["tenant_id", "contract_id"]
            isOneToOne: false
            referencedRelation: "saas_contracts"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "saas_licenses_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      saas_recommendations: {
        Row: {
          action_state: string
          application_id: string | null
          currency: string | null
          destructive_action: boolean
          estimated_savings_minor: number | null
          evidence: Json
          explanation: string
          generated_at: string
          id: string
          kind: string
          recommendation_key: string
          reviewed_at: string | null
          reviewed_by: string | null
          severity: string
          tenant_id: string
          title: string
        }
        Insert: {
          action_state?: string
          application_id?: string | null
          currency?: string | null
          destructive_action?: boolean
          estimated_savings_minor?: number | null
          evidence?: Json
          explanation: string
          generated_at?: string
          id?: string
          kind: string
          recommendation_key: string
          reviewed_at?: string | null
          reviewed_by?: string | null
          severity: string
          tenant_id: string
          title: string
        }
        Update: {
          action_state?: string
          application_id?: string | null
          currency?: string | null
          destructive_action?: boolean
          estimated_savings_minor?: number | null
          evidence?: Json
          explanation?: string
          generated_at?: string
          id?: string
          kind?: string
          recommendation_key?: string
          reviewed_at?: string | null
          reviewed_by?: string | null
          severity?: string
          tenant_id?: string
          title?: string
        }
        Relationships: [
          {
            foreignKeyName: "saas_recommendations_reviewed_by_fkey"
            columns: ["reviewed_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "saas_recommendations_tenant_id_application_id_fkey"
            columns: ["tenant_id", "application_id"]
            isOneToOne: false
            referencedRelation: "saas_applications"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "saas_recommendations_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      saas_savings_ledger: {
        Row: {
          amount_minor: number
          application_id: string | null
          currency: string
          evidence_ref_hash: string
          id: string
          measurement: string
          period_end: string
          period_start: string
          recommendation_id: string | null
          recorded_at: string
          recorded_by: string | null
          tenant_id: string
        }
        Insert: {
          amount_minor: number
          application_id?: string | null
          currency: string
          evidence_ref_hash: string
          id?: string
          measurement: string
          period_end: string
          period_start: string
          recommendation_id?: string | null
          recorded_at?: string
          recorded_by?: string | null
          tenant_id: string
        }
        Update: {
          amount_minor?: number
          application_id?: string | null
          currency?: string
          evidence_ref_hash?: string
          id?: string
          measurement?: string
          period_end?: string
          period_start?: string
          recommendation_id?: string | null
          recorded_at?: string
          recorded_by?: string | null
          tenant_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "saas_savings_ledger_recommendation_id_fkey"
            columns: ["recommendation_id"]
            isOneToOne: false
            referencedRelation: "saas_recommendations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "saas_savings_ledger_recorded_by_fkey"
            columns: ["recorded_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "saas_savings_ledger_tenant_id_application_id_fkey"
            columns: ["tenant_id", "application_id"]
            isOneToOne: false
            referencedRelation: "saas_applications"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "saas_savings_ledger_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "saas_savings_ledger_tenant_id_recommendation_id_fkey"
            columns: ["tenant_id", "recommendation_id"]
            isOneToOne: false
            referencedRelation: "saas_recommendations"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      saas_usage_facts: {
        Row: {
          activity_bucket: string
          application_id: string
          created_at: string
          currency: string | null
          id: number
          identity_id: string | null
          metric: string
          quantity: number
          source: string
          source_ref_hash: string | null
          tenant_id: string
        }
        Insert: {
          activity_bucket: string
          application_id: string
          created_at?: string
          currency?: string | null
          id?: never
          identity_id?: string | null
          metric: string
          quantity: number
          source: string
          source_ref_hash?: string | null
          tenant_id: string
        }
        Update: {
          activity_bucket?: string
          application_id?: string
          created_at?: string
          currency?: string | null
          id?: never
          identity_id?: string | null
          metric?: string
          quantity?: number
          source?: string
          source_ref_hash?: string | null
          tenant_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "saas_usage_facts_identity_id_fkey"
            columns: ["identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "saas_usage_facts_tenant_id_application_id_fkey"
            columns: ["tenant_id", "application_id"]
            isOneToOne: false
            referencedRelation: "saas_applications"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "saas_usage_facts_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      spend_budgets: {
        Row: {
          approval_policy_id: string | null
          chargeback_tag: string | null
          consumed: number
          created_at: string
          created_by: string
          currency: string | null
          enforcement: string
          hard_limit: number
          id: string
          metric: string
          period_end: string
          period_start: string
          scope_id: string | null
          scope_type: string
          soft_limit: number
          tenant_id: string
          updated_at: string
        }
        Insert: {
          approval_policy_id?: string | null
          chargeback_tag?: string | null
          consumed?: number
          created_at?: string
          created_by: string
          currency?: string | null
          enforcement?: string
          hard_limit: number
          id?: string
          metric: string
          period_end: string
          period_start: string
          scope_id?: string | null
          scope_type: string
          soft_limit: number
          tenant_id: string
          updated_at?: string
        }
        Update: {
          approval_policy_id?: string | null
          chargeback_tag?: string | null
          consumed?: number
          created_at?: string
          created_by?: string
          currency?: string | null
          enforcement?: string
          hard_limit?: number
          id?: string
          metric?: string
          period_end?: string
          period_start?: string
          scope_id?: string | null
          scope_type?: string
          soft_limit?: number
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "spend_budgets_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "spend_budgets_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      sync_changes: {
        Row: {
          entity_id: string
          entity_type: string
          entity_version: number | null
          occurred_at: string
          operation: string
          sequence: number
          tenant_id: string
          workspace_id: string
        }
        Insert: {
          entity_id: string
          entity_type: string
          entity_version?: number | null
          occurred_at?: string
          operation: string
          sequence?: never
          tenant_id: string
          workspace_id: string
        }
        Update: {
          entity_id?: string
          entity_type?: string
          entity_version?: number | null
          occurred_at?: string
          operation?: string
          sequence?: never
          tenant_id?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "sync_changes_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "sync_changes_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      tenant_connectors: {
        Row: {
          configuration_summary: Json
          connector_key: string
          created_at: string
          created_by: string
          discovered_records: number
          display_name: string
          granted_scopes: string[]
          id: string
          last_health_at: string | null
          last_sync_at: string | null
          next_sync_at: string | null
          status: string
          tenant_id: string
          token_expires_at: string | null
          token_rotation_state: string
          updated_at: string
        }
        Insert: {
          configuration_summary?: Json
          connector_key: string
          created_at?: string
          created_by: string
          discovered_records?: number
          display_name: string
          granted_scopes?: string[]
          id?: string
          last_health_at?: string | null
          last_sync_at?: string | null
          next_sync_at?: string | null
          status?: string
          tenant_id: string
          token_expires_at?: string | null
          token_rotation_state?: string
          updated_at?: string
        }
        Update: {
          configuration_summary?: Json
          connector_key?: string
          created_at?: string
          created_by?: string
          discovered_records?: number
          display_name?: string
          granted_scopes?: string[]
          id?: string
          last_health_at?: string | null
          last_sync_at?: string | null
          next_sync_at?: string | null
          status?: string
          tenant_id?: string
          token_expires_at?: string | null
          token_rotation_state?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "tenant_connectors_connector_key_fkey"
            columns: ["connector_key"]
            isOneToOne: false
            referencedRelation: "connector_catalog"
            referencedColumns: ["connector_key"]
          },
          {
            foreignKeyName: "tenant_connectors_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "tenant_connectors_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      tenant_entitlements: {
        Row: {
          ai_credits_remaining: number
          automation_runs_remaining: number
          max_devices: number | null
          max_members: number
          max_workspaces: number
          plan_code: string
          source: string
          subscription_status: string
          tenant_id: string
          updated_at: string
          valid_until: string | null
        }
        Insert: {
          ai_credits_remaining?: number
          automation_runs_remaining?: number
          max_devices?: number | null
          max_members?: number
          max_workspaces?: number
          plan_code?: string
          source?: string
          subscription_status?: string
          tenant_id: string
          updated_at?: string
          valid_until?: string | null
        }
        Update: {
          ai_credits_remaining?: number
          automation_runs_remaining?: number
          max_devices?: number | null
          max_members?: number
          max_workspaces?: number
          plan_code?: string
          source?: string
          subscription_status?: string
          tenant_id?: string
          updated_at?: string
          valid_until?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "tenant_entitlements_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: true
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      tenant_memberships: {
        Row: {
          created_at: string
          identity_id: string
          role: string
          status: string
          tenant_id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          identity_id: string
          role: string
          status?: string
          tenant_id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          identity_id?: string
          role?: string
          status?: string
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "tenant_memberships_identity_id_fkey"
            columns: ["identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "tenant_memberships_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
      tenants: {
        Row: {
          created_at: string
          created_by: string
          encrypted_name: string | null
          id: string
          kind: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          created_by: string
          encrypted_name?: string | null
          id?: string
          kind: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          created_by?: string
          encrypted_name?: string | null
          id?: string
          kind?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "tenants_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
        ]
      }
      vault_item_revisions: {
        Row: {
          aad_hash: string
          algorithm: string
          ciphertext: string
          created_at: string
          created_by: string
          envelope_version: number
          item_id: string
          key_version: number
          nonce: string
          revision: number
          tenant_id: string
          workspace_id: string
        }
        Insert: {
          aad_hash: string
          algorithm: string
          ciphertext: string
          created_at?: string
          created_by: string
          envelope_version: number
          item_id: string
          key_version: number
          nonce: string
          revision: number
          tenant_id: string
          workspace_id: string
        }
        Update: {
          aad_hash?: string
          algorithm?: string
          ciphertext?: string
          created_at?: string
          created_by?: string
          envelope_version?: number
          item_id?: string
          key_version?: number
          nonce?: string
          revision?: number
          tenant_id?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "vault_item_revisions_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "vault_item_revisions_tenant_id_item_id_fkey"
            columns: ["tenant_id", "item_id"]
            isOneToOne: false
            referencedRelation: "vault_items"
            referencedColumns: ["tenant_id", "id"]
          },
          {
            foreignKeyName: "vault_item_revisions_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      vault_items: {
        Row: {
          content_type: string
          created_at: string
          created_by: string
          deleted_at: string | null
          head_revision: number
          id: string
          schema_version: number
          tenant_id: string
          updated_at: string
          workspace_id: string
        }
        Insert: {
          content_type: string
          created_at?: string
          created_by: string
          deleted_at?: string | null
          head_revision?: number
          id?: string
          schema_version: number
          tenant_id: string
          updated_at?: string
          workspace_id: string
        }
        Update: {
          content_type?: string
          created_at?: string
          created_by?: string
          deleted_at?: string | null
          head_revision?: number
          id?: string
          schema_version?: number
          tenant_id?: string
          updated_at?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "vault_items_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "vault_items_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      workspace_invites: {
        Row: {
          accepted_at: string | null
          accepted_by: string | null
          created_at: string
          created_by: string
          expires_at: string
          id: string
          key_aad_hash: string
          key_nonce: string
          recipient_email_hash: string
          revoked_at: string | null
          role: string
          status: string
          tenant_id: string
          token_hash: string | null
          updated_at: string
          workspace_id: string
          wrapped_workspace_key: string
        }
        Insert: {
          accepted_at?: string | null
          accepted_by?: string | null
          created_at?: string
          created_by: string
          expires_at: string
          id: string
          key_aad_hash: string
          key_nonce: string
          recipient_email_hash: string
          revoked_at?: string | null
          role: string
          status?: string
          tenant_id: string
          token_hash?: string | null
          updated_at?: string
          workspace_id: string
          wrapped_workspace_key: string
        }
        Update: {
          accepted_at?: string | null
          accepted_by?: string | null
          created_at?: string
          created_by?: string
          expires_at?: string
          id?: string
          key_aad_hash?: string
          key_nonce?: string
          recipient_email_hash?: string
          revoked_at?: string | null
          role?: string
          status?: string
          tenant_id?: string
          token_hash?: string | null
          updated_at?: string
          workspace_id?: string
          wrapped_workspace_key?: string
        }
        Relationships: [
          {
            foreignKeyName: "workspace_invites_accepted_by_fkey"
            columns: ["accepted_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "workspace_invites_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "workspace_invites_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      workspace_memberships: {
        Row: {
          created_at: string
          identity_id: string
          role: string
          status: string
          tenant_id: string
          updated_at: string
          workspace_id: string
        }
        Insert: {
          created_at?: string
          identity_id: string
          role: string
          status?: string
          tenant_id: string
          updated_at?: string
          workspace_id: string
        }
        Update: {
          created_at?: string
          identity_id?: string
          role?: string
          status?: string
          tenant_id?: string
          updated_at?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "workspace_memberships_identity_id_fkey"
            columns: ["identity_id"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "workspace_memberships_tenant_id_identity_id_fkey"
            columns: ["tenant_id", "identity_id"]
            isOneToOne: false
            referencedRelation: "tenant_memberships"
            referencedColumns: ["tenant_id", "identity_id"]
          },
          {
            foreignKeyName: "workspace_memberships_tenant_id_workspace_id_fkey"
            columns: ["tenant_id", "workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["tenant_id", "id"]
          },
        ]
      }
      workspaces: {
        Row: {
          created_at: string
          created_by: string
          current_key_version: number
          encrypted_name: string | null
          id: string
          key_rotation_required: boolean
          kind: string
          name_aad_hash: string | null
          name_nonce: string | null
          status: string
          suite: string
          tenant_id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          created_by: string
          current_key_version?: number
          encrypted_name?: string | null
          id?: string
          key_rotation_required?: boolean
          kind?: string
          name_aad_hash?: string | null
          name_nonce?: string | null
          status?: string
          suite?: string
          tenant_id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          created_by?: string
          current_key_version?: number
          encrypted_name?: string | null
          id?: string
          key_rotation_required?: boolean
          kind?: string
          name_aad_hash?: string | null
          name_nonce?: string | null
          status?: string
          suite?: string
          tenant_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "workspaces_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "identities"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "workspaces_tenant_id_fkey"
            columns: ["tenant_id"]
            isOneToOne: false
            referencedRelation: "tenants"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      accept_access_capsule: {
        Args: {
          p_capsule_id: string
          p_recipient_key_aad_hash: string
          p_recipient_key_nonce: string
          p_recipient_wrapped_key: string
          p_token_hash: string
        }
        Returns: undefined
      }
      accept_organization_invitation: {
        Args: { p_invitation_id: string; p_token_hash: string }
        Returns: Json
      }
      accept_workspace_invite: {
        Args: {
          p_invite_id: string
          p_root_key_nonce: string
          p_root_wrapped_workspace_key: string
          p_token_hash: string
        }
        Returns: Json
      }
      apply_stripe_billing_event: {
        Args: {
          p_api_version: string
          p_billing_interval?: string
          p_cancel_at_period_end?: boolean
          p_canceled_at?: string
          p_currency?: string
          p_customer_id: string
          p_event_id: string
          p_event_type: string
          p_livemode: boolean
          p_payload_sha256: string
          p_period_ends_at?: string
          p_period_started_at?: string
          p_plan_code?: string
          p_price_id?: string
          p_product_id?: string
          p_quantity?: number
          p_status?: string
          p_subscription_id?: string
          p_tenant_id: string
        }
        Returns: boolean
      }
      apply_stripe_billing_event_checked: {
        Args: {
          p_api_version: string
          p_billing_interval?: string
          p_cancel_at_period_end?: boolean
          p_canceled_at?: string
          p_currency?: string
          p_customer_id: string
          p_event_id: string
          p_event_type: string
          p_livemode: boolean
          p_payload_sha256: string
          p_period_ends_at?: string
          p_period_started_at?: string
          p_plan_code?: string
          p_price_id?: string
          p_product_id?: string
          p_quantity?: number
          p_status?: string
          p_subscription_id?: string
          p_tenant_id: string
        }
        Returns: boolean
      }
      bootstrap_personal_vault: {
        Args: {
          p_device_public_key: string
          p_kdf_parameters: Json
          p_master_nonce: string
          p_master_wrapped_root: string
          p_recovery_nonce: string
          p_recovery_verifier: string
          p_recovery_wrapped_root: string
          p_salt: string
          p_workspace_nonce: string
          p_workspace_wrapped_key: string
        }
        Returns: Json
      }
      consume_access_capsule: {
        Args: { p_capsule_id: string }
        Returns: number
      }
      create_attachment: {
        Args: {
          p_aad_hash: string
          p_attachment_id: string
          p_ciphertext_sha256: string
          p_ciphertext_size: number
          p_encrypted_metadata: string
          p_item_id: string
          p_key_version: number
          p_metadata_aad_hash: string
          p_metadata_nonce: string
          p_nonce: string
          p_storage_path: string
          p_tenant_id: string
          p_workspace_id: string
        }
        Returns: undefined
      }
      create_mission: {
        Args: {
          p_definition_aad_hash: string
          p_definition_nonce: string
          p_encrypted_definition: string
          p_item_ids: string[]
          p_mission_id: string
          p_tenant_id: string
          p_workspace_id: string
        }
        Returns: undefined
      }
      create_shared_workspace: {
        Args: {
          p_encrypted_name: string
          p_key_nonce: string
          p_name_aad_hash: string
          p_name_nonce: string
          p_suite: string
          p_tenant_id: string
          p_workspace_id: string
          p_workspace_kind: string
          p_wrapped_workspace_key: string
        }
        Returns: Json
      }
      create_vault_item: {
        Args: {
          p_aad_hash: string
          p_ciphertext: string
          p_content_type: string
          p_item_id: string
          p_nonce: string
          p_schema_version: number
          p_tenant_id: string
          p_workspace_id: string
        }
        Returns: number
      }
      decide_access_request: {
        Args: { p_decision: string; p_request_id: string }
        Returns: string
      }
      delete_vault_item: {
        Args: { p_expected_revision: number; p_item_id: string }
        Returns: undefined
      }
      evaluate_organization_device_readiness: {
        Args: {
          p_device_id: string
          p_identity_id: string
          p_tenant_id: string
        }
        Returns: Json
      }
      export_organization_audit: {
        Args: {
          p_after_sequence?: number
          p_limit?: number
          p_tenant_id: string
        }
        Returns: {
          action: string
          actor_identity_id: string
          event_hash: string
          metadata: Json
          occurred_at: string
          previous_hash: string
          sequence: number
          target_id: string
          target_type: string
        }[]
      }
      manage_organization_member_lifecycle: {
        Args: {
          p_department_id?: string
          p_event_type: string
          p_identity_id: string
          p_reason_code?: string
          p_tenant_id: string
        }
        Returns: undefined
      }
      onboard_organization_member: {
        Args: {
          p_department_id?: string
          p_display_name: string
          p_identity_id: string
          p_job_title?: string
          p_tenant_id: string
        }
        Returns: undefined
      }
      phase5_saas_dashboard: { Args: { p_tenant_id: string }; Returns: Json }
      refresh_saas_recommendations: {
        Args: { p_tenant_id: string }
        Returns: number
      }
      reserve_phase5_budget: {
        Args: {
          p_budget_id: string
          p_quantity: number
          p_source_ref_hash: string
          p_tenant_id: string
        }
        Returns: Json
      }
      resolve_organization_policies: {
        Args: { p_identity_id: string; p_tenant_id: string }
        Returns: {
          configuration: Json
          policy_id: string
          policy_type: string
          priority: number
          source_scope_id: string
          source_scope_type: string
          version: number
        }[]
      }
      restore_vault_item: {
        Args: { p_expected_revision: number; p_item_id: string }
        Returns: undefined
      }
      revoke_access_capsule: {
        Args: { p_capsule_id: string }
        Returns: undefined
      }
      revoke_organization_invitation: {
        Args: { p_invitation_id: string }
        Returns: undefined
      }
      revoke_workspace_invite: {
        Args: { p_invite_id: string }
        Returns: undefined
      }
      revoke_workspace_member: {
        Args: { p_identity_id: string; p_workspace_id: string }
        Returns: undefined
      }
      rotate_master_with_recovery: {
        Args: {
          p_kdf_parameters: Json
          p_master_nonce: string
          p_master_wrapped_root: string
          p_recovery_verifier: string
          p_salt: string
        }
        Returns: undefined
      }
      set_recovery_verifier_once: {
        Args: { p_verifier: string }
        Returns: undefined
      }
      update_vault_item: {
        Args: {
          p_aad_hash: string
          p_ciphertext: string
          p_expected_revision: number
          p_item_id: string
          p_nonce: string
        }
        Returns: number
      }
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends (DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never) = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends (PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never) = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {},
  },
} as const
