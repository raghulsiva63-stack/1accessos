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
      accept_workspace_invite: {
        Args: {
          p_invite_id: string
          p_root_key_nonce: string
          p_root_wrapped_workspace_key: string
          p_token_hash: string
        }
        Returns: Json
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
      restore_vault_item: {
        Args: { p_expected_revision: number; p_item_id: string }
        Returns: undefined
      }
      revoke_access_capsule: {
        Args: { p_capsule_id: string }
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
