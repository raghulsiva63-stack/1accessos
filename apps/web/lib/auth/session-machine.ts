export type AuthSessionTransition = {
  nextUserId: string | null;
  accountChanged: boolean;
  clearVaultState: boolean;
  passwordRecovery: boolean;
};

/**
 * Supabase can emit SIGNED_IN again for reauthentication and TOKEN_REFRESHED
 * throughout a session. Those events must never remount vault setup or discard
 * an in-memory recovery key. Only an actual account boundary clears vault state.
 */
export function authSessionTransition(
  previousUserId: string | null,
  nextUserId: string | null,
  event: string,
): AuthSessionTransition {
  const accountChanged = previousUserId !== nextUserId;
  return {
    nextUserId,
    accountChanged,
    clearVaultState: accountChanged || nextUserId === null,
    passwordRecovery: event === "PASSWORD_RECOVERY" && nextUserId !== null,
  };
}
