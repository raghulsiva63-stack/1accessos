type SessionArea = {
  get(key: string): Promise<Record<string, unknown>>;
  set(values: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
};

// Supabase owns refresh-token rotation; the adapter persists its current session
// in Chrome's trusted, browser-session-only area, never storage.local.
export function sessionStorageAdapter(area: SessionArea) {
  return {
    async getItem(key: string): Promise<string | null> {
      const value = (await area.get(key))[key];
      return typeof value === 'string' ? value : null;
    },
    async setItem(key: string, value: string) { await area.set({ [key]: value }); },
    async removeItem(key: string) { await area.remove(key); },
  };
}
