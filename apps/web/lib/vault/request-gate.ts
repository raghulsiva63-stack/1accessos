type Ticket = { scope: string; generation: number; channel: string; version: number };

/** Prevent responses from an obsolete selection or request from reaching the UI. */
export class WorkspaceRequestGate {
  private scope: string | null = null;
  private generation = 0;
  private versions = new Map<string, number>();
  select(scope: string | null) {
    this.scope = scope;
    this.generation += 1;
    this.versions.clear();
  }
  issue(scope: string, channel: string): Ticket | null {
    if (scope !== this.scope) return null;
    const version = (this.versions.get(channel) ?? 0) + 1;
    this.versions.set(channel, version);
    return { scope, generation: this.generation, channel, version };
  }
  accepts(ticket: Ticket | null) {
    return ticket !== null && ticket.scope === this.scope && ticket.generation === this.generation && this.versions.get(ticket.channel) === ticket.version;
  }
}
