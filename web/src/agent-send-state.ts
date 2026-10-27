export class AgentMessageSendState {
  private inFlight = false;
  private pending?: { content: string; id: string };

  begin(content: string, createID: () => string): string | undefined {
    if (this.inFlight) return undefined;
    if (this.pending?.content !== content) {
      this.pending = { content, id: createID() };
    }
    this.inFlight = true;
    return this.pending.id;
  }

  complete(sent: boolean) {
    this.inFlight = false;
    if (sent) this.pending = undefined;
  }
}
