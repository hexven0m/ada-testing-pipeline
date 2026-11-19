/** Read-only console diagnostics. Never retain raw errors, paths or page data. */
export class DetectorErrorEvidence {
  constructor() { this.errors = []; this.traces = []; }
  event(message) {
    if (message.method !== "Runtime.consoleAPICalled") return;
    const args = message.params.args;
    if (!Array.isArray(args) || args[0]?.type !== "string") return;
    if (message.params.type === "debug" && args[0].value === "ADA mode diagnostic:") {
      const stages = ["begin", "message", "ready", "printed", "responded", "pre-bounce", "bounced",
        "final-events", "exception", "cleaned", "ineligible"];
      try {
        const value = JSON.parse(args[1]?.value);
        const names = ["ready", "before", "after", "returned", "pong", "threw"];
        if (this.traces.length < 32 && stages.includes(value.stage) &&
            (value.events === null || (value.events && names.every(name => typeof value.events[name] === "boolean"))) &&
            Number.isFinite(value.elapsed_ms) && value.elapsed_ms >= 0 && value.elapsed_ms < 30000) {
          this.traces.push({ stage: value.stage, elapsed_ms: value.elapsed_ms,
            events: value.events === null ? null : Object.fromEntries(names.map(name => [name, value.events[name]])) });
        }
      } catch { /* Ignore malformed diagnostics and unrelated content. */ }
      return;
    }
    if (message.params.type !== "error") return;
    const match = /^Error calling detect_(headless|ads_power|dolphin_anty|gologin|multilogin|octo):$/.exec(args[0].value);
    if (!match || this.errors.length >= 32) return;
    const description = args[1]?.description;
    const incomplete = typeof description === "string" &&
      /^Error: Mode observation unavailable(?:\n|$)/.test(description);
    this.errors.push({ detector: match[1], category: incomplete ? "mode-observation-unavailable" : "UNKNOWN" });
  }
}
