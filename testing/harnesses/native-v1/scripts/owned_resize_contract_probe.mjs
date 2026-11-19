/** Fixed receiver/error-semantics experiment; no geometry, identity or classifier.
 * CSS Sizing 4 specifies requestResize() with no arguments and requires an
 * opted-in iframe document. Main/blank frames here deliberately do not opt in.
 * API availability alone is not a product-owned artifact.
 */
export function probeResizeContracts() {
  const cases = ["direct", "extra-argument-trap", "foreign-receiver"];
  const borrowed = ["main-on-frame", "frame-on-main"];
  const rows = [];
  const before = { url: location.href, history: history.length,
    frames: document.querySelectorAll("iframe").length };
  const sentinel = {};
  const allowed = ["TypeError", "NotAllowedError", "SecurityError", "InvalidStateError"];
  function observe(context, name, source, receiver) {
    const row = { context, case: name, state: "observed", outcome: "unsupported",
      zero_arity: null, argument_touched: false };
    rows.push(row);
    try {
      const fn = source?.requestResize;
      if (typeof fn !== "function") { row.state = "unsupported"; return; }
      row.zero_arity = fn.length === 0;
      const trap = new Proxy({}, { get() { row.argument_touched = true; throw sentinel; },
        ownKeys() { row.argument_touched = true; throw sentinel; } });
      const value = Reflect.apply(fn, name === "foreign-receiver" ? {} : receiver,
        name === "extra-argument-trap" ? [trap] : []);
      row.outcome = value === undefined ? "returned-undefined" : "returned-other";
    } catch (error) {
      if (error === sentinel) row.outcome = "sentinel";
      else {
        try { row.outcome = allowed.includes(error?.name) ? error.name : "unrecognized-error"; }
        catch { row.outcome = "unrecognized-error"; }
        if (row.outcome === "unrecognized-error") row.state = "UNKNOWN";
      }
    }
  }
  for (const name of cases) observe("main", name, globalThis, globalThis);
  let frame;
  let cleaned = true;
  try {
    frame = document.createElement("iframe");
    frame.style.display = "none";
    document.documentElement.appendChild(frame);
    const realm = frame.contentWindow;
    if (!realm || realm === globalThis) throw sentinel;
    for (const name of cases) observe("frame", name, realm, realm);
    observe("borrowed", borrowed[0], globalThis, realm);
    observe("borrowed", borrowed[1], realm, globalThis);
  } catch {
    for (const [context, schedule] of [["frame", cases], ["borrowed", borrowed]]) {
      for (const name of schedule) if (!rows.some(row => row.context === context && row.case === name)) {
        rows.push({ context, case: name, state: "UNKNOWN", outcome: "realm-unavailable",
          zero_arity: null, argument_touched: false });
      }
    }
  } finally {
    try { if (frame) { frame.remove(); cleaned = frame.isConnected === false; } }
    catch { cleaned = false; }
  }
  return { diagnostic_only: true, classification: "NOT_A_CLASSIFIER", rows,
    cleanup_confirmed: cleaned, url_restored: location.href === before.url,
    history_unchanged: history.length === before.history,
    frame_count_restored: document.querySelectorAll("iframe").length === before.frames };
}

export function validResizeStudy(value) {
  const keys = ["diagnostic_only", "classification", "rows", "cleanup_confirmed",
    "url_restored", "history_unchanged", "frame_count_restored"];
  const schedule = ["main:direct", "main:extra-argument-trap", "main:foreign-receiver",
    "frame:direct", "frame:extra-argument-trap", "frame:foreign-receiver",
    "borrowed:main-on-frame", "borrowed:frame-on-main"];
  const outcomes = ["returned-undefined", "returned-other", "TypeError", "NotAllowedError",
    "SecurityError", "InvalidStateError", "sentinel", "unrecognized-error", "unsupported", "realm-unavailable"];
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)) &&
    value.diagnostic_only === true && value.classification === "NOT_A_CLASSIFIER" &&
    keys.slice(3).every(key => typeof value[key] === "boolean") &&
    Array.isArray(value.rows) && value.rows.length === schedule.length &&
    value.rows.every((row, index) => row && typeof row === "object" && !Array.isArray(row) &&
      Object.keys(row).length === 6 && ["context", "case", "state", "outcome", "zero_arity", "argument_touched"]
        .every(key => Object.hasOwn(row, key)) &&
      `${row.context}:${row.case}` === schedule[index] &&
      ["observed", "unsupported", "UNKNOWN"].includes(row.state) && outcomes.includes(row.outcome) &&
      (row.zero_arity === null || typeof row.zero_arity === "boolean") &&
      typeof row.argument_touched === "boolean" &&
      (row.state === "unsupported" ? row.outcome === "unsupported" && row.zero_arity === null :
        row.state === "UNKNOWN" ? ["unrecognized-error", "realm-unavailable"].includes(row.outcome) :
          !["unrecognized-error", "realm-unavailable", "unsupported"].includes(row.outcome) &&
            typeof row.zero_arity === "boolean"));
}
