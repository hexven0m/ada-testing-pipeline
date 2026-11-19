/** Test-only opaque-value semantics motivated by Octium's native API tracer.
 * Extra conversion is a research lead, never sufficient vendor attribution.
 * These APIs should preserve an arbitrary reason/detail without serializing it.
 */
export function probeApiTraceContracts(context) {
  const rows = [];
  for (const name of ["controllerReason", "staticSignalReason", "customEventDetail", "messageEventData"]) {
    const hooks = { primitiveRead: 0, primitiveCall: 0, stringRead: 0,
      stringCall: 0, jsonRead: 0, jsonCall: 0, tagRead: 0 };
    const value = Object.create(null);
    Object.defineProperties(value, {
      [Symbol.toPrimitive]: { get() { hooks.primitiveRead++; return () => { hooks.primitiveCall++; return "fixed"; }; } },
      [Symbol.toStringTag]: { get() { hooks.tagRead++; return "FixedTestValue"; } },
      toString: { get() { hooks.stringRead++; return () => { hooks.stringCall++; return "fixed"; }; } },
      toJSON: { get() { hooks.jsonRead++; return () => { hooks.jsonCall++; return "fixed"; }; } },
    });
    const row = { name, state: "observed", identityPreserved: null, hooks };
    try {
      let returned;
      if (name === "controllerReason") {
        if (typeof context.AbortController !== "function") { row.state = "unsupported"; rows.push(row); continue; }
        const controller = new context.AbortController();
        controller.abort(value);
        returned = controller.signal.reason;
      } else if (name === "staticSignalReason") {
        if (typeof context.AbortSignal?.abort !== "function") { row.state = "unsupported"; rows.push(row); continue; }
        returned = context.AbortSignal.abort(value).reason;
      } else if (name === "customEventDetail") {
        if (typeof context.CustomEvent !== "function") { row.state = "unsupported"; rows.push(row); continue; }
        returned = new context.CustomEvent("fixed-contract-test", { detail: value }).detail;
      } else {
        if (typeof context.MessageEvent !== "function") { row.state = "unsupported"; rows.push(row); continue; }
        returned = new context.MessageEvent("fixed-contract-test", { data: value }).data;
      }
      row.identityPreserved = returned === value;
    } catch { row.state = "test-error"; }
    rows.push(row);
  }
  return { classification: "NOT_A_CLASSIFIER", rows };
}
