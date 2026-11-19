/** Owned-session research only; fixed invalid receivers, no browser identity reads.
 * Web IDL checks the receiver before converting arguments. A patch that reads
 * an argument first can expose a semantic difference despite native-looking code.
 * An anomaly is NOT proof of Octo: ordinary wrappers/extensions can do this too.
 */
export async function probeBrandArgumentOrder(context, { timeoutMs = 250 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 1000) {
    throw new RangeError("Invalid observation budget");
  }
  const definitions = [
    ["Permissions", "query"], ["NavigatorUAData", "getHighEntropyValues"],
    ["RTCPeerConnection", "setConfiguration"], ["RTCDataChannel", "send"],
    ["HTMLCanvasElement", "toDataURL"], ["OffscreenCanvas", "convertToBlob"],
    ["WebGLRenderingContext", "getParameter"], ["WebGL2RenderingContext", "getParameter"],
  ];
  const rows = await Promise.all(definitions.map(async ([owner, method]) => {
    const hooks = { get: 0, has: 0, ownKeys: 0, descriptor: 0 };
    const sentinel = Object.create(null);
    let tracking = true;
    function accessed(kind) {
      if (tracking) hooks[kind] = Math.min(32, hooks[kind] + 1);
      throw sentinel;
    }
    // A poisoned argument stops conversion before the API could do real work.
    // The receiver is never navigator, a real permission object or a GPU context.
    const argument = new Proxy(Object.create(null), {
      get() { return accessed("get"); }, has() { return accessed("has"); },
      ownKeys() { return accessed("ownKeys"); },
      getOwnPropertyDescriptor() { return accessed("descriptor"); },
    });
    const row = { owner, method, state: "observed", outcome: "unavailable", hooks };
    function failure(error) {
      if (error === sentinel) return "argument-access";
      try { return error?.name === "TypeError" ? "TypeError" : "other-error"; }
      catch { row.state = "UNKNOWN"; return "UNKNOWN"; }
    }
    let timer;
    try {
      const prototype = context[owner]?.prototype;
      const fn = prototype && Object.getOwnPropertyDescriptor(prototype, method)?.value;
      if (typeof fn !== "function") { row.state = "unsupported"; return row; }
      let returned;
      try { returned = Reflect.apply(fn, Object.create(null), [argument]); }
      catch (error) { row.outcome = "throw-" + failure(error); return row; }
      let promise;
      try {
        // Intrinsic handler accepts only genuine Promises, never arbitrary thenables.
        promise = Promise.prototype.then.call(returned, () => "resolved", error => "reject-" + failure(error));
      } catch { row.outcome = "returned-non-promise"; return row; }
      row.outcome = await Promise.race([promise, new Promise(resolve => {
        timer = setTimeout(() => resolve("timeout"), timeoutMs);
      })]);
      if (row.outcome === "timeout" || row.outcome.includes("UNKNOWN")) row.state = "UNKNOWN";
    } catch { row.state = "UNKNOWN"; row.outcome = "descriptor-unavailable"; }
    finally { tracking = false; clearTimeout(timer); }
    if (row.outcome.includes("UNKNOWN")) row.state = "UNKNOWN";
    return row;
  }));
  return { classification: "NOT_A_CLASSIFIER", rows };
}
