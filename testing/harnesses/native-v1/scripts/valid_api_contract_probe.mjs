/** Fixed-input, valid-receiver research. No vendor classification or device reads.
 * Self-contained so the owned-session harness can evaluate it in a page.
 */
export async function probeValidApiContracts(context, { timeoutMs = 400 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 1000) {
    throw new RangeError("Invalid observation budget");
  }
  const allowedErrors = new Set(["TypeError", "InvalidStateError", "NotSupportedError",
    "SecurityError", "SyntaxError", "InvalidAccessError", "OperationError"]);
  function category(error, sentinel) {
    if (sentinel && error === sentinel) return "sentinel";
    try { return allowedErrors.has(error?.name) ? error.name : "UNKNOWN"; }
    catch { return "UNKNOWN"; }
  }
  function tracked(values, trace, sentinelKey = null, sentinel = null) {
    const known = new Set([...Object.keys(values), "toJSON"]);
    function record(value) { if (trace.length < 64) trace.push(value); }
    return new Proxy(values, {
      get(target, key) {
        record(typeof key === "string" && known.has(key) ? key : "other-key");
        if (key === sentinelKey) throw sentinel;
        return Reflect.get(target, key);
      },
      ownKeys(target) { record("ownKeys"); return Reflect.ownKeys(target); },
      getOwnPropertyDescriptor(target, key) {
        record("descriptor"); return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });
  }
  async function observe(realm) {
    const rows = [];
    const sentinel = Object.create(null);
    function sync(name, available, callback) {
      const row = { name, state: available ? "observed" : "unsupported", trace: [] };
      rows.push(row);
      if (!available) return;
      try {
        Object.assign(row, callback(row.trace));
        if (row.outcome === "UNKNOWN" || row.afterClose === "UNKNOWN") row.state = "UNKNOWN";
      }
      catch (error) { row.state = "UNKNOWN"; row.error = category(error, sentinel); }
    }
    const Candidate = realm.RTCIceCandidate;
    // Documentation-range address is supplied by this probe, never discovered.
    const fixed = { candidate: "candidate:1 1 udp 2122260223 192.0.2.1 5000 typ host",
      sdpMid: "ada-fixed", sdpMLineIndex: 0, usernameFragment: "ada-test" };
    const keys = Object.keys(fixed);
    sync("candidate-roundtrip", typeof Candidate === "function", trace => {
      const input = { ...fixed };
      const candidate = new Candidate(tracked(input, trace));
      input.candidate = "";
      const a = candidate.toJSON();
      const b = candidate.toJSON();
      const copy = new Candidate(a);
      const snapshot = keys.every(key => candidate[key] === fixed[key]);
      const jsonMatches = keys.every(key => a[key] === fixed[key]);
      const reconstructed = keys.every(key => copy[key] === fixed[key]);
      a.candidate = "";
      return { snapshot, jsonMatches, reconstructed, independentJSON: a !== b &&
        candidate.candidate === fixed.candidate && b.candidate === fixed.candidate };
    });
    sync("candidate-coercion", typeof Candidate === "function", trace => {
      const text = { [Symbol.toPrimitive](hint) {
        trace.push(hint === "string" ? "primitive-string" : "primitive-other");
        return fixed.candidate;
      } };
      const candidate = new Candidate(tracked({ ...fixed, candidate: text }, trace));
      return { matches: candidate.candidate === fixed.candidate };
    });
    sync("candidate-getter-error", typeof Candidate === "function", trace => {
      try { new Candidate(tracked({ ...fixed }, trace, "sdpMid", sentinel)); }
      catch (error) { return { outcome: category(error, sentinel) }; }
      return { outcome: "returned" };
    });
    sync("candidate-missing-mid", typeof Candidate === "function", trace => {
      try { new Candidate(tracked({ candidate: fixed.candidate }, trace)); }
      catch (error) { return { outcome: category(error) }; }
      return { outcome: "returned" };
    });
    const Peer = realm.RTCPeerConnection;
    let peer;
    sync("peer-configuration", typeof Peer === "function", trace => {
      try {
        peer = new Peer({ iceServers: [], iceCandidatePoolSize: 0 });
        const config = { iceServers: [], iceTransportPolicy: "relay", bundlePolicy: "balanced",
          rtcpMuxPolicy: "require", iceCandidatePoolSize: 0 };
        peer.setConfiguration(tracked(config, trace));
        const a = peer.getConfiguration();
        const b = peer.getConfiguration();
        a.iceServers.push({ urls: "stun:invalid.example" }); // Local copy only; never applied.
        a.iceTransportPolicy = "all";
        const c = peer.getConfiguration();
        const result = { fixedPolicy: b.iceTransportPolicy === "relay",
          independentConfig: a !== b && b !== c && c.iceServers.length === 0 &&
            c.iceTransportPolicy === "relay" };
        peer.close();
        peer.close();
        result.closed = peer.signalingState === "closed";
        try { peer.setConfiguration(config); result.afterClose = "returned"; }
        catch (error) { result.afterClose = category(error); }
        return result;
      } finally { if (peer) peer.close(); }
    });
    async function permission(name, value, throwing = false) {
      const row = { name, state: "observed", trace: [] };
      rows.push(row);
      let timer;
      try {
        const permissions = realm.navigator?.permissions;
        if (typeof permissions?.query !== "function") { row.state = "unsupported"; return; }
        const input = tracked({ name: value }, row.trace, throwing ? "name" : null, sentinel);
        let returned;
        try { returned = permissions.query(input); }
        catch (error) { row.outcome = "throw-" + category(error, sentinel); return; }
        let pending;
        try {
          pending = Promise.prototype.then.call(returned, () => "resolved",
            error => "reject-" + category(error, sentinel));
        } catch { row.outcome = "not-a-promise"; return; }
        row.outcome = await Promise.race([pending, new Promise(resolve => {
          timer = setTimeout(() => resolve("timeout"), timeoutMs);
        })]);
        if (row.outcome === "timeout" || row.outcome.includes("UNKNOWN")) row.state = "UNKNOWN";
      } catch { row.state = "UNKNOWN"; }
      finally {
        clearTimeout(timer);
        if (row.outcome?.includes("UNKNOWN")) row.state = "UNKNOWN";
      }
    }
    // Query only: never request permission or read the user's permission state.
    for (const name of ["camera", "microphone", "notifications"]) {
      await permission("permission-" + name, name);
    }
    await permission("permission-invalid", "ada-unsupported-permission");
    await permission("permission-getter-error", "notifications", true);
    return { rows };
  }
  const result = { classification: "NOT_A_CLASSIFIER", main: await observe(context),
    iframe: { state: "unsupported" }, frameRemoved: false };
  let frame;
  try {
    if (!context.document?.documentElement) return result;
    frame = context.document.createElement("iframe");
    frame.hidden = true;
    frame.setAttribute("aria-hidden", "true");
    context.document.documentElement.appendChild(frame);
    const realm = frame.contentWindow;
    if (!realm || realm === context || realm.Object === context.Object) {
      result.iframe = { state: "UNKNOWN" }; return result;
    }
    result.iframe = await observe(realm);
  } catch { result.iframe = { state: "UNKNOWN" }; }
  finally {
    if (frame) {
      try { frame.remove(); result.frameRemoved = !frame.isConnected; }
      catch { result.frameRemoved = false; }
    }
  }
  return result;
}
