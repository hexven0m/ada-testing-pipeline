/** Owned-session research only. Fixed-input API semantics, never a classifier.
 * No device values, rendered coordinates, permission states, offers, or ICE.
 * Self-contained because the harness serializes this function into the page.
 */
export async function probeJointContracts(context, { timeoutMs = 400 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 1000) {
    throw new RangeError("Invalid observation budget");
  }
  const errors = new Set(["TypeError", "InvalidStateError", "NotSupportedError",
    "SecurityError", "SyntaxError", "InvalidAccessError", "OperationError"]);
  function category(error, sentinel) {
    if (error === sentinel) return "sentinel";
    try { return errors.has(error?.name) ? error.name : "UNKNOWN"; }
    catch { return "UNKNOWN"; }
  }
  function attempt(fn, sentinel) {
    try { fn(); return "returned"; }
    catch (error) { return category(error, sentinel); }
  }
  function unknown() { return { state: "UNKNOWN" }; }
  function unsupported() { return { state: "unsupported" }; }
  function observed(values) {
    return { state: JSON.stringify(values).includes('"UNKNOWN"') ? "UNKNOWN" : "observed", values };
  }
  async function observe(realm) {
    const result = { rectList: unsupported(), permissionConversion: unsupported(), closedPeer: unsupported() };
    const sentinel = Object.create(null);
    let element;
    try {
      if (realm?.document?.body && typeof realm.DOMRectList === "function") {
        element = realm.document.createElement("div");
        element.style.cssText = "position:fixed;left:-2000px;top:0;width:13px;height:17px;visibility:hidden";
        realm.document.body.appendChild(element);
        const list = element.getClientRects();
        // A missing layout box is not a positive signal.
        if (list.length !== 1) result.rectList = unknown();
        else {
          const descriptor = Object.getOwnPropertyDescriptor(list, "0");
          const item = realm.DOMRectList.prototype.item;
          const trace = [];
          const index = { valueOf() { trace.push("valueOf"); return 0; },
            toString() { trace.push("toString"); return "0"; } };
          result.rectList = observed({
            instance: list instanceof realm.DOMRectList,
            sameObject: list[0] === list[0] && list[0] === list.item(0),
            stringIndex: list.item("0") === list[0], nullIndex: list.item(null) === list[0],
            outsideNull: list.item(99) === null, negativeNull: list.item(-1) === null,
            ownData: Boolean(descriptor && "value" in descriptor),
            enumerable: descriptor?.enumerable === true,
            configurable: descriptor?.configurable === true,
            writable: descriptor?.writable === true,
            noArgument: attempt(() => item.call(list), sentinel),
            bigintIndex: attempt(() => item.call(list, 0n), sentinel),
            invalidReceiver: attempt(() => item.call({}, index), sentinel),
            receiverTrace: trace.splice(0),
            coercionSame: item.call(list, index) === list[0], coercionTrace: trace.splice(0),
            throwingIndex: attempt(() => item.call(list, { valueOf() { throw sentinel; } }), sentinel),
          });
        }
      }
    } catch { result.rectList = unknown(); }
    finally { try { if (element) element.remove(); } catch { result.rectList = unknown(); } }

    try {
      const permissions = realm?.navigator?.permissions;
      if (typeof permissions?.query === "function") {
        const query = permissions.query;
        const cases = ["invalid-name", "throwing-name", "invalid-receiver"];
        const rows = await Promise.all(cases.map(async name => {
          const trace = [];
          const input = { get name() {
            trace.push("name");
            if (name === "throwing-name") throw sentinel;
            return { toString() { trace.push("toString"); return "ada-not-a-permission"; } };
          } };
          let value;
          try { value = query.call(name === "invalid-receiver" ? {} : permissions, input); }
          catch (error) { return { name, boundary: "throw", outcome: category(error, sentinel), trace }; }
          const returnTrace = trace.slice();
          let timer;
          try {
            const pending = Promise.prototype.then.call(value, () => "resolved",
              error => category(error, sentinel));
            const outcome = await Promise.race([pending, new Promise(resolve => {
              timer = setTimeout(() => resolve("UNKNOWN"), timeoutMs);
            })]);
            return { name, boundary: "promise", outcome, returnTrace, trace };
          } catch { return { name, boundary: "not-a-promise", trace }; }
          finally { clearTimeout(timer); }
        }));
        result.permissionConversion = observed(rows);
      }
    } catch { result.permissionConversion = unknown(); }

    let peer;
    try {
      if (typeof realm?.RTCPeerConnection === "function") {
        peer = new realm.RTCPeerConnection({ iceServers: [], iceCandidatePoolSize: 0 });
        peer.close();
        const rows = [];
        for (const name of ["empty", "invalid-enum", "throwing-getter", "empty-iterator", "invalid-receiver"]) {
          const trace = [];
          const config = name === "empty" ? {} : {
            get bundlePolicy() {
              trace.push("bundlePolicy");
              if (name === "throwing-getter") throw sentinel;
              return name === "invalid-enum" ? "ada-invalid" : "balanced";
            },
            get iceServers() {
              trace.push("iceServers");
              return { [Symbol.iterator]() {
                trace.push("iterator");
                return { next() { trace.push("next"); return { done: true }; } };
              } };
            },
          };
          rows.push({ name, outcome: attempt(() => realm.RTCPeerConnection.prototype.setConfiguration.call(
            name === "invalid-receiver" ? {} : peer, config), sentinel), trace });
        }
        result.closedPeer = observed(rows);
      }
    } catch { result.closedPeer = unknown(); }
    finally { try { if (peer) peer.close(); } catch { result.closedPeer = unknown(); } }
    return result;
  }
  const main = await observe(context);
  let frame;
  let child = null;
  let cleanupConfirmed = true;
  try {
    if (context?.document?.body) {
      frame = context.document.createElement("iframe");
      frame.style.cssText = "position:fixed;left:-4000px;top:0;width:300px;height:200px;visibility:hidden";
      context.document.body.appendChild(frame);
      if (frame.contentWindow?.document?.body) child = await observe(frame.contentWindow);
    }
  } catch { child = null; }
  finally {
    try { if (frame) { frame.remove(); cleanupConfirmed = !frame.isConnected; } }
    catch { cleanupConfirmed = false; }
  }
  const complete = cleanupConfirmed && child !== null && [main, child].every(realm =>
    Object.values(realm).every(family => family.state === "observed"));
  return { version: 1, state: complete ? "observed" : "UNKNOWN", main, frame: child,
    crossRealmEqual: complete ? JSON.stringify(main) === JSON.stringify(child) : null, cleanupConfirmed };
}

/** Diagnostic failure must not discard an already measured detector verdict. */
export async function collectJointContracts(send, sessionId) {
  try {
    const response = await send("Runtime.evaluate", {
      expression: `(${probeJointContracts.toString()})(window)`,
      awaitPromise: true, returnByValue: true,
    }, sessionId);
    if (response.error || response.result?.exceptionDetails) return { state: "UNKNOWN", reason: "evaluation" };
    const value = response.result?.result?.value;
    if (value?.version !== 1 || !["observed", "UNKNOWN"].includes(value.state)) {
      return { state: "UNKNOWN", reason: "result-contract" };
    }
    return value;
  } catch { return { state: "UNKNOWN", reason: "transport" }; }
}
