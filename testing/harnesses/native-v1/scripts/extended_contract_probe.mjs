/** Additional owned-session API hypotheses, NOT a classifier.
 * All objects/inputs are synthetic. No media access, device values, ICE,
 * canvas rendering, persistent state, or raw error messages are collected.
 */
export function probeExtendedContracts(context) {
  const families = ["crossRealmBorrowing", "reentrantDictionary", "cloneVsJSON", "emptyMediaStream"];
  const errors = new Set(["TypeError", "DataCloneError", "InvalidStateError", "NotSupportedError"]);
  const fixed = { candidate: "", sdpMid: "ada-synthetic", sdpMLineIndex: 0, usernameFragment: "ada-fixed" };
  function category(error, sentinel) {
    if (error === sentinel) return "sentinel";
    try { return errors.has(error?.name) ? error.name : "UNKNOWN"; }
    catch { return "UNKNOWN"; }
  }
  function agrees(value, input = fixed) {
    return Boolean(value && Object.keys(input).every(key => value[key] === input[key]));
  }
  function observe(realm, other) {
    const result = Object.fromEntries(families.map(name => [name, { state: "unsupported" }]));
    const sentinel = Object.create(null);
    function run(name, supported, fn) {
      if (!supported) return;
      try {
        const values = fn();
        result[name] = { state: JSON.stringify(values).includes('"UNKNOWN"') ? "UNKNOWN" : "observed", values };
      } catch { result[name] = { state: "UNKNOWN" }; }
    }
    const Candidate = realm?.RTCIceCandidate;
    const candidateSupported = typeof Candidate === "function";
    run("crossRealmBorrowing", candidateSupported && other && other !== realm &&
        typeof other.RTCIceCandidate === "function" && Candidate !== other.RTCIceCandidate, () => {
      const foreign = new other.RTCIceCandidate({ ...fixed });
      const method = Candidate.prototype.toJSON;
      const json = Reflect.apply(method, foreign, []);
      let invalidReceiver;
      try { Reflect.apply(method, {}, []); invalidReceiver = { category: "returned" }; }
      catch (error) {
        invalidReceiver = { category: category(error, sentinel),
          methodRealmTypeError: error instanceof realm.TypeError,
          otherRealmTypeError: error instanceof other.TypeError };
      }
      return { borrowedJSONMatches: agrees(json), objectFromMethodRealm:
        Object.getPrototypeOf(json) === realm.Object.prototype, invalidReceiver };
    });
    run("reentrantDictionary", candidateSupported, () => {
      const trace = [];
      let innerMatches = false;
      const input = { ...fixed };
      Object.defineProperty(input, "candidate", { get() {
        trace.push("candidate-get");
        const nested = { ...fixed, sdpMid: "ada-nested", sdpMLineIndex: 3 };
        innerMatches = agrees(new Candidate(nested).toJSON(), nested);
        trace.push("nested-return");
        input.sdpMLineIndex = 7;
        return "";
      } });
      const outer = new Candidate(input);
      const expected = { ...fixed, sdpMLineIndex: 7 };
      let jsonReads = 0;
      const poisoned = { ...fixed, get toJSON() { jsonReads++; throw sentinel; } };
      let ignoredJSON;
      try { ignoredJSON = agrees(new Candidate(poisoned).toJSON()) ? "preserved" : "changed"; }
      catch (error) { ignoredJSON = category(error, sentinel); }
      return { trace, innerMatches, laterMemberMutationObserved: agrees(outer.toJSON(), expected),
        unusedJSONHook: { reads: jsonReads, outcome: ignoredJSON } };
    });
    run("cloneVsJSON", typeof realm?.DOMRect === "function" && typeof realm?.structuredClone === "function", () => {
      const rect = new realm.DOMRect(7, 11, 13, 17);
      let reads = 0;
      let calls = 0;
      Object.defineProperty(rect, "toJSON", { get() {
        reads++;
        return () => { calls++; return "ada-fixed-json"; };
      } });
      let clone;
      try {
        const copied = realm.structuredClone(rect);
        clone = { outcome: "returned", valuesMatch: copied.x === 7 && copied.y === 11 &&
          copied.width === 13 && copied.height === 17, freshObject: copied !== rect };
      } catch (error) { clone = { outcome: category(error, sentinel) }; }
      clone.hookReads = reads;
      clone.hookCalls = calls;
      reads = 0; calls = 0;
      let jsonMatches;
      try { jsonMatches = realm.JSON.stringify(rect) === '"ada-fixed-json"'; }
      catch { jsonMatches = "UNKNOWN"; }
      const json = { matches: jsonMatches, hookReads: reads, hookCalls: calls };
      let proxyClone;
      try { realm.structuredClone(new Proxy({ value: "fixed" }, {})); proxyClone = "returned"; }
      catch (error) { proxyClone = category(error, sentinel); }
      return { clone, json, proxyClone };
    });
    run("emptyMediaStream", typeof realm?.MediaStream === "function", () => {
      const Stream = realm.MediaStream;
      const stream = new Stream([]);
      const a = stream.getTracks();
      const b = stream.getTracks();
      a.push("ada-fixed"); // Mutate only a returned JS array, never the stream.
      const cloned = stream.clone();
      let fakeTrack;
      try { stream.addTrack({}); fakeTrack = "returned"; }
      catch (error) { fakeTrack = category(error, sentinel); }
      let invalidReceiver;
      try { Reflect.apply(Stream.prototype.getTracks, {}, []); invalidReceiver = "returned"; }
      catch (error) { invalidReceiver = category(error, sentinel); }
      return { independentArrays: a !== b && b.length === 0 && stream.getTracks().length === 0,
        emptyClone: cloned !== stream && cloned.getTracks().length === 0,
        inactive: stream.active === false && cloned.active === false, fakeTrack, invalidReceiver };
    });
    return result;
  }
  let frame;
  let other;
  let main;
  let child = null;
  let cleanupConfirmed = true;
  try {
    if (context?.document?.body) {
      frame = context.document.createElement("iframe");
      frame.style.cssText = "position:fixed;left:-4000px;top:0;width:100px;height:100px;visibility:hidden";
      context.document.body.appendChild(frame);
      other = frame.contentWindow;
    }
    main = observe(context, other);
    if (other && other !== context) child = observe(other, context);
  } catch {
    main = main || Object.fromEntries(families.map(name => [name, { state: "UNKNOWN" }]));
  } finally {
    try { if (frame) { frame.remove(); cleanupConfirmed = !frame.isConnected; } }
    catch { cleanupConfirmed = false; }
  }
  const complete = cleanupConfirmed && child !== null && [main, child].every(realm =>
    families.every(name => realm[name].state === "observed"));
  return { version: 1, state: complete ? "observed" : "UNKNOWN", classification: "NOT_A_CLASSIFIER",
    main, frame: child, crossRealmEqual: complete ? JSON.stringify(main) === JSON.stringify(child) : null,
    cleanupConfirmed };
}

export async function collectExtendedContracts(send, sessionId) {
  try {
    const response = await send("Runtime.evaluate", {
      expression: `(${probeExtendedContracts.toString()})(window)`, returnByValue: true,
    }, sessionId);
    if (response.error || response.result?.exceptionDetails) return { state: "UNKNOWN", reason: "evaluation" };
    const value = response.result?.result?.value;
    if (value?.version !== 1 || !["observed", "UNKNOWN"].includes(value.state)) {
      return { state: "UNKNOWN", reason: "result-contract" };
    }
    return value;
  } catch { return { state: "UNKNOWN", reason: "transport" }; }
}

/** Exercise the capture API's failure path without requesting a device.
 * The valid receiver gets audio:false and video:false, which the Media Capture
 * specification requires to reject before selecting or opening equipment.
 */
export async function probeNoCaptureMediaContract(context) {
  const names = new Set(["TypeError", "NotAllowedError", "NotFoundError", "SecurityError"]);
  function category(error, marker) {
    if (error === marker) return "argument-hook";
    try { return names.has(error?.name) ? error.name : "UNKNOWN"; }
    catch { return "UNKNOWN"; }
  }
  async function observe(realm) {
    const method = realm?.MediaDevices?.prototype?.getUserMedia;
    const real = realm?.navigator?.mediaDevices;
    if (typeof method !== "function" || !real) return { state: "unsupported" };
    const marker = Object.create(null);
    let calls = 0;
    const poisoned = new Proxy({}, {
      get() { calls++; throw marker; },
      ownKeys() { calls++; throw marker; },
      getOwnPropertyDescriptor() { calls++; throw marker; },
    });
    async function invoke(receiver, input) {
      let value;
      try { value = Reflect.apply(method, receiver, [input]); }
      catch (error) { return { boundary: "sync", outcome: category(error, marker) }; }
      let timer;
      try {
        const settled = Promise.prototype.then.call(value,
          () => ({ boundary: "promise", outcome: "resolved" }),
          error => ({ boundary: "promise", outcome: category(error, marker) }));
        return await Promise.race([settled, new Promise(resolve => {
          timer = setTimeout(() => resolve({ boundary: "timeout", outcome: "UNKNOWN" }), 750);
        })]);
      } catch { return { boundary: "non-promise", outcome: "UNKNOWN" }; }
      finally { clearTimeout(timer); }
    }
    const wrongReceiver = await invoke(Object.create(null), poisoned);
    const trace = [];
    const noCapture = {
      get audio() { trace.push("audio"); return false; },
      get video() { trace.push("video"); return false; },
      get toJSON() { trace.push("toJSON"); throw marker; },
    };
    const validReceiver = await invoke(real, noCapture);
    const state = [wrongReceiver, validReceiver].some(row => row.outcome === "UNKNOWN")
      ? "UNKNOWN" : "observed";
    return { state, wrongReceiver: { ...wrongReceiver, argumentHookCalls: calls },
      validReceiver: { ...validReceiver, argumentTrace: trace } };
  }
  let frame = null;
  let main = { state: "UNKNOWN" };
  let child = { state: "UNKNOWN" };
  let cleanupConfirmed = true;
  try {
    main = await observe(context);
    if (context?.document?.body) {
      frame = context.document.createElement("iframe");
      frame.hidden = true;
      context.document.body.appendChild(frame);
      const other = frame.contentWindow;
      if (other && other !== context && other.MediaDevices !== context.MediaDevices) {
        child = await observe(other);
      }
    }
  } catch { /* Keep incomplete or unsupported cases out of classifier evidence. */ }
  finally {
    try { if (frame) { frame.remove(); cleanupConfirmed = !frame.isConnected; } }
    catch { cleanupConfirmed = false; }
  }
  const complete = cleanupConfirmed && main.state === "observed" && child.state === "observed";
  return { version: 1, classification: "NOT_A_CLASSIFIER", state: complete ? "observed" : "UNKNOWN",
    main, frame: child, crossRealmEqual: complete ? JSON.stringify(main) === JSON.stringify(child) : null,
    cleanupConfirmed };
}

export async function collectNoCaptureMediaContract(send, sessionId) {
  try {
    const response = await send("Runtime.evaluate", {
      expression: `(${probeNoCaptureMediaContract.toString()})(window)`,
      awaitPromise: true, returnByValue: true,
    }, sessionId);
    if (response.error || response.result?.exceptionDetails) return { state: "UNKNOWN", reason: "evaluation" };
    const value = response.result?.result?.value;
    return value?.version === 1 && ["observed", "UNKNOWN"].includes(value.state)
      ? value : { state: "UNKNOWN", reason: "result-contract" };
  } catch { return { state: "UNKNOWN", reason: "transport" }; }
}
