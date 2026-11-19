/** Laboratory-only print-event experiment. Never a submission detector. */
export async function probeOwnedPrint(context, { progress = false } = {}) {
  const result = { state: "complete", ready: false, before: false, after: false,
    returned: false, pong: false, threw: false, frameRemoved: false,
    urlRestored: false, historyUnchanged: false, hypothesis: null };
  const originalUrl = context.location.href;
  const originalLength = context.history.length;
  const originalState = context.history.state;
  let bounceUrl = null;
  let frame;
  let listener;
  const pause = ms => new Promise(resolve => context.setTimeout(resolve, ms));
  const wait = async (predicate, limit) => {
    for (let elapsed = 0; elapsed < limit; elapsed += 25) {
      if (predicate()) return true;
      await pause(Math.min(25, limit - elapsed));
    }
    return Boolean(predicate());
  };
  try {
    frame = context.document.createElement("iframe");
    frame.setAttribute("sandbox", "allow-scripts allow-modals");
    frame.style.cssText = "border:0;position:fixed;left:-200px;top:-200px;height:1px;width:1px";
    listener = event => {
      if (event.source !== frame.contentWindow || event.data?.namespace !== "ada-print-lab-v1") return;
      const key = event.data.event;
      if (["ready", "before", "after", "returned", "pong", "threw"].includes(key)) {
        result[key] = true;
        if (progress) context.console.log("ada-owned-print:" + key);
      }
    };
    context.addEventListener("message", listener);
    frame.srcdoc = `<!doctype html><title>Owned print experiment</title><script>
      const send = event => parent.postMessage({namespace:"ada-print-lab-v1", event}, "*");
      addEventListener("beforeprint", () => send("before"));
      addEventListener("afterprint", () => send("after"));
      addEventListener("message", event => {
        if (event.source !== parent || event.data?.namespace !== "ada-print-lab-v1") return;
        if (event.data.command === "ping") send("pong");
        if (event.data.command === "print") {
          try { print(); send("returned"); } catch { send("threw"); }
        }
      });
      send("ready");
    </script>`;
    context.document.body.appendChild(frame);
    if (!await wait(() => result.ready, 3000)) {
      result.state = "UNKNOWN";
      result.reason = "print-frame-not-ready";
      return result;
    }
    const send = command => frame.contentWindow.postMessage({ namespace: "ada-print-lab-v1", command }, "*");
    send("print");
    await pause(128);
    send("ping");
    await wait(() => result.returned || result.threw, 650);
    await wait(() => result.pong, 325);
    // Reproduce ADA_agent's same-document bounce, but always restore it in
    // finally. No print acceptance, printer destination, or kiosk flag exists.
    if (context.location.href !== originalUrl || context.history.length !== originalLength) {
      throw new Error("Unrelated navigation");
    }
    const bounce = new URL(originalUrl);
    bounce.hash = bounce.hash === "#ada-print-lab" ? "ada-print-lab-alt" : "ada-print-lab";
    bounceUrl = bounce.href;
    context.location.replace(bounceUrl);
    if (!await wait(() => context.location.href === bounce.href, 1600)) {
      result.state = "UNKNOWN";
      result.reason = "print-navigation-unverified";
    }
    if (context.location.href === bounceUrl) context.history.replaceState(originalState, "", originalUrl);
    await wait(() => result.after, 400);
  } catch {
    result.state = "UNKNOWN";
    result.reason = "print-operation-error";
  } finally {
    try {
      // Never undo an unrelated application/user navigation.
      if (bounceUrl && context.location.href === bounceUrl) {
        context.history.replaceState(originalState, "", originalUrl);
      }
      result.urlRestored = context.location.href === originalUrl;
      result.historyUnchanged = context.history.length === originalLength;
    } catch {
      result.state = "UNKNOWN";
      result.reason = "print-restoration-error";
    }
    try {
      if (listener) context.removeEventListener("message", listener);
      if (frame) frame.remove();
      result.frameRemoved = Boolean(frame && frame.isConnected === false);
    } catch {
      result.state = "UNKNOWN";
      result.reason = "print-cleanup-error";
    }
    if (!result.urlRestored || !result.historyUnchanged || !result.frameRemoved) {
      result.state = "UNKNOWN";
      result.reason ||= "print-cleanup-unverified";
    }
    if (result.state === "complete" && (!result.before || !result.returned || result.threw ||
        (!result.after && !result.pong))) {
      result.state = "UNKNOWN";
      result.reason = "print-observation-incomplete";
    }
    if (result.state === "complete") {
      result.hypothesis = !result.after;
    }
  }
  return result;
}

export async function collectOwnedPrint(send, sessionId, { owned = false } = {}) {
  if (!owned) throw new Error("Print experiment requires an explicitly owned test session");
  let response;
  try {
    response = await send("Runtime.evaluate", {
      expression: `(${probeOwnedPrint.toString()})(window)`,
      awaitPromise: true, returnByValue: true,
    }, sessionId);
  } catch {
    // Terminate only this owned renderer evaluation, never a personal target.
    try { await send("Runtime.terminateExecution", {}, sessionId); } catch { /* Launcher still owns cleanup. */ }
    return { state: "UNKNOWN", reason: "print-evaluation-failed", hypothesis: null };
  }
  const value = response?.result?.result?.value;
  const fields = ["ready", "before", "after", "returned", "pong", "threw", "frameRemoved", "urlRestored", "historyUnchanged"];
  if (response?.error || response?.result?.exceptionDetails || !value || typeof value !== "object" ||
      Array.isArray(value) || !["complete", "UNKNOWN"].includes(value.state) ||
      fields.some(key => typeof value[key] !== "boolean") ||
      (value.state === "complete" && (typeof value.hypothesis !== "boolean" || !value.ready || !value.frameRemoved ||
       !value.urlRestored || !value.historyUnchanged || !value.before || !value.returned ||
       value.threw || (!value.after && !value.pong) || value.hypothesis !==
       (value.returned && value.pong && !value.after && value.before && !value.threw))) ||
      (value.state === "UNKNOWN" && value.hypothesis !== null)) {
    return { state: "UNKNOWN", reason: "print-evaluation-failed", hypothesis: null };
  }
  const result = { state: value.state, hypothesis: value.hypothesis };
  for (const key of fields) result[key] = value[key];
  if (value.state === "UNKNOWN") {
    const reasons = ["print-frame-not-ready", "print-navigation-unverified", "print-operation-error",
      "print-restoration-error", "print-cleanup-error", "print-cleanup-unverified", "print-observation-incomplete"];
    result.reason = reasons.includes(value.reason) ? value.reason : "print-evaluation-failed";
  }
  return result;
}
