/** Controlled activation in disposable sessions only; not a detector. */
export async function probeOwnedPopup(context) {
  const result = { state: "complete", activation: context.navigator?.userActivation?.isActive === true,
    opened: false, closed: false };
  let child;
  const pause = () => new Promise(resolve => setTimeout(resolve, 100));
  const parent = () => [context.innerWidth, context.innerHeight, context.outerWidth,
    context.outerHeight, context.screenX, context.screenY];
  const before = parent();
  try {
    child = context.open("about:blank", "_blank", "popup,width=320,height=240,left=100,top=100");
    result.opened = Boolean(child);
    if (!child) return result;
    const snapshot = () => [child.outerWidth, child.outerHeight, child.screenX, child.screenY];
    await pause();
    const initial = snapshot();
    child.resizeTo(480, 320);
    await pause();
    const resized = snapshot();
    result.resizeChanged = initial[0] !== resized[0] || initial[1] !== resized[1];
    result.resizeHonored = resized[0] === 480 && resized[1] === 320;
    child.moveTo(80, 90);
    await pause();
    const moved = snapshot();
    result.moveChanged = resized[2] !== moved[2] || resized[3] !== moved[3];
    result.moveHonored = moved[2] === 80 && moved[3] === 90;
    child.moveTo(0, -100);
    await pause();
    const boundary = snapshot();
    result.negativeYHonored = boundary[3] === -100;
    result.negativeYClamped = boundary[3] >= 0;
  } catch {
    result.state = "UNKNOWN";
    result.reason = "popup-operation-error";
  } finally {
    if (child) {
      try {
        child.close();
        await pause();
        result.closed = child.closed === true;
        if (!result.closed) {
          result.state = "UNKNOWN";
          result.reason = "popup-cleanup-unverified";
        }
      } catch {
        result.state = "UNKNOWN";
        result.reason = "popup-cleanup-error";
      }
    }
    result.parentUnchanged = parent().every((value, index) => Object.is(value, before[index]));
  }
  return result;
}

export async function collectOwnedPopup(send, sessionId, { owned = false } = {}) {
  if (!owned) throw new Error("Activated popup requires an explicitly owned test session");
  let response;
  try {
    response = await send("Runtime.evaluate", {
      expression: `(${probeOwnedPopup.toString()})(window)`,
      userGesture: true, awaitPromise: true, returnByValue: true,
    }, sessionId);
  } catch {
    return { state: "UNKNOWN", reason: "popup-evaluation-failed" };
  }
  const value = response?.result?.result?.value;
  if (response?.error || response?.result?.exceptionDetails ||
      !value || typeof value !== "object" || Array.isArray(value) ||
      !["complete", "UNKNOWN"].includes(value.state)) {
    return { state: "UNKNOWN", reason: "popup-evaluation-failed" };
  }
  const basic = ["activation", "opened", "closed", "parentUnchanged"];
  const operations = ["resizeChanged", "resizeHonored", "moveChanged", "moveHonored",
    "negativeYHonored", "negativeYClamped"];
  if (basic.some(key => typeof value[key] !== "boolean") ||
      (value.state === "complete" && value.opened &&
       (operations.some(key => typeof value[key] !== "boolean") || !value.closed))) {
    return { state: "UNKNOWN", reason: "popup-evaluation-failed" };
  }
  const result = { state: value.state };
  for (const key of [...basic, ...operations]) {
    if (typeof value[key] === "boolean") result[key] = value[key];
  }
  if (value.state === "UNKNOWN") {
    const reasons = ["popup-operation-error", "popup-cleanup-unverified", "popup-cleanup-error"];
    result.reason = reasons.includes(value.reason) ? value.reason : "popup-evaluation-failed";
  }
  return result;
}
