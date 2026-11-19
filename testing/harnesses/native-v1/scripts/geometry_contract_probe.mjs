/** Owned-session laboratory probe. Fixed synthetic geometry only; never export
 * coordinates, rendering output, profile settings, or a browser identity.
 * A mismatch is not an Octo verdict.
 */
export async function probeGeometryContracts(context) {
  function representations(realm, rectangle) {
    const result = { ownJSON: "UNKNOWN", nativeJSON: "UNKNOWN", clone: "UNKNOWN",
      stableReads: "UNKNOWN" };
    const fields = ["x", "y", "width", "height", "top", "right", "bottom", "left"];
    try {
      const original = fields.map(name => rectangle[name]);
      const agrees = other => fields.every((name, index) =>
        Object.is(other[name], original[index]));
      result.stableReads = agrees(rectangle) ? "matches" : "differs";
      try { result.ownJSON = agrees(rectangle.toJSON()) ? "matches" : "differs"; }
      catch { result.ownJSON = "test-error"; }
      try {
        result.nativeJSON = agrees(realm.DOMRectReadOnly.prototype.toJSON.call(rectangle))
          ? "matches" : "differs";
      } catch { result.nativeJSON = "test-error"; }
      if (typeof realm.structuredClone !== "function") result.clone = "unsupported";
      else {
        try { result.clone = agrees(realm.structuredClone(rectangle)) ? "matches" : "differs"; }
        catch { result.clone = "test-error"; }
      }
    } catch { result.stableReads = "test-error"; }
    return result;
  }
  function inspectRealm(realm) {
    const result = { state: "observed", fromRect: "UNKNOWN",
      accessOrder: "UNKNOWN", json: "UNKNOWN", clone: "UNKNOWN",
      invalidReceiver: "UNKNOWN", layout: "UNKNOWN", snapshot: "UNKNOWN" };
    if (typeof realm.DOMRect?.fromRect !== "function" ||
        typeof realm.DOMRectReadOnly?.prototype?.toJSON !== "function") {
      result.state = "unsupported";
      return result;
    }
    try {
      const trace = [];
      const input = {};
      for (const [name, value] of [["x", 7], ["y", 11], ["width", 13], ["height", 17]]) {
        Object.defineProperty(input, name, { get() { trace.push(name); return value; } });
      }
      const rect = realm.DOMRect.fromRect(input);
      result.constructedRepresentations = representations(realm, rect);
      const fields = ["x", "y", "width", "height"];
      const values = [7, 11, 13, 17];
      result.accessOrder = trace.join(","); // Only four fixed dictionary member names.
      result.fromRect = fields.every((name, index) => rect[name] === values[index])
        ? "matches" : "differs";
      const json = rect.toJSON();
      result.json = fields.every(name => json?.[name] === rect[name])
        ? "matches" : "differs";
      if (typeof realm.structuredClone === "function") {
        try {
          const clone = realm.structuredClone(rect);
          result.clone = fields.every(name => clone?.[name] === rect[name])
            ? "matches" : "differs";
        } catch { result.clone = "error"; }
      } else result.clone = "unsupported";
      try {
        realm.DOMRectReadOnly.prototype.toJSON.call(Object.create(null));
        result.invalidReceiver = "accepted";
      } catch (error) {
        result.invalidReceiver = error?.name === "TypeError" ? "TypeError" : "other-error";
      }
    } catch {
      result.state = "test-error";
      return result;
    }
    const document = realm.document;
    if (!document?.body) { result.layout = "unsupported"; result.snapshot = "unsupported"; return result; }
    const element = document.createElement("div");
    element.style.cssText = "position:fixed;left:10px;top:20px;width:31px;height:37px;" +
      "padding:0;border:0;margin:0;visibility:hidden;transform:none";
    try {
      document.body.appendChild(element);
      const before = element.getBoundingClientRect();
      const pieces = element.getClientRects();
      result.boundingRepresentations = representations(realm, before);
      const old = [before.x, before.y, before.width, before.height];
      const first = pieces.length === 1 ? pieces[0] : null;
      result.clientRepresentations = first ? representations(realm, first) : { state: "unavailable" };
      const close = (a, b) => Number.isFinite(a) && Number.isFinite(b) && Math.abs(a - b) < 0.5;
      result.layoutExact = first && ["x", "y", "width", "height"].every(name =>
        Object.is(before[name], first[name])) ? "matches" : "differs";
      result.layout = first && ["x", "y", "width", "height"].every(name =>
        close(before[name], first[name])) ? "matches" : "differs";
      element.style.width = "53px";
      const after = element.getBoundingClientRect();
      result.snapshot = ["x", "y", "width", "height"].every((name, index) =>
        before[name] === old[index]) && !close(after.width, old[2]) ? "matches" : "differs";
    } catch { result.layout = "test-error"; result.snapshot = "test-error"; }
    finally { element.remove(); }
    return result;
  }

  const main = inspectRealm(context);
  const output = { state: "observed", classification: "NOT_A_CLASSIFIER",
    main, iframe: { state: "UNKNOWN" }, frameRemoved: false };
  const document = context.document;
  if (!document?.body) { output.iframe.state = "unsupported"; return output; }
  const frame = document.createElement("iframe");
  // display:none suppresses layout in the child document and manufactures a
  // cross-realm difference even in stock Chrome. Keep it rendered off-screen.
  frame.style.cssText = "position:absolute;left:-10000px;top:0;width:128px;" +
    "height:128px;visibility:hidden;pointer-events:none;border:0";
  try {
    document.body.appendChild(frame);
    const child = frame.contentWindow;
    output.iframe = child ? inspectRealm(child) : { state: "unavailable" };
  } catch { output.iframe = { state: "test-error" }; }
  finally { frame.remove(); output.frameRemoved = !frame.isConnected; }
  return output;
}
