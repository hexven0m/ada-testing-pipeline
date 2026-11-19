/** Harness-only patch-consistency experiment, not a fingerprint or mode rule. */
export async function probeModeRealmConsistency(context, { timeoutMs = 750 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 1000) {
    throw new RangeError("Invalid bounded frame timeout");
  }
  const errorName = error => String(error?.name || "Error");
  const snapshot = realm => [realm.innerWidth, realm.innerHeight, realm.outerWidth,
    realm.outerHeight, realm.screenX, realm.screenY, realm.screen?.width, realm.screen?.height];
  const equal = (left, right) => left.length === right.length &&
    left.every((value, index) => Object.is(value, right[index]));
  function compare(realm) {
    const result = { checks: {}, state: "complete" };
    let style;
    let marker;
    try {
      if (!realm.document?.createElement || !realm.matchMedia || !realm.getComputedStyle) {
        return { state: "UNKNOWN", reason: "unsupported" };
      }
      const definitions = [
        ["viewportWidth", "width", realm.innerWidth],
        ["viewportHeight", "height", realm.innerHeight],
        // Compare only against already exposed transient screen dimensions.
        // No search/enumeration, actual device values, resolution/color/font
        // queries, identity key or off-page attribute classification.
        ["screenWidth", "device-width", realm.screen?.width],
        ["screenHeight", "device-height", realm.screen?.height],
        ["pointerNone", "pointer", "none"], ["hoverNone", "hover", "none"],
        ["anyPointerNone", "any-pointer", "none"], ["anyHoverNone", "any-hover", "none"],
      ];
      const id = "ada-realm-probe-" + Math.random().toString(36).slice(2);
      marker = realm.document.createElement("div");
      marker.id = id;
      marker.setAttribute("aria-hidden", "true");
      marker.style.cssText = "position:fixed;width:0;height:0;visibility:hidden;pointer-events:none";
      style = realm.document.createElement("style");
      const entries = definitions.map(([name, feature, value], index) => ({ name, index,
        valid: typeof value === "string" || Number.isFinite(value) && value > 0,
        query: `(${feature}: ${typeof value === "number" ? value + "px" : value})`,
      }));
      style.textContent = entries.filter(entry => entry.valid).map(entry =>
        `#${id}{--ada-r${entry.index}:no}@media ${entry.query}{#${id}{--ada-r${entry.index}:yes}}`).join("\n");
      const parent = realm.document.body || realm.document.documentElement;
      parent.appendChild(style);
      parent.appendChild(marker);
      const computed = realm.getComputedStyle(marker);
      for (const entry of entries) {
        if (!entry.valid) { result.checks[entry.name] = { state: "UNKNOWN", reason: "invalid-claim" }; continue; }
        const value = computed.getPropertyValue(`--ada-r${entry.index}`).trim();
        const css = value === "yes" ? true : value === "no" ? false : null;
        const js = realm.matchMedia(entry.query).matches;
        result.checks[entry.name] = { css, js: typeof js === "boolean" ? js : null,
          consistent: css === null || typeof js !== "boolean" ? null : css === js };
      }
    } catch (error) {
      result.state = "UNKNOWN";
      result.error = errorName(error);
    } finally {
      marker?.remove();
      style?.remove();
    }
    return result;
  }
  let original;
  try { original = snapshot(context); }
  catch (error) { return { state: "UNKNOWN", error: errorName(error) }; }
  const result = { top: compare(context), frame: { created: false } };
  let frame;
  let timer;
  try {
    if (!context.document?.createElement) {
      result.frame.state = "UNKNOWN";
      return result;
    }
    frame = context.document.createElement("iframe");
    frame.setAttribute("aria-hidden", "true");
    frame.style.cssText = "position:fixed;left:-10000px;top:0;width:320px;height:200px;visibility:hidden;pointer-events:none;border:0";
    const loaded = new Promise((resolve, reject) => {
      frame.onload = resolve;
      timer = setTimeout(() => reject(new Error("frame timeout")), timeoutMs);
    });
    frame.srcdoc = "<!doctype html><title>ADA temporary realm consistency</title>";
    (context.document.body || context.document.documentElement).appendChild(frame);
    result.frame.created = true;
    await loaded;
    const realm = frame.contentWindow;
    result.frame.comparison = compare(realm);
    const parentNow = snapshot(context);
    result.topSnapshotStable = equal(original, parentNow);
    const child = snapshot(realm);
    result.frame.outerGeometryMatchesParent = equal(child.slice(2, 6), parentNow.slice(2, 6));
    result.frame.exposedScreenMatchesParent = equal(child.slice(6), parentNow.slice(6));
  } catch (error) {
    result.frame.state = "UNKNOWN";
    result.frame.error = errorName(error);
  } finally {
    clearTimeout(timer);
    frame?.remove();
  }
  return result;
}
