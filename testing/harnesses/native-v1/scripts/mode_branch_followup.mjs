/** Harness-only diagnostics. No mode verdict, persistent identity, or raw hints. */
export function probePassiveWindowUi(context) {
  const bars = {};
  for (const name of ["toolbar", "menubar", "locationbar", "personalbar", "scrollbars", "statusbar"]) {
    try {
      const value = context[name]?.visible;
      bars[name] = typeof value === "boolean" ? value : null;
    } catch { bars[name] = null; }
  }
  const displayMode = {};
  for (const name of ["browser", "standalone", "minimal-ui", "fullscreen", "picture-in-picture"]) {
    try {
      const value = context.matchMedia(`(display-mode: ${name})`).matches;
      displayMode[name] = typeof value === "boolean" ? value : null;
    } catch { displayMode[name] = null; }
  }
  return { bars, displayMode };
}

export async function probeOctoBranches(context, { timeoutMs = 750 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 1000) {
    throw new RangeError("Invalid diagnostic timeout");
  }
  const kit = context.__adaTransientProbeV2;
  if (!kit) return { state: "missing-probe-kit" };
  const product = /(?:octobrowser|octo_browser|octium(?:browser)?)/i;
  const chromeProduct = /(?:octobrowser|octium|^octo$)/i;
  const safe = fn => { try { return Boolean(fn()); } catch { return null; } };
  const navigatorPrototype = context.Navigator?.prototype || null;
  const webglPrototype = context.WebGLRenderingContext?.prototype || null;
  const owners = [navigatorPrototype, context.navigator];
  const properties = ["platform", "languages", "hardwareConcurrency", "deviceMemory"];
  // Match the existing product detector's predicates, not a new fingerprint.
  const result = {
    state: "complete",
    chromeProductName: safe(() => context.chrome && kit.names(context.chrome, chromeProduct)),
    legacyScrollMarker: safe(() => kit.legacyScrollMarker()),
    navigatorNamedPatch: safe(() => kit.namedPatch(owners, properties, product)),
    webglNamedPatch: safe(() => kit.namedPatch([webglPrototype], ["getParameter"], product)),
    navigatorNamedWrapper: safe(() => kit.namedWrapperFrame(owners, properties, product)),
    webglNamedWrapper: safe(() => kit.namedWrapperFrame([webglPrototype], ["getParameter"], product)),
    ownedNamesTogether: safe(() => (kit.names(context.navigator, product) ||
      kit.names(navigatorPrototype, product) || kit.names(webglPrototype, product)) &&
      kit.names(context, product)),
    emptyBrands: null,
    buildPredicate: null,
    buildCheckState: "skipped-prerequisite",
  };
  // Report booleans only. Never retain UA strings, brand names, version values,
  // hardware values, or stack contents, and never use this module in a commit.
  try {
    let hints = context.navigator?.userAgentData;
    result.emptyBrands = Boolean(hints && Array.isArray(hints.brands) && hints.brands.length === 0);
    if (!result.legacyScrollMarker || !result.emptyBrands) return result;
    const descriptor = navigatorPrototype && Object.getOwnPropertyDescriptor(navigatorPrototype, "userAgentData");
    if (typeof descriptor?.get === "function") hints = descriptor.get.call(context.navigator);
    if (typeof hints?.getHighEntropyValues !== "function") {
      result.buildCheckState = "unavailable";
      return result;
    }
    let timer;
    const expired = {};
    let values;
    try {
      values = await Promise.race([
        hints.getHighEntropyValues(["fullVersionList"]),
        new Promise(resolve => { timer = setTimeout(() => resolve(expired), timeoutMs); }),
      ]);
    } finally { clearTimeout(timer); }
    if (values === expired) {
      result.buildCheckState = "timeout";
      return result;
    }
    result.buildCheckState = "returned";
    result.buildPredicate = Boolean(values && (values.fullVersionList || []).some(entry => {
      if (!entry || !/^(?:Google Chrome|Chromium)$/.test(String(entry.brand))) return false;
      const parts = String(entry.version || "").split(".").map(Number);
      return parts.length === 4 && parts.every(Number.isFinite) &&
        parts[0] === 153 && parts[2] === 8010 && parts[3] >= 44;
    }));
  } catch {
    result.buildCheckState = "error";
  }
  return result;
}
