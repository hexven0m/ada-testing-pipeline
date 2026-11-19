/** Disposable-page experiment only; never included in submitted detectors. */
export async function probeOwnedFormatterCounterexample(context) {
  const constructor = context.Error;
  if (typeof constructor !== "function" || typeof context.detect_multilogin !== "function") {
    return { baseline_product: null, custom_formatter_product: null, formatter_restored: true };
  }
  const original = Object.getOwnPropertyDescriptor(constructor, "prepareStackTrace");
  if (original && !original.configurable) {
    return { baseline_product: null, custom_formatter_product: null, formatter_restored: true };
  }
  let baseline = null;
  let modified = null;
  let installed = false;
  let restored = false;
  try {
    const value = await context.detect_multilogin();
    if (typeof value === "boolean") baseline = value;
    // A legitimate page formatter retains URL-backed frames but blanks inline
    // frames. Raw CallSites and filenames stay inside this disposable page.
    Object.defineProperty(constructor, "prepareStackTrace", {
      configurable: true, writable: true,
      value: function (_error, sites) {
        return "Error\n" + sites.map(function (site) {
          const file = site.getFileName();
          return typeof file === "string" && file.startsWith("blob:")
            ? "    at owned-url-frame" : "    at";
        }).join("\n");
      },
    });
    installed = true;
    const next = await context.detect_multilogin();
    if (typeof next === "boolean") modified = next;
  } catch {
    modified = null;
  } finally {
    try {
      if (installed) {
        if (original) Object.defineProperty(constructor, "prepareStackTrace", original);
        else delete constructor.prepareStackTrace;
      }
      const current = Object.getOwnPropertyDescriptor(constructor, "prepareStackTrace");
      restored = original ? Boolean(current &&
        ["value", "get", "set", "writable", "enumerable", "configurable"].every(
          key => current[key] === original[key])) : current === undefined;
    } catch { restored = false; }
  }
  return { baseline_product: baseline, custom_formatter_product: modified, formatter_restored: restored };
}
