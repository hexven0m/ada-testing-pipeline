/** Harness-only descriptor inspection: no device values or API calls. */
export function probeOctoOwnedSurfaces(context, { scope = "product" } = {}) {
  if (!["product", "mode"].includes(scope)) throw new RangeError("Invalid artifact scope");
  const product = scope === "mode" ? /(?:headless|headful|windowless)/i
    : /(?:octobrowser|octo_browser|octium(?:browser)?)/i;
  const owners = {};
  const unavailable = [];
  for (const name of ["chrome", "navigator", "JSON", "Math", "Reflect", "Object", "Function", "Date", "Intl", "CSS"]) {
    try { owners[name] = context[name]; }
    catch { unavailable.push(name); }
  }
  owners.window = context;
  for (const name of ["Navigator", "NavigatorUAData", "Permissions", "Screen", "Document", "Element", "Performance",
    "HTMLCanvasElement", "WebGLRenderingContext", "WebGL2RenderingContext"]) {
    try { owners[`${name}.prototype`] = context[name]?.prototype; }
    catch { unavailable.push(`${name}.prototype`); }
  }
  const matches = [];
  const coverage = [];
  for (const [ownerName, owner] of Object.entries(owners)) {
    if (!owner) {
      unavailable.push(ownerName);
      continue;
    }
    let names;
    try { names = Object.getOwnPropertyNames(owner); }
    catch { unavailable.push(ownerName); continue; }
    const limited = names.length > 2000;
    const inspected = names.slice(0, 2000);
    let functions = 0;
    let errors = 0;
    for (const property of inspected) {
      // Ignore every detector/helper injected by this test harness, so our
      // own product regexes and function names cannot become false evidence.
      if (/^(?:detect_|__ada)/.test(property)) continue;
      try {
        const descriptor = Object.getOwnPropertyDescriptor(owner, property);
        const fns = [descriptor?.value, descriptor?.get, descriptor?.set]
          .filter(value => typeof value === "function");
        let namedSource = false;
        let namedFunction = false;
        for (const fn of fns) {
          functions += 1;
          namedFunction ||= product.test(String(fn.name || ""));
          namedSource ||= product.test(Function.prototype.toString.call(fn));
        }
        const namedProperty = product.test(property) ||
          (scope === "product" && ownerName === "chrome" && /^octo$/i.test(property));
        if (namedProperty || namedFunction || namedSource) {
          matches.push({ owner: ownerName, property, namedProperty, namedFunction, namedSource });
        }
      } catch { errors += 1; }
    }
    coverage.push({ owner: ownerName, inspected: inspected.length, functions, errors, limited });
  }
  // Return only explicit product-name evidence and coverage, never arbitrary
  // property values, function source, UA hints, IDs, or hardware readouts.
  return { matches, coverage, unavailable };
}
