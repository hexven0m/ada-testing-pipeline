/** Harness-only transient geometry/permission checks, not a mode classifier. */
export async function probeModeSurface(context) {
  const result = { getters: [], permissions: {}, frame: { created: false } };
  const describeError = error => String(error?.name || "Error");
  const getter = (object, key) => {
    let owner = object;
    while (owner) {
      const descriptor = Object.getOwnPropertyDescriptor(owner, key);
      if (descriptor) return descriptor.get || null;
      owner = Object.getPrototypeOf(owner);
    }
    return null;
  };
  const properties = [
    ["window", "innerWidth"], ["window", "innerHeight"],
    ["window", "outerWidth"], ["window", "outerHeight"],
    ["window", "screenX"], ["window", "screenY"],
    ["screen", "width"], ["screen", "height"],
    ["screen", "availWidth"], ["screen", "availHeight"],
    ["screen", "availLeft"], ["screen", "availTop"],
  ];
  for (const [owner, key] of properties) {
    const subject = owner === "window" ? context : context.screen;
    try {
      const fn = subject && getter(subject, key);
      const item = { owner, property: key, getterExists: Boolean(fn) };
      if (fn) {
        const source = Function.prototype.toString.call(fn);
        item.nativeSource = source.includes("[native code]");
        item.explicitModeName = /headless|headful|windowless/i.test(fn.name + " " + source);
        item.directMatchesGetter = Object.is(subject[key], fn.call(subject));
      }
      result.getters.push(item);
    } catch (error) {
      result.getters.push({ owner, property: key, error: describeError(error) });
    }
  }

  // Transient viewport consistency, not rendering-output or device identity.
  // Scrollbars, page zoom, mobile UI and page CSS can cause ordinary mismatches;
  // a mismatch must never be treated as proof of either launch mode.
  result.viewport = {};
  try {
    if (context.matchMedia && context.innerWidth > 0 && context.innerHeight > 0) {
      result.viewport.widthMediaMatches = context.matchMedia(`(width: ${context.innerWidth}px)`).matches;
      result.viewport.heightMediaMatches = context.matchMedia(`(height: ${context.innerHeight}px)`).matches;
    }
    if (context.visualViewport) {
      result.viewport.visualWidthMatches = Math.abs(context.visualViewport.width - context.innerWidth) < 0.5;
      result.viewport.visualHeightMatches = Math.abs(context.visualViewport.height - context.innerHeight) < 0.5;
    }
  } catch (error) {
    result.viewport.error = describeError(error);
  }
  let layoutProbe;
  try {
    if (context.document?.createElement) {
      layoutProbe = context.document.createElement("div");
      if (typeof layoutProbe.getBoundingClientRect === "function") {
        layoutProbe.setAttribute("aria-hidden", "true");
        layoutProbe.style.cssText = "position:fixed;left:0;top:0;width:100vw;height:100vh;visibility:hidden;pointer-events:none;margin:0;padding:0;border:0";
        (context.document.body || context.document.documentElement).appendChild(layoutProbe);
        const rectangle = layoutProbe.getBoundingClientRect();
        result.viewport.layoutWidthMatches = Math.abs(rectangle.width - context.innerWidth) < 0.5;
        result.viewport.layoutHeightMatches = Math.abs(rectangle.height - context.innerHeight) < 0.5;
      }
    }
  } catch (error) {
    result.viewport.layoutError = describeError(error);
  } finally {
    layoutProbe?.remove();
  }

  // Queries only: never request permissions, show a picker, read/write the
  // clipboard, obtain location, enumerate devices, or change stored settings.
  const permissionNames = ["clipboard-read", "clipboard-write", "notifications",
    "window-management", "geolocation", "camera", "microphone", "display-capture"];
  await Promise.all(permissionNames.map(async name => {
    let timer;
    try {
      if (!context.navigator?.permissions?.query) {
        result.permissions[name] = { state: "unsupported" };
        return;
      }
      result.permissions[name] = await Promise.race([
        context.navigator.permissions.query({ name }).then(value => ({ state: value.state })),
        new Promise(resolve => {
          timer = setTimeout(() => resolve({ state: "UNKNOWN", reason: "timeout" }), 250);
        }),
      ]);
    } catch (error) {
      result.permissions[name] = { state: "error", error: describeError(error) };
    } finally {
      clearTimeout(timer);
    }
  }));

  let frame;
  let timer;
  try {
    if (!context.document?.createElement) {
      result.frame.state = "unsupported";
      return result;
    }
    frame = context.document.createElement("iframe");
    frame.setAttribute("aria-hidden", "true");
    frame.style.cssText = "position:fixed;width:320px;height:200px;visibility:hidden;border:0";
    const ready = new Promise((resolve, reject) => {
      frame.onload = resolve;
      timer = setTimeout(() => reject(new Error("frame timeout")), 750);
    });
    frame.srcdoc = "<!doctype html><title>ADA temporary mode surface</title>";
    (context.document.body || context.document.documentElement).appendChild(frame);
    result.frame.created = true;
    await ready;
    const realm = frame.contentWindow;
    result.frame.getters = properties.map(([owner, key]) => {
      const subject = owner === "window" ? context : context.screen;
      const realmSubject = owner === "window" ? realm : realm.screen;
      try {
        const fn = getter(realmSubject, key);
        return { owner, property: key, getterExists: Boolean(fn),
          crossRealmMatchesDirect: fn ? Object.is(fn.call(subject), subject[key]) : null };
      } catch (error) {
        return { owner, property: key, error: describeError(error) };
      }
    });
  } catch (error) {
    result.frame.error = describeError(error);
  } finally {
    clearTimeout(timer);
    frame?.remove();
  }
  return result;
}
