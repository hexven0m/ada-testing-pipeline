/** Harness-only transient behavior; never a device identity or mode verdict. */
export async function probeModeExecution(context, { popup = false } = {}) {
  const result = { receivers: [], permissions: {}, popup: { attempted: false },
    secureContext: context.isSecureContext === true };
  result.explicitModeProduct = {
    userAgentHeadlessChrome: /(?:^|\s)HeadlessChrome\/\d/.test(context.navigator?.userAgent || ""),
    clientHintHeadlessChrome: Array.isArray(context.navigator?.userAgentData?.brands) &&
      context.navigator.userAgentData.brands.some(item => item?.brand === "HeadlessChrome"),
  };
  const errorName = error => String(error?.name || "Error");
  const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
  const properties = ["innerWidth", "innerHeight", "outerWidth", "outerHeight", "screenX", "screenY"];
  for (const property of properties) {
    try {
      let owner = context;
      let descriptor;
      while (owner && !descriptor) {
        descriptor = Object.getOwnPropertyDescriptor(owner, property);
        owner = Object.getPrototypeOf(owner);
      }
      if (!descriptor) {
        result.receivers.push({ property, state: "missing" });
        continue;
      }
      const getter = descriptor.get;
      const item = { property, kind: typeof getter === "function" ? "getter" : "value" };
      if (typeof getter === "function") {
        item.nativeSource = Function.prototype.toString.call(getter).includes("[native code]");
        // Record binding behavior, not the returned geometry or function body.
        for (const [name, receiver] of [["valid", context], ["invalid", Object.create(null)]]) {
          try { item[name] = { returnedType: typeof getter.call(receiver) }; }
          catch (error) { item[name] = { error: errorName(error) }; }
        }
      }
      result.receivers.push(item);
    } catch (error) {
      result.receivers.push({ property, state: "error", error: errorName(error) });
    }
  }

  // Query current origin permissions only. Do not request permission, read
  // clipboard/location data, or use policy differences as a headless rule.
  for (const name of ["notifications", "window-management"]) {
    let timer;
    try {
      if (!context.navigator?.permissions?.query) {
        result.permissions[name] = { state: "unsupported" };
        continue;
      }
      result.permissions[name] = await Promise.race([
        context.navigator.permissions.query({ name }).then(value => ({ state: value.state })),
        new Promise(resolve => {
          timer = setTimeout(() => resolve({ state: "UNKNOWN", reason: "timeout" }), 250);
        }),
      ]);
    } catch (error) {
      result.permissions[name] = { state: "error", error: errorName(error) };
    } finally {
      clearTimeout(timer);
    }
  }
  result.permissions.notificationProperty = context.Notification?.permission || "unsupported";

  // Compare CSS evaluation with the JS media-query API to look for an
  // inconsistent page-environment patch. No image, font, or device readout.
  let style;
  let marker;
  try {
    if (!context.document?.createElement || !context.getComputedStyle) {
      result.cssInput = { state: "unsupported" };
    } else {
      const queries = ["(pointer: none)", "(hover: none)", "(any-pointer: none)",
        "(any-hover: none)", "(pointer: fine)", "(hover: hover)"];
      const id = "ada-mode-css-" + Math.random().toString(36).slice(2);
      marker = context.document.createElement("div");
      marker.id = id;
      marker.style.cssText = "position:fixed;width:0;height:0;visibility:hidden";
      style = context.document.createElement("style");
      style.textContent = queries.map((query, index) =>
        `#${id} { --ada-mode-q${index}: no; } @media ${query} { #${id} { --ada-mode-q${index}: yes; } }`).join("\n");
      const parent = context.document.body || context.document.documentElement;
      parent.appendChild(style);
      parent.appendChild(marker);
      const computed = context.getComputedStyle(marker);
      result.cssInput = queries.map((query, index) => {
        const cssValue = computed.getPropertyValue(`--ada-mode-q${index}`).trim();
        const css = cssValue === "yes" ? true : cssValue === "no" ? false : null;
        const js = context.matchMedia(query).matches;
        return { query, css, js, consistent: css === null ? null : css === js };
      });
    }
  } catch (error) {
    result.cssInput = { state: "error", error: errorName(error) };
  } finally {
    marker?.remove();
    style?.remove();
  }

  result.windowAliases = {
    screenLeftEqualsX: typeof context.screenLeft === "number" && context.screenLeft === context.screenX,
    screenTopEqualsY: typeof context.screenTop === "number" && context.screenTop === context.screenY,
  };

  if (!popup) return result;
  let child;
  result.popup.attempted = true;
  try {
    // Use only disposable test sessions. This may briefly show a local blank
    // popup; it performs no external navigation or trusted-input injection.
    child = context.open("about:blank", "_blank", "popup,width=320,height=240,left=100,top=100");
    result.popup.opened = Boolean(child);
    if (!child) return result;
    const snapshot = () => ({ innerWidth: child.innerWidth, innerHeight: child.innerHeight,
      outerWidth: child.outerWidth, outerHeight: child.outerHeight,
      screenX: child.screenX, screenY: child.screenY });
    await delay(100);
    result.popup.initial = snapshot();
    child.resizeTo(480, 320);
    await delay(100);
    result.popup.afterResize = snapshot();
    child.moveTo(80, 90);
    await delay(100);
    result.popup.afterMove = snapshot();
    child.moveTo(0, -100);
    await delay(100);
    result.popup.afterBoundaryMove = snapshot();
  } catch (error) {
    result.popup.error = errorName(error);
  } finally {
    if (child) {
      try {
        child.close();
        await delay(50);
        result.popup.closedAfterProbe = Boolean(child.closed);
      } catch (error) { result.popup.cleanupError = errorName(error); }
    }
  }
  return result;
}
