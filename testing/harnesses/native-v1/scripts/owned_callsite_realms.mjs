/** Transient owned script contexts. No classifier, identity values or raw errors. */
export async function probeOwnedCallsiteRealms(context, helperSource, detectorSource) {
  const originalHelper = context.__adaCallsiteStudy;
  const originalDetector = context.detect_multilogin;
  const source = helperSource + "\n" + detectorSource;
  function sanitize(value) {
    if (!value || typeof value !== "object" || Array.isArray(value) ||
        Object.keys(value).length !== 3 || !Object.hasOwn(value, "product") ||
        typeof value.product !== "boolean" ||
        !["bareFirstFrames", "legacyScrollMarker"].every(key => Object.hasOwn(value, key) &&
          (typeof value[key] === "boolean" || value[key] === null))) return null;
    return { product: value.product, bareFirstFrames: value.bareFirstFrames,
      legacyScrollMarker: value.legacyScrollMarker };
  }
  const read = async () => sanitize({ ...context.__adaCallsiteStudy(),
    product: await context.detect_multilogin() });
  async function scriptContext(kind) {
    let script;
    let blobUrl;
    let timer;
    try {
      return await new Promise(resolve => {
        let finished = false;
        function finish(value) { if (!finished) { finished = true; resolve(value); } }
        timer = context.setTimeout(() => finish(null), 1500);
        script = context.document.createElement("script");
        script.onerror = () => finish(null);
        script.onload = () => { void read().then(finish, () => finish(null)); };
        if (kind === "inline") script.textContent = source;
        else {
          blobUrl = context.URL.createObjectURL(new context.Blob([source], { type: "text/javascript" }));
          script.src = blobUrl;
        }
        context.document.body.appendChild(script);
        if (kind === "inline") { void read().then(finish, () => finish(null)); }
      });
    } catch { return null; }
    finally {
      context.clearTimeout(timer);
      if (script) script.remove();
      if (blobUrl) context.URL.revokeObjectURL(blobUrl);
      context.__adaCallsiteStudy = originalHelper;
      context.detect_multilogin = originalDetector;
    }
  }
  async function opaqueContext() {
    let frame;
    let listener;
    let timer;
    try {
      return await new Promise(resolve => {
        let finished = false;
        function finish(value) { if (!finished) { finished = true; resolve(value); } }
        frame = context.document.createElement("iframe");
        frame.setAttribute("sandbox", "allow-scripts");
        frame.style.cssText = "border:0;position:fixed;left:-200px;top:-200px;width:1px;height:1px";
        listener = event => {
          if (event.source !== frame.contentWindow || !event.data ||
              event.data.namespace !== "ada-owned-callsite-realms-v1") return;
          finish(sanitize(event.data.result));
        };
        context.addEventListener("message", listener);
        timer = context.setTimeout(() => finish(null), 1500);
        const child = source + `
          addEventListener("load", async () => {
            let result = null;
            try {
              result = { ...window.__adaCallsiteStudy(), product: await window.detect_multilogin() };
            } catch {}
            parent.postMessage({ namespace: "ada-owned-callsite-realms-v1", result }, "*");
          }, { once: true });`;
        frame.srcdoc = "<!doctype html><body><script>" + child.replace(/<\/script/gi, "<\\/script") + "</script>";
        context.document.body.appendChild(frame);
      });
    } catch { return null; }
    finally {
      context.clearTimeout(timer);
      if (listener) context.removeEventListener("message", listener);
      if (frame) frame.remove();
    }
  }
  return { inline: await scriptContext("inline"), blob: await scriptContext("blob"),
    opaque_srcdoc: await opaqueContext() };
}
