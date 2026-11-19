/** Owned-session research only: static native-bundle leads, never profile data. */
export async function probeOctoNativeBridge(context, { workerTimeoutMs = 1000 } = {}) {
  if (!Number.isInteger(workerTimeoutMs) || workerTimeoutMs < 1 || workerTimeoutMs > 2000) {
    throw new RangeError("Invalid worker diagnostic budget");
  }
  function inspect(realm) {
    const paths = [["OctoFunction"], ["tartar"], ["chrome", "octo"],
      ["chrome", "cookies"], ["chrome", "cookies", "getOctoProfileID"],
      ["chrome", "cookies", "getOctoProfileName"],
      ["chrome", "cookies", "getOctoProfileExtraInfo"]];
    return paths.map(path => {
      let subject = realm;
      let state = "unknown";
      try {
        for (let index = 0; index < path.length; index++) {
          if (subject === null || !["object", "function"].includes(typeof subject)) {
            state = "absent";
            break;
          }
          let holder = subject;
          let descriptor;
          for (let depth = 0; holder && depth < 8; depth++) {
            descriptor = Object.getOwnPropertyDescriptor(holder, path[index]);
            if (descriptor) break;
            holder = Object.getPrototypeOf(holder);
          }
          if (!descriptor) {
            state = holder ? "unknown" : "absent";
            break;
          }
          if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) {
            state = "accessor-not-read";
            break;
          }
          subject = descriptor.value;
          state = typeof subject === "function" ? "callable-not-called" : "data-not-read";
        }
      } catch { state = "unknown"; }
      // Export no field values, profile names, IDs, cookies, or function source.
      return { path: path.join("."), state };
    });
  }

  const result = { classification: "NOT_A_CLASSIFIER", main: inspect(context),
    iframe: { state: "unsupported" }, worker: { state: "unsupported" },
    cleanup: { frameRemoved: null, workerTerminated: null, objectUrlRevoked: null } };
  let frame;
  try {
    if (context.document?.body) {
      frame = context.document.createElement("iframe");
      frame.style.cssText = "position:absolute;left:-10000px;visibility:hidden;width:100px;height:100px";
      context.document.body.appendChild(frame);
      result.iframe = frame.contentWindow
        ? { state: "observed", rows: inspect(frame.contentWindow) } : { state: "unknown" };
    }
  } catch { result.iframe = { state: "unknown" }; }
  finally {
    if (frame) {
      try { frame.remove(); result.cleanup.frameRemoved = !frame.isConnected; }
      catch { result.cleanup.frameRemoved = false; }
    }
  }

  let worker;
  let objectUrl;
  let timer;
  try {
    if (typeof context.Worker === "function" && typeof context.Blob === "function" &&
        typeof context.URL?.createObjectURL === "function" &&
        typeof context.URL?.revokeObjectURL === "function") {
      // Inspect only our fresh worker, never an extension/background worker.
      const script = `self.postMessage((${inspect.toString()})(self));`;
      objectUrl = context.URL.createObjectURL(new context.Blob([script], { type: "text/javascript" }));
      worker = new context.Worker(objectUrl);
      result.worker = await new Promise(resolve => {
        timer = setTimeout(() => resolve({ state: "timeout" }), workerTimeoutMs);
        worker.onerror = event => { event.preventDefault(); resolve({ state: "unknown" }); };
        worker.onmessage = event => {
          const rows = event.data;
          const states = ["absent", "unknown", "accessor-not-read", "callable-not-called", "data-not-read"];
          if (!Array.isArray(rows) || rows.length !== result.main.length ||
              rows.some((row, index) => !row || row.path !== result.main[index].path ||
                !states.includes(row.state))) {
            resolve({ state: "invalid-report" });
          } else {
            resolve({ state: "observed", rows: rows.map(row => ({ path: row.path, state: row.state })) });
          }
        };
      });
    }
  } catch { result.worker = { state: "unknown" }; }
  finally {
    if (timer !== undefined) clearTimeout(timer);
    if (worker) {
      try { worker.terminate(); result.cleanup.workerTerminated = true; }
      catch { result.cleanup.workerTerminated = false; }
    }
    if (objectUrl !== undefined) {
      try { context.URL.revokeObjectURL(objectUrl); result.cleanup.objectUrlRevoked = true; }
      catch { result.cleanup.objectUrlRevoked = false; }
    }
  }
  return result;
}
