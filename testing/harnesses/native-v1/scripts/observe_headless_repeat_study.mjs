/** A second-call completion observation AFTER the untouched frontend submits.
 * This does not intercept the first call or certify its return. For detectors
 * with a source-reviewed cached promise, it can reveal a rejected/non-Boolean
 * cached result that the frontend's catch/coercion would otherwise hide.
 */
import { pathToFileURL } from "node:url";
import { observeFrontend, observerErrorReason } from "./observe_ada_frontend.mjs";

export async function probeHeadlessRepeat() {
  const before = { url: location.href, history: history.length,
    frames: document.querySelectorAll("iframe").length };
  const started = performance.now();
  let timer;
  let result = { state: "MISSING" };
  if (typeof window.detect_headless === "function") {
    try {
      const outcome = await Promise.race([
        Promise.resolve().then(() => window.detect_headless()).then(value =>
          typeof value === "boolean" ? { state: "BOOLEAN", value } : { state: "NON_BOOLEAN" }),
        new Promise(resolve => { timer = setTimeout(() => resolve({ state: "TIMEOUT" }), 3500); }),
      ]);
      result = outcome;
    } catch {
      result = { state: "THREW" };
    } finally {
      clearTimeout(timer);
    }
  }
  return { ...result, observation: "second-call-after-frontend", diagnostic_only: true,
    original_call_intercepted: false, duration_ms: performance.now() - started,
    url_restored: location.href === before.url, history_unchanged: history.length === before.history,
    frame_count_restored: document.querySelectorAll("iframe").length === before.frames };
}

export function validHeadlessRepeat(value) {
  return value !== null && typeof value === "object" &&
    ["MISSING", "BOOLEAN", "NON_BOOLEAN", "TIMEOUT", "THREW"].includes(value.state) &&
    (value.state === "BOOLEAN" ? typeof value.value === "boolean" : !("value" in value)) &&
    value.observation === "second-call-after-frontend" && value.diagnostic_only === true &&
    value.original_call_intercepted === false && Number.isFinite(value.duration_ms) &&
    value.duration_ms >= 0 && value.duration_ms < 10000 &&
    ["url_restored", "history_unchanged", "frame_count_restored"].every(key => typeof value[key] === "boolean");
}

export async function observeHeadlessRepeat(port, url) {
  const observed = await observeFrontend({ port, url, diagnosticProbe: probeHeadlessRepeat });
  if (!validHeadlessRepeat(observed.diagnostic_probe)) throw new Error("owned-headless-repeat-contract");
  observed.headless_repeat_study = observed.diagnostic_probe;
  delete observed.diagnostic_probe;
  return observed;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(await observeHeadlessRepeat(Number(process.argv[2]), process.argv[3]))); }
  catch (error) {
    console.log(JSON.stringify({ state: "UNKNOWN", reason: observerErrorReason(error),
      ...(error.diagnostics ? { diagnostics: error.diagnostics } : {}) }));
    process.exitCode = 1;
  }
}
