/** Owned diagnostic only. Compare script origins AFTER the original page posts.
 * Never a scorer/runner observer: partial transport cannot qualify a submission.
 * No raw stacks, attributes, URLs or source contents are exported.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { createCdpRpc } from "./cdp_rpc.mjs";
import { CollectorEvidence, files, taskUrl } from "./observe_ada_frontend.mjs";
import { DetectorErrorEvidence } from "./frontend_error_evidence.mjs";
import { callsiteProbeSource, validCallsiteResult } from "./product_callsite_probe.mjs";
import { probeOwnedCallsiteRealms } from "./owned_callsite_realms.mjs";
import { probeOwnedFormatterCounterexample } from "./owned_formatter_counterexample.mjs";
import { probeOwnedProductCallers } from "./owned_product_caller_controls.mjs";

export async function observeCallsites({ port, url, directory }) {
  const { url: target } = taskUrl(url);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error("callsite-config");
  const contents = Object.fromEntries(files.map(name => [name, readFileSync(join(directory, name), "utf8")]));
  const hash = value => createHash("sha256").update(value).digest("hex");
  const manifest = Object.fromEntries(files.map(name => [name, hash(contents[name])]));
  const version = await fetch(`http://127.0.0.1:${port}/json/version`,
    { signal: AbortSignal.timeout(5000) }).then(response => response.json());
  const endpoint = new URL(version.webSocketDebuggerUrl);
  if (endpoint.protocol !== "ws:" || !["localhost", "127.0.0.1"].includes(endpoint.hostname) ||
      Number(endpoint.port) !== port || endpoint.username || endpoint.password) throw new Error("callsite-endpoint");
  const socket = new WebSocket(endpoint);
  const rpc = createCdpRpc(socket, { timeoutMs: 5000 });
  const evidence = new CollectorEvidence(target.href);
  const errors = new DetectorErrorEvidence();
  const sources = new Map();
  const hashes = {};
  const work = new Set();
  const saved = [];
  let session;
  let id;
  let sourceFailed = false;
  let helperCreated = false;
  const send = async (method, params = {}, active = session) => {
    const reply = await rpc.request(method, params, active);
    if (reply.error) throw new Error("callsite-cdp");
    return reply.result;
  };
  const evaluate = async expression => {
    const reply = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (reply.exceptionDetails) throw new Error("callsite-evaluation");
    return reply.result?.value;
  };
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    rpc.receive(message);
    if (!session || message.sessionId !== session) return;
    evidence.event(message); errors.event(message);
    const p = message.params || {};
    if (message.method === "Network.responseReceived") {
      let address;
      try { address = new URL(p.response.url); } catch { return; }
      const name = address.pathname.split("/").at(-1);
      if (address.origin === target.origin && address.pathname === "/static/detections/" + name && files.includes(name)) {
        if (p.response.status !== 200) sourceFailed = true;
        else sources.set(p.requestId, name);
      }
    }
    if (message.method === "Network.loadingFinished" && sources.has(p.requestId)) {
      const name = sources.get(p.requestId); sources.delete(p.requestId);
      const pending = send("Network.getResponseBody", { requestId: p.requestId }).then(body => {
        const bytes = Buffer.from(body.body, body.base64Encoded ? "base64" : "utf8");
        if (bytes.length > 262144 || hash(bytes) !== manifest[name]) throw new Error("callsite-source");
        hashes[name] = manifest[name];
      }).catch(() => { sourceFailed = true; });
      work.add(pending); void pending.finally(() => work.delete(pending));
    }
  };
  socket.onclose = () => rpc.close();
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("callsite-connect")), 5000);
      socket.onopen = () => { clearTimeout(timer); resolve(); };
      socket.onerror = () => { clearTimeout(timer); reject(new Error("callsite-connect")); };
    });
    id = (await send("Target.createTarget", { url: "about:blank" }, undefined)).targetId;
    session = (await send("Target.attachToTarget", { targetId: id, flatten: true }, undefined)).sessionId;
    if (!id || !session) throw new Error("callsite-target");
    for (const method of ["Page.enable", "Runtime.enable", "Network.enable"]) await send(method);
    await send("Network.setCacheDisabled", { cacheDisabled: true });
    if ((await send("Page.navigate", { url: target.href })).errorText) throw new Error("callsite-navigation");
    const started = Date.now();
    let original;
    while (Date.now() - started < 30000) {
      if (sourceFailed || evidence.rejected.length || evidence.accepted.length > 1) throw new Error("callsite-original");
      original = evidence.accepted[0] || [...evidence.requests.values()].find(item => item.status === 200)?.payload;
      if (original && files.every(name => hashes[name] === manifest[name])) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!original || !files.every(name => hashes[name] === manifest[name])) throw new Error("callsite-original-timeout");
    const page = await evaluate("({title:document.title,ready:document.readyState,url:location.href})");
    if (page?.title !== "Detections Visualizer" || page.ready !== "complete" || page.url !== target.href) {
      throw new Error("callsite-page");
    }
    // Original predictions are recorded before any study script or replacement.
    const originalFrameworks = original.submitted_framework ||
      original.results.filter(item => item.detected).map(item => item.framework_name);
    const originalProduct = originalFrameworks.includes("multilogin");
    const originalMode = original.headless;
    if (await evaluate("Object.hasOwn(window, '__adaCallsiteStudy') || Boolean(document.getElementById('ada-owned-callsite-script'))")) {
      throw new Error("callsite-existing-helper");
    }
    helperCreated = true;
    await evaluate(`new Promise((resolve, reject) => {
      if (Object.hasOwn(window, "__adaCallsiteStudy")) return reject(new Error("callsite-existing-helper"));
      const script = document.createElement("script");
      script.id = "ada-owned-callsite-script";
      script.onload = () => resolve(true); script.onerror = () => reject(new Error("callsite-helper-load"));
      script.src = ${JSON.stringify(target.origin + "/__callsite.js")}; document.body.appendChild(script);
    })`);
    const externalProduct = await evaluate("window.detect_multilogin()");
    const externalProbe = await evaluate("window.__adaCallsiteStudy()");
    for (const name of ["detect_multilogin", "__adaCallsiteStudy"]) {
      const value = await send("Runtime.evaluate", { expression: "window[" + JSON.stringify(name) + "]" });
      if (!value.result?.objectId) throw new Error("callsite-function");
      saved.push({ name, objectId: value.result.objectId });
    }
    await evaluate(contents["multilogin.js"]);
    const evaluatedProduct = await evaluate("window.detect_multilogin()");
    await evaluate(callsiteProbeSource);
    const evaluatedProbe = await evaluate("window.__adaCallsiteStudy()");
    if (typeof externalProduct !== "boolean" || typeof evaluatedProduct !== "boolean" ||
        !validCallsiteResult(externalProbe) || !validCallsiteResult(evaluatedProbe)) throw new Error("callsite-value");
    const pageRealms = await evaluate(`(${probeOwnedCallsiteRealms.toString()})(window,
      ${JSON.stringify(callsiteProbeSource)}, ${JSON.stringify(contents["multilogin.js"])})`);
    const formatterCounterexample = await evaluate(`(${probeOwnedFormatterCounterexample.toString()})(window)`);
    if (!formatterCounterexample || formatterCounterexample.formatter_restored !== true) {
      throw new Error("callsite-formatter-cleanup");
    }
    const productCallerControls = await evaluate(`(${probeOwnedProductCallers.toString()})(window)`);
    return { state: "callsite-study", diagnostic_only: true, submission_certified: false,
      detector_sha256: manifest, original_mode: originalMode, original_product: originalProduct,
      original_submitted_framework: originalFrameworks,
      original_detector_errors: errors.errors, original_transport_complete: evidence.accepted.length === 1,
      externally_loaded: { product: externalProduct, probe: externalProbe },
      evaluated_copy: { product: evaluatedProduct, probe: evaluatedProbe }, page_created_contexts: pageRealms,
      formatter_counterexample: formatterCounterexample, product_caller_controls: productCallerControls };
  } finally {
    let restored = true;
    for (const item of saved) {
      try {
        const reply = await send("Runtime.callFunctionOn", { objectId: item.objectId,
          functionDeclaration: "function(name){window[name]=this;return window[name]===this;}",
          arguments: [{ value: item.name }], returnByValue: true });
        if (reply.exceptionDetails || reply.result?.value !== true) restored = false;
        await send("Runtime.releaseObject", { objectId: item.objectId });
      } catch { restored = false; }
    }
    if (helperCreated) {
      try { await evaluate("document.getElementById('ada-owned-callsite-script')?.remove(); delete window.__adaCallsiteStudy"); }
      catch { restored = false; }
    }
    let closed = !id;
    try { if (id) closed = (await send("Target.closeTarget", { targetId: id }, null)).success === true; }
    finally { await Promise.allSettled([...work]); rpc.close(); socket.close(); }
    if (!restored || !closed) throw new Error("callsite-cleanup");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(await observeCallsites({ port: Number(process.argv[2]),
    url: process.argv[3], directory: process.argv[4] }))); }
  catch { console.log(JSON.stringify({ state: "UNKNOWN", diagnostic_only: true, reason: "callsite-study-failed" })); process.exitCode = 1; }
}
