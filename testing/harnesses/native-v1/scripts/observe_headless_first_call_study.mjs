/** Source-pinned first invocation in a separate owned document.
 * The original React page submits and closes before this diagnostic opens.
 * No detector is replaced, wrapped or coerced. This is not the original
 * frontend call, a genuine-human visit or an official headless-gate verdict.
 */
import { createHash } from "node:crypto";
import {bindOwnedScriptSources} from "./owned_script_source_binding.mjs";
import { pathToFileURL } from "node:url";
import { createCdpRpc } from "./cdp_rpc.mjs";
import { observeFrontend, observerErrorReason, taskUrl } from "./observe_ada_frontend.mjs";

export async function probeFirstHeadless() {
  const before = { url: location.href, history: history.length,
    frames: document.querySelectorAll("iframe").length };
  const started = performance.now();
  let timer;
  let result = { state: "MISSING" };
  if (typeof window.detect_headless === "function") {
    try {
      result = await Promise.race([
        Promise.resolve().then(() => window.detect_headless()).then(value =>
          typeof value === "boolean" ? { state: "BOOLEAN", value } : { state: "NON_BOOLEAN" }),
        // Two complete recovery attempts have a sum of source budgets below22s.
        // This is the separate observer budget; detector deadlines are unchanged.
        new Promise(resolve => { timer = setTimeout(() => resolve({ state: "TIMEOUT" }), 25000); }),
      ]);
    } catch { result = { state: "THREW" }; }
    finally { clearTimeout(timer); }
  }
  return { ...result, observation: "first-call-separate-document", diagnostic_only: true,
    original_call_intercepted: false, duration_ms: performance.now() - started,
    url_restored: location.href === before.url, history_unchanged: history.length === before.history,
    frame_count_restored: document.querySelectorAll("iframe").length === before.frames };
}

export function validFirstHeadless(value) {
  return value !== null && typeof value === "object" &&
    ["MISSING", "BOOLEAN", "NON_BOOLEAN", "TIMEOUT", "THREW"].includes(value.state) &&
    (value.state === "BOOLEAN" ? typeof value.value === "boolean" : !("value" in value)) &&
    value.observation === "first-call-separate-document" && value.diagnostic_only === true &&
    value.original_call_intercepted === false && Number.isFinite(value.duration_ms) &&
    value.duration_ms >= 0 && value.duration_ms < 30000 &&
    ["url_restored", "history_unchanged", "frame_count_restored"].every(key => typeof value[key] === "boolean");
}

export function firstHeadlessUrl(url) {
  const target = taskUrl(url).url;
  target.pathname = "/__headless_first";
  return target;
}

export async function observeFreshHeadless(port, url, expectedHashes, expectedPreloadHash) {
  const target = firstHeadlessUrl(url);
  if (!Number.isInteger(port) || port < 1024 || port > 65535 ||
      !/^[a-f0-9]{64}$/.test(expectedHashes?.["headless.js"] || "") ||
      !/^[a-f0-9]{64}$/.test(expectedPreloadHash || "")) {
    throw new Error("owned-headless-first-config");
  }
  const version = await fetch(`http://127.0.0.1:${port}/json/version`,
    { signal: AbortSignal.timeout(5000) }).then(response => {
    if (!response.ok) throw new Error("cdp-readiness-failed");
    return response.json();
  });
  const endpoint = new URL(version.webSocketDebuggerUrl);
  if (endpoint.protocol !== "ws:" || !["localhost", "127.0.0.1"].includes(endpoint.hostname) ||
      Number(endpoint.port) !== port || endpoint.username || endpoint.password) {
    throw new Error("non-owned-cdp-endpoint");
  }
  const socket = new WebSocket(endpoint);
  // Let the page-side diagnostic settle before the observer's RPC deadline.
  const rpc = createCdpRpc(socket, { timeoutMs: 28000 });
  const sources = new Map(), hashes = {}, pending = new Set();
  const contexts=new Map(),scripts=[],methods={},bodyUnknowns=[];
  let mainFrame,sourceBindingComplete=false;
  const failures = [];
  let sessionId, targetId;
  async function send(method, params = {}, session = sessionId) {
    const reply = await rpc.request(method, params, session);
    if (reply.error) throw new Error("owned-headless-first-rpc");
    return reply.result || {};
  }
  socket.onmessage = event => {
    let message;
    try { message = JSON.parse(event.data); } catch { return; }
    rpc.receive(message);
    if (message.sessionId !== sessionId) return;
    const params = message.params || {};
    if(message.method==="Runtime.executionContextCreated")contexts.set(params.context.id,{...(params.context.auxData||{}),uniqueId:params.context.uniqueId});
    if(message.method==="Runtime.executionContextDestroyed") {
      contexts.delete(params.executionContextId);
      for(const [id,ctx] of contexts)if(ctx.uniqueId===params.executionContextUniqueId)contexts.delete(id);
    }
    if(message.method==="Runtime.executionContextsCleared")contexts.clear();
    if(message.method==="Debugger.scriptParsed"&&scripts.length<64&&[`${target.origin}/static/detections/headless.js`,`${target.origin}/static/js/user-agent-spoof.js`].includes(params.url))scripts.push({scriptId:params.scriptId,url:params.url,executionContextId:params.executionContextId});
    if (message.method === "Network.responseReceived" && !sourceBindingComplete) {
      for (const [name, path] of [["headless.js", "/static/detections/headless.js"],
        ["preload", "/static/js/user-agent-spoof.js"]]) {
        if (params.response?.url === `${target.origin}${path}`) {
          if (params.response.status === 200) sources.set(params.requestId, name);
          else failures.push("detector-source-http-failed");
        }
      }
      // The dedicated document must not run a React bundle or submit a collector.
      if (params.response?.url?.startsWith(`${target.origin}/static/js/main.`)) {
        failures.push("owned-headless-first-unexpected-bundle");
      }
    }
    if (message.method === "Network.requestWillBeSent" &&
        params.request?.url === `${target.origin}/_payload`) {
      failures.push("owned-headless-first-unexpected-collector");
    }
    if (message.method === "Network.loadingFinished" && sources.has(params.requestId)) {
      const name = sources.get(params.requestId);
      sources.delete(params.requestId);
      const work = send("Network.getResponseBody", { requestId: params.requestId }).then(body => {
        const bytes = Buffer.from(body.body, body.base64Encoded ? "base64" : "utf8");
        if (bytes.length > 262144) throw new Error("detector-source-limit");
        hashes[name] = createHash("sha256").update(bytes).digest("hex");
        methods[name]="network-response-body";
      }).catch(() => bodyUnknowns.push(name));
      pending.add(work);
      void work.finally(() => pending.delete(work));
    }
  };
  socket.onclose = () => rpc.close();
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("cdp-connect-timeout")), 5000);
      socket.onopen = () => { clearTimeout(timer); resolve(); };
      socket.onerror = () => { clearTimeout(timer); reject(new Error("cdp-connect-failed")); };
    });
    targetId = (await send("Target.createTarget", { url: "about:blank" }, null)).targetId;
    if (!targetId) throw new Error("owned-target-missing");
    sessionId = (await send("Target.attachToTarget", { targetId, flatten: true }, null)).sessionId;
    if (!sessionId) throw new Error("owned-session-missing");
    await send("Page.enable");
    await send("Network.enable");
    await send("Runtime.enable");
    await send("Network.setCacheDisabled", { cacheDisabled: true });
    const navigation = await send("Page.navigate", { url: target.href });
    mainFrame=navigation.frameId;
    if (navigation.errorText) throw new Error("owned-headless-first-navigation");
    const started = Date.now();
    let ready = false;
    while (Date.now() - started < 15000) {
      if (failures.length) throw new Error(failures[0]);
      const probe = await send("Runtime.evaluate", { returnByValue: true,
        expression: `location.href === ${JSON.stringify(target.href)} && document.readyState === 'complete' && ` +
          `document.title === 'ADA raw mode diagnostic' && typeof window.detect_headless === 'function'` });
      if (!probe.exceptionDetails && probe.result?.value === true) {
        ready = true; break;
      }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    if (!ready) throw new Error("detector-source-unverified");
    await Promise.allSettled([...pending]);
    const provedContext=await bindOwnedScriptSources({send,scripts,contexts,mainFrame,origin:target.origin,
      expected:{"headless.js":expectedHashes["headless.js"],preload:expectedPreloadHash},hashes,methods});
    if (hashes["headless.js"] !== expectedHashes["headless.js"] || hashes.preload !== expectedPreloadHash)
      throw new Error("detector-source-unverified");
    sourceBindingComplete=true;
    const contract=await send("Runtime.evaluate",{...provedContext,returnByValue:true,
      expression:`location.href === ${JSON.stringify(target.href)} && document.readyState === 'complete' && document.title === 'ADA raw mode diagnostic' && typeof window.detect_headless === 'function'`});
    if(contract.exceptionDetails||contract.result?.value!==true)throw new Error("detector-source-unverified");
    const probe = await send("Runtime.evaluate", { ...provedContext, expression: `(${probeFirstHeadless.toString()})()`,
      returnByValue: true, awaitPromise: true });
    const result = probe.result?.value;
    if (probe.exceptionDetails || !validFirstHeadless(result) || failures.length) {
      throw new Error("owned-headless-first-result");
    }
    return { ...result, source_verification:{methods,network_body_unknowns:bodyUnknowns}, detector_sha256: hashes["headless.js"], source_bound: true,
      preload_sha256: hashes.preload, preload_source_bound: true,
      page: "dedicated-raw-mode-document", frontend_unchanged: true };
  } finally {
    let closed = targetId === undefined;
    try {
      if (targetId) closed = (await send("Target.closeTarget", { targetId }, null)).success === true;
    } catch {closed=false;} finally {
      await Promise.allSettled([...pending]);
      rpc.close(); socket.close();
    }
    if (!closed) throw new Error("owned-target-cleanup-unverified");
  }
}

export async function observeHeadlessFirst(port, url, expectedPreloadHash) {
  const result = await observeFrontend({ port, url });
  try {
    result.headless_first_call_study = await observeFreshHeadless(port, url, result.detector_sha256, expectedPreloadHash);
  } catch (error) {
    if (error?.message === "owned-target-cleanup-unverified") throw error;
    result.headless_first_call_study = { state: "UNKNOWN", reason: observerErrorReason(error),
      observation: "first-call-separate-document", diagnostic_only: true, original_call_intercepted: false };
  }
  return result;
}

/** Retain bounded transport diagnostics; never promote an uncompleted POST. */
export function failedHeadlessObservation(error) {
  const result = { state: "UNKNOWN", reason: observerErrorReason(error) };
  const input = error?.diagnostics;
  if (!input || typeof input !== "object") return result;
  const files = new Set(["headless.js", "ads_power.js", "dolphin_anty.js",
    "gologin.js", "multilogin.js", "octo.js"]);
  const diagnostics = {};
  for (const key of ["accepted_collectors", "pending_collectors"]) {
    if (Number.isInteger(input[key]) && input[key] >= 0 && input[key] <= 23) diagnostics[key] = input[key];
  }
  if (Array.isArray(input.observed_source_names)) {
    diagnostics.observed_source_names = input.observed_source_names.filter(name => files.has(name)).slice(0, 6);
  }
  if (input.detector_sha256 && typeof input.detector_sha256 === "object") {
    diagnostics.detector_sha256 = Object.fromEntries(Object.entries(input.detector_sha256)
      .filter(([name, hash]) => files.has(name) && /^[a-f0-9]{64}$/.test(hash)));
  }
  if (Array.isArray(input.transport_failures)) {
    diagnostics.transport_failures = input.transport_failures.slice(0, 16).map(item => ({
      error: /^net::ERR_[A-Z_]+$/.test(item?.error || "") ? item.error : "UNKNOWN",
      canceled: item?.canceled === true,
    }));
  }
  if (Array.isArray(input.pending_collector_statuses)) {
    diagnostics.pending_collector_statuses = input.pending_collector_statuses.slice(0, 23)
      .filter(status => status === null || (Number.isInteger(status) && status >= 100 && status <= 599));
  }
  if (Array.isArray(input.source_loads)) {
    diagnostics.source_loads = input.source_loads.filter(item => files.has(item?.name)).slice(0, 12)
      .map(item => ({ name: item.name,
        response_status: Number.isInteger(item.response_status) ? item.response_status : null,
        loading_finished: item.loading_finished === true,
        ...(item.failed ? { failed: /^net::ERR_[A-Z_]+$/.test(item.failed) ? item.failed : "UNKNOWN" } : {}),
      }));
  }
  if (/^net::ERR_[A-Z_]+$/.test(input.navigation_error || "")) {
    diagnostics.navigation_error = input.navigation_error;
  }
  result.diagnostics = diagnostics;
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(await observeHeadlessFirst(Number(process.argv[2]), process.argv[3], process.argv[4]))); }
  catch (error) {
    console.log(JSON.stringify(failedHeadlessObservation(error)));
    process.exitCode = 1;
  }
}
