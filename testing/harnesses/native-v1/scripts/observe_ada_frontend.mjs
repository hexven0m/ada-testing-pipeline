/** Observe the unmodified ADA frontend. Never call/inject detectors or submit a payload. */
import { createHash } from "node:crypto";

import { pathToFileURL } from "node:url";
import { createCdpRpc } from "./cdp_rpc.mjs";
import { DetectorErrorEvidence } from "./frontend_error_evidence.mjs";

export const products = ["ads_power", "dolphin_anty", "gologin", "multilogin", "octo"];
export const files = ["headless.js", ...products.map(name => `${name}.js`)];

/** Preserve only literal Boolean/null returns; never serialize arbitrary raw data. */
export function rawProductEvidence(payload) {
  const verdicts = {}, types = {};
  for (const name of products) {
    const row = payload.results.find(item => item.framework_name === name);
    const present = Object.hasOwn(row, "raw");
    const value = row.raw;
    types[name] = !present ? "missing" : value === null ? "null" : typeof value;
    verdicts[name] = typeof value === "boolean" ? value : null;
  }
  return { raw_product_verdicts: verdicts, raw_product_types: types,
    raw_product_payload_consistent: payload.results.every(item =>
      typeof item.raw === "boolean" && item.raw === item.detected),
    // The unchanged bundle applies Boolean(t), then drops t. An observed
    // false may be a catch fallback; absence of a console error is not proof.
    headless_raw_completion: "UNVERIFIED_FRONTEND_COERCION" };
}

export function taskUrl(value, collectorContract = "session-bound") {
  const url = new URL(value);
  const keys = [...url.searchParams.keys()];
  const order = url.searchParams.get("order_number");
  const scoringSessionId = url.searchParams.get("session_id");
  const legacy = collectorContract === "legacy-order";
  if (!legacy && collectorContract !== "session-bound") throw new Error("task-url-contract");
  // Match the Python owned runner's narrow TLS authority, not arbitrary HTTPS.
  // Certificate validation stays enabled in the browser and network client.
  const ownedHttps = url.protocol === "https:" &&
    url.hostname === process.env.ADA_PRIVATE_HTTPS_HOST && ["", "443", "18443"].includes(url.port);
  if ((url.protocol !== "http:" && !ownedHttps) || url.username || url.password || url.hash ||
      url.pathname !== "/_web" || keys.length !== (legacy ? 1 : 2) ||
      !keys.includes("order_number") || (!legacy && !keys.includes("session_id")) ||
      !/^(0|[1-9][0-9]*)$/.test(order || "") || Number(order) > 22 ||
      (!legacy && !/^[A-Za-z0-9_-]{32,128}$/.test(scoringSessionId || ""))) {
    throw new Error("task-url-contract");
  }
  return { url, order: Number(order), scoringSessionId };
}

export function validPayload(payload, order, scoringSessionId, collectorContract = "session-bound") {
  // The published template puts this identity in a backtick string. The
  // Pydantic collector accepts its canonical decimal form; preserve strict
  // identity while accepting BOTH observed wire representations.
  const identityMatches = payload?.order_number === order || payload?.order_number === String(order);
  const sessionMatches = collectorContract === "legacy-order"
    ? payload && !Object.hasOwn(payload, "session_id") && scoringSessionId === null
    : collectorContract === "session-bound" && typeof scoringSessionId === "string" && payload?.session_id === scoringSessionId;
  return payload !== null && typeof payload === "object" &&
    sessionMatches &&
    identityMatches && typeof payload.headless === "boolean" &&
    Array.isArray(payload.results) && payload.results.length === products.length &&
    payload.results.every(item => item && typeof item.detected === "boolean" &&
      products.includes(item.framework_name)) &&
    new Set(payload.results.map(item => item.framework_name)).size === products.length;
}

/** A page title, DOM Done, HTTP response without a body match, or stale order cannot pass. */
export class CollectorEvidence {
  constructor(target, collectorContract = "session-bound") {
    const { url, order, scoringSessionId } = taskUrl(target, collectorContract);
    this.collectorContract = collectorContract;
    this.origin = url.origin;
    this.order = order;
    this.scoringSessionId = scoringSessionId;
    this.requests = new Map();
    this.accepted = [];
    this.rejected = [];
    this.transportFailures = [];
  }

  event(message) {
    const p = message.params || {};
    if (message.method === "Network.requestWillBeSent") {
      // Redirect/reuse cannot retain an earlier body association.
      this.requests.delete(p.requestId);
      const request = p.request || {};
      if (request.url !== `${this.origin}/_payload` || request.method !== "POST") return;
      let payload;
      try { payload = JSON.parse(request.postData); } catch { return; }
      if (validPayload(payload, this.order, this.scoringSessionId, this.collectorContract)) this.requests.set(p.requestId, { payload });
    } else if (message.method === "Network.responseReceived") {
      const item = this.requests.get(p.requestId);
      if (!item) return;
      if (p.response?.url !== `${this.origin}/_payload` || !Number.isInteger(p.response?.status)) {
        this.requests.delete(p.requestId);
        return;
      }
      item.status = p.response.status;
    } else if (message.method === "Network.loadingFailed") {
      if (this.requests.has(p.requestId)) {
        this.rejected.push("collector-network-failed");
        this.transportFailures.push({ error: /^net::ERR_[A-Z_]+$/.test(p.errorText || "") ? p.errorText : "UNKNOWN",
          canceled: p.canceled === true });
      }
      this.requests.delete(p.requestId);
    } else if (message.method === "Network.loadingFinished") {
      const item = this.requests.get(p.requestId);
      this.requests.delete(p.requestId);
      if (!item || item.status === undefined) return;
      if (item.status < 200 || item.status >= 300) {
        this.rejected.push(`collector-http-${item.status}`);
        return;
      }
      this.accepted.push({ order_number: this.order, http_status: item.status,
        headless: item.payload.headless,
        submitted_framework: item.payload.results.filter(x => x.detected).map(x => x.framework_name),
        observer_evidence_version: 2, collector_response_complete: true,
        session_binding_verified: this.collectorContract === "session-bound",
        ...rawProductEvidence(item.payload) });
    }
  }
}

export function observerDiagnostics(evidence, hashes, detectorErrors, navigationError) {
  const result = { accepted_collectors: evidence.accepted.length,
    pending_collectors: evidence.requests.size, observed_source_names: Object.keys(hashes),
    pending_collector_statuses: [...evidence.requests.values()].map(item => item.status ?? null),
    detector_sha256: { ...hashes }, transport_failures: evidence.transportFailures,
    header_confirmed_verdicts: [...evidence.requests.values()].filter(item => item.status === 200).map(item => ({
      order_number: evidence.order, headless: item.payload.headless,
      submitted_framework: item.payload.results.filter(x => x.detected).map(x => x.framework_name) })),
    detector_errors: detectorErrors.errors, mode_diagnostic_trace: detectorErrors.traces };
  if (navigationError) result.navigation_error = /^net::ERR_[A-Z_]+$/.test(navigationError) ? navigationError : "UNKNOWN";
  return result;
}

export function observerErrorReason(error) {
  const message = typeof error?.message === "string" ? error.message : "";
  // Map only this harness's exact RPC errors. Never retain arbitrary browser
  // responses, exception stacks, task URLs or profile paths.
  const methods = new Set(["Target.createTarget", "Target.attachToTarget", "Target.closeTarget",
    "Page.enable", "Page.navigate", "Network.enable", "Runtime.enable",
    "Network.setCacheDisabled", "Network.getResponseBody", "Network.streamResourceContent", "Runtime.evaluate"]);
  for (const [prefix, category] of [["CDP request timed out: ", "cdp-request-timeout"],
    ["CDP request could not be sent: ", "cdp-request-send-failed"]]) {
    if (message.startsWith(prefix) && methods.has(message.slice(prefix.length))) {
      return category + ":" + message.slice(prefix.length);
    }
  }
  if (["CDP connection is closed", "CDP connection closed before its reply"].includes(message)) {
    return "cdp-connection-closed";
  }
  const safe = /^(task-url-contract|observer-config-contract|cdp-[a-z-]+(?::[A-Za-z.]+)?|non-owned-cdp-endpoint|owned-[a-z-]+|frontend-[a-z-]+|detector-source-[a-z-]+|duplicate-collector-submission|collector-[a-z-]+(?:-\d+)?)$/;
  return safe.test(message) ? message : "observer-failed";
}

export function pageEnvironment(value) {
  // Availability is diagnostic context, never product or human evidence.
  const names = ["secure_context", "media_devices_api", "permissions_api", "structured_clone_api"];
  return Object.fromEntries(names.map((name) => [name,
    typeof value?.[name] === "boolean" ? value[name] : null]));
}

export function pageContextProbe() {
  function optional(read) { try { return read(); } catch { return null; } }
  return {url: location.href, title: document.title, ready: document.readyState,
    secure_context: optional(() => window.isSecureContext),
    media_devices_api: optional(() => Boolean(navigator.mediaDevices)),
    permissions_api: optional(() => Boolean(navigator.permissions)),
    structured_clone_api: optional(() => typeof window.structuredClone === "function")};
}

export async function observeFrontend({ port, url, timeoutMs = 45000, collectorContract = "session-bound",
  diagnosticProbe = null }) {
  const { url: target } = taskUrl(url, collectorContract);
  if (!Number.isInteger(port) || port < 1024 || port > 65535 ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120000) {
    throw new Error("observer-config-contract");
  }
  const started = Date.now();
  // A vendor's start call can return before its browser accepts DevTools
  // connections. Keep asking for about ten seconds, then report it by name.
  let version;
  while (version === undefined) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`,
        { signal: AbortSignal.timeout(5000) });
      if (!response.ok) throw new Error("cdp-readiness-failed");
      version = await response.json();
    } catch {
      if (Date.now() - started > 10000) throw new Error("cdp-readiness-failed");
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }
  const endpoint = new URL(version.webSocketDebuggerUrl);
  if (endpoint.protocol !== "ws:" || !["localhost", "127.0.0.1"].includes(endpoint.hostname) ||
      Number(endpoint.port) !== port || endpoint.username || endpoint.password) {
    throw new Error("non-owned-cdp-endpoint");
  }
  const socket = new WebSocket(endpoint);
  const rpc = createCdpRpc(socket, { timeoutMs: 5000 });
  const evidence = new CollectorEvidence(target.href, collectorContract);
  const detectorErrors = new DetectorErrorEvidence();
  const sources = new Map();
  const sourceLoads = new Map();
  const hashes = {};
  const sourceErrors = [];
  const outstanding = new Set();
  let sessionId;
  let targetId;
  async function send(method, params = {}, session = sessionId) {
    const reply = await rpc.request(method, params, session);
    if (reply.error) throw new Error(`cdp-method-failed:${method}`);
    return reply.result;
  }
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    rpc.receive(message);
    if (!sessionId || message.sessionId !== sessionId) return;
    evidence.event(message);
    detectorErrors.event(message);
    const p = message.params || {};
    if (message.method === "Network.requestWillBeSent") {
      sources.delete(p.requestId);
      let requested;
      try { requested = new URL(p.request.url); } catch { requested = null; }
      const name = requested?.pathname.split("/").at(-1);
      if (requested?.origin === target.origin &&
          requested.pathname === `/static/detections/${name}` && files.includes(name)) {
        sourceLoads.set(p.requestId, { name, response_status: null, loading_finished: false });
      }
    }
    if (message.method === "Network.loadingFinished" && sourceLoads.has(p.requestId)) {
      sourceLoads.get(p.requestId).loading_finished = true;
    }
    if (message.method === "Network.loadingFailed" && sourceLoads.has(p.requestId)) {
      sourceLoads.get(p.requestId).failed = /^net::ERR_[A-Z_]+$/.test(p.errorText) ? p.errorText : "UNKNOWN";
      sourceErrors.push("detector-source-network-failed");
    }
    if (message.method === "Network.responseReceived") {
      if (evidence.requests.has(p.requestId)) {
        // Read only the collector response. Do not wrap page fetch, evaluate detector code or replay
        // requests. Discard the response bytes; loadingFinished is still
        // required, so unavailable streaming never becomes a synthetic pass.
        const work = send("Network.getResponseBody", { requestId: p.requestId }).catch(() => {});
        outstanding.add(work);
        void work.finally(() => outstanding.delete(work));
      }
      let sourceUrl;
      try { sourceUrl = new URL(p.response.url); } catch { return; }
      const name = sourceUrl.pathname.split("/").at(-1);
      if (sourceUrl.origin === target.origin &&
          sourceUrl.pathname === `/static/detections/${name}` && files.includes(name)) {
        if (sourceLoads.has(p.requestId)) sourceLoads.get(p.requestId).response_status = p.response.status;
        if (p.response.status !== 200) sourceErrors.push("detector-source-http-failed");
        else sources.set(p.requestId, name);
      }
    }
    if (message.method === "Network.loadingFinished" && sources.has(p.requestId)) {
      const name = sources.get(p.requestId);
      sources.delete(p.requestId);
      const work = send("Network.getResponseBody", { requestId: p.requestId }).then(body => {
        const data = Buffer.from(body.body, body.base64Encoded ? "base64" : "utf8");
        if (data.length > 262144) throw new Error("detector-source-limit");
        const hash = createHash("sha256").update(data).digest("hex");
        if (hashes[name] && hashes[name] !== hash) throw new Error("detector-source-changed");
        hashes[name] = hash;
      }).catch(() => { sourceErrors.push("detector-source-unverified"); });
      outstanding.add(work);
      void work.finally(() => outstanding.delete(work));
    }
  };
  socket.onclose = () => rpc.close();
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("cdp-connect-timeout")), 5000);
      socket.onopen = () => { clearTimeout(timer); resolve(); };
      socket.onerror = () => { clearTimeout(timer); reject(new Error("cdp-connect-failed")); };
    });
    targetId = (await send("Target.createTarget", { url: "about:blank" }, undefined)).targetId;
    if (!targetId) throw new Error("owned-target-missing");
    sessionId = (await send("Target.attachToTarget", { targetId, flatten: true }, undefined)).sessionId;
    if (!sessionId) throw new Error("owned-session-missing");
    await send("Page.enable");
    await send("Network.enable");
    await send("Runtime.enable");
    await send("Network.setCacheDisabled", { cacheDisabled: true });
    const navigationStarted = Date.now();
    const navigation = await send("Page.navigate", { url: target.href });
    if (navigation.errorText) {
      const failure = new Error("frontend-navigation-failed");
      failure.navigationError = /^net::ERR_[A-Z_]+$/.test(navigation.errorText) ? navigation.errorText : "UNKNOWN";
      throw failure;
    }
    while (Date.now() - started < timeoutMs) {
      if (evidence.rejected.length) throw new Error(evidence.rejected[0]);
      if (sourceErrors.length) throw new Error(sourceErrors[0]);
      if (evidence.accepted.length > 1) throw new Error("duplicate-collector-submission");
      if (evidence.accepted.length === 1 && files.every(name => hashes[name])) {
        const page = await send("Runtime.evaluate", {
          expression: `(${pageContextProbe.toString()})()`, returnByValue: true });
        const value = page.result?.value;
        if (page.exceptionDetails || value?.url !== target.href ||
            value?.title !== "Detections Visualizer" || value?.ready !== "complete") {
          throw new Error("frontend-page-contract");
        }
        const collected = { state: "collector-confirmed", collector_contract: collectorContract, ...evidence.accepted[0],
          detector_sha256: hashes, page_environment: pageEnvironment(value),
          detector_errors: detectorErrors.errors, mode_diagnostic_trace: detectorErrors.traces,
          duration_ms: Date.now() - navigationStarted, observer_budget_ms: timeoutMs,
          completed_within_observer_budget: Date.now() - started <= timeoutMs };
        // Opt-in research only, AFTER the unchanged frontend has submitted.
        // Never modify detector functions or use these measurements as a score.
        if (diagnosticProbe !== null) {
          if (typeof diagnosticProbe !== "function") throw new Error("observer-config-contract");
          const study = await send("Runtime.evaluate", { expression: `(${diagnosticProbe.toString()})()`,
            returnByValue: true, awaitPromise: true });
          if (study.exceptionDetails) throw new Error("owned-diagnostic-probe-failed");
          collected.diagnostic_probe = study.result?.value;
        }
        return collected;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    const failure = new Error("frontend-collector-timeout");
    failure.diagnostics = observerDiagnostics(evidence, hashes, detectorErrors);
    failure.diagnostics.source_loads = [...sourceLoads.values()];
    throw failure;
  } catch (error) {
    if (!error.diagnostics) error.diagnostics = observerDiagnostics(evidence, hashes, detectorErrors, error.navigationError);
    error.diagnostics.source_loads = [...sourceLoads.values()];
    throw error;
  } finally {
    let closed = targetId === undefined;
    try {
      if (targetId) closed = (await send("Target.closeTarget", { targetId }, null)).success === true;
    } finally {
      await Promise.allSettled([...outstanding]);
      rpc.close();
      socket.close();
    }
    if (!closed) throw new Error("owned-target-cleanup-unverified");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await observeFrontend({ port: Number(process.argv[2]), url: process.argv[3],
      diagnosticProbe: null, timeoutMs: Number(process.argv[4] || 45000), collectorContract: process.argv[5] || "session-bound" });
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch (error) {
    // Never print raw CDP/API responses or stack traces.
    process.stdout.write(JSON.stringify({ state: "UNKNOWN", reason: observerErrorReason(error),
      ...(error.diagnostics ? { diagnostics: error.diagnostics } : {}) }) + "\n");
    process.exitCode = 1;
  }
}
