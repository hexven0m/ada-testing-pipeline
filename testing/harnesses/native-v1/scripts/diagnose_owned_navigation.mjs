/** Read-only route isolation in one newly owned browser, not a detector test. */
import { pathToFileURL } from "node:url";
import { lookup } from "node:dns/promises";
import { isIPv4 } from "node:net";
import { createCdpRpc } from "./cdp_rpc.mjs";
import { taskUrl, observerErrorReason } from "./observe_ada_frontend.mjs";

export function navigationTargets(value, port) {
  const { url } = taskUrl(value);
  const collector = process.env.ADA_PRIVATE_HTTPS_HOST;
  const privateAddress = isIPv4(url.hostname) &&
    /^(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)/.test(url.hostname);
  if ((!["127.0.0.1", "localhost", collector].includes(url.hostname) && !privateAddress) ||
      !Number.isInteger(port) || port < 1024 || port > 65535) throw new Error("observer-config-contract");
  return [
    { label: "task-page", url: url.href },
    { label: "private-root", url: url.origin + "/" },
    { label: "owned-loopback-control", url: `http://127.0.0.1:${port}/json/version` },
    { label: "owned-localhost-control", url: `http://localhost:${port}/json/version` },
    ...(collector ? [{ label: "owned-tailnet-dns-control", url: `http://${collector}:18092/health` },
      { label: "owned-tailnet-https-control", url: `https://${collector}/health` }] : []),
    { label: "public-http-control", url: "http://example.com/" },
    { label: "public-https-control", url: "https://example.com/" },
  ];
}

export async function diagnoseNavigation(port, url) {
  const targets = navigationTargets(url, port);
  const version = await fetch(`http://127.0.0.1:${port}/json/version`,
    { signal: AbortSignal.timeout(5000) }).then(r => r.json());
  const endpoint = new URL(version.webSocketDebuggerUrl);
  if (endpoint.protocol !== "ws:" || endpoint.hostname !== "127.0.0.1" ||
      Number(endpoint.port) !== port || endpoint.username || endpoint.password) throw new Error("non-owned-cdp-endpoint");
  const socket = new WebSocket(endpoint);
  const rpc = createCdpRpc(socket, { timeoutMs: 5000 });
  let current;
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    rpc.receive(message);
    if (!current || message.sessionId !== current.session || !message.params) return;
    const p = message.params;
    if (message.method === "Network.requestWillBeSent" && p.type === "Document" &&
        p.request?.url === current.url) current.requests.add(p.requestId);
    if (!current.requests.has(p.requestId)) return;
    if (message.method === "Network.responseReceived" && p.response?.url === current.url &&
        Number.isInteger(p.response.status)) current.status = p.response.status;
    if (message.method === "Network.loadingFailed") {
      current.error = /^net::ERR_[A-Z_]+$/.test(p.errorText || "") ? p.errorText : "UNKNOWN";
      const allowed = new Set(["other", "csp", "mixed-content", "origin", "inspector", "integrity",
        "subresource-filter", "content-type"]);
      current.blockedReason = allowed.has(p.blockedReason) ? p.blockedReason : "UNKNOWN";
    }
  };
  socket.onclose = () => rpc.close();
  const send = async (method, params = {}, session) => {
    const reply = await rpc.request(method, params, session);
    if (reply.error) throw new Error("cdp-method-failed:" + method);
    return reply.result;
  };
  const results = [];
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("cdp-connect-timeout")), 5000);
      socket.onopen = () => { clearTimeout(timer); resolve(); };
      socket.onerror = () => { clearTimeout(timer); reject(new Error("cdp-connect-failed")); };
    });
    for (const target of targets) {
      if (["owned-tailnet-dns-control", "owned-tailnet-https-control"].includes(target.label)) {
        let addresses;
        try { addresses = await lookup(new URL(target.url).hostname, { all: true }); } catch { addresses = []; }
        if (!addresses.length || addresses.some(row => row.address !== "100.98.218.14")) {
          results.push({ route: target.label, status: null, error: "owned-dns-unavailable",
            blocked_reason: null, harness_error: null });
          continue; // Never visit an unexpected address for this owned resource.
        }
      }
      let id;
      current = { url: target.url, requests: new Set(), status: null, error: null, blockedReason: null };
      try {
        id = (await send("Target.createTarget", { url: "about:blank" })).targetId;
        current.session = (await send("Target.attachToTarget", { targetId: id, flatten: true })).sessionId;
        await send("Page.enable", {}, current.session);
        await send("Network.enable", {}, current.session);
        const reply = await send("Page.navigate", { url: target.url }, current.session);
        if (reply.errorText) current.error = /^net::ERR_[A-Z_]+$/.test(reply.errorText) ? reply.errorText : "UNKNOWN";
        await new Promise(resolve => setTimeout(resolve, 500));
      } catch (error) {
        current.harnessError = observerErrorReason(error);
      } finally {
        if (id && (await send("Target.closeTarget", { targetId: id })).success !== true) {
          throw new Error("owned-target-cleanup-unverified");
        }
      }
      results.push({ route: target.label, status: current.status, error: current.error,
        blocked_reason: current.blockedReason, harness_error: current.harnessError || null });
    }
    return { state: "navigation-diagnostic-only", submission_certified: false, navigation: results };
  } finally {
    rpc.close();
    socket.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.stdout.write(JSON.stringify(await diagnoseNavigation(Number(process.argv[2]), process.argv[3])) + "\n");
  } catch (error) {
    process.stdout.write(JSON.stringify({ state: "UNKNOWN", reason: observerErrorReason(error) }) + "\n");
    process.exitCode = 1;
  }
}
