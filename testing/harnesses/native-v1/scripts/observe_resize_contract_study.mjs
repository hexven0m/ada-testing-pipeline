import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { observeFrontend, observerErrorReason } from "./observe_ada_frontend.mjs";
import { probeResizeContracts, validResizeStudy } from "./owned_resize_contract_probe.mjs";

export async function observeResizeStudy(port, url) {
  // Research runs only after the unchanged frontend's collector receipt.
  const value = await observeFrontend({ port, url, diagnosticProbe: probeResizeContracts });
  if (!validResizeStudy(value.diagnostic_probe)) throw new Error("owned-resize-study-contract");
  value.resize_contract_study = value.diagnostic_probe;
  value.resize_probe_sha256 = createHash("sha256").update(probeResizeContracts.toString()).digest("hex");
  value.resize_runtime_version = { state: "UNKNOWN", source: "owned-loopback-json-version" };
  try {
    const version = await fetch(`http://127.0.0.1:${port}/json/version`,
      { signal: AbortSignal.timeout(3000) }).then(response => response.ok ? response.json() : null);
    const match = /^(Chrome|Chromium|HeadlessChrome|Octium)\/([0-9]{1,3}(?:\.[0-9]{1,6}){3})$/.exec(version?.Browser);
    if (match) value.resize_runtime_version = { state: "observed", product: match[1],
      version: match[2], source: "owned-loopback-json-version" };
  } catch { /* Missing version remains unknown, never a classifier. */ }
  delete value.diagnostic_probe;
  return value;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(await observeResizeStudy(Number(process.argv[2]), process.argv[3]))); }
  catch (error) {
    console.log(JSON.stringify({ state: "UNKNOWN", reason: observerErrorReason(error) }));
    process.exitCode = 1;
  }
}
