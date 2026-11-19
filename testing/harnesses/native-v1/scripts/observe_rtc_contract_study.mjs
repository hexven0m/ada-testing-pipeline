import { pathToFileURL } from "node:url";
import { observeFrontend, observerErrorReason } from "./observe_ada_frontend.mjs";
import { probeRTCContracts, validRTCStudy } from "./owned_candidate_research_probe.mjs";

export async function observeRTCStudy(port, url) {
  const observed = await observeFrontend({ port, url, diagnosticProbe: probeRTCContracts });
  if (!validRTCStudy(observed.diagnostic_probe)) throw new Error("owned-rtc-study-contract");
  observed.rtc_contract_study = observed.diagnostic_probe;
  delete observed.diagnostic_probe;
  return observed;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(await observeRTCStudy(Number(process.argv[2]), process.argv[3]))); }
  catch (error) {
    console.log(JSON.stringify({ state: "UNKNOWN", reason: observerErrorReason(error),
      ...(error.diagnostics ? { diagnostics: error.diagnostics } : {}) }));
    process.exitCode = 1;
  }
}
