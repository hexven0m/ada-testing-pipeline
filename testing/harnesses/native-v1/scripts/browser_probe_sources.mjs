/** Load the challenge's actual preload before its six independent detectors. */
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";

export const detectorNames = Object.freeze([
  "headless", "ads_power", "dolphin_anty", "gologin", "multilogin", "octo",
]);

export async function loadBrowserProbeSources({ detectorDirectory, preloadPath,
  preload = "challenge", reader = readFile }) {
  if (!["challenge", "native"].includes(preload)) {
    throw new Error("ADA_PROBE_PRELOAD must be challenge or native");
  }
  const scripts = [];
  const detectorSha256 = {};
  let preloadSha256 = null;
  if (preload === "challenge") {
    const content = await reader(preloadPath, "utf8");
    preloadSha256 = createHash("sha256").update(content).digest("hex");
    scripts.push({ name: "challenge-user-agent-preload", content });
  }
  for (const name of detectorNames) {
    const content = await reader(join(detectorDirectory, `${name}.js`), "utf8");
    detectorSha256[`${name}.js`] = createHash("sha256").update(content).digest("hex");
    scripts.push({ name, content });
  }
  // Keep the established preload contract stable for existing matrix readers.
  return { scripts, detectorSha256, setup: { preload, preloadSha256 } };
}
