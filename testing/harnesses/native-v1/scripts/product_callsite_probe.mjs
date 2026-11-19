/** Diagnostic branch observations only, never a product or mode classifier. */
import { readFileSync } from "node:fs";
export const callsiteProbeSource = readFileSync(new URL("./product_callsite_helper.js", import.meta.url), "utf8");

export function validCallsiteResult(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === 2 && ["bareFirstFrames", "legacyScrollMarker"].every(
      key => Object.hasOwn(value, key) && (typeof value[key] === "boolean" || value[key] === null));
}
