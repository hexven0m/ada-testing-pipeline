/** Launch only the already-created owned profile; credentials never enter argv. */
import fs from "node:fs";
import readline from "node:readline";
import { pathToFileURL } from "node:url";

// This path is provisioned from the exact existing gologin 3.0.5 installation.
const sdkEntry = process.env.ADA_GOLOGIN_SDK_ENTRY ||
  "/opt/ada-runner/node_modules/gologin/src/index.js";
const { GologinApi } = await import(pathToFileURL(sdkEntry).href);

const input = readline.createInterface({ input: process.stdin });
const config = await new Promise(resolve => input.once("line", line => resolve(JSON.parse(line))));
if (!/^[a-f0-9]{24}$/.test(config.owned_profile_id) || !["headed", "headless"].includes(config.mode)) {
  throw new Error("Owned profile session contract rejected");
}
const token = fs.readFileSync("/etc/ada-runner/credentials/gologin.token", "utf8").trim();
const gl = GologinApi({ token });
let browser;
let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  try {
    if (browser) await browser.close();
    process.stdout.write("ADA_OWNED_STOPPED\n");
    process.exit(0);
  } catch {
    process.exit(1);
  }
}
process.once("SIGTERM", stop);
input.on("line", line => { if (line === "STOP") void stop(); });
try {
  const extraParams = ["--no-sandbox", "--disable-dev-shm-usage"];
  if (config.mode === "headless") extraParams.push("--headless");
  ({ browser } = await gl.launch({ profileId: config.owned_profile_id, extra_params: extraParams }));
  process.stdout.write("ADA_OWNED_SESSION=" + JSON.stringify({ port: new URL(browser.wsEndpoint()).port }) + "\n");
} catch {
  process.stdout.write('ADA_OWNED_SESSION={"stage":"sdk-launch-failed"}\n');
  process.exitCode = 1;
  input.close();
}
