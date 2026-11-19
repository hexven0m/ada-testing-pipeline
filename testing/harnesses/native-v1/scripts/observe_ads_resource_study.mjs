import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {observeFrontend, observerErrorReason} from './observe_ada_frontend.mjs';
import {probeAssistantControl} from './observe_assistant_control.mjs';

const BASELINE_HASH = '1d325c5899f5e0818890ccd69202480cd28ee1463913c9c18d00b49b0b04f6bd';
const digest = source => createHash('sha256').update(source).digest('hex');

// This supplemental probe runs ONLY after the unchanged React collector receipt.
// Private exports never replace the page's detector exports or its native result.
export function composedAdsResourceProbe(baselineSource, candidateSource) {
  if (digest(baselineSource) !== BASELINE_HASH) throw new Error('ads-resource-baseline-contract');
  return Function(`return async function () {
    const phase = 'POST_PREDICTION_SYNTHETIC_COUNTERCONTROL';
    const base = 'chrome-extension://gcaiimgaiohlnlflkjjmcohobkpbbnfi/';
    const urls = new Set([base + 'dist/contentScripts/style.css', base + 'dist/security/index.html']);
    const originalFetch = window.fetch;
    const originalDetector = window.detect_ads_power;
    const framesBefore = document.querySelectorAll('iframe').length;
    const compile = source => new Function('window', source +
      '\\nreturn {resource: nuAdsAssistantResource, detect: detect_ads_power};')({chrome: window.chrome});
    const baseline = compile(${JSON.stringify(baselineSource)});
    const candidate = compile(${JSON.stringify(candidateSource)});
    const cases = [];
    let failed = false;
    for (const fixture of ['native-empty-url', 'page-owned-url']) {
      const wrapper = function (...args) {
        if (typeof args[0] === 'string' && urls.has(args[0])) {
          const response = new Response('owned fixture', {status: 200});
          if (fixture === 'page-owned-url') Object.defineProperty(response, 'url', {value: args[0]});
          return Promise.resolve(response);
        }
        return Reflect.apply(originalFetch, this, args);
      };
      try {
        window.fetch = wrapper;
        if (window.fetch !== wrapper) throw new Error('owned wrapper unavailable');
        const checkedPageResource = async () => {
          const outcomes = await Promise.all([...urls].map(async url => {
            const response = await fetch(url);
            return response.ok === true && response.status === 200 && response.url === url;
          }));
          return outcomes.some(Boolean);
        };
        const values = await Promise.all([baseline.resource(), checkedPageResource(),
          candidate.resource(), baseline.detect(), candidate.detect()]);
        cases.push({fixture, baseline_resource: values[0], page_checked_resource: values[1],
          candidate_resource: values[2], baseline_detected: values[3], candidate_detected: values[4]});
      } catch {
        failed = true;
      } finally {
        window.fetch = originalFetch;
      }
    }
    const fetch_restored = window.fetch === originalFetch;
    const exports_unchanged = window.detect_ads_power === originalDetector;
    const frames_removed = document.querySelectorAll('iframe').length === framesBefore;
    const assistant_control = await (${probeAssistantControl.toString()})();
    return {assistant_control, ads_resource_study: {
      phase, state: failed || !fetch_restored || !exports_unchanged || !frames_removed ? 'UNKNOWN' : 'complete',
      cases, fetch_restored, exports_unchanged, frames_removed
    }};
  };`)();
}

export function validAdsResourceStudy(value) {
  const keys = ['phase', 'state', 'cases', 'fetch_restored', 'exports_unchanged', 'frames_removed'];
  if (!value || Object.keys(value).sort().join() !== keys.sort().join() ||
      value.phase !== 'POST_PREDICTION_SYNTHETIC_COUNTERCONTROL' || value.state !== 'complete') return false;
  if (!Array.isArray(value.cases) || value.cases.length !== 2 ||
      value.fetch_restored !== true || value.exports_unchanged !== true || value.frames_removed !== true) return false;
  const caseKeys = ['fixture', 'baseline_resource', 'page_checked_resource', 'candidate_resource',
    'baseline_detected', 'candidate_detected'];
  return value.cases.every((row, index) => row &&
    Object.keys(row).sort().join() === caseKeys.sort().join() &&
    row.fixture === ['native-empty-url', 'page-owned-url'][index] &&
    caseKeys.filter(key => key !== 'fixture').every(key => typeof row[key] === 'boolean'));
}

export async function observeAdsResourceStudy(port, url, candidatePath, baselinePath) {
  const baselineSource = fs.readFileSync(baselinePath, 'utf8');
  const candidateSource = fs.readFileSync(candidatePath, 'utf8');
  const probe = composedAdsResourceProbe(baselineSource, candidateSource);
  const value = await observeFrontend({port, url, diagnosticProbe: probe});
  if (value.detector_sha256?.['ads_power.js'] !== digest(candidateSource)) throw new Error('ads-resource-source-contract');
  if (!validAdsResourceStudy(value.diagnostic_probe?.ads_resource_study)) throw new Error('ads-resource-study-contract');
  value.ads_resource_study = value.diagnostic_probe.ads_resource_study;
  value.ads_resource_study.baseline_sha256 = digest(baselineSource);
  value.ads_resource_study.candidate_sha256 = digest(candidateSource);
  value.assistant_control = value.diagnostic_probe.assistant_control;
  delete value.diagnostic_probe;
  return value;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {console.log(JSON.stringify(await observeAdsResourceStudy(Number(process.argv[2]), process.argv[3], process.argv[4], process.argv[5])));}
  catch (error) {
    console.log(JSON.stringify({state: 'UNKNOWN', reason: observerErrorReason(error),
      ...(error.diagnostics ? {diagnostics: error.diagnostics} : {})}));
    process.exitCode = 1;
  }
}
