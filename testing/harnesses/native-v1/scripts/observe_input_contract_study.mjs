import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {observeFrontend, observerErrorReason} from './observe_ada_frontend.mjs';
import {probeInputContracts, validInputStudy} from './owned_input_contract_probe.mjs';
import {probeAssistantControl} from './observe_assistant_control.mjs';

// The observer serializes one self-contained function into the owned page.
// Both diagnostics run AFTER the unchanged React result and collector receipt.
export function composedInputProbe() {
  return Function(`return async function () {
    const [input_contract_study, assistant_control] = await Promise.all([
      (${probeInputContracts.toString()})(), (${probeAssistantControl.toString()})()
    ]);
    return {input_contract_study, assistant_control};
  };`)();
}

export async function observeInputStudy(port, url) {
  const value = await observeFrontend({port, url, diagnosticProbe: composedInputProbe()});
  if (!validInputStudy(value.diagnostic_probe?.input_contract_study)) throw new Error('owned-input-study-contract');
  value.input_contract_study = value.diagnostic_probe.input_contract_study;
  value.assistant_control = value.diagnostic_probe.assistant_control;
  value.input_probe_sha256 = createHash('sha256').update(probeInputContracts.toString()).digest('hex');
  delete value.diagnostic_probe;
  return value;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {console.log(JSON.stringify(await observeInputStudy(Number(process.argv[2]), process.argv[3])));}
  catch (error) {
    console.log(JSON.stringify({state: 'UNKNOWN', reason: observerErrorReason(error),
      ...(error.diagnostics ? {diagnostics: error.diagnostics} : {})}));
    process.exitCode = 1;
  }
}
