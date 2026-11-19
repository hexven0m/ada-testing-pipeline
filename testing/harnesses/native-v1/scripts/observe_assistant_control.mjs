/** Inspect the fixed helper resource AFTER original frontend predictions. */
import {pathToFileURL} from 'node:url';
import {observeFrontend, observerErrorReason} from './observe_ada_frontend.mjs';

export async function probeAssistantControl() {
  const prefix = 'chrome-extension://gcaiimgaiohlnlflkjjmcohobkpbbnfi/';
  const results = await Promise.all(['dist/contentScripts/style.css', 'dist/security/index.html'].map(async path => {
    try {
      const response = await fetch(prefix + path, {signal: AbortSignal.timeout(1200), cache: 'no-store'});
      return response.ok === true;
    } catch { return false; }
  }));
  // Enum-only audit of actual gathering, not raw candidates, addresses or SDP.
  // The launch flag alone does not prove which RTC behavior occurred.
  const rtc = await new Promise(resolve => {
    let peer, channel, timer, ended = false, descriptionReady = false;
    const audit = {state: 'UNKNOWN', local_configuration_retained: false,
      types: {host: 0, srflx: 0, prflx: 0, relay: 0, other: 0},
      protocols: {udp: 0, tcp: 0, other: 0}, cleanup_confirmed: false};
    function finish(complete) {
      if (ended) return;
      ended = true;
      clearTimeout(timer);
      let cleaned = true;
      try {if (peer) peer.onicecandidate = null;} catch {cleaned = false;}
      try {if (peer) peer.onicegatheringstatechange = null;} catch {cleaned = false;}
      try {if (channel) channel.close();} catch {cleaned = false;}
      try {if (peer) peer.close();} catch {cleaned = false;}
      audit.cleanup_confirmed = cleaned;
      audit.state = complete && cleaned ? 'complete' : 'UNKNOWN';
      resolve(audit);
    }
    function completed() {
      try {if (descriptionReady && peer.iceGatheringState === 'complete') finish(true);}
      catch {finish(false);}
    }
    try {
      timer = setTimeout(() => finish(false), 3000);
      peer = new RTCPeerConnection({iceServers: [], iceTransportPolicy: 'all'});
      const configuration = peer.getConfiguration();
      audit.local_configuration_retained = Array.isArray(configuration?.iceServers) &&
        configuration.iceServers.length === 0 && configuration.iceTransportPolicy === 'all';
      if (!audit.local_configuration_retained) {finish(false); return;}
      channel = peer.createDataChannel('ada-owned-rtc-control');
      peer.onicecandidate = event => {
        if (ended) return;
        try {
          if (!event || !('candidate' in event)) {finish(false); return;}
          if (event.candidate === null) {completed(); return;}
          const candidate = event.candidate;
          // Empty generation markers are not connectivity candidates.
          if (candidate.candidate === '') return;
          const kind = Object.hasOwn(audit.types, candidate.type) ? candidate.type : 'other';
          const protocol = Object.hasOwn(audit.protocols, candidate.protocol) ? candidate.protocol : 'other';
          audit.types[kind]++;
          audit.protocols[protocol]++;
        } catch {finish(false);}
      };
      peer.onicegatheringstatechange = completed;
      Promise.resolve(peer.createOffer()).then(offer => {
        if (!ended) return peer.setLocalDescription(offer);
      }).then(() => {
        if (!ended) {descriptionReady = true; completed();}
      }).catch(() => finish(false));
    } catch {finish(false);}
  });
  return {diagnostic_only: true, classification: 'NOT_A_CLASSIFIER',
    resource_accessible: results.some(Boolean), rtc};
}

export async function observeAssistantControl(port, url) {
  const value = await observeFrontend({port, url, diagnosticProbe: probeAssistantControl});
  value.assistant_control = value.diagnostic_probe;
  delete value.diagnostic_probe;
  return value;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {console.log(JSON.stringify(await observeAssistantControl(Number(process.argv[2]), process.argv[3])));}
  catch (error) {
    console.log(JSON.stringify({state: 'UNKNOWN', reason: observerErrorReason(error)}));
    process.exitCode = 1;
  }
}
