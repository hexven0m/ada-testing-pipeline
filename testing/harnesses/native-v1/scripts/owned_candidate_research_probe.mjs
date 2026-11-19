/** Dedicated candidate research through the existing diagnostic-only hook.
 * Boolean/count output only; no addresses, raw SDP/stacks, or device queries.
 * This is a research observer in a COPY, never the frontend/scorer.
 */
export async function probeRTCContracts() {
  const result = {study: 'candidate-contracts-20261026', diagnostic_only: true,
    submission_certified: false, rtc: null, stacks: null, css: []};
  result.rtc = await new Promise(resolve => {
    let peer, channel, timer, ready = false, ended = false;
    const records = [], seen = new Set();
    const out = {complete: false, cleaned: false, notifications: 0,
      nullUfrag: 0, populatedUfrag: 0, allUfragsAgreeWithSDP: null,
      allConstructedRoundTripsAgree: true, allEventsTrusted: true,
      hasHost: false, hasSrflx: false, duplicatesFull: false, duplicatesCore: false,
      fullDistinct: 0, coreDistinct: 0};
    function finish(complete) {
      if (ended) return;
      ended = true; clearTimeout(timer); out.complete = complete;
      try {
        if (complete) {
          const sdp = peer.localDescription?.sdp;
          const match = typeof sdp === 'string' ? /(?:^|\r?\n)a=ice-ufrag:([^\r\n]+)/.exec(sdp) : null;
          out.allUfragsAgreeWithSDP = Boolean(match) && records.every(r => r.ufrag === match[1]);
          const full = new Set(records.map(r => r.full)), core = new Set(records.map(r => r.core));
          out.fullDistinct = full.size; out.coreDistinct = core.size;
          out.duplicatesFull = full.size < records.length;
          out.duplicatesCore = core.size < records.length;
        }
      } catch { out.complete = false; }
      let clean = true;
      try { if (peer) peer.onicecandidate = null; } catch { clean = false; }
      try { if (peer) peer.onicegatheringstatechange = null; } catch { clean = false; }
      try { if (channel) channel.close(); } catch { clean = false; }
      try { if (peer) peer.close(); } catch { clean = false; }
      out.cleaned = clean; resolve(out);
    }
    function complete() {
      if (ready && peer.iceGatheringState === 'complete') finish(true);
    }
    try {
      timer = setTimeout(() => finish(false), 3000);
      peer = new RTCPeerConnection({iceServers: [], iceTransportPolicy: 'all'});
      channel = peer.createDataChannel('owned-candidate-research');
      peer.onicegatheringstatechange = complete;
      peer.onicecandidate = event => {
        if (ended) return;
        try {
          if (event.candidate === null) { complete(); return; }
          const c = event.candidate, raw = c.candidate;
          if (typeof raw !== 'string' || raw.length > 8192 || records.length >= 32) { finish(false); return; }
          if (!raw) return;
          const fields = raw.trim().split(/\s+/);
          out.notifications++;
          out.allEventsTrusted &&= event.isTrusted === true && !seen.has(event);
          seen.add(event);
          out.hasHost ||= c.type === 'host'; out.hasSrflx ||= c.type === 'srflx';
          if (c.usernameFragment === null) out.nullUfrag++;
          else if (typeof c.usernameFragment === 'string' && c.usernameFragment) out.populatedUfrag++;
          const json = c.toJSON(), reconstructed = new RTCIceCandidate(json);
          out.allConstructedRoundTripsAgree &&= ['candidate','sdpMid','sdpMLineIndex','usernameFragment']
            .every(k => reconstructed[k] === c[k]);
          records.push({full:JSON.stringify([raw.trim().replace(/\s+/g,' '),c.sdpMid,c.sdpMLineIndex,c.usernameFragment]),
            core:JSON.stringify([fields.slice(0,8).join(' '),c.sdpMid,c.sdpMLineIndex,c.usernameFragment]),
            ufrag:c.usernameFragment});
        } catch { finish(false); }
      };
      Promise.resolve(peer.createOffer()).then(o => peer.setLocalDescription(o)).then(() => {
        if (ended) return; ready = true; complete();
      }).catch(() => finish(false));
    } catch { finish(false); }
  });
  let script;
  try {
    script = document.createElement('script');
    script.textContent = "const ownedStacks = [new Error('owned-error').stack,new TypeError('owned-type').stack,new RangeError('owned-range').stack];" +
      "const ownedCaptured = {};Error.captureStackTrace(ownedCaptured);ownedStacks.push(ownedCaptured.stack);" +
      "try{Object.defineProperty(null,'owned',{})}catch(ownedException){ownedStacks.push(ownedException.stack)}" +
      "document.currentScript.__ownedStacks = ownedStacks;";
    document.documentElement.appendChild(script);
    const values = script.__ownedStacks;
    result.stacks = Array.isArray(values) ? values.map(stack => {
      const lines = typeof stack === 'string' ? stack.split(/\r?\n/) : [];
      return {string: typeof stack === 'string', firstBare:/^\s*at\s*$/.test(lines[1] ?? ''),
        bareFrames:lines.filter(line => /^\s*at\s*$/.test(line)).length,
        frames:Math.max(0,lines.length-1),
        nativeFrames:lines.filter(line => line.includes('(<anonymous>)')).length};
    }) : null;
    delete script.__ownedStacks;
  } catch { result.stacks = null; }
  finally { if (script) script.remove(); }

  result.implicit_forms = [];
  for (const form of ['block', 'function']) {
    let node;
    const body = "var items=[];try{Object.defineProperty(null,'owned',{})}catch(e){items.push(e.stack)}" +
      "try{Object.getPrototypeOf(null)}catch(e){items.push(e.stack)}" +
      "document.currentScript.__adaForms=items;";
    try {
      node = document.createElement('script');
      node.textContent = form === 'block' ? '{' + body.replace('var items', 'let items') + '}' :
        '(function(){' + body + '}());';
      document.documentElement.appendChild(node);
      result.implicit_forms.push({form, samples:Array.isArray(node.__adaForms) ? node.__adaForms.map(value => {
        const lines = typeof value === 'string' ? value.split(/\r?\n/) : [];
        const operation = /\bat ((?:Function|Object)\.)?(defineProperty|getPrototypeOf) \(<anonymous>\)/.exec(lines[1] ?? '');
        return {typeError:/^TypeError:/.test(lines[0] ?? ''),
          nativeOperation:operation ? (operation[1] ?? '') + operation[2] : null,
          secondBare:/^\s*at\s*$/.test(lines[2] ?? ''),
          secondHasAnonymous:/<anonymous>/.test(lines[2] ?? ''), frames:Math.max(0,lines.length-1)};
      }) : null});
    } finally { if (node) { delete node.__adaForms; node.remove(); } }
  }

  async function stylesheet(path, child) {
    let frame, link, timer;
    const out = {path_kind:path.includes('__ada_absent_') ? 'negative' : 'positive',
      child, loaded:false, trusted:false, sheet:false, rules:'UNREAD', cleaned:false,
      terminal:'TIMEOUT', errorTrusted:null, errorOwned:null, errorSheetNull:null,
      ownerAgrees:null, mediaAgrees:null};
    try {
      let doc = document;
      if (child) {
        frame = document.createElement('iframe');
        frame.style.cssText = 'position:fixed;left:-200px;top:-200px;width:1px;height:1px;border:0';
        document.documentElement.appendChild(frame); doc = frame.contentDocument;
      }
      await new Promise(resolve => {
        link = doc.createElement('link'); link.rel = 'stylesheet'; link.media = 'not all';
        link.href = 'chrome-extension://gcaiimgaiohlnlflkjjmcohobkpbbnfi/' + path;
        link.onload = event => {
          out.loaded = true; out.trusted = event.isTrusted === true;
          out.terminal = 'LOAD';
          out.ownerAgrees = event.target === link && link.ownerDocument === doc;
          out.mediaAgrees = link.media === 'not all' && link.rel === 'stylesheet';
          out.sheet = typeof doc.defaultView.CSSStyleSheet === 'function' && link.sheet instanceof doc.defaultView.CSSStyleSheet;
          try { out.rules = typeof link.sheet?.cssRules?.length === 'number' ? 'READABLE' : 'ABSENT'; }
          catch(e) { out.rules = e.name === 'SecurityError' ? 'SECURITY_ERROR' : 'OTHER_ERROR'; }
          resolve();
        };
        link.onerror = event => {
          out.terminal = 'ERROR'; out.errorTrusted = event.isTrusted === true;
          out.errorOwned = event.target === link; out.errorSheetNull = link.sheet === null;
          resolve();
        };
        timer = setTimeout(resolve,1800);
        (doc.head || doc.documentElement).appendChild(link);
      });
    } catch { out.rules = 'SETUP_ERROR'; }
    finally {
      clearTimeout(timer);
      if (link) { link.onload = null; link.onerror = null; link.remove(); }
      if (frame) frame.remove();
      out.cleaned = (!link || !link.isConnected) && (!frame || !frame.isConnected);
    }
    return out;
  }
  for (const [path,child] of [['dist/contentScripts/style.css',false],
      ['dist/contentScripts/__ada_absent_control__.css',false],
      ['dist/contentScripts/style.css',true],
      ['dist/contentScripts/__ada_absent_control__.css',true]]) {
    result.css.push(await stylesheet(path,child));
  }
  return result;
}

export function validRTCStudy(value) {
  return value?.study === 'candidate-contracts-20261026' && value.diagnostic_only === true &&
    value.submission_certified === false && typeof value.rtc === 'object' &&
    Array.isArray(value.css) && value.css.length === 4 && value.css.every(r => r.cleaned === true);
}
