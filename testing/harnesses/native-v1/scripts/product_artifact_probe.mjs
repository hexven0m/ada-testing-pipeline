/** Owned-session diagnostics only: named code and transient protocol behavior.
 * No IP/SDP values, font/rendering output, hardware data or raw source exported.
 * Neither candidate counts nor generic API anomalies are product classifiers.
 */
export async function probeProductArtifacts(context, { timeoutMs = 2500,
  protocolConformance = false, receiverConformance = false, wrapperConformance = false,
  pageResourceDiagnostic = false, imageLimitDiagnostic = false } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3000) {
    throw new RangeError("Invalid diagnostic budget");
  }
  if (typeof receiverConformance !== "boolean") throw new TypeError("Invalid receiver diagnostic option");
  if (typeof wrapperConformance !== "boolean") throw new TypeError("Invalid wrapper diagnostic option");
  if (typeof pageResourceDiagnostic !== "boolean") throw new TypeError("Invalid page resource option");
  if (typeof imageLimitDiagnostic !== "boolean") throw new TypeError("Invalid image limit option");
  const patterns = {
    ads_power: /adspower|ads_power|sunbrowser|flowerbrowser/i,
    dolphin_anty: /dolphin[ _-]?anty|antybrowser/i,
    gologin: /gologin|go_login|orbita(?!l)/i,
    multilogin: /multilogin|multi_login|mimicbrowser|stealthfox/i,
    octo: /octobrowser|octo_browser|octium(?:browser)?/i,
  };
  const owners = { window: context };
  const unavailable = [];
  for (const name of ["chrome", "navigator", "Error", "Intl", "JSON", "Reflect"]) {
    try { owners[name] = context[name]; } catch { unavailable.push(name); }
  }
  for (const [name, owner, property] of [
    ["chrome.runtime", owners.chrome, "runtime"],
    ["chrome.app", owners.chrome, "app"],
  ]) {
    try { owners[name] = owner && Object.getOwnPropertyDescriptor(owner, property)?.value; }
    catch { unavailable.push(name); }
  }
  try {
    const app = owners["chrome.app"];
    owners["chrome.app.runtime"] = app && Object.getOwnPropertyDescriptor(app, "runtime")?.value;
  } catch { unavailable.push("chrome.app.runtime"); }
  try { owners["navigator.mediaDevices"] = owners.navigator?.mediaDevices; }
  catch { unavailable.push("navigator.mediaDevices"); }
  for (const name of ["RTCPeerConnection", "MediaDevices", "MediaDeviceInfo",
    "InputDeviceInfo", "MediaStreamTrack"]) {
    try { owners[name] = context[name]; } catch { unavailable.push(name); }
  }
  for (const name of ["Navigator", "NavigatorUAData", "Screen", "Permissions", "Document",
    "HTMLCanvasElement", "WebGLRenderingContext", "WebGL2RenderingContext",
    "RTCPeerConnection", "RTCIceCandidate", "RTCDataChannel", "MediaDevices",
    "MediaDeviceInfo", "InputDeviceInfo", "MediaStreamTrack", "MediaStream",
    "HTMLMediaElement", "Function", "Error"]) {
    try { owners[name + ".prototype"] = context[name]?.prototype; }
    catch { unavailable.push(name + ".prototype"); }
  }
  const matches = [];
  const coverage = [];
  const symbolMatches = [];
  const symbolCoverage = [];
  for (const [ownerName, owner] of Object.entries(owners)) {
    if (!owner) { unavailable.push(ownerName); continue; }
    // Symbols on browser-owned interfaces may expose a product-owned hook.
    // Exclude window: a page can create its own global symbols. Never export
    // symbol descriptions or read symbol-keyed values.
    if (ownerName !== "window") {
      try {
        const symbols = Object.getOwnPropertySymbols(owner);
        symbolCoverage.push({ owner: ownerName, inspected: Math.min(symbols.length, 256),
          limited: symbols.length > 256 });
        for (const symbol of symbols.slice(0, 256)) {
          const description = symbol.description;
          if (typeof description !== "string") continue;
          for (const [product, pattern] of Object.entries(patterns)) {
            if (pattern.test(description)) symbolMatches.push({ product, owner: ownerName });
          }
        }
      } catch { symbolCoverage.push({ owner: ownerName, inspected: 0, limited: true }); }
    }
    let properties;
    try { properties = Object.getOwnPropertyNames(owner); }
    catch { unavailable.push(ownerName); continue; }
    let errors = 0;
    let inspected = 0;
    for (const property of properties.slice(0, 2000)) {
      // Candidate helpers are page globals too; their own source is not browser evidence.
      // Submission globals are probe contamination, never product evidence.
      if (/^(?:detect_|__ada|nu[A-Z]|NU_)/.test(property)) continue;
      inspected++;
      try {
        const descriptor = Object.getOwnPropertyDescriptor(owner, property);
        const functions = [descriptor?.value, descriptor?.get, descriptor?.set]
          .filter(value => typeof value === "function");
        for (const [product, pattern] of Object.entries(patterns)) {
          const namedProperty = pattern.test(property);
          const namedFunction = functions.some(fn => pattern.test(fn.name));
          const namedCode = functions.some(fn => pattern.test(Function.prototype.toString.call(fn)));
          if (namedProperty || namedFunction || namedCode) {
            // Even a matched identifier/source can include account-specific
            // text. Export only the known owner and booleans, not that text.
            matches.push({ product, owner: ownerName, namedProperty, namedFunction, namedCode });
          }
        }
      } catch { errors++; }
    }
    coverage.push({ owner: ownerName, inspected, errors, limited: properties.length > 2000 });
  }
  // This is an attribution lead only. A site can create its own DOM nodes,
  // and resource timing may omit extension traffic. Export matches by kind,
  // never raw URLs, DOM strings, extension IDs or page text.
  const pageResources = { state: "NOT_RUN", classification: "NOT_A_CLASSIFIER",
    namedExtensionResources: [], namedDomNodes: [], inspectedResources: 0,
    inspectedNodes: 0, limited: false };
  if (pageResourceDiagnostic) {
    pageResources.state = "observed";
    const extensionResources = new Set();
    const domNodes = new Set();
    try {
      const entries = context.performance?.getEntriesByType?.("resource") || [];
      pageResources.inspectedResources = Math.min(entries.length, 1000);
      pageResources.limited ||= entries.length > 1000;
      for (const entry of Array.from(entries).slice(0, 1000)) {
        const url = entry?.name;
        if (typeof url !== "string" || !url.startsWith("chrome-extension://")) continue;
        for (const [product, pattern] of Object.entries(patterns)) {
          if (pattern.test(url)) extensionResources.add(product);
        }
      }
    } catch { pageResources.state = "UNKNOWN"; }
    try {
      const nodes = context.document?.querySelectorAll?.("[id], [class], script[src], link[href], iframe[src]") || [];
      pageResources.inspectedNodes = Math.min(nodes.length, 1000);
      pageResources.limited ||= nodes.length > 1000;
      for (const node of Array.from(nodes).slice(0, 1000)) {
        const attributes = [node.getAttribute?.("id"), node.getAttribute?.("class")];
        const url = node.getAttribute?.("src") || node.getAttribute?.("href");
        if (typeof url === "string" && url.startsWith("chrome-extension://")) {
          attributes.push(url);
        }
        for (const [product, pattern] of Object.entries(patterns)) {
          if (attributes.some(value => typeof value === "string" && pattern.test(value))) {
            domNodes.add(product);
          }
        }
      }
    } catch { pageResources.state = "UNKNOWN"; }
    pageResources.namedExtensionResources = [...extensionResources];
    pageResources.namedDomNodes = [...domNodes];
  }
  let imageLimit = { state: "NOT_RUN", classification: "NOT_A_CLASSIFIER",
    small: null, large: null };
  if (imageLimitDiagnostic) {
    // Octo documents a configurable image-size limit. Check only two fixed
    // data images; this never probes a network address or reads image pixels.
    // A blocked image is not product ownership until ordinary browsers and
    // other vendor/profile settings have been ruled out.
    if (typeof context.Image !== "function") imageLimit.state = "unsupported";
    else {
      const prefix = '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">';
      const suffix = '<rect width="1" height="1" fill="green"/></svg>';
      async function loadImage(padding) {
        return new Promise(resolve => {
          let image;
          let timer;
          let settled = false;
          function finish(outcome) {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (image) { image.onload = null; image.onerror = null; }
            resolve(outcome);
          }
          try {
            image = new context.Image();
            image.onload = () => finish("load");
            image.onerror = () => finish("error");
            timer = setTimeout(() => finish("UNKNOWN"), timeoutMs);
            image.src = "data:image/svg+xml," + encodeURIComponent(prefix +
              "<desc>" + "a".repeat(padding) + "</desc>" + suffix);
          } catch { finish("UNKNOWN"); }
        });
      }
      const [small, large] = await Promise.all([loadImage(100), loadImage(20000)]);
      imageLimit = { state: "observed", classification: "NOT_A_CLASSIFIER", small, large };
    }
  }
  let stack = { state: "UNKNOWN", bareFirstFrames: null };
  try {
    function outer() { function inner() { return String(new context.Error().stack || ""); } return inner(); }
    const frames = outer().split("\n").slice(1).filter(line => line.trim());
    stack = { state: "complete", bareFirstFrames: frames.length >= 3 &&
      frames.slice(0, 3).every(frame => /^\s*at\s*$/.test(frame)) };
  } catch { /* No raw errors or stack paths are exported. */ }
  let receivers = { state: "NOT_RUN", classification: "NOT_A_CLASSIFIER" };
  if (receiverConformance) {
    // The receiver is always a new unbranded object, never a real navigator,
    // screen, rendering context, peer or data channel. Returned values and
    // raw errors/stacks are discarded. Generic nonconformance is NOT product
    // ownership; this laboratory check cannot label a vendor or a human.
    const definitions = [
      ["Navigator", "platform", "get"], ["Navigator", "languages", "get"],
      ["Navigator", "hardwareConcurrency", "get"], ["Navigator", "deviceMemory", "get"],
      ["Navigator", "plugins", "get"], ["Navigator", "mimeTypes", "get"],
      ["Screen", "width", "get"], ["Screen", "height", "get"],
      ["Screen", "availWidth", "get"], ["Screen", "availHeight", "get"],
      ["RTCPeerConnection", "getConfiguration", "value"],
      ["RTCIceCandidate", "toJSON", "value"], ["RTCDataChannel", "send", "value"],
      ["MediaDevices", "enumerateDevices", "value"],
      ["MediaStreamTrack", "getSettings", "value"],
      ["InputDeviceInfo", "getCapabilities", "value"],
    ];
    const cases = [];
    for (const [owner, property, kind] of definitions) {
      let outcome = "unavailable";
      let settlement = "NOT_RUN";
      try {
        const prototype = context[owner]?.prototype;
        const descriptor = prototype && Object.getOwnPropertyDescriptor(prototype, property);
        const fn = descriptor?.[kind];
        if (typeof fn === "function") {
          try {
            const value = Reflect.apply(fn, Object.create(null), property === "send" ? [""] : []);
            // Attaching intrinsic handlers prevents an unexpected rejected
            // promise from escaping; it does not access arbitrary thenables.
            let settledPromise;
            try {
              if (owner === "MediaDevices" && property === "enumerateDevices") {
                settledPromise = Promise.prototype.then.call(value, () => "resolved", error => {
                  try { return error?.name === "TypeError" ? "rejected-TypeError" : "rejected-other"; }
                  catch { return "UNKNOWN"; }
                });
              } else Promise.prototype.then.call(value, () => {}, () => {});
            } catch { /* Not a promise. */ }
            if (owner === "MediaDevices" && property === "enumerateDevices") {
              if (settledPromise) {
                let timer;
                try {
                  settlement = await Promise.race([settledPromise,
                    new Promise(resolve => { timer = setTimeout(() => resolve("timeout"), 250); })]);
                } finally { clearTimeout(timer); }
              } else settlement = "non-promise";
            }
            outcome = "returned";
          } catch (error) {
            try { outcome = error?.name === "TypeError" ? "rejected-TypeError" : "rejected-other"; }
            catch { outcome = "UNKNOWN"; }
          }
        }
      } catch { outcome = "descriptor-UNKNOWN"; }
      cases.push({ owner, property, outcome, ...(owner === "MediaDevices" &&
        property === "enumerateDevices" ? { settlement } : {}) });
    }
    receivers = { state: "observed", classification: "NOT_A_CLASSIFIER", cases };
  }
  let wrappers = { state: "NOT_RUN", classification: "NOT_A_CLASSIFIER" };
  if (wrapperConformance) {
    // Inspect fixed API function objects, not their device/rendering values.
    // The real API is never invoked: construction uses an empty local target
    // with the inspected function only as newTarget. This is a wrapper lead,
    // never a browser/version/identity classifier.
    const definitions = [
      ["Navigator", "platform", "get"], ["Navigator", "languages", "get"],
      ["Navigator", "hardwareConcurrency", "get"], ["Navigator", "deviceMemory", "get"],
      ["Navigator", "maxTouchPoints", "get"], ["Navigator", "plugins", "get"],
      ["Navigator", "mimeTypes", "get"], ["Screen", "width", "get"],
      ["Screen", "height", "get"], ["Screen", "availWidth", "get"],
      ["Screen", "availHeight", "get"], ["HTMLCanvasElement", "toDataURL", "value"],
      ["HTMLCanvasElement", "toBlob", "value"], ["WebGLRenderingContext", "getParameter", "value"],
      ["WebGL2RenderingContext", "getParameter", "value"], ["RTCPeerConnection", "getConfiguration", "value"],
      ["RTCIceCandidate", "toJSON", "value"], ["Permissions", "query", "value"],
      ["MediaDevices", "enumerateDevices", "value"],
      ["MediaDevices", "getUserMedia", "value"],
      ["MediaDevices", "getDisplayMedia", "value"],
      ["MediaDeviceInfo", "toJSON", "value"],
      ["InputDeviceInfo", "getCapabilities", "value"],
      ["MediaStreamTrack", "getSettings", "value"],
      ["MediaStreamTrack", "getCapabilities", "value"],
      ["Date", "getTimezoneOffset", "value"], ["Function", "toString", "value"],
    ];
    const cases = [];
    for (const [owner, property, kind] of definitions) {
      const row = { owner, property, kind, state: "unavailable" };
      try {
        const prototype = context[owner]?.prototype;
        const fn = prototype && Object.getOwnPropertyDescriptor(prototype, property)?.[kind];
        if (typeof fn === "function") {
          const code = Function.prototype.toString.call(fn);
          const name = Object.getOwnPropertyDescriptor(fn, "name");
          const length = Object.getOwnPropertyDescriptor(fn, "length");
          row.nativeLike = /\{\s*\[native code\]\s*\}/.test(code);
          row.ownToString = Boolean(Object.getOwnPropertyDescriptor(fn, "toString"));
          row.nameIsData = Boolean(name && Object.hasOwn(name, "value"));
          row.lengthIsData = Boolean(length && Object.hasOwn(length, "value"));
          row.ownPrototype = Boolean(Object.getOwnPropertyDescriptor(fn, "prototype"));
          row.productNamedCode = Object.values(patterns).some(pattern => pattern.test(code));
          try {
            Reflect.construct(function OwnedEmptyTarget() {}, [], fn);
            row.constructorOutcome = "accepted";
          } catch (error) {
            row.constructorOutcome = error?.name === "TypeError" ? "rejected-TypeError" : "UNKNOWN";
          }
          row.state = "observed";
        }
      } catch { row.state = "UNKNOWN"; }
      cases.push(row);
    }
    wrappers = { state: "observed", classification: "NOT_A_CLASSIFIER", cases };
  }
  let constructedTypes = { state: "unsupported", hostLiteralHasHostType: null,
    srflxLiteralHasSrflxType: null };
  if (typeof context.RTCIceCandidate === "function") {
    try {
      // Fixed documentation-range inputs, not observed addresses or topology.
      // Construction parses strings only; these candidates are never sent to
      // a peer or remote destination. Read type enums, not candidate/SDP/IP.
      const host = new context.RTCIceCandidate({ sdpMid: "0", sdpMLineIndex: 0,
        candidate: "candidate:ada1 1 udp 2122260223 192.0.2.1 9 typ host" });
      const srflx = new context.RTCIceCandidate({ sdpMid: "0", sdpMLineIndex: 0,
        candidate: "candidate:ada2 1 udp 1686052863 192.0.2.2 9 typ srflx raddr 192.0.2.1 rport 9" });
      constructedTypes = { state: "complete", hostLiteralHasHostType: host.type === "host",
        srflxLiteralHasSrflxType: srflx.type === "srflx" };
    } catch {
      constructedTypes = { state: "UNKNOWN", hostLiteralHasHostType: null,
        srflxLiteralHasSrflxType: null };
    }
  }
  const protocol = await new Promise(resolve => {
    const result = { state: "UNKNOWN", configuredServerCount: null,
      types: { host: 0, srflx: 0, prflx: 0, relay: 0, unknown: 0 }, closed: false };
    if (protocolConformance) result.transport = { state: "UNKNOWN", types: null,
      eventTypesAgree: null, localOfferRetained: null };
    let peer;
    let channel;
    let timer;
    let finished = false;
    function finish(state) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (protocolConformance && state === "complete") {
        try {
          // Read only the type enums at a second API layer. Never read ICE
          // addresses, SDP, credentials, stats or machine capabilities.
          const transport = peer?.sctp?.transport?.iceTransport;
          if (typeof transport?.getLocalCandidates === "function") {
            const types = { host: 0, srflx: 0, prflx: 0, relay: 0, unknown: 0 };
            for (const candidate of transport.getLocalCandidates()) {
              const type = candidate.type;
              types[Object.hasOwn(types, type) ? type : "unknown"]++;
            }
            result.transport = { state: "complete", types,
              eventTypesAgree: Object.keys(types).every(type => types[type] === result.types[type]),
              localOfferRetained: peer.localDescription?.type === "offer" &&
                peer.signalingState === "have-local-offer" };
          } else result.transport.state = "unsupported";
        } catch { /* Preserve UNKNOWN, not raw error strings. */ }
      }
      try { if (channel) channel.close(); } catch { /* Peer cleanup remains required. */ }
      try {
        if (peer) {
          peer.onicecandidate = null;
          peer.onicegatheringstatechange = null;
          peer.close();
          result.closed = peer.signalingState === "closed";
        }
      } catch { result.closed = false; }
      result.state = result.closed ? state : "UNKNOWN";
      resolve(result);
    }
    try {
      if (typeof context.RTCPeerConnection !== "function") {
        resolve({ ...result, state: "unsupported" }); return;
      }
      peer = new context.RTCPeerConnection({ iceServers: [] });
      timer = setTimeout(() => finish("UNKNOWN"), timeoutMs);
      const servers = peer.getConfiguration().iceServers;
      result.configuredServerCount = Array.isArray(servers) ? servers.length : null;
      channel = peer.createDataChannel("ada-owned-protocol-audit");
      peer.onicecandidate = event => {
        try {
          if (event.candidate) {
            const type = event.candidate.type;
            result.types[Object.hasOwn(result.types, type) ? type : "unknown"]++;
          } else if (peer.iceGatheringState === "complete") finish("complete");
        } catch { finish("UNKNOWN"); }
      };
      peer.onicegatheringstatechange = () => {
        if (peer.iceGatheringState === "complete") finish("complete");
      };
      Promise.resolve(peer.createOffer()).then(offer => {
        if (!finished) return peer.setLocalDescription(offer);
      }).catch(() => finish("UNKNOWN"));
    } catch { finish("UNKNOWN"); }
  });
  let conformance = { state: "NOT_RUN" };
  if (protocolConformance) {
    // No ICE servers, remote peer, media permission or network identity reads.
    // The relay policy MUST NOT expose host/srflx candidates. This tests a
    // protocol contract, not a machine's addresses or network topology.
    conformance = await new Promise(resolve => {
      const result = { state: "UNKNOWN", configuredServerCount: null,
        relayPolicyRetained: null, invalidPolicyRejected: null,
        channelOptionsRetained: null, candidateBrandValid: true,
        types: { host: 0, srflx: 0, prflx: 0, relay: 0, unknown: 0 }, closed: false };
      let peer;
      let channel;
      let timer;
      let finished = false;
      function finish(state) {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        try { if (channel) channel.close(); } catch { /* Still close peer. */ }
        try {
          if (peer) {
            peer.onicecandidate = null;
            peer.onicegatheringstatechange = null;
            peer.close();
            result.closed = peer.signalingState === "closed";
          }
        } catch { result.closed = false; }
        result.state = result.closed ? state : "UNKNOWN";
        resolve(result);
      }
      try {
        if (typeof context.RTCPeerConnection !== "function") {
          resolve({ ...result, state: "unsupported" }); return;
        }
        peer = new context.RTCPeerConnection({ iceServers: [], iceTransportPolicy: "relay" });
        timer = setTimeout(() => finish("UNKNOWN"), timeoutMs);
        const config = peer.getConfiguration();
        result.configuredServerCount = Array.isArray(config.iceServers) ? config.iceServers.length : null;
        result.relayPolicyRetained = config.iceTransportPolicy === "relay";
        try {
          peer.setConfiguration({ iceServers: [], iceTransportPolicy: "ada-invalid-policy" });
          result.invalidPolicyRejected = false;
        } catch (error) { result.invalidPolicyRejected = error?.name === "TypeError"; }
        // Reapply the valid configuration even after a nonconforming rejection.
        peer.setConfiguration({ iceServers: [], iceTransportPolicy: "relay" });
        channel = peer.createDataChannel("ada-owned-conformance", { ordered: false,
          protocol: "ada-fixed-protocol", maxRetransmits: 0 });
        result.channelOptionsRetained = channel.ordered === false &&
          channel.protocol === "ada-fixed-protocol" && channel.maxRetransmits === 0;
        peer.onicecandidate = event => {
          try {
            if (event.candidate) {
              result.candidateBrandValid &&= typeof context.RTCIceCandidate === "function" &&
                event.candidate instanceof context.RTCIceCandidate;
              const type = event.candidate.type;
              result.types[Object.hasOwn(result.types, type) ? type : "unknown"]++;
            } else if (peer.iceGatheringState === "complete") finish("complete");
          } catch { finish("UNKNOWN"); }
        };
        peer.onicegatheringstatechange = () => {
          if (peer.iceGatheringState === "complete") finish("complete");
        };
        Promise.resolve(peer.createOffer()).then(offer => {
          if (!finished) return peer.setLocalDescription(offer);
        }).catch(() => finish("UNKNOWN"));
      } catch { finish("UNKNOWN"); }
    });
  }
  // Laboratory hypotheses only. An observed anomaly does not establish which
  // vendor patched it, and a four-host observation can be perfectly ordinary.
  const complete = protocol.state === "complete" && protocol.closed;
  const emptyServers = protocol.configuredServerCount === 0;
  return { matches, coverage, symbolMatches, symbolCoverage, unavailable,
    pageResources, imageLimit, stack, receivers, wrappers,
    constructedTypes, protocol, conformance,
    hypotheses: { serverReflexiveWithoutConfiguredServer: complete && emptyServers &&
      protocol.types.srflx > 0 && protocol.types.host === 0,
    fourHostOnly: complete && protocol.types.host === 4 &&
      ["srflx", "prflx", "relay", "unknown"].every(type => protocol.types[type] === 0) },
    classification: "NOT_A_CLASSIFIER" };
}
