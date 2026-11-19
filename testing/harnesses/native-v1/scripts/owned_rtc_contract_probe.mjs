/** Page-local research, NOT a detector. Export only API-contract booleans.
 * No media/device queries, external STUN, identities, raw SDP/IPs or stacks.
 */
export async function probeRTCContracts() {
  const result = { diagnostic_only: true, submission_certified: false,
    sequential: true, fixed: {}, gathered: [] };
  const fields = ["candidate", "sdpMid", "sdpMLineIndex", "usernameFragment"];
  const check = (name, fn) => {
    try { result.fixed[name] = Boolean(fn()); } catch { result.fixed[name] = null; }
  };
  const input = { candidate: "candidate:7 1 udp 2122260223 192.0.2.1 12345 typ host",
    sdpMid: "owned", sdpMLineIndex: 0, usernameFragment: "owned123" };
  const agrees = (json, value) => json && typeof json === "object" && !Array.isArray(json) &&
    Object.keys(json).length === fields.length && fields.every(key =>
      Object.hasOwn(json, key) && json[key] === value[key]);
  let sample;
  try { sample = new RTCIceCandidate(input); } catch { /* Unknown, not a product match. */ }
  check("constructedValuesPreserved", () => fields.every(key => sample[key] === input[key]));
  check("constructedJSONAgrees", () => agrees(sample.toJSON(), sample));
  check("prototypeJSONAgrees", () => agrees(RTCIceCandidate.prototype.toJSON.call(sample), sample));
  check("jsonStringifyAgrees", () => agrees(JSON.parse(JSON.stringify(sample)), sample));
  check("constructedNativePrototype", () => Object.getPrototypeOf(sample) === RTCIceCandidate.prototype);
  check("missingMediaIdRejected", () => {
    try { new RTCIceCandidate({ candidate: input.candidate }); return false; }
    catch (error) { return error instanceof TypeError; }
  });
  check("foreignReceiverRejected", () => {
    try { RTCIceCandidate.prototype.toJSON.call({}); return false; }
    catch (error) { return error instanceof TypeError; }
  });
  check("candidateGetterReadsUnderlyingValue", () => {
    const getter = Object.getOwnPropertyDescriptor(RTCIceCandidate.prototype, "candidate")?.get;
    return typeof getter === "function" && getter.call(sample) === input.candidate;
  });
  check("fixedCandidateTypeParsed", () => sample.type === "host" && sample.protocol === "udp");

  function gather(explicitConfiguration) {
    return new Promise(resolve => {
      const observation = { complete: false, cleanup_confirmed: false, hasCandidates: false,
        emptyServersPreserved: null, eventNativePrototype: true, eventTrusted: true,
        candidateNativePrototype: true, directJSONAgrees: true, prototypeJSONAgrees: true,
        candidateGetterAgrees: true, eventSDPAgrees: null, candidateCoreSDPAgrees: null,
        candidateTypeSDPAgrees: null, sdpHasCandidates: null, parsedTypeAgrees: true,
        explicitEmptyConfiguration: explicitConfiguration,
        fourHostNotifications: false, fourDistinctHostRecords: false,
        duplicateCandidateEvents: false, hostOnlyNotifications: false,
        twoDistinctHostRecords: false, eachRecordExactlyTwice: false,
        duplicateFullRecords: false, reusedEventObject: false,
        malformedCandidateRecord: false, emptyGenerationMarker: false,
        completionBeforeDescription: false };
      let peer, channel, timer;
      let ended = false, descriptionReady = false;
      const candidates = [];
      const distinctHosts = new Set();
      const distinctRecords = new Set();
      const fullRecordCounts = new Map();
      const eventObjects = new Set();
      let hostNotifications = 0, otherNotifications = 0;
      function finish(complete) {
        if (ended) return;
        ended = true;
        clearTimeout(timer);
        observation.complete = complete;
        if (complete) {
          observation.fourHostNotifications = hostNotifications === 4;
          observation.fourDistinctHostRecords = distinctHosts.size === 4;
          observation.twoDistinctHostRecords = distinctHosts.size === 2;
          observation.eachRecordExactlyTwice = fullRecordCounts.size > 0 &&
            [...fullRecordCounts.values()].every(count => count === 2);
          observation.hostOnlyNotifications = hostNotifications > 0 && otherNotifications === 0;
          try {
            const sdp = peer.localDescription?.sdp;
            observation.eventSDPAgrees = typeof sdp === "string" &&
              candidates.every(raw => sdp.split(/\r?\n/).includes("a=" + raw));
            if (typeof sdp === "string") {
              const lines = sdp.split(/\r?\n/).filter(line => line.startsWith("a=candidate:"))
                .map(line => line.slice(2).trim().split(/\s+/));
              observation.sdpHasCandidates = lines.length > 0;
              observation.candidateCoreSDPAgrees = candidates.every(raw => {
                const core = raw.trim().split(/\s+/).slice(0, 8);
                return core.length === 8 && lines.some(tokens => core.every((value, index) => tokens[index] === value));
              });
              observation.candidateTypeSDPAgrees = candidates.every(raw => {
                const kind = /(?:^|\s)typ\s+([a-z]+)(?:\s|$)/.exec(raw)?.[1];
                return kind && lines.some(tokens => tokens[6] === "typ" && tokens[7] === kind);
              });
            }
          } catch { observation.eventSDPAgrees = null; }
        }
        let cleaned = true;
        try { if (peer) peer.onicecandidate = null; } catch { cleaned = false; }
        try { if (peer) peer.onicegatheringstatechange = null; } catch { cleaned = false; }
        try { if (channel) channel.close(); } catch { cleaned = false; }
        try { if (peer) peer.close(); } catch { cleaned = false; }
        observation.cleanup_confirmed = cleaned;
        resolve(observation);
      }
      function complete() {
        if (ended) return;
        try {
          if (peer.iceGatheringState === "complete") {
            if (descriptionReady) finish(true);
            else observation.completionBeforeDescription = true;
          }
        }
        catch { finish(false); }
      }
      try {
        timer = setTimeout(() => finish(false), 2500);
        // Separate the original no-argument constructor from explicit defaults;
        // wrapper argument handling must not be mistaken for an OS difference.
        peer = explicitConfiguration ?
          new RTCPeerConnection({ iceServers: [], iceTransportPolicy: "all" }) : new RTCPeerConnection();
        const configured = peer.getConfiguration();
        observation.emptyServersPreserved = Array.isArray(configured.iceServers) &&
          configured.iceServers.length === 0 && configured.iceTransportPolicy === "all";
        channel = peer.createDataChannel("owned-contract-study");
        peer.onicegatheringstatechange = complete;
        peer.onicecandidate = event => {
          if (ended) return;
          try {
            if (event.candidate === null) { complete(); return; }
            const candidate = event.candidate;
            const raw = candidate.candidate;
            if (typeof raw !== "string" || raw.length > 8192 || candidates.length >= 128) { finish(false); return; }
            if (raw === "") { observation.emptyGenerationMarker = true; return; }
            candidates.push(raw);
            if (eventObjects.has(event)) observation.reusedEventObject = true;
            eventObjects.add(event);
            const normalized = raw.trim().replace(/\s+/g, " ");
            if (distinctRecords.has(normalized)) observation.duplicateCandidateEvents = true;
            distinctRecords.add(normalized);
            // Candidate text alone can coincide across different media sections.
            // Keep the full transient protocol tuple in page memory only.
            const fullRecord = JSON.stringify([normalized, candidate.sdpMid,
              candidate.sdpMLineIndex, candidate.usernameFragment]);
            const count = (fullRecordCounts.get(fullRecord) ?? 0) + 1;
            fullRecordCounts.set(fullRecord, count);
            if (count > 1) observation.duplicateFullRecords = true;
            const tokens = normalized.split(" ");
            const valid = tokens.length >= 8 && /^candidate:\S+$/.test(tokens[0]) &&
              /^[1-9][0-9]*$/.test(tokens[1]) && /^(udp|tcp)$/i.test(tokens[2]) &&
              /^[0-9]+$/.test(tokens[3]) && /^[0-9]+$/.test(tokens[5]) &&
              Number(tokens[5]) <= 65535 && tokens[6] === "typ" &&
              /^(host|srflx|prflx|relay)$/.test(tokens[7]);
            if (!valid) observation.malformedCandidateRecord = true;
            if (valid && tokens[7] === "host") {
              hostNotifications++;
              distinctHosts.add(normalized);
            } else otherNotifications++;
            observation.hasCandidates = true;
            observation.eventNativePrototype &&= Object.getPrototypeOf(event) === RTCPeerConnectionIceEvent.prototype;
            observation.eventTrusted &&= event.isTrusted === true;
            observation.candidateNativePrototype &&= Object.getPrototypeOf(candidate) === RTCIceCandidate.prototype;
            observation.directJSONAgrees &&= Boolean(agrees(candidate.toJSON(), candidate));
            observation.prototypeJSONAgrees &&= Boolean(agrees(RTCIceCandidate.prototype.toJSON.call(candidate), candidate));
            const getter = Object.getOwnPropertyDescriptor(RTCIceCandidate.prototype, "candidate")?.get;
            observation.candidateGetterAgrees &&= typeof getter === "function" && getter.call(candidate) === raw;
            const kind = /(?:^|\s)typ\s+([a-z]+)(?:\s|$)/.exec(raw)?.[1];
            observation.parsedTypeAgrees &&= typeof kind === "string" && candidate.type === kind;
          } catch { finish(false); }
        };
        Promise.resolve(peer.createOffer()).then(offer => {
          if (!ended) return peer.setLocalDescription(offer);
        }).then(() => {
          if (ended) return;
          descriptionReady = true;
          complete();
        }).catch(() => finish(false));
      } catch { finish(false); }
    });
  }
  // ABBA, sequentially: constructor form must not be confounded with the
  // simultaneous allocation of another peer or the order of the first gather.
  // Each peer owns its bounded lifetime and closes before the next is created.
  for (const explicitConfiguration of [false, true, true, false]) {
    result.gathered.push(await gather(explicitConfiguration));
  }
  return result;
}

export function validRTCStudy(value) {
  const fixed = ["constructedValuesPreserved", "constructedJSONAgrees", "prototypeJSONAgrees",
    "jsonStringifyAgrees", "constructedNativePrototype", "missingMediaIdRejected", "foreignReceiverRejected",
    "candidateGetterReadsUnderlyingValue", "fixedCandidateTypeParsed"];
  const gathered = ["complete", "cleanup_confirmed", "hasCandidates", "emptyServersPreserved",
    "eventNativePrototype", "eventTrusted", "candidateNativePrototype", "directJSONAgrees",
    "prototypeJSONAgrees", "candidateGetterAgrees", "eventSDPAgrees", "candidateCoreSDPAgrees",
    "candidateTypeSDPAgrees", "sdpHasCandidates", "parsedTypeAgrees",
    "explicitEmptyConfiguration", "fourHostNotifications", "fourDistinctHostRecords",
    "duplicateCandidateEvents", "hostOnlyNotifications", "malformedCandidateRecord",
    "emptyGenerationMarker", "completionBeforeDescription", "twoDistinctHostRecords",
    "eachRecordExactlyTwice", "duplicateFullRecords", "reusedEventObject"];
  const matches = (object, keys) => object && typeof object === "object" && !Array.isArray(object) &&
    Object.keys(object).length === keys.length && keys.every(key => Object.hasOwn(object, key) &&
      (typeof object[key] === "boolean" || object[key] === null));
  return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 5 &&
    value.diagnostic_only === true && value.submission_certified === false && value.sequential === true &&
    matches(value.fixed, fixed) && Array.isArray(value.gathered) && value.gathered.length === 4 &&
    value.gathered.every((row, index) => matches(row, gathered) &&
      row.explicitEmptyConfiguration === (index === 1 || index === 2));
}
