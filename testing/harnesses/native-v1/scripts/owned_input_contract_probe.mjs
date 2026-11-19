/** Fixed-input research only. No gathered addresses, SDP, device data or identity. */
export async function probeInputContracts() {
  const rows = [];
  const names = ['candidate-order', 'candidate-reverse-insertion', 'candidate-dual-fault',
    'candidate-reentrant-input', 'candidate-coercion-fault', 'candidate-json-trap',
    'description-order', 'description-dual-fault', 'closed-peer-conversion',
    'peer-reentrant-close', 'offer-close-settlement'];
  const borrowed = ['frame-on-main-candidate', 'main-on-frame-candidate',
    'frame-on-main-peer', 'main-on-frame-peer', 'foreign-candidate-receiver', 'foreign-peer-receiver'];
  const allowedErrors = ['TypeError', 'InvalidStateError', 'NotSupportedError', 'SecurityError',
    'SyntaxError', 'InvalidAccessError', 'OperationError', 'NotAllowedError', 'AbortError'];
  // All values originate here. This documentation-range address is never output.
  const fixed = {candidate: 'candidate:7 1 udp 2122260223 192.0.2.1 12345 typ host',
    sdpMid: 'owned', sdpMLineIndex: 0, usernameFragment: 'owned123'};
  const sentinelA = {}, sentinelB = {};
  function outcome(error) {
    if (error === sentinelA) return 'first-sentinel';
    if (error === sentinelB) return 'second-sentinel';
    try {if (allowedErrors.includes(error?.name)) return error.name;} catch { /* enum only */ }
    return 'unrecognized-error';
  }
  function makeRow(context, name) {
    return {context, case: name, state: 'observed', outcome: 'returned', trace: [],
      contract_matches: null, cleanup_confirmed: true};
  }
  function dictionary(row, keys, values, actions = {}) {
    const value = {};
    for (const key of keys) Object.defineProperty(value, key, {enumerable: true, configurable: true,
      get() {if (row.trace.length < 32) row.trace.push(key);
        return actions[key] ? actions[key]() : values[key];}});
    return value;
  }
  function closePeer(row, peer) {
    if (!peer) return;
    try {peer.close(); if (peer.signalingState !== 'closed') row.cleanup_confirmed = false;}
    catch {row.cleanup_confirmed = false;}
    if (!row.cleanup_confirmed) row.state = 'UNKNOWN';
  }
  async function run(context, realm, name) {
    const row = makeRow(context, name);
    rows.push(row);
    let peer;
    try {
      const Candidate = realm?.RTCIceCandidate, Description = realm?.RTCSessionDescription;
      const Peer = realm?.RTCPeerConnection;
      if ((name.startsWith('candidate-') && typeof Candidate !== 'function') ||
          (name.startsWith('description-') && typeof Description !== 'function') ||
          ((name.includes('peer') || name === 'offer-close-settlement') && typeof Peer !== 'function')) {
        row.state = 'unsupported'; row.outcome = 'unsupported'; return;
      }
      // Web IDL uses Unicode lexical order: capital L precedes lower-case i.
      const keys = ['candidate', 'sdpMLineIndex', 'sdpMid', 'usernameFragment'];
      if (name === 'candidate-order' || name === 'candidate-reverse-insertion') {
        new Candidate(dictionary(row, name === 'candidate-order' ? keys : [...keys].reverse(), fixed));
        row.contract_matches = row.trace.join('|') === keys.join('|');
      } else if (name === 'candidate-dual-fault') {
        new Candidate(dictionary(row, [...keys].reverse(), fixed,
          {candidate: () => {throw sentinelA;}, sdpMid: () => {throw sentinelB;}}));
      } else if (name === 'candidate-reentrant-input') {
        let mid = 'before';
        const value = new Candidate(dictionary(row, [...keys].reverse(), fixed,
          {candidate: () => {row.trace.push('mutate-mid'); mid = 'after'; return fixed.candidate;},
            sdpMid: () => mid}));
        row.contract_matches = value.sdpMid === 'after';
      } else if (name === 'candidate-coercion-fault') {
        const primitive = {[Symbol.toPrimitive](hint) {
          row.trace.push(hint === 'string' ? 'primitive-string' : hint === 'number' ? 'primitive-number' : 'primitive-default');
          throw sentinelA;
        }};
        new Candidate(dictionary(row, [...keys].reverse(), {...fixed, candidate: primitive},
          {sdpMid: () => {throw sentinelB;}}));
      } else if (name === 'candidate-json-trap') {
        const value = {...fixed};
        Object.defineProperty(value, 'toJSON', {get() {row.trace.push('toJSON'); throw sentinelA;}});
        const candidate = new Candidate(value);
        row.contract_matches = row.trace.length === 0 && candidate.sdpMid === fixed.sdpMid;
      } else if (name === 'description-order' || name === 'description-dual-fault') {
        new Description(dictionary(row, ['type', 'sdp'], {type: 'offer', sdp: 'v=0\r\n'},
          name === 'description-dual-fault' ? {sdp: () => {throw sentinelA;}, type: () => {throw sentinelB;}} : {}));
        row.contract_matches = row.trace.join('|') === 'sdp|type';
      } else if (name === 'closed-peer-conversion') {
        peer = new Peer({iceServers: [], iceTransportPolicy: 'all'});
        peer.close();
        peer.setConfiguration(dictionary(row, ['iceTransportPolicy', 'iceServers'],
          {iceServers: [], iceTransportPolicy: 'all'},
          {iceServers: () => {throw sentinelA;}, iceTransportPolicy: () => {throw sentinelB;}}));
      } else if (name === 'peer-reentrant-close') {
        peer = new Peer({iceServers: [], iceTransportPolicy: 'all'});
        peer.setConfiguration(dictionary(row, ['iceTransportPolicy', 'iceServers'],
          {iceServers: [], iceTransportPolicy: 'all'}, {iceServers: () => {
            row.trace.push('close'); peer.close(); return [];
          }}));
      } else if (name === 'offer-close-settlement') {
        peer = new Peer({iceServers: [], iceTransportPolicy: 'all'});
        row.trace.push('create-offer');
        const promise = Promise.resolve(peer.createOffer()).then(() => 'fulfilled', error => outcome(error));
        row.trace.push('close'); peer.close();
        let timer;
        try {
          row.outcome = await Promise.race([promise, new Promise(resolve => {
            timer = setTimeout(() => resolve('timeout'), 600);
          })]);
        } finally {clearTimeout(timer);}
        if (row.outcome === 'timeout') row.state = 'UNKNOWN';
        else row.trace.push('settled');
      }
    } catch (error) {row.outcome = outcome(error);}
    finally {closePeer(row, peer);}
  }
  for (const name of names) await run('main', globalThis, name);
  let frame;
  try {
    frame = document.createElement('iframe');
    frame.style.display = 'none';
    document.documentElement.appendChild(frame);
    const realm = frame.contentWindow;
    for (const name of names) await run('frame', realm, name);
    for (const name of borrowed) {
      const row = makeRow('borrowed', name);
      rows.push(row);
      let peer;
      try {
        const main = globalThis;
        const source = name.startsWith('main-on-frame') ? main : realm;
        const receiverRealm = name.startsWith('main-on-frame') ? realm : main;
        if (!source || !receiverRealm || typeof source.RTCIceCandidate !== 'function' ||
            typeof source.RTCPeerConnection !== 'function' || typeof receiverRealm.RTCIceCandidate !== 'function' ||
            typeof receiverRealm.RTCPeerConnection !== 'function') {
          row.state = 'unsupported'; row.outcome = 'unsupported'; continue;
        }
        if (name.includes('candidate')) {
          const receiver = name === 'foreign-candidate-receiver' ? {} : new receiverRealm.RTCIceCandidate({...fixed});
          const value = source.RTCIceCandidate.prototype.toJSON.call(receiver);
          row.contract_matches = value.candidate === fixed.candidate && value.sdpMid === fixed.sdpMid &&
            value.sdpMLineIndex === fixed.sdpMLineIndex && value.usernameFragment === fixed.usernameFragment;
        } else {
          if (name !== 'foreign-peer-receiver') peer = new receiverRealm.RTCPeerConnection({iceServers: [], iceTransportPolicy: 'all'});
          const value = source.RTCPeerConnection.prototype.getConfiguration.call(peer || {});
          row.contract_matches = Array.isArray(value.iceServers) && value.iceServers.length === 0 && value.iceTransportPolicy === 'all';
        }
      } catch (error) {row.outcome = outcome(error);}
      finally {closePeer(row, peer);}
    }
  } catch {
    // Complete the fixed schedule without treating a missing realm as evidence.
    for (const [context, schedule] of [['frame', names], ['borrowed', borrowed]]) {
      for (const name of schedule) if (!rows.some(row => row.context === context && row.case === name)) {
        const row = makeRow(context, name); row.state = 'UNKNOWN'; row.outcome = 'realm-unavailable'; rows.push(row);
      }
    }
  } finally {
    let cleaned = true;
    try {if (frame) {frame.remove(); cleaned = !frame.isConnected;}} catch {cleaned = false;}
    if (!cleaned) for (const row of rows.filter(row => row.context !== 'main')) {
      row.cleanup_confirmed = false; row.state = 'UNKNOWN';
    }
  }
  return {diagnostic_only: true, classification: 'NOT_A_CLASSIFIER', version: 1,
    cleanup_confirmed: rows.every(row => row.cleanup_confirmed), rows};
}

export function validInputStudy(value) {
  const cases = ['candidate-order', 'candidate-reverse-insertion', 'candidate-dual-fault',
    'candidate-reentrant-input', 'candidate-coercion-fault', 'candidate-json-trap',
    'description-order', 'description-dual-fault', 'closed-peer-conversion',
    'peer-reentrant-close', 'offer-close-settlement'];
  const borrowed = ['frame-on-main-candidate', 'main-on-frame-candidate', 'frame-on-main-peer',
    'main-on-frame-peer', 'foreign-candidate-receiver', 'foreign-peer-receiver'];
  const schedule = [...cases.map(name => 'main:' + name), ...cases.map(name => 'frame:' + name),
    ...borrowed.map(name => 'borrowed:' + name)];
  const outcomes = ['returned', 'fulfilled', 'first-sentinel', 'second-sentinel', 'timeout', 'unsupported',
    'realm-unavailable', 'unrecognized-error', 'TypeError', 'InvalidStateError', 'NotSupportedError',
    'SecurityError', 'SyntaxError', 'InvalidAccessError', 'OperationError', 'NotAllowedError', 'AbortError'];
  const traces = ['candidate', 'sdpMid', 'sdpMLineIndex', 'usernameFragment', 'sdp', 'type', 'iceServers',
    'iceTransportPolicy', 'mutate-mid', 'primitive-string', 'primitive-number', 'primitive-default',
    'toJSON', 'close', 'create-offer', 'settled'];
  const keys = (object, names) => object !== null && typeof object === 'object' && !Array.isArray(object) &&
    Object.keys(object).sort().join('|') === [...names].sort().join('|');
  if (!keys(value, ['diagnostic_only', 'classification', 'version', 'cleanup_confirmed', 'rows']) ||
      value.diagnostic_only !== true || value.classification !== 'NOT_A_CLASSIFIER' || value.version !== 1 ||
      typeof value.cleanup_confirmed !== 'boolean' || !Array.isArray(value.rows) || value.rows.length !== schedule.length) return false;
  const seen = new Set();
  for (const row of value.rows) {
    if (!keys(row, ['context', 'case', 'state', 'outcome', 'trace', 'contract_matches', 'cleanup_confirmed']) ||
        !schedule.includes(row.context + ':' + row.case) || seen.has(row.context + ':' + row.case) ||
        !['observed', 'unsupported', 'UNKNOWN'].includes(row.state) || !outcomes.includes(row.outcome) ||
        !Array.isArray(row.trace) || row.trace.length > 32 || !row.trace.every(part => traces.includes(part)) ||
        !(row.contract_matches === null || typeof row.contract_matches === 'boolean') ||
        typeof row.cleanup_confirmed !== 'boolean' || (!row.cleanup_confirmed && row.state !== 'UNKNOWN') ||
        (['timeout', 'realm-unavailable'].includes(row.outcome) && row.state !== 'UNKNOWN') ||
        (row.state === 'unsupported') !== (row.outcome === 'unsupported')) return false;
    seen.add(row.context + ':' + row.case);
  }
  return seen.size === schedule.length && value.cleanup_confirmed === value.rows.every(row => row.cleanup_confirmed);
}
