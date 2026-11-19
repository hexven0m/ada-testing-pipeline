/** Research-only fixed-input SDP lifecycle probe. No media, local SDP or ICE gathering.
 * Self-contained for evaluation in disposable owned browser sessions.
 */
export async function probeSdpContracts(context, { timeoutMs = 600 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 1000) {
    throw new RangeError("Invalid observation budget");
  }
  const allowed = new Set(["TypeError", "InvalidStateError", "InvalidAccessError",
    "OperationError", "SyntaxError", "NotSupportedError", "DataCloneError"]);
  const sentinel = Object.create(null);
  function category(error) {
    if (error === sentinel) return "sentinel";
    try { return allowed.has(error?.name) ? error.name : "UNKNOWN"; }
    catch { return "UNKNOWN"; }
  }
  async function outcome(callback) {
    let timer;
    try {
      let value;
      try { value = callback(); }
      catch (error) { return "throw-" + category(error); }
      let pending;
      try {
        pending = Promise.prototype.then.call(value, () => "resolved",
          error => "reject-" + category(error));
      } catch { return "not-a-promise"; }
      return await Promise.race([pending, new Promise(resolve => {
        timer = setTimeout(() => resolve("timeout"), timeoutMs);
      })]);
    } finally { clearTimeout(timer); }
  }
  // All values are synthetic. No local description/answer is generated or applied,
  // and no ICE candidates, media tracks, servers or data channels are supplied.
  const lines = ["v=0", "o=- 123 2 IN IP4 192.0.2.1", "s=-", "t=0 0",
    "a=group:BUNDLE 0", "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
    "c=IN IP4 0.0.0.0", "a=ice-ufrag:fixed123",
    "a=ice-pwd:fixedPassword01234567890123456789", "a=ice-options:trickle",
    "a=fingerprint:sha-256 " + Array(32).fill("AB").join(":"),
    "a=setup:actpass", "a=mid:0", "a=sctp-port:5000", "a=max-message-size:262144"];
  async function observe(realm) {
    const rows = [];
    for (const name of ["offer-crlf", "offer-lf", "offer-coercion",
      "offer-sdp-getter-error", "offer-invalid-type"]) {
      const row = { name, state: "observed", trace: [] };
      rows.push(row);
      let peer;
      try {
        if (typeof realm.RTCPeerConnection !== "function") {
          row.state = "unsupported"; continue;
        }
        peer = new realm.RTCPeerConnection({ iceServers: [], iceCandidatePoolSize: 0 });
        const separator = name === "offer-lf" ? "\n" : "\r\n";
        const fixed = lines.join(separator) + separator;
        const input = { type: name === "offer-invalid-type" ? "ada-invalid" : "offer", sdp: fixed };
        const record = event => { if (row.trace.length < 32) row.trace.push(event); };
        if (name === "offer-coercion") {
          input.sdp = { [Symbol.toPrimitive](hint) {
            record(hint === "string" ? "primitive-string" : "primitive-other"); return fixed;
          } };
        }
        const tracked = new Proxy(input, { get(target, key) {
          record(key === "type" || key === "sdp" ? key : "other-key");
          if (name === "offer-sdp-getter-error" && key === "sdp") throw sentinel;
          return Reflect.get(target, key);
        } });
        row.setOutcome = await outcome(() => peer.setRemoteDescription(tracked));
        if (row.setOutcome !== "resolved") {
          row.stillStable = peer.signalingState === "stable";
          if (!name.startsWith("offer-sdp-getter") && name !== "offer-invalid-type") row.state = "UNKNOWN";
          continue;
        }
        const first = peer.remoteDescription;
        const second = peer.remoteDescription;
        const pending = peer.pendingRemoteDescription;
        const json = first.toJSON();
        const copy = first.toJSON();
        input.type = "rollback";
        input.sdp = "";
        const normalized = text => String(text).split(/\r?\n/).filter(Boolean).sort().join("\n");
        row.offerState = peer.signalingState === "have-remote-offer";
        row.noCurrent = peer.currentRemoteDescription === null;
        row.pendingAgrees = pending?.type === first.type && pending?.sdp === first.sdp;
        row.sameReadObject = first === second;
        row.typePreserved = first.type === "offer";
        // The WebRTC spec permits textual reformatting: these are observations,
        // not assumptions that a differing string is a standards violation.
        row.exactText = first.sdp === fixed;
        row.sameLines = normalized(first.sdp) === normalized(fixed);
        row.jsonAgrees = json.type === first.type && json.sdp === first.sdp;
        row.jsonKeys = Object.keys(json).sort().join(",") === "sdp,type";
        row.stringifyAgrees = JSON.stringify(first) === JSON.stringify(copy);
        json.sdp = "";
        row.independentJSON = json !== copy && copy.sdp === first.sdp && first.sdp.length > 0;
        row.cloneOutcome = "unsupported";
        if (typeof realm.structuredClone === "function") {
          try { realm.structuredClone(first); row.cloneOutcome = "returned"; }
          catch (error) { row.cloneOutcome = category(error); }
        }
        row.rollbackOutcome = await outcome(() => peer.setRemoteDescription({ type: "rollback" }));
        row.rollbackCleared = peer.signalingState === "stable" && peer.remoteDescription === null &&
          peer.pendingRemoteDescription === null && peer.currentRemoteDescription === null;
        row.oldSnapshotRetained = first.type === "offer" && first.sdp === copy.sdp;
        row.noLocalDescription = peer.localDescription === null;
        row.noGathering = peer.iceGatheringState === "new";
        peer.close();
        row.closedOutcome = await outcome(() => peer.setRemoteDescription({ type: "offer", sdp: fixed }));
      } catch (error) { row.state = "UNKNOWN"; row.error = category(error); }
      finally {
        if (peer) {
          try { peer.close(); row.peerClosed = peer.signalingState === "closed"; }
          catch { row.peerClosed = false; row.state = "UNKNOWN"; }
        }
        if (Object.values(row).some(value => typeof value === "string" &&
          (value.includes("UNKNOWN") || value === "timeout" || value === "not-a-promise"))) row.state = "UNKNOWN";
      }
    }
    return { rows };
  }
  const result = { classification: "NOT_A_CLASSIFIER", version: 1,
    main: await observe(context), iframe: { state: "unsupported" }, frameRemoved: false };
  let frame;
  try {
    if (!context.document?.documentElement) return result;
    frame = context.document.createElement("iframe");
    frame.hidden = true;
    frame.setAttribute("aria-hidden", "true");
    context.document.documentElement.appendChild(frame);
    if (!frame.contentWindow || frame.contentWindow === context ||
        frame.contentWindow.Object === context.Object) { result.iframe.state = "UNKNOWN"; return result; }
    result.iframe = await observe(frame.contentWindow);
  } catch { result.iframe = { state: "UNKNOWN" }; }
  finally {
    if (frame) {
      try { frame.remove(); result.frameRemoved = !frame.isConnected; }
      catch { result.frameRemoved = false; }
    }
  }
  return result;
}
