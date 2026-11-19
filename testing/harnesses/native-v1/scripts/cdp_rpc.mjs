/** Bound harness requests; a hung/disconnected probe is an error, not a pass. */
export function createCdpRpc(socket, { timeoutMs = 10000 } = {}) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error("Invalid CDP timeout");
  const pending = new Map();
  let nextId = 0;
  let closed = false;
  return {
    request(method, params = {}, sessionId) {
      if (closed) return Promise.reject(new Error("CDP connection is closed"));
      return new Promise((resolve, reject) => {
        const id = ++nextId;
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`CDP request timed out: ${method}`));
        }, timeoutMs);
        pending.set(id, { resolve, reject, timer });
        try {
          socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
        } catch {
          clearTimeout(timer);
          pending.delete(id);
          reject(new Error(`CDP request could not be sent: ${method}`));
        }
      });
    },
    receive(message) {
      const request = pending.get(message.id);
      if (!request) return;
      clearTimeout(request.timer);
      pending.delete(message.id);
      request.resolve(message);
    },
    close() {
      closed = true;
      for (const request of pending.values()) {
        clearTimeout(request.timer);
        request.reject(new Error("CDP connection closed before its reply"));
      }
      pending.clear();
    },
    pendingCount() { return pending.size; },
  };
}
