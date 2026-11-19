/**
 * Context-free, fixed-input WebGL receiver research. No browser classifier.
 * All observations are Boolean; returned values are discarded after typeof.
 * The plain-object/vendor case repeats an Oct28 negative as a control.
 */
export function probeAdsReceiverContracts() {
  function empty() {
    return { available: false, complete: false, candidate: false,
      plain: blank(), shaped: blank(), nullReceiver: blank(), proxy: blank(),
      brandBeforeConversion: false, proxyUntouched: false };
  }
  function blank() {
    return { normalTypeError: false, vendorTypeError: false, rendererTypeError: false,
      vendorString: false, rendererString: false, complete: false };
  }
  function observe(realm, name) {
    const result = empty();
    try {
      const proto = realm[name]?.prototype;
      const method = proto && Object.getOwnPropertyDescriptor(proto, 'getParameter')?.value;
      result.available = typeof method === 'function';
      if (!result.available) return result;
      function call(receiver, token) {
        try {
          return { string: typeof Reflect.apply(method, receiver, [token]) === 'string', typeError: false, complete: true };
        } catch (error) {
          const typeError = error instanceof realm.TypeError;
          return { string: false, typeError, complete: typeError };
        }
      }
      let touched = false;
      const proxy = new realm.Proxy(Object.create(proto), {
        get(target, key, receiver) { touched = true; return Reflect.get(target, key, receiver); }
      });
      const cases = [['plain', {}], ['shaped', Object.create(proto)], ['nullReceiver', null], ['proxy', proxy]];
      for (const [key, receiver] of cases) {
        const rounds = [];
        for (let repeat = 0; repeat < 2; repeat += 1) {
          const normal = call(receiver, 0x0d33);
          const vendor = call(receiver, 0x9245);
          const renderer = call(receiver, 0x9246);
          rounds.push({ normalTypeError: normal.typeError, vendorTypeError: vendor.typeError,
            rendererTypeError: renderer.typeError, vendorString: vendor.string,
            rendererString: renderer.string, complete: normal.complete && vendor.complete && renderer.complete });
        }
        for (const flag of Object.keys(result[key])) result[key][flag] = rounds.every(round => round[flag]);
      }
      let converted = false;
      const token = { [Symbol.toPrimitive]() { converted = true; return 0x9245; } };
      const coercion = call(Object.create(proto), token);
      result.brandBeforeConversion = coercion.typeError && !converted;
      result.proxyUntouched = !touched;
      result.complete = cases.every(([key]) => result[key].complete) && coercion.complete;
      // A research candidate needs a normal brand-check control for the SAME receiver.
      // Availability or an exception is never a positive signal.
      result.candidate = result.complete && cases.some(([key]) => {
        const row = result[key];
        return row.normalTypeError && row.vendorString && row.rendererString;
      });
    } catch { result.complete = false; result.candidate = false; }
    return result;
  }
  function realmChecks(realm) {
    return { webgl1: observe(realm, 'WebGLRenderingContext'), webgl2: observe(realm, 'WebGL2RenderingContext') };
  }
  const result = { cleanupConfirmed: false, page: { webgl1: empty(), webgl2: empty() },
    child: { webgl1: empty(), webgl2: empty() } };
  let frame = null;
  try {
    result.page = realmChecks(window);
    frame = document.createElement('iframe');
    frame.hidden = true;
    document.documentElement.appendChild(frame);
    if (frame.contentWindow && frame.contentWindow !== window) result.child = realmChecks(frame.contentWindow);
  } catch { /* Unsupported or incomplete results remain false. */ }
  finally {
    try {
      if (frame) frame.remove();
      result.cleanupConfirmed = !frame || !frame.isConnected;
    } catch { result.cleanupConfirmed = false; }
    if (!result.cleanupConfirmed) {
      for (const realm of [result.page, result.child]) {
        realm.webgl1.candidate = false;
        realm.webgl2.candidate = false;
      }
    }
  }
  return result;
}
