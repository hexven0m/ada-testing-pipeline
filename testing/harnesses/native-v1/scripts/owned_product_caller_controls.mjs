/** Post-prediction, disposable-page controls; never a submitted classifier. */
export async function probeOwnedProductCallers(context) {
  const callers = {
    ads_power: async function ordinaryAdsPowerPage() { return await context.detect_ads_power(); },
    dolphin_anty: async function ordinaryDolphinAntyPage() { return await context.detect_dolphin_anty(); },
    gologin: async function ordinaryOrbitaPage() { return await context.detect_gologin(); },
    multilogin: async function ordinaryMultiloginPage() { return await context.detect_multilogin(); },
    octo: async function ordinaryOctiumPage() { return await context.detect_octo(); },
  };
  const cases = [];
  for (const [product, caller] of Object.entries(callers)) {
    let baseline = null;
    let namedCaller = null;
    const fn = context["detect_" + product];
    if (typeof fn === "function") {
      try { const value = await fn(); if (typeof value === "boolean") baseline = value; } catch {}
      try { const value = await caller(); if (typeof value === "boolean") namedCaller = value; } catch {}
    }
    cases.push({ product, baseline, named_caller: namedCaller });
  }
  return { classification: "NOT_A_CLASSIFIER", cases };
}
