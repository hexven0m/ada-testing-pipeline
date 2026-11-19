#!/usr/bin/env node

/** ADA probe; opt-in diagnostics modify only temporary test DOM/popups. */
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createCdpRpc } from "./cdp_rpc.mjs";
import { probeModeExecution } from "./mode_execution_probe.mjs";
import { probeModeSurface } from "./mode_surface_probe.mjs";
import { probePassiveWindowUi, probeOctoBranches } from "./mode_branch_followup.mjs";
import { probeOctoOwnedSurfaces } from "./octo_owned_surface_probe.mjs";
import { probeModeRealmConsistency } from "./mode_realm_consistency_probe.mjs";
import { probeProductArtifacts } from "./product_artifact_probe.mjs";
import { probeGeometryContracts } from "./geometry_contract_probe.mjs";
import { probeApiTraceContracts } from "./api_trace_probe.mjs";
import { probeBrandArgumentOrder } from "./brand_argument_probe.mjs";
import { probeOctoNativeBridge } from "./octo_native_bridge_probe.mjs";
import { probeValidApiContracts } from "./valid_api_contract_probe.mjs";
import { probeSdpContracts } from "./sdp_contract_probe.mjs";
import { collectJointContracts } from "./joint_contract_probe.mjs";
import { collectExtendedContracts, collectNoCaptureMediaContract } from "./extended_contract_probe.mjs";
import { prepareOctoTrace } from "./octo_candidate_trace.mjs";
import { detectorNames as names, loadBrowserProbeSources } from "./browser_probe_sources.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const port = Number(process.env.ADA_CDP_PORT);
const targetUrl = process.env.ADA_PROBE_URL || "about:blank";
const octoDiagnostic = process.env.ADA_OCTO_DIAGNOSTIC === "1";
const octoOwnedDiagnostic = process.env.ADA_OCTO_OWNED_DIAGNOSTIC === "1";
const octoApiSurface = process.env.ADA_OCTO_API_SURFACE === "1";
const blockPayload = process.env.ADA_BLOCK_PAYLOAD === "1";
const expectedTitle = process.env.ADA_EXPECT_TITLE || null;
const expectedBodyText = process.env.ADA_EXPECT_BODY_TEXT || null;
const networkDiagnostic = process.env.ADA_NETWORK_DIAGNOSTIC === "1";
const targetDiagnostic = process.env.ADA_TARGET_DIAGNOSTIC === "1";
const modeBehaviorDiagnostic = process.env.ADA_MODE_BEHAVIOR_DIAGNOSTIC === "1";
const modeExecutionDiagnostic = process.env.ADA_MODE_EXECUTION_DIAGNOSTIC === "1";
const popupDiagnostic = process.env.ADA_POPUP_MODE_DIAGNOSTIC === "1";
const modeSurfaceDiagnostic = process.env.ADA_MODE_SURFACE_DIAGNOSTIC === "1";
const modeBranchDiagnostic = process.env.ADA_MODE_BRANCH_DIAGNOSTIC === "1";
const octoOwnedSurfaceDiagnostic = process.env.ADA_OCTO_OWNED_SURFACES === "1";
const realmConsistencyDiagnostic = process.env.ADA_MODE_REALM_CONSISTENCY === "1";
const modeOwnedSurfaceDiagnostic = process.env.ADA_MODE_OWNED_SURFACES === "1";
const activatedPopupDiagnostic = process.env.ADA_OWNED_ACTIVATED_POPUP === "1";
const printDiagnostic = process.env.ADA_OWNED_PRINT_DIAGNOSTIC === "1";
const productArtifactDiagnostic = process.env.ADA_PRODUCT_ARTIFACT_DIAGNOSTIC === "1";
const geometryContractDiagnostic = process.env.ADA_GEOMETRY_CONTRACT_DIAGNOSTIC === "1";
const octoBridgeDiagnostic = process.env.ADA_OCTO_BRIDGE_DIAGNOSTIC === "1";
const validApiDiagnostic = process.env.ADA_VALID_API_DIAGNOSTIC === "1";
const sdpContractDiagnostic = process.env.ADA_SDP_CONTRACT_DIAGNOSTIC === "1";
const jointContractDiagnostic = process.env.ADA_JOINT_CONTRACT_DIAGNOSTIC === "1";
const extendedContractDiagnostic = process.env.ADA_EXTENDED_CONTRACT_DIAGNOSTIC === "1";
const headlessBranchDiagnostic = process.env.ADA_HEADLESS_BRANCH_DIAGNOSTIC === "1";
const headlessPrintDiagnostic = process.env.ADA_HEADLESS_PRINT_DIAGNOSTIC === "1";
const candidateBranchDiagnostic = process.env.ADA_CANDIDATE_BRANCH_DIAGNOSTIC === "1";
if ((activatedPopupDiagnostic || printDiagnostic || productArtifactDiagnostic ||
     geometryContractDiagnostic || octoBridgeDiagnostic || validApiDiagnostic || sdpContractDiagnostic ||
     jointContractDiagnostic || extendedContractDiagnostic) &&
    process.env.ADA_OWNED_TEST_SESSION !== "1") {
  throw new Error("Active experiments are restricted to explicitly owned disposable test sessions");
}
if ((headlessPrintDiagnostic || candidateBranchDiagnostic) &&
    process.env.ADA_OWNED_TEST_SESSION !== "1") {
  throw new Error("Candidate branch diagnostics require an owned disposable test session");
}
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("Set ADA_CDP_PORT to a local CDP tunnel port");
}

const directory = process.env.ADA_DETECTOR_DIR ||
  join(root, "src/ada_challenge/challenge/templates/static/detections");
const plan = await loadBrowserProbeSources({ detectorDirectory: directory,
  preloadPath: join(root, "src/ada_challenge/challenge/templates/static/js/user-agent-spoof.js"),
  preload: process.env.ADA_PROBE_PRELOAD || "challenge" });
const octoTrace = validApiDiagnostic ? prepareOctoTrace(plan.scripts.find(s => s.name === "octo").content) : "null";
const versionResponse = await fetch(`http://127.0.0.1:${port}/json/version`, {
  signal: AbortSignal.timeout(5000),
});
if (!versionResponse.ok) throw new Error(`CDP returned HTTP ${versionResponse.status}`);
const { webSocketDebuggerUrl, Browser: browserEngine } = await versionResponse.json();
if (!webSocketDebuggerUrl) throw new Error("CDP browser endpoint is missing");
const socket = new WebSocket(webSocketDebuggerUrl.replace(/127\.0\.0\.1:\d+/, `127.0.0.1:${port}`));
const rpc = createCdpRpc(socket, { timeoutMs: 15000 });
const networkEvents = [];
let lastDocumentRequestId = null;
socket.onmessage = event => {
  const message = JSON.parse(event.data);
  if (message.method === "Network.loadingFailed" && message.params?.type === "Document") {
    networkEvents.push({ error: message.params.errorText });
  } else if (message.method === "Network.responseReceived" &&
      message.params?.type === "Document") {
    lastDocumentRequestId = message.params.requestId;
    networkEvents.push({
      status: message.params.response?.status,
      url: message.params.response?.url || null,
      remoteIPAddress: message.params.response?.remoteIPAddress || null,
      remotePort: message.params.response?.remotePort || null,
      errorCode: message.params.response?.headers?.["x-error-code"] || null,
      headerNames: Object.keys(message.params.response?.headers || {}).sort(),
    });
  }
  rpc.receive(message);
};
socket.onclose = () => rpc.close();
await new Promise((done, fail) => {
  const timer = setTimeout(() => {
    socket.close();
    fail(new Error("CDP connection timed out"));
  }, 5000);
  socket.onopen = () => { clearTimeout(timer); done(); };
  socket.onerror = () => { clearTimeout(timer); fail(new Error("CDP connection failed")); };
});
const send = (method, params = {}, sessionId) => rpc.request(method, params, sessionId);

let targetId;
try {
  let extensionTargets = [];
  if (targetDiagnostic) {
    const targets = await send("Target.getTargets");
    extensionTargets = (targets.result?.targetInfos || [])
      .filter(info => info.url?.startsWith("chrome-extension://"))
      .map(info => ({type: info.type, url: info.url}));
  }
  const created = await send("Target.createTarget", { url: "about:blank" });
  targetId = created.result?.targetId;
  if (!targetId) throw new Error(JSON.stringify(created.error || created));
  const attached = await send("Target.attachToTarget", { targetId, flatten: true });
  const sessionId = attached.result?.sessionId;
  if (!sessionId) throw new Error(JSON.stringify(attached.error || attached));
  await send("Page.enable", {}, sessionId);
  if (targetUrl !== "about:blank") await send("Network.enable", {}, sessionId);
  if (blockPayload) {
    const blocked = await send("Network.setBlockedURLs", {
      urls: ["*://*/_payload*"],
    }, sessionId);
    if (blocked.error) throw new Error(JSON.stringify(blocked.error));
  }
  if (targetUrl !== "about:blank") {
    const navigation = await send("Page.navigate", { url: targetUrl }, sessionId);
    if (navigation.error || navigation.result?.errorText) {
      throw new Error(JSON.stringify(navigation.error || navigation.result));
    }
    let ready = false;
    for (let attempt = 0; attempt < 150; attempt++) {
      const readiness = await send("Runtime.evaluate", {
        expression: `location.href === ${JSON.stringify(targetUrl)} && ` +
          `document.readyState === 'complete' && ` +
          `${expectedTitle ? `document.title === ${JSON.stringify(expectedTitle)}` : "true"} && ` +
          `${expectedBodyText ? `Boolean(document.body && document.body.textContent.includes(${JSON.stringify(expectedBodyText)}))` : "true"}`,
        returnByValue: true,
      }, sessionId);
      if (readiness.result?.result?.value) {
        ready = true;
        break;
      }
      await new Promise(done => setTimeout(done, 100));
    }
    if (!ready) {
      let responseBody = null;
      if (networkDiagnostic && lastDocumentRequestId) {
        const bodyResult = await send("Network.getResponseBody", {
          requestId: lastDocumentRequestId,
        }, sessionId);
        responseBody = bodyResult.result?.body?.slice(0, 400) || null;
      }
      throw new Error("Navigation did not reach the requested complete page" +
        (networkDiagnostic ? `; document network events: ${JSON.stringify(networkEvents.slice(-5))}` +
          `; response body: ${JSON.stringify(responseBody)}` : ""));
    }
  }
  for (const source of plan.scripts) {
    const loaded = await send("Runtime.evaluate", { expression: source.content }, sessionId);
    if (loaded.error || loaded.result?.exceptionDetails) {
      throw new Error(`Could not load ${source.name}: ${JSON.stringify(loaded.error || loaded.result.exceptionDetails)}`);
    }
  }
  const expression = `(async () => {
    const verdict = {};
    let headlessObservation = null;
    for (const name of ${JSON.stringify(names)}) {
      const before = name === 'headless' ? {
        url: location.href, historyLength: history.length,
        frames: document.querySelectorAll('iframe').length, started: performance.now(),
      } : null;
      try {
        const answer = await window['detect_' + name]();
        if (typeof answer !== 'boolean') throw new TypeError('Detector did not resolve to a Boolean');
        verdict[name] = answer;
      }
      catch (error) { verdict[name] = 'ERROR: ' + String(error); }
      if (before) headlessObservation = {
        durationMs: performance.now() - before.started,
        urlRestored: location.href === before.url,
        historyUnchanged: history.length === before.historyLength,
        frameCountRestored: document.querySelectorAll('iframe').length === before.frames,
      };
    }
    // Keep harness-only measurements independent from detector internals.
    const m = {
      innerWidth, innerHeight, outerWidth, outerHeight, screenX, screenY,
      screenWidth: screen.width, screenHeight: screen.height,
      availWidth: screen.availWidth, availHeight: screen.availHeight,
      availLeft: Number.isFinite(screen.availLeft) ? screen.availLeft : null,
      availTop: Number.isFinite(screen.availTop) ? screen.availTop : null,
    };
    return JSON.stringify({
      verdict,
      headlessObservation,
      ...(${headlessBranchDiagnostic} ? {
        headlessBranches: await (async () => {
          try {
            return {
              noInput: typeof nuNoInputDevice === 'function' ? nuNoInputDevice() : null,
              viewport: typeof nuHeadlessViewportShell === 'function'
                ? nuHeadlessViewportShell() : null,
              threeDevices: typeof nuHeadlessThreeDeviceShape === 'function'
                ? await nuHeadlessThreeDeviceShape() : null,
              printRound: ${headlessPrintDiagnostic}
                ? (typeof nuPrintRound === 'function' ? await nuPrintRound() : null) : null,
            };
          } catch (error) {
            return { error: String(error?.name || 'Error') };
          }
        })(),
      } : {}),
      ...(${candidateBranchDiagnostic} ? {
        candidateBranches: await (async () => {
          const bounded = async fn => {
            try { return await fn(); } catch { return null; }
          };
          const [adsIce, adsDelayed, adsMedia, octoIce, octoMedia,
            multiloginIce, multiloginMedia] = await Promise.all([
            bounded(() => typeof nuAdsIceShape === 'function' ? nuAdsIceShape() : null),
            bounded(() => typeof nuAdsDelayedIceShape === 'function' ? nuAdsDelayedIceShape() : null),
            bounded(() => typeof nuAdsMediaShape === 'function' ? nuAdsMediaShape() : null),
            bounded(() => typeof nuOctIceShape === 'function' ? nuOctIceShape() : null),
            bounded(() => typeof nuOctMediaShape === 'function' ? nuOctMediaShape() : null),
            bounded(() => typeof nuMultiloginIceShape === 'function' ? nuMultiloginIceShape() : null),
            bounded(() => typeof nuMultiloginMediaShape === 'function' ? nuMultiloginMediaShape() : null),
          ]);
          return { adsIce, adsDelayed, adsMedia, octoIce, octoMedia,
            multiloginIce, multiloginMedia };
        })(),
      } : {}),
      testSetup: ${JSON.stringify(plan.setup)},
      detectorSha256: ${JSON.stringify(plan.detectorSha256)},
      pageTitle: document.title,
      documentReadyState: document.readyState,
      ...(${productArtifactDiagnostic} ? {
        productArtifacts: {
          ...(await (${probeProductArtifacts.toString()})(window, {
            wrapperConformance: true,
            protocolConformance: true, receiverConformance: true,
            pageResourceDiagnostic: true, imageLimitDiagnostic: true })),
          // Test-only public resource reachability; never export response data.
          adsAssistantResourceAccessible: await (async () => {
            const urls = [
              'chrome-extension://gcaiimgaiohlnlflkjjmcohobkpbbnfi/dist/contentScripts/style.css',
              'chrome-extension://gcaiimgaiohlnlflkjjmcohobkpbbnfi/dist/security/index.html',
            ];
            return (await Promise.all(urls.map(async url => {
              const controller = new AbortController();
              const timer = setTimeout(() => controller.abort(), 650);
              try {
                const response = await fetch(url, { cache: 'no-store', signal: controller.signal });
                return response.ok;
              } catch { return false; }
              finally { clearTimeout(timer); }
            }))).some(Boolean);
          })(),
        },
      } : {}),
      ...(${geometryContractDiagnostic} ? {
        geometryContracts: await (${probeGeometryContracts.toString()})(window),
        apiTraceContracts: (${probeApiTraceContracts.toString()})(window),
        brandArgumentOrder: await (${probeBrandArgumentOrder.toString()})(window),
      } : {}),
      ...(${octoBridgeDiagnostic} ? {
        octoNativeBridge: await (${probeOctoNativeBridge.toString()})(window),
      } : {}),
      ...(${validApiDiagnostic} ? {
        // Trace the unchanged classifier first; active research cannot seed its evidence.
        octoCandidateTrace: await (${octoTrace}),
        validApiContracts: await (${probeValidApiContracts.toString()})(window),
      } : {}),
      ...(${sdpContractDiagnostic} ? {
        sdpContracts: await (${probeSdpContracts.toString()})(window),
      } : {}),
      ...(${networkDiagnostic} ? { documentNetworkEvents: ${JSON.stringify(networkEvents)} } : {}),
      modeEvidence: {
        ...m,
        platform: navigator.platform,
        browserMajor: (/Chrome\\/(\\d+)/.exec(navigator.userAgent) || [])[1] || null,
        pointerNone: matchMedia('(pointer: none)').matches,
        hoverNone: matchMedia('(hover: none)').matches,
        anyPointerNone: matchMedia('(any-pointer: none)').matches,
        anyHoverNone: matchMedia('(any-hover: none)').matches,
        inputless: /^(?:MacIntel|Win32|Linux)/.test(navigator.platform) &&
          m.innerWidth > 0 && m.innerHeight > 0 &&
          m.screenWidth > 0 && m.screenHeight > 0 &&
          matchMedia('(pointer: none)').matches && matchMedia('(hover: none)').matches &&
          matchMedia('(any-pointer: none)').matches && matchMedia('(any-hover: none)').matches,
        // The classifier's branches are intentionally private to headless.js.
        geometry: null,
        execution: null,
      },
      ...(${modeExecutionDiagnostic} ? {
        harnessBrowserVersion: ${JSON.stringify(browserEngine || null)},
        modeExecution: await (${probeModeExecution.toString()})(window, { popup: ${popupDiagnostic} }),
      } : {}),
      ...(${modeSurfaceDiagnostic} ? {
        modeSurface: await (${probeModeSurface.toString()})(window),
      } : {}),
      ...(${modeBranchDiagnostic} ? {
        passiveWindowUi: (${probePassiveWindowUi.toString()})(window),
        octoBranches: await (${probeOctoBranches.toString()})(window),
      } : {}),
      ...(${octoOwnedSurfaceDiagnostic} ? {
        octoOwnedSurfaces: (${probeOctoOwnedSurfaces.toString()})(window),
      } : {}),
      ...(${realmConsistencyDiagnostic} ? {
        modeRealmConsistency: await (${probeModeRealmConsistency.toString()})(window),
      } : {}),
      ...(${modeOwnedSurfaceDiagnostic} ? {
        modeOwnedSurfaces: (${probeOctoOwnedSurfaces.toString()})(window, {scope: "mode"}),
      } : {}),
      ...(${modeBehaviorDiagnostic} ? {
        modeBehavior: await (async () => {
          // Harness-only, transient checks. Do not interpret focus or a
          // background tab as headless, or turn these observations into an
          // identity/device fingerprint. Remove the frame even on timeout.
          const describe = context => ({
            visibilityState: context.document.visibilityState,
            hasFocus: context.document.hasFocus(),
            pointerNone: context.matchMedia('(pointer: none)').matches,
            hoverNone: context.matchMedia('(hover: none)').matches,
            anyPointerNone: context.matchMedia('(any-pointer: none)').matches,
            anyHoverNone: context.matchMedia('(any-hover: none)').matches,
            outerWidth: context.outerWidth,
            outerHeight: context.outerHeight,
            screenX: context.screenX,
            screenY: context.screenY,
          });
          const frame = document.createElement('iframe');
          frame.setAttribute('aria-hidden', 'true');
          frame.style.cssText = 'position:fixed;width:320px;height:200px;left:0;top:0;visibility:hidden;border:0';
          let timer;
          try {
            const ready = new Promise((resolve, reject) => {
              frame.onload = resolve;
              timer = setTimeout(() => reject(new Error('Frame did not load')), 1000);
            });
            frame.srcdoc = '<!doctype html><title>ADA transient mode probe</title>';
            (document.body || document.documentElement).appendChild(frame);
            await ready;
            return { top: describe(window), sameOriginFrame: describe(frame.contentWindow) };
          } catch (error) {
            return { error: String(error) };
          } finally {
            clearTimeout(timer);
            frame.remove();
          }
        })(),
      } : {}),
      ...(${targetDiagnostic} ? {extensionTargets: ${JSON.stringify(extensionTargets)}} : {}),
      ...(${octoDiagnostic} ? {
        octoEvidence: await (async () => {
          const hints = navigator.userAgentData;
          const values = hints?.getHighEntropyValues
            ? await hints.getHighEntropyValues(['fullVersionList']) : null;
          return {
            legacyScrollMarker: window.__adaTransientProbeV2.legacyScrollMarker(),
            emptyBrands: Array.isArray(hints?.brands) && hints.brands.length === 0,
            brandNames: Array.isArray(hints?.brands)
              ? hints.brands.map(item => item.brand) : null,
            fullVersionBrandNames: Array.isArray(values?.fullVersionList)
              ? values.fullVersionList.map(item => item.brand) : null,
            chromeVersion: values?.fullVersionList?.find(item =>
              item.brand === 'Google Chrome' || item.brand === 'Chromium')?.version || null,
            chromeProductName: window.chrome &&
              window.__adaTransientProbeV2.names(window.chrome, /(?:octobrowser|octium|^octo$)/i),
          };
        })(),
      } : {}),
      ...(${octoOwnedDiagnostic} ? {
        octoOwnedEvidence: (() => {
          const pattern = /octo(?:browser)?|octium/i;
          const owners = {
            window,
            chrome: window.chrome,
            navigator,
            navigatorPrototype: typeof Navigator === 'undefined' ? null : Navigator.prototype,
            screenPrototype: typeof Screen === 'undefined' ? null : Screen.prototype,
            documentPrototype: typeof Document === 'undefined' ? null : Document.prototype,
            webglPrototype: typeof WebGLRenderingContext === 'undefined'
              ? null : WebGLRenderingContext.prototype,
            canvasPrototype: typeof HTMLCanvasElement === 'undefined'
              ? null : HTMLCanvasElement.prototype,
          };
          const namedProperties = {};
          for (const [ownerName, owner] of Object.entries(owners)) {
            try {
              namedProperties[ownerName] = owner
                ? Object.getOwnPropertyNames(owner).filter(name => pattern.test(name)) : [];
            } catch { namedProperties[ownerName] = []; }
          }
          const candidates = [
            ['navigator', 'platform'],
            ['navigator', 'languages'],
            ['navigator', 'userAgent'],
            ['navigator', 'userAgentData'],
            ['navigator', 'plugins'],
            ['navigatorPrototype', 'platform'],
            ['navigatorPrototype', 'languages'],
            ['navigatorPrototype', 'userAgent'],
            ['navigatorPrototype', 'userAgentData'],
            ['navigatorPrototype', 'hardwareConcurrency'],
            ['navigatorPrototype', 'deviceMemory'],
            ['navigatorPrototype', 'plugins'],
            ['navigatorPrototype', 'mimeTypes'],
            ['navigatorPrototype', 'webdriver'],
            ['screenPrototype', 'width'],
            ['screenPrototype', 'height'],
            ['screenPrototype', 'availWidth'],
            ['screenPrototype', 'availHeight'],
            ['webglPrototype', 'getParameter'],
            ['canvasPrototype', 'toDataURL'],
            ['canvasPrototype', 'toBlob'],
          ];
          const patchedProperties = [];
          const descriptorShapes = [];
          const stackFrames = (() => {
            function outerProbe() {
              function innerProbe() { return String(new Error('ada-stack-probe').stack || ''); }
              return innerProbe();
            }
            return outerProbe().split('\\n').slice(1).filter(line => line.trim());
          })();
          for (const [ownerName, property] of candidates) {
            const owner = owners[ownerName];
            if (!owner) continue;
            let descriptor;
            try { descriptor = Object.getOwnPropertyDescriptor(owner, property); }
            catch { continue; }
            const fn = descriptor && (descriptor.get || descriptor.value);
            if (typeof fn !== 'function') continue;
            let source = '';
            let stack = '';
            try { source = Function.prototype.toString.call(fn); } catch {}
            try { fn.call(Object.create(null)); }
            catch (error) { stack = String(error && error.stack || ''); }
            const productName = pattern.test(fn.name);
            const productSource = pattern.test(source);
            const productFrame = stack.split('\\n').some(frame =>
              !frame.includes('detect_') && !frame.includes('detections/') &&
              pattern.test(frame));
            descriptorShapes.push({ ownerName, property,
              kind: descriptor.get ? 'getter' : 'value',
              name: fn.name,
              nativeSource: /\\[native code\\]/.test(source),
              invalidReceiverError: stack ? stack.split(':')[0] : null,
              stackFrames: stack ? stack.split('\\n').length - 1 : 0 });
            if (productName || productSource || productFrame) {
              patchedProperties.push({ ownerName, property,
                productName, productSource, productFrame });
            }
          }
          return { namedProperties, patchedProperties, descriptorShapes,
            stackShape: { frameCount: stackFrames.length,
              firstThreeSanitized: stackFrames.length >= 3 &&
                stackFrames.slice(0, 3).every(frame => /^\\s*at\\s*$/.test(frame)) } };
        })(),
      } : {}),
      ...(${octoApiSurface} ? {
        octoApiSurface: (() => {
          const owners = {
            window,
            chrome: window.chrome,
            navigator,
            navigatorPrototype: typeof Navigator === 'undefined' ? null : Navigator.prototype,
            screenPrototype: typeof Screen === 'undefined' ? null : Screen.prototype,
            documentPrototype: typeof Document === 'undefined' ? null : Document.prototype,
          };
          const result = {};
          for (const [name, owner] of Object.entries(owners)) {
            try { result[name] = owner ? Object.getOwnPropertyNames(owner).sort() : []; }
            catch { result[name] = []; }
          }
          return result;
        })(),
      } : {}),
    });
  })()`;
  const result = await send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  }, sessionId);
  if (result.error || result.result?.exceptionDetails || !result.result?.result?.value) {
    throw new Error(JSON.stringify(result.error || result.result));
  }
  const report = JSON.parse(result.result.result.value);
  if (jointContractDiagnostic) {
    report.jointContracts = await collectJointContracts(send, sessionId);
  }
  if (extendedContractDiagnostic) {
    report.extendedContracts = await collectExtendedContracts(send, sessionId);
    report.noCaptureMediaContract = await collectNoCaptureMediaContract(send, sessionId);
  }
  // Run only after measuring the unchanged detectors. This laboratory gesture
  // is never part of a submitted detector or a genuine-human gate.
  if (activatedPopupDiagnostic) {
    const { collectOwnedPopup } = await import("./owned_popup_probe.mjs");
    report.ownedActivatedPopup = await collectOwnedPopup(send, sessionId, { owned: true });
  }
  if (printDiagnostic) {
    const { collectOwnedPrint } = await import("./owned_print_probe.mjs");
    report.ownedPrint = await collectOwnedPrint(send, sessionId, { owned: true });
  }
  console.log(JSON.stringify(report));
} finally {
  try {
    if (targetId) await send("Target.closeTarget", { targetId });
  } finally {
    socket.close();
    rpc.close();
  }
}
