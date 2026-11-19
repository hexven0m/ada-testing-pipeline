/** Exact-source, test-only tracing. Never edits or replaces window.detect_octo. */
import { createHash } from "node:crypto";

export function prepareOctoTrace(source) {
  const sha256 = createHash("sha256").update(source).digest("hex");
  const legacy = sha256 === "c2549191c08b25b6c5ffeefb7bdff3396f65f79f57f030053498fd57bb8025bf";
  const updated = sha256 === "c4a2bc362bf4a7fda72ec3fa3d6b1c3f042bf0566f9230a77c6483475ea9f6e5";
  if (!legacy && !updated) {
    return `({state:'unsupported-source', sourceSha256:${JSON.stringify(sha256)}})`;
  }
  let code = source;
  function replace(before, after) {
    if (code.split(before).length !== 2) throw new Error("Octo trace source contract changed");
    code = code.replace(before, after);
  }
  replace('if (typeof window !== "undefined") window.detect_octo = detect_octo;', "");
  replace("async function __adaOctoInvoke(fn, ErrorType)",
    "async function __adaOctoInvoke(fn, ErrorType, observed)");
  replace("catch (error) { return wrapperNames(error, ErrorType); }",
    "catch (error) { observed.syncThrows++; return wrapperNames(error, ErrorType); }");
  replace("[function () { return []; },\n        function (error) { return wrapperNames(error, ErrorType); }]);",
    "[function () { observed.resolved++; return []; },\n        function (error) { observed.rejected++; return wrapperNames(error, ErrorType); }]);");
  replace("} catch { return []; }\n    var timer;", "} catch { observed.nonPromise++; return []; }\n    var timer;");
  replace("timer = setTimeout(function () { resolve([]); }, 250);",
    "timer = setTimeout(function () { observed.timeouts++; resolve([]); }, 250);");
  replace("async function artifacts(realm) {", `async function artifacts(realm) {
    var observed={missingTargets:[], missingMethods:[], scannedProperties:0,
      syncThrows:0, resolved:0, rejected:0, nonPromise:0, timeouts:0, markers:0,
      formatterRejected:0, descriptorErrors:0, errorBrandAvailable:false};
    trace.realms.push(observed);`);
  replace('var ErrorType = data(realm, "Error");',
    'var ErrorType = data(realm, "Error"); observed.errorBrandAvailable=typeof data(ErrorType,"isError")==="function";');
  replace("if (!subject) continue;", "if (!subject) { observed.missingTargets.push(target[0]); continue; }");
  replace("try { names = ownNames(subject).slice(0, 256); } catch { continue; }",
    "try { names = ownNames(subject).slice(0, 256); observed.scannedProperties+=names.length; } catch { observed.descriptorErrors++; continue; }");
  replace("if (!ordinaryFormatter(ErrorType)) continue;",
    "if (!ordinaryFormatter(ErrorType)) { observed.formatterRejected++; continue; }");
  replace('if (typeof fn !== "function") continue;',
    'if (typeof fn !== "function") { observed.missingMethods.push(target[0]+"/"+selected); continue; }');
  replace("__adaOctoInvoke(callback, ErrorType).then", "__adaOctoInvoke(callback, ErrorType, observed).then");
  replace("return found;", "observed.markers=found.size; return found;");
  replace("if (primary.size === 0) return false;", 'if (primary.size === 0) { trace.exit="no-primary-marker"; return false; }');
  replace("if (!document.documentElement) return false;", 'if (!document.documentElement) { trace.exit="no-document-root"; return false; }');
  replace('data(realm, "Navigator") === data(window, "Navigator")) return false;',
    'data(realm, "Navigator") === data(window, "Navigator")) { trace.exit="no-independent-frame"; return false; }');
  // Frame timeout has its own timer separate from each API call.
  replace("timer = setTimeout(function () { resolve(new Set()); }, 450);",
    'timer = setTimeout(function () { trace.frameTimedOut=true; resolve(new Set()); }, 450);');
  if (legacy) {
    replace("for (var marker of primary) if (secondary.has(marker)) return true;\n    return false;",
      'for (var marker of primary) if (secondary.has(marker)) { trace.exit="corroborated"; return true; }\n    trace.exit="no-corroboration"; return false;');
    replace("} catch { return false; }\n  finally", '} catch { trace.exit="frame-error"; return false; }\n  finally');
  } else {
    replace("if (secondary.has(marker)) { matched = true; break; }",
      'if (secondary.has(marker)) { trace.exit="corroborated"; matched = true; break; }');
    replace("} catch { matched = false; }\n  finally",
      '} catch { trace.exit="frame-error"; matched = false; }\n  finally');
    replace("return matched;", 'if (trace.exit==="UNKNOWN") trace.exit="no-corroboration"; return matched;');
    replace("try { if (frame) frame.remove(); } catch { matched = false; }",
      'try { if (frame) frame.remove(); } catch { trace.exit="cleanup-error"; matched = false; }');
  }
  return `(async()=>{const trace={state:'observed',sourceSha256:${JSON.stringify(sha256)},
    exit:'UNKNOWN',frameTimedOut:false,realms:[]}; ${code}
    try {trace.verdict=await detect_octo();} catch {trace.state='UNKNOWN';}
    return trace;})()`;
}
