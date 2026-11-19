// Owned call-site study only. Not a submission detector or product classifier.
(() => {
  window.__adaCallsiteStudy = function () {
    function outerProbe() {
      function innerProbe() { return String(new Error("ada-callsite-probe").stack || ""); }
      return innerProbe();
    }
    let stack = null;
    let css = null;
    let marker;
    try {
      const frames = outerProbe().split("\n").slice(1).filter(line => line.trim());
      stack = frames.length >= 3 && frames.slice(0, 3).every(frame => /^\s*at\s*$/.test(frame));
    } catch { /* No raw errors or stack paths leave the page. */ }
    try {
      css = false;
      if (CSS.supports("scroll-marker-group", "before") && !CSS.supports("scroll-marker-group", "links")) {
        marker = document.createElement("div");
        marker.style.setProperty("scroll-marker-group", "before");
        document.body.appendChild(marker);
        css = getComputedStyle(marker).getPropertyValue("scroll-marker-group") === "before links";
      }
    } catch { css = null; }
    finally { if (marker) marker.remove(); }
    return { bareFirstFrames: stack, legacyScrollMarker: css };
  };
})();
