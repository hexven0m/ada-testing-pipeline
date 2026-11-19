#!/usr/bin/env python3
"""Disposable stock Chrome diagnostic control; never a genuine-human check."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from urllib.request import urlopen


ASSISTANT_ID = "gcaiimgaiohlnlflkjjmcohobkpbbnfi"
CONTROL_PRESETS = ("default", "udp-disabled", "fake-media", "assistant", "assistant-udp-disabled",
                   "kiosk-printing", "disable-print-preview")


def chrome_runtime_version(value):
    """Allowlisted runtime metadata for version-matched controls, never a classifier."""
    browser = value.get("Browser") if isinstance(value, dict) else None
    match = re.fullmatch(r"(HeadlessChrome|Chrome|Chromium)/([0-9]{1,3}(?:\.[0-9]{1,6}){3})",
                         browser) if isinstance(browser, str) else None
    if not match:
        return {"state": "UNKNOWN", "source": "owned-loopback-json-version"}
    return {"state": "observed", "product": match[1], "version": match[2],
            "source": "owned-loopback-json-version"}


def require_control_launch_tools(modes):
    """Fail before creating profiles/servers when the headed launcher is absent."""
    if not modes or any(mode not in {"headed", "headless"} for mode in modes):
        raise ValueError("mode-contract")
    if sys.platform.startswith("linux") and "headed" in modes:
        if any(shutil.which(tool) is None for tool in ("xvfb-run", "Xvfb", "xauth")):
            raise ValueError("headed-control-display-tools-unavailable; use a prepared host or --modes headless")


def control_configuration(preset="default", browser_binary=None, extension_directory=None):
    """Named disposable controls only; never arbitrary flags or account profiles.

    Extension flags are not evidence that an extension loaded. A caller running
    an assistant control must independently attest resource access afterward.
    Branded Chrome removed --load-extension; assistant controls explicitly use
    Chrome for Testing/Chromium and must not be called stock-Chrome evidence.
    """
    if preset not in CONTROL_PRESETS:
        raise ValueError("control-preset-contract")
    assistant = preset.startswith("assistant")
    if assistant is not (extension_directory is not None):
        raise ValueError("control-extension-contract")
    if browser_binary is None:
        binary = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" if sys.platform == "darwin" else shutil.which("google-chrome")
        flavor = "stock-chrome"
    else:
        path = Path(browser_binary)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("control-binary-contract")
        # Explicit opt-in testing binary; never describe it as stock Chrome.
        binary, flavor = str(path), "explicit-test-binary"
    if not binary or not Path(binary).is_file():
        raise ValueError("stock-chrome-unavailable")
    if assistant and browser_binary is None:
        raise ValueError("assistant-requires-explicit-testing-binary")
    extra = []
    extension_hash = None
    if assistant:
        directory = Path(extension_directory)
        if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
            raise ValueError("control-extension-contract")
        try:
            raw = (directory / "manifest.json").read_bytes()
            manifest = json.loads(raw)
            key = base64.b64decode(manifest["key"], validate=True)
            encoded = hashlib.sha256(key).hexdigest()[:32]
            actual_id = "".join(chr(ord("a") + int(c, 16)) for c in encoded)
            paths = {"dist/contentScripts/style.css", "dist/security/index.html"}
            accessible = any(paths.intersection(item.get("resources", []))
                for item in manifest.get("web_accessible_resources", []) if isinstance(item, dict))
            if actual_id != ASSISTANT_ID or not accessible:
                raise ValueError("control-extension-contract")
            extension_hash = hashlib.sha256(raw).hexdigest()
        except (OSError, ValueError, TypeError, KeyError):
            raise ValueError("control-extension-contract") from None
        extra += ["--load-extension=" + str(directory), "--disable-extensions-except=" + str(directory),
            "--disable-background-networking", "--disable-component-update", "--disable-sync",
            "--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1, EXCLUDE localhost"]
    udp_disabled = preset in {"udp-disabled", "assistant-udp-disabled"}
    # The command-line switch alone did not suppress UDP in our unified
    # headless control. Use the documented profile pref, then attest behavior.
    preferences = {"webrtc": {"ip_handling_policy": "disable_non_proxied_udp"}} if udp_disabled else {}
    if preset == "fake-media":
        extra += ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream"]
    if preset == "kiosk-printing":
        extra += ["--kiosk-printing"]
    if preset == "disable-print-preview":
        extra += ["--disable-print-preview"]
    return {"binary": binary, "flavor": flavor, "extra_arguments": extra,
            "extension_manifest_sha256": extension_hash, "assistant": assistant,
            "profile_preferences": preferences, "rtc_policy_required": udp_disabled}


def prepare_owned_preferences(profile, preferences):
    """Initialize only a newly made, empty diagnostic profile; never merge data."""
    if profile.is_symlink() or not profile.is_dir() or any(profile.iterdir()):
        raise ValueError("control-profile-not-empty")
    if preferences not in ({}, {"webrtc": {"ip_handling_policy": "disable_non_proxied_udp"}}):
        raise ValueError("control-preferences-contract")
    if preferences:
        default = profile / "Default"
        default.mkdir(mode=0o700, exist_ok=False)
        with (default / "Preferences").open("x") as output:
            os.chmod(output.name, 0o600)
            json.dump(preferences, output)


def attest_control_variant(configured, frontend):
    """A preset name or launch argument is not evidence of an exercised case."""
    if not configured["assistant"] and not configured["rtc_policy_required"]:
        return
    probe = frontend.get("assistant_control")
    if (not isinstance(probe, dict) or probe.get("diagnostic_only") is not True or
            probe.get("classification") != "NOT_A_CLASSIFIER"):
        raise ValueError("control-variant-unverified")
    if configured["assistant"] and probe.get("resource_accessible") is not True:
        raise ValueError("control-extension-unverified")
    if configured["rtc_policy_required"]:
        rtc = probe.get("rtc")
        if (not isinstance(rtc, dict) or rtc.get("state") != "complete" or
                rtc.get("local_configuration_retained") is not True or
                rtc.get("cleanup_confirmed") is not True or
                not isinstance(rtc.get("protocols"), dict) or
                type(rtc["protocols"].get("udp")) is not int or rtc["protocols"]["udp"] != 0):
            raise ValueError("control-rtc-policy-unverified")


def run_control(*, mode, url, allowed_origin, candidate_directory, artifacts, observer=None,
                control_preset="default", browser_binary=None, extension_directory=None):
    if __package__:
        from .run_owned_frontend_task import candidate_hashes, target_order, frontend_mode_evidence
        from . import run_owned_vendor_profiles as profiles
    else:
        from run_owned_frontend_task import candidate_hashes, target_order, frontend_mode_evidence
        import run_owned_vendor_profiles as profiles
    order = target_order(url, allowed_origin)
    if mode not in {"headed", "headless"}:
        raise ValueError("mode-contract")
    require_control_launch_tools([mode])
    manifest = candidate_hashes(candidate_directory)
    configured = control_configuration(control_preset, browser_binary, extension_directory)
    artifacts.mkdir(mode=0o700, exist_ok=False)
    profile = artifacts / "private-user-data"
    profile.mkdir(mode=0o700)
    prepare_owned_preferences(profile, configured["profile_preferences"])
    binary = configured["binary"]
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    args = [binary, "--user-data-dir=" + str(profile), "--remote-debugging-port=" + str(port),
            "--remote-debugging-address=127.0.0.1", "--no-first-run", "--no-default-browser-check",
            "--window-size=1280,720", *configured["extra_arguments"], "about:blank"]
    if mode == "headless":
        args.insert(1, "--headless=new")
    if sys.platform.startswith("linux"):
        if os.getuid() == 0:
            args.insert(1, "--no-sandbox")  # Only this root-owned disposable control.
        # Match the existing stock-control harness: an empty disposable profile
        # must not wait for a desktop keyring. Never use this on saved profiles,
        # and never put account cookies/passwords in this diagnostic profile.
        args.insert(1, "--password-store=basic")
        args.insert(1, "--disable-dev-shm-usage")
        if mode == "headed":
            args = ["xvfb-run", "-a", *args]
    process = None
    result = {"state": "UNKNOWN", "vendor": "chrome_control", "mode": mode, "order_number": order,
        "host_os": profiles.HOST_OS, "diagnostic_only": True, "human_verified": False,
        "cleanup_confirmed": False, "expected_detector_sha256": manifest,
        "control_preset": control_preset, "browser_flavor": configured["flavor"],
        "rtc_policy_required": configured["rtc_policy_required"],
        "extension_manifest_sha256": configured["extension_manifest_sha256"]}
    try:
        process = subprocess.Popen(args, start_new_session=True, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                with urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1) as response:
                    result["browser_runtime"] = chrome_runtime_version(json.load(response))
                break
            except OSError:
                if process.poll() is not None:
                    raise ValueError("control-start-failed")
                time.sleep(0.1)
        else:
            raise ValueError("control-not-ready")
        audit = profiles.native_mode(port)
        result["native_launch_audit"] = audit
        if audit.get("state") != "verified" or audit.get("headless_flag") is not (mode == "headless"):
            raise ValueError("control-native-mode-unverified")
        if observer is None:
            observed = subprocess.run([profiles.node_path(), str(Path(__file__).with_name("observe_ada_frontend.mjs")),
                                       str(port), url, "45000"], capture_output=True, text=True, timeout=65)
            frontend, observed_code = json.loads(observed.stdout), observed.returncode
        else:
            frontend, observed_code = observer(port, url), 0
        result["frontend_observation"] = frontend
        if (observed_code or frontend.get("state") != "collector-confirmed" or
                frontend.get("detector_sha256") != manifest or frontend.get("order_number") != order or
                type(frontend.get("headless")) is not bool or type(frontend.get("http_status")) is not int or
                not 200 <= frontend["http_status"] < 300):
            raise ValueError("control-completion-unverified")
        result["frontend"] = frontend
        attest_control_variant(configured, frontend)
        result.update(frontend_mode_evidence(frontend, mode))
        result["product_false_positive"] = bool(frontend["submitted_framework"])
        result["state"] = "delivered"
    except (OSError, ValueError, profiles.ProfileError, subprocess.TimeoutExpired) as error:
        allowed = {"control-start-failed", "control-not-ready", "control-native-mode-unverified",
                   "control-completion-unverified", "control-extension-unverified",
                   "control-variant-unverified", "control-rtc-policy-unverified",
                   "frontend-mode-evidence-mismatch"}
        result["failure"] = {"stage": str(error) if str(error) in allowed else "control-UNKNOWN"}
    finally:
        # Only the new session/process group created above; never pkill a name.
        if process is None:
            # Popen failed before returning a child; no owned browser exists.
            result["cleanup_confirmed"] = True
        else:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            for _ in range(50):
                if not profiles.socket_owners(port):
                    result["cleanup_confirmed"] = True
                    break
                time.sleep(0.1)
        if not result["cleanup_confirmed"]:
            result["state"] = "UNKNOWN"
        with (artifacts / "report.json").open("x") as output:
            os.chmod(output.name, 0o600)
            json.dump(result, output, indent=2)
        # Empty test profile data is deliberately retained as private evidence.
    return result
