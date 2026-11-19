"""Mac SDK session for one new owned GoLogin profile; no personal profile IDs."""

import json
import os
from pathlib import Path
import re
import socket
import sys
import time
from gologin_session_support import (LaunchObservation, SessionFailure, listener_owners,
                                    configure_executable_version, configuration_audit, network_configuration_audit,
                                    finish_owned_session)

os.environ["DISABLE_TELEMETRY"] = "true"
from gologin import GoLogin

config = json.loads(sys.stdin.readline())
if not re.fullmatch(r"[a-f0-9]{24}", config.get("owned_profile_id", "")) or config.get("mode") not in {"headed", "headless"}:
    raise ValueError("Owned profile session contract rejected")
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
binary = Path.home() / ".gologin/browser/orbita-browser-151/Orbita-Browser.app/Contents/MacOS/Orbita"
if not binary.is_file():
    raise RuntimeError("Installed Orbita executable unavailable")
token = (Path.home() / ".ada-runner/credentials/gologin.token").read_text().strip()
extra_params = ["--headless=new"] if config["mode"] == "headless" else []
netlog = None
if config.get("private_netlog_path") is not None:
    from owned_network_trace import reserve_capture
    netlog, flags = reserve_capture(Path(__file__).resolve().parents[1], config["private_netlog_path"])
    extra_params.extend(flags)
gl = GoLogin({"token": token, "profile_id": config["owned_profile_id"], "port": port,
              "executable_path": str(binary), "uploadCookiesToServer": False,
              "spawn_browser": False,
              "writeCookiesFromServer": False, "restore_last_session": False,
              "extra_params": extra_params})
observation = LaunchObservation(binary)
failure = None
cleanup = False
launch_config = {'disposable_profile_cleanup': config.get('discard_test_profile', False) is True}
spawned_at = None
try:
    configure_executable_version(gl, binary)
    # Prepare exactly this newly owned profile first. The explicit binary's
    # actual major must be initialized before the SDK writes secure settings.
    gl.start()
    launch_config.update({**configuration_audit(gl), **network_configuration_audit(gl)})
    with observation.observe(GoLogin):
        spawned_at = time.monotonic()
        address = gl.spawnBrowser()
    actual_port = observation.wait_ready(address, gl.pid)
    if actual_port != port:
        raise SessionFailure("debugger-port-mismatch")
    print("ADA_OWNED_SESSION=" + json.dumps({"port": actual_port, "ready": True,
          "startup": {**observation.diagnostics(), **launch_config}}), flush=True)
    sys.stdin.readline()
except Exception as error:
    failure = error.reason if isinstance(error, SessionFailure) else "sdk-start-exception"
    print("ADA_OWNED_SESSION=" + json.dumps({"reason": failure,
          "startup": {**observation.diagnostics(), **launch_config}}), flush=True)
    # Preserve the parent/child handshake even on startup failure so the
    # parent does not consume the cleanup marker in the readiness read.
    sys.stdin.readline()
finally:
    if netlog is not None and spawned_at is not None and observation.child is not None:
        # The SDK kills its browser rather than asking it to exit gracefully.
        # Let this diagnostic-only startup log flush at its fixed 20s deadline
        # before owned shutdown. This is not a detector timing modification.
        remaining = max(0, min(21, spawned_at + 21 - time.monotonic()))
        if observation.child.poll() is None and remaining:
            time.sleep(remaining)
    try:
        # Newly-created empty test profiles are deleted by the owned parent;
        # committing their ephemeral browsing state to the cloud is unnecessary
        # and can hang after native exit. Never opt saved/user profiles in.
        cleanup = finish_owned_session(gl, observation, port,
            config.get('discard_test_profile', False))
    except Exception:
        cleanup = False
    if cleanup:
        print("ADA_OWNED_STOPPED", flush=True)
    else:
        print("ADA_OWNED_CLEANUP_UNVERIFIED", flush=True)
        sys.exit(2)
