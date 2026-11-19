"""Owned Mac launch checks. Never export commands, profile IDs or raw SDK output."""

from contextlib import contextmanager
import importlib
import json
import plistlib
import re
import subprocess
import threading
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener


class SessionFailure(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def finish_owned_session(sdk, observation, port, discard_test_profile=False):
    """Close only the captured child; disposable tests need no cloud commit.

    The parent verifies newly-created ownership before opting in. Missing opt-in
    retains SDK synchronization. Unknown child/listener evidence is not success.
    """
    if type(discard_test_profile) is not bool:
        raise SessionFailure('disposable-session-contract')
    if not discard_test_profile:
        try:
            if (observation.child is not None and observation.child.poll() is None
                    and sdk.pid == observation.child.pid):
                sdk.stop()
        except Exception:
            pass  # The captured-child fallback still has to establish exit.
    observation.stop_child()
    no_child = not observation.spawn_attempted and sdk.pid == 0
    exited = observation.child is not None and observation.child.poll() is not None
    return (exited or no_child) and not listener_owners(port)


def configure_executable_version(sdk, binary):
    """Explicit executable paths skip the installed SDK's version initialization."""
    try:
        metadata = plistlib.loads((binary.parent.parent / "Info.plist").read_bytes())
        version = metadata.get("CFBundleShortVersionString", "")
        if not isinstance(version, str) or not re.fullmatch(r"[1-9][0-9]{1,2}(?:\.[0-9]+){1,3}", version):
            raise ValueError()
    except (OSError, ValueError, TypeError, AttributeError):
        raise SessionFailure("installed-browser-version-unverified") from None
    sdk.orbita_major_version = int(version.split(".")[0])
    sdk.chromium_version = version


def configuration_audit(sdk):
    """Verify vendor-issued configuration, never disclose the signed token."""
    threshold = sdk.profile.get("securedOrbitaVersion")
    if threshold is not None and (type(threshold) is not int or threshold <= 0):
        raise SessionFailure("secured-config-contract-invalid")
    required = threshold is not None and sdk.orbita_major_version >= threshold
    try:
        from pathlib import Path
        config = json.loads((Path(sdk.profile_path) / "orbita.config").read_text())
        token = config.get("gologin", {}).get("profile_token")
        present = isinstance(token, str) and bool(token.strip())
    except (OSError, ValueError, TypeError, AttributeError):
        present = False
    audit = {"sdk_orbita_major": sdk.orbita_major_version,
             "secured_config_required": required, "secured_config_present": present}
    if required and not present:
        raise SessionFailure("secured-profile-config-missing")
    return audit


def network_configuration_audit(sdk):
    """Own-profile launch metadata only; no proxy endpoints, IDs or secrets."""
    profile = sdk.profile if isinstance(sdk.profile, dict) else {}
    proxy = profile.get("proxy")
    proxy = proxy if isinstance(proxy, dict) else {}
    mode = proxy.get("mode", "none")
    modes = {"none", "http", "https", "socks4", "socks5", "geolocation", "gologin", "tor"}
    actual = getattr(sdk, "proxy", None)
    actual = actual if isinstance(actual, dict) else {}
    counts = {}
    for key, label in (("chromeExtensions", "profile_extensions_count"),
                       ("userChromeExtensions", "user_extensions_count")):
        value = profile.get(key, [])
        counts[label] = len(value) if isinstance(value, list) and len(value) <= 1000 else None
    return {"profile_proxy_mode": mode if isinstance(mode, str) and mode in modes else "UNKNOWN",
            "profile_proxy_host_configured": isinstance(proxy.get("host"), str) and bool(proxy["host"]),
            "sdk_proxy_host_configured": isinstance(actual.get("host"), str) and bool(actual["host"]),
            "sdk_proxy_object_truthy": bool(getattr(sdk, "proxy", None)),
            **counts}


def debugger_port(address):
    """Accept only the SDK's loopback HTTP address; never connect off-host."""
    if not isinstance(address, str):
        raise SessionFailure("debugger-address-invalid")
    try:
        parsed = urlsplit(address if "://" in address else "http://" + address)
        port = parsed.port
        valid = (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                 and not parsed.username and not parsed.password and not parsed.query
                 and not parsed.fragment and parsed.path in {"", "/"}
                 and port is not None and 1024 <= port <= 65534)
    except ValueError:
        valid = False
    if not valid:
        raise SessionFailure("debugger-address-invalid")
    return port


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def version_ready(port):
    """Check the browser-level CDP contract, not just whether TCP accepts."""
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(
                "http://127.0.0.1:%d/json/version" % port, timeout=1) as response:
            raw = response.read(65537)
            if response.status != 200 or len(raw) > 65536:
                return False
            value = json.loads(raw)
        if not isinstance(value, dict):
            return False
        endpoint = urlsplit(value.get("webSocketDebuggerUrl", ""))
        return (endpoint.scheme == "ws" and endpoint.hostname in {"127.0.0.1", "localhost", "::1"}
                and endpoint.port == port and endpoint.path.startswith("/devtools/browser/")
                and not endpoint.username and not endpoint.password and not endpoint.query
                and not endpoint.fragment and isinstance(value.get("Browser"), str)
                and bool(value["Browser"]))
    except (OSError, ValueError, TypeError):
        return False


def listener_owners(port):
    """Return only PIDs, keeping names/commands out of diagnostics."""
    result = subprocess.run(["lsof", "-nP", "-iTCP:%d" % port, "-sTCP:LISTEN", "-Fp"],
                            capture_output=True, text=True, timeout=5)
    if result.returncode not in (0, 1):
        raise SessionFailure("listener-audit-unavailable")
    return {int(line[1:]) for line in result.stdout.splitlines()
            if line.startswith("p") and line[1:].isdigit()}


class LaunchObservation:
    """Capture only the child created by this SDK call, draining output safely."""
    PATTERNS = {
        "architecture-mismatch": (b"bad cpu type", b"exec format error", b"incompatible architecture"),
        "dynamic-loader-error": (b"dyld:", b"library not loaded"),
        "permission-denied": (b"permission denied", b"operation not permitted"),
        "profile-lock": (b"processsingleton", b"singletonlock", b"profile appears to be in use"),
        "debug-port-bind-failed": (b"cannot start http server for devtools", b"address already in use"),
        "headless-flag-rejected": (b"unrecognized flag: --headless", b"unknown option: --headless"),
    }

    def __init__(self, executable):
        self.executable = str(executable)
        self.child = None
        self.spawn_attempted = False
        self.categories = set()
        self.readers = []
        self.launch_flags = {}

    def drain(self, stream):
        tail = b""
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                # Raw bytes are neither retained nor printed. Bounded overlap
                # catches phrases spanning reads without holding entire logs.
                sample = (tail + chunk).lower()
                for category, patterns in self.PATTERNS.items():
                    if any(pattern in sample for pattern in patterns):
                        self.categories.add(category)
                tail = sample[-128:]
        finally:
            stream.close()

    def spawn(self, original, args, *extra, **kwargs):
        if not isinstance(args, (list, tuple)) or not args or str(args[0]) != self.executable:
            return original(args, *extra, **kwargs)
        if self.child is not None:
            raise SessionFailure("multiple-owned-browser-spawns")
        self.spawn_attempted = True
        self.launch_flags = {
            "dns_wildcard_block_configured": any(isinstance(value, str) and
                value.startswith("--host-resolver-rules=") and "MAP * 0.0.0.0" in value for value in args),
            "proxy_server_arg_present": any(isinstance(value, str) and value.startswith("--proxy-server=") for value in args),
            "load_extension_arg_present": any(isinstance(value, str) and value.startswith("--load-extension=") for value in args),
        }
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.child = original(args, *extra, **kwargs)
        for stream in (self.child.stdout, self.child.stderr):
            thread = threading.Thread(target=self.drain, args=(stream,), daemon=True)
            thread.start()
            self.readers.append(thread)
        return self.child

    @contextmanager
    def observe(self, sdk_class):
        module = importlib.import_module(sdk_class.__module__)
        original = module.subprocess
        observer = self

        class Proxy:
            def Popen(self, *args, **kwargs):
                return observer.spawn(original.Popen, *args, **kwargs)

            def __getattr__(self, name):
                return getattr(original, name)

        module.subprocess = Proxy()
        try:
            yield
        finally:
            module.subprocess = original

    def diagnostics(self):
        if self.child is not None and self.child.poll() is not None:
            for reader in self.readers:
                reader.join(timeout=0.5)
        return {"child_observed": self.child is not None,
                "child_exit_code": None if self.child is None else self.child.poll(),
                "startup_categories": sorted(self.categories) or ["UNKNOWN"], **self.launch_flags}

    def wait_ready(self, address, sdk_pid, timeout=10):
        port = debugger_port(address)
        if self.child is None or sdk_pid != self.child.pid:
            raise SessionFailure("owned-child-unverified")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.child.poll() is not None:
                raise SessionFailure("browser-exited-before-readiness")
            owners = listener_owners(port)
            if owners and owners != {self.child.pid}:
                raise SessionFailure("debug-listener-not-owned")
            if owners == {self.child.pid} and version_ready(port):
                return port
            time.sleep(0.2)
        raise SessionFailure("debugger-not-ready")

    def stop_child(self):
        """Fallback targets the actual Popen child, never a global browser class."""
        if self.child is None:
            return
        if self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=5)
