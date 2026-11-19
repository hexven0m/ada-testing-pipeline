#!/usr/bin/env python3
"""Portable, owned-profile diagnostic matrix; NOT an official scorer run.

Run on the browser host from an isolated copy of the candidate and probe files.
Only new profiles, the host-configured dedicated Dolphin test profile, or an
idle AdsPower profile an earlier run created ("ADA owned <hex>") are selected.
Reused profiles are never deleted. Tokens stay in that host's store.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("headless", "ads_power", "dolphin_anty", "gologin", "multilogin", "octo")
OS_CLAIMS = {v: ("windows", "linux", "macos") for v in NAMES if v != "headless"}
OS_CLAIMS["octo"] = ("windows", "macos")
# "default" omits only fingerprint.webrtc. Other lab profile fields stay explicit;
# this is not proof of a GUI default or a deployed validator's profile recipe.
OCTO_WEBRTC_MODES = ("disable_non_proxied_udp", "real", "ip", "default")
HOST_OS = "linux" if sys.platform.startswith("linux") else "macos"
CREDS = Path("/etc/ada-runner/credentials") if HOST_OS == "linux" else Path.home() / ".ada-runner/credentials"
LOCAL_OCTO = "http://127.0.0.1:58888/api/profiles"
OCTO_CLOUD = "https://app.octobrowser.net/api/v2/automation/profiles"
DOLPHIN_CLOUD = "https://dolphin-anty-api.com"
DOLPHIN_LOCAL = "http://127.0.0.1:3001/v1.0"
ML_LOCAL = "https://127.0.0.1:45001/api"
ML_TOKEN_STORE = "auto"
ADS_WEBRTC = None  # Settings sweep only; None leaves the vendor default.
ADS_SCREEN = None  # Settings sweep only; "width_height", None leaves the vendor default.
ADS_LEFTOVER_FALLBACK = True  # Main test only; a settings row must run the OS claim it reports.
OCTO_SCREEN = "1920x1080"  # Settings sweep may request another listed screen.
OCTO_MINIMAL = False  # Settings sweep only: send the OS claim and leave the rest to Octo.
OCTO_NOISE = None  # Settings sweep only: True/False sets every Octo noise switch; None leaves them.


class ProfileError(Exception):
    def __init__(self, stage, http=None, reason="UNKNOWN", retry_after=None):
        self.stage, self.http, self.reason, self.retry_after = stage, http, reason, retry_after
        super().__init__(stage)  # Never a raw response, URL, secret, ID or command.


def probe_failure_reason(stdout, stderr):
    """Classify known harness messages; never persist raw probe output.

    Categories identify the failed boundary, not a proven underlying cause.
    In particular a Runtime.evaluate timeout is not proof of a detector hang.
    """
    text = ((stderr if isinstance(stderr, str) else '') + '\n' +
            (stdout if isinstance(stdout, str) else ''))[:65536]
    if 'CDP request timed out: Runtime.evaluate' in text:
        return 'runtime-evaluation-timeout'
    for method, category in (
            ('Target.createTarget', 'cdp-target-create-timeout'),
            ('Target.attachToTarget', 'cdp-target-attach-timeout'),
            ('Target.closeTarget', 'cdp-target-close-timeout'),
            ('Page.navigate', 'cdp-navigation-request-timeout'),
            ('Page.enable', 'cdp-page-enable-timeout'),
            ('Runtime.enable', 'cdp-runtime-enable-timeout')):
        if 'CDP request timed out: ' + method in text:
            return category
    if 'CDP request timed out:' in text:
        return 'cdp-request-timeout'
    if 'Could not load ' in text:
        return 'source-load-failed'
    if 'Navigation did not reach the requested complete page' in text:
        return 'navigation-not-complete'
    if 'CDP browser endpoint is missing' in text:
        return 'cdp-endpoint-missing'
    if 'CDP returned HTTP ' in text:
        return 'cdp-http-refused'
    if ('CDP connection closed before its reply' in text or
            'CDP connection is closed' in text):
        return 'cdp-disconnected'
    if 'net::ERR_' in text:
        return 'network-error'
    return 'probe-process-failed'


def run_page_probe(command, env):
    try:
        probe = subprocess.run(command, env=env, text=True, capture_output=True,
                               timeout=70, check=False)
    except subprocess.TimeoutExpired:
        raise ProfileError('page-probe', reason='probe-process-timeout') from None
    if probe.returncode:
        raise ProfileError('page-probe', reason=probe_failure_reason(probe.stdout, probe.stderr))
    try:
        result = json.loads(probe.stdout)
        if not isinstance(result, dict):
            raise ValueError
        return result
    except (ValueError, TypeError):
        raise ProfileError('page-probe', reason='invalid-probe-output') from None


def preserve_native_audit(row, port):
    """Audit a started owned browser even when page delivery fails."""
    if port is None or 'launch_audit' in row:
        return
    try:
        row['launch_audit'] = native_mode(checked_port(port))
    except (ProfileError, OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        row['native_audit_failure'] = 'UNVERIFIED'


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward credentials to a redirected host.


def sanitize_gologin_startup(value):
    """Retain only enumerated evidence from the owned Mac child observer."""
    value = value if isinstance(value, dict) else {}
    categories = {"architecture-mismatch", "dynamic-loader-error", "permission-denied", "profile-lock",
                  "debug-port-bind-failed", "headless-flag-rejected", "UNKNOWN"}
    supplied = value.get("startup_categories", [])
    supplied = supplied if isinstance(supplied, list) else []
    code = value.get("child_exit_code")
    result = {"child_observed": value.get("child_observed") is True,
              "child_exit_code": code if type(code) is int and -255 <= code <= 255 else None,
              "startup_categories": sorted({x for x in supplied if isinstance(x, str) and x in categories}) or ["UNKNOWN"]}
    if type(value.get("sdk_orbita_major")) is int and 10 <= value["sdk_orbita_major"] <= 999:
        result["sdk_orbita_major"] = value["sdk_orbita_major"]
    for key in ("disposable_profile_cleanup", "secured_config_required", "secured_config_present", "profile_proxy_host_configured",
                "sdk_proxy_host_configured", "sdk_proxy_object_truthy", "dns_wildcard_block_configured",
                "proxy_server_arg_present", "load_extension_arg_present"):
        if type(value.get(key)) is bool:
            result[key] = value[key]
    modes = {"none", "http", "https", "socks4", "socks5", "geolocation", "gologin", "tor", "UNKNOWN"}
    mode = value.get("profile_proxy_mode")
    if isinstance(mode, str) and mode in modes:
        result["profile_proxy_mode"] = mode
    for key in ("profile_extensions_count", "user_extensions_count"):
        if type(value.get(key)) is int and 0 <= value[key] <= 1000:
            result[key] = value[key]
    return result


def dolphin_validation_fields(raw):
    """Expose only mentioned API field names, never response text or values."""
    allowed = ("platform", "useragent", "webglInfo", "cpu", "memory", "osVersion")
    try:
        value = raw.decode("utf-8", "replace")
    except (AttributeError, TypeError):
        return ()
    return tuple(name for name in allowed if re.search(r"\b" + re.escape(name) + r"\b", value, re.I))


def adspower_business_failure(data):
    """Enum-only diagnosis of a rejected request; never export message text."""
    text = " ".join(value[:2048].lower() for key in ("msg", "message")
                    if isinstance(value := data.get(key), str))
    if ((re.search(r"daily|today|今日|当天|每日", text) and
         re.search(r"creat|创建|新建", text) and re.search(r"limit|quota|exceed|上限|限制|超", text))):
        return "daily-create-quota-exhausted"
    if re.search(r"max profiles|profile quota|profile limit|配置文件.{0,12}上限", text):
        return "profile-quota-exhausted"
    if re.search(r"rate.limit|too frequent|too many requests|请求.{0,8}频繁|访问.{0,8}频繁", text):
        return "rate-limited"
    return "UNKNOWN"


ADSPOWER_MESSAGE_MARKERS = {
    "limit": r"limit|quota|exceed|上限|限额|超出|超过",
    "daily": r"daily|today|今日|当天|每日",
    "monthly": r"monthly|this month|每月|本月",
    "creation": r"creat|创建|新建",
    "profiles": r"profile|environment|\benv\b|配置文件|环境",
    "authentication": r"authenticat|unauthori[sz]ed|credential|api.key|token|login|登录|密钥",
    "subscription": r"subscription|license|licence|expired|套餐|订阅|到期",
    "input": r"invalid|required|parameter|字段|参数|必填",
    "group": r"\bgroup\b|分组",
    "rate": r"rate.limit|too frequent|too many requests|请求.{0,8}频繁|访问.{0,8}频繁",
}


def adspower_create_evidence(data):
    """Bounded response facts, not inferred causes or raw provider messages."""
    data = data if isinstance(data, dict) else {}
    code = data.get("code")
    number = code if type(code) is int and -10000 <= code <= 10000 else None
    text = " ".join(value[:2048].lower() for key in ("msg", "message")
                    if isinstance(value := data.get(key), str))
    return {"schema_version": 1, "business_code": number,
            "code_state": "missing-or-malformed" if number is None else "zero" if number == 0 else "nonzero",
            "message_markers": sorted(key for key, pattern in ADSPOWER_MESSAGE_MARKERS.items()
                                      if re.search(pattern, text))}


def sanitize_adspower_create_evidence(value):
    """Revalidate the enum-only audit before copying it into a task report."""
    keys = {"schema_version", "business_code", "code_state", "message_markers"}
    if (not isinstance(value, dict) or set(value) != keys or
            type(value.get("schema_version")) is not int or value["schema_version"] != 1):
        return None
    code, markers = value.get("business_code"), value.get("message_markers")
    if (code is not None and (type(code) is not int or not -10000 <= code <= 10000)) or (
            not isinstance(markers, list) or len(markers) > len(ADSPOWER_MESSAGE_MARKERS) or
            any(not isinstance(marker, str) or marker not in ADSPOWER_MESSAGE_MARKERS for marker in markers) or
            markers != sorted(set(markers))):
        return None
    state = "missing-or-malformed" if code is None else "zero" if code == 0 else "nonzero"
    if value.get("code_state") != state:
        return None
    return {"schema_version": 1, "business_code": code, "code_state": state,
            "message_markers": list(markers)}


def dolphin_profile_parameters(profile_os, headers):
    """One vendor-generated nominal config, never a page/device fingerprint.

    Independent GPU draws plus a fixed CPU can fail the vendor's compatibility
    table. Keep masking modes unchanged but take the configured values together.
    Ignore fonts, voices, screen and all other identity-bearing dataset fields.
    """
    if profile_os not in {"windows", "linux", "macos"}:
        raise ProfileError("profile-template-os-contract")
    generated = api("GET", DOLPHIN_CLOUD + "/fingerprints/fingerprint?" + urlencode({
        "browser_type": "anty", "platform": profile_os, "browser_version": "153",
        "type": "fingerprint", "screen": "1920x1080"}), "coherent-profile-template", headers=headers)
    try:
        ua = generated["userAgent"]
        cpu, memory = generated["hardwareConcurrency"], generated["deviceMemory"]
        graphics = generated["webgl"]
        vendor, renderer = graphics["unmaskedVendor"], graphics["unmaskedRenderer"]
        if (not isinstance(ua, str) or not ua.startswith("Mozilla/5.0 ") or len(ua) > 2048 or
                type(cpu) is not int or not 1 <= cpu <= 64 or
                type(memory) is not int or memory not in {1, 2, 4, 8} or
                any(not isinstance(value, str) or not value or len(value) > 2048 or
                    any(ord(char) < 32 for char in value) for value in (ua, vendor, renderer))):
            raise ValueError
        info = {"mode": "manual", "vendor": vendor, "renderer": renderer}
        maximum = generated.get("webgl2Maximum")
        if maximum is not None:
            if isinstance(maximum, str):
                if len(maximum) > 16384:
                    raise ValueError
                maximum = json.loads(maximum)
            if not isinstance(maximum, dict) or len(maximum) > 200:
                raise ValueError
            serialized = json.dumps(maximum, allow_nan=False)
            if len(serialized) > 16384:
                raise ValueError
            info["webgl2Maximum"] = serialized
        result = {"useragent": {"mode": "manual", "value": ua}, "webglInfo": info,
                  "cpu": {"mode": "manual", "value": cpu}, "memory": {"mode": "manual", "value": memory}}
        version = generated.get("platformVersion")
        if version is not None:
            if not isinstance(version, str) or not re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){0,3}", version):
                raise ValueError
            # Generator schema and create schema use different field names.
            # The documented browser_profiles request accepts osVersion.
            result["osVersion"] = version
        return result
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ProfileError("coherent-profile-template-contract") from None


def dolphin_profile_template(profile_os, headers, draws=3):
    """A generated template that passes the checks; a failed draw created nothing, so draw again."""
    for draw in range(draws):
        try:
            return dolphin_profile_parameters(profile_os, headers)
        except ProfileError as error:
            if error.stage != "coherent-profile-template-contract" or draw + 1 == draws:
                raise
            time.sleep(1)


def api(method, url, stage, *, headers=None, body=None, accepted=(200,), timeout=180):
    request = Request(url, data=None if body is None else json.dumps(body).encode(),
                      method=method, headers={**(headers or {}), "Content-Type": "application/json"})
    context = ssl._create_unverified_context() if url.startswith("https://127.0.0.1:") else None
    try:
        with build_opener(NoRedirect(), HTTPSHandler(context=context)).open(request, timeout=timeout) as response:
            if response.status not in accepted:
                raise ProfileError(stage, response.status)
            data = response.read(2_000_001)
            if len(data) > 2_000_000:
                raise ProfileError(stage, reason="response-limit")
            return json.loads(data or b"{}")
    except HTTPError as error:
        reason = {401: "authorization-refused", 403: "access-or-quota-refused",
                  429: "rate-limited"}.get(error.code, "UNKNOWN")
        if error.code == 422 and stage == "create" and url == DOLPHIN_CLOUD + "/browser_profiles":
            detail = error.read(10000)
            fields = dolphin_validation_fields(detail)
            reason = ("dolphin-hardware-incompatible" if b"incompatible" in detail.lower() else
                      "validation-mentions-" + "-".join(fields) if fields else "UNKNOWN")
        # Read only a known quota phrase, without retaining the response.
        if error.code == 403 and b"max profiles" in error.read(10000).lower():
            reason = "profile-quota-exhausted"
        delay = error.headers.get("Retry-After", "") if error.headers else ""
        delay = int(delay) if str(delay).isdigit() and int(delay) <= 3600 else None
        raise ProfileError(stage, error.code, reason, delay) from None
    except (URLError, TimeoutError, OSError, ValueError) as error:
        # A refused connection to a local app port never reached the app, so
        # nothing was created or started. Any other failure stays ambiguous.
        absent = (url.startswith(("http://127.0.0.1:", "https://127.0.0.1:")) and
                  isinstance(getattr(error, "reason", error), ConnectionRefusedError))
        raise ProfileError(stage, reason="app-not-listening" if absent else "network-or-client-error") from None


def envfile(path):
    result = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def credentials(vendor):
    if vendor == "ads_power":
        cfg = envfile(CREDS / "adspower.env")
        root = cfg.get("api_root", "http://127.0.0.1:50325").rstrip("/")
        if not re.fullmatch(r"http://127\.0\.0\.1:\d{1,5}", root):
            raise ProfileError("non-loopback-adspower-api")
        return root + "/api/v2/browser-profile", {"Authorization": "Bearer " + cfg["api_key"]}
    if vendor == "multilogin":
        token = envfile(CREDS / "multilogin.env")["token"]
        store = Path.home() / ".ada-matrix/secrets.json"
        if ML_TOKEN_STORE == "auto" and HOST_OS == "macos" and store.is_file():
            token = json.loads(store.read_text()).get("ml_token") or token
        return ML_LOCAL, {"Authorization": token}
    token = (CREDS / {"dolphin_anty": "dolphin.token", "gologin": "gologin.token",
                      "octo": "octo.token"}[vendor]).read_text().strip()
    return None, {"X-Octo-Api-Token": token} if vendor == "octo" else {"Authorization": "Bearer " + token}


def checked_id(value):
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise ProfileError("created-profile-id-contract")
    value = str(value)
    if not re.fullmatch(r"[A-Za-z0-9-]{1,80}", value):
        raise ProfileError("created-profile-id-contract")
    return value


def dolphin_saved_id():
    """Optional reusable Dolphin test profile for this host; no file means create a new one."""
    try:
        value = (CREDS / "dolphin.saved_profile_id").read_text().strip()
    except OSError:
        return None
    return checked_id(value) if value else None


def dolphin_reuse_pool():
    """Explicit operator-configured allowlist; never select an arbitrary account profile."""
    path = CREDS / "dolphin.reuse_profiles.json"
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text())
        if (value.get("policy") != "reuse-only" or value.get("host_os") != HOST_OS or
                not isinstance(value.get("profiles"), list) or not 1 <= len(value["profiles"]) <= 100):
            raise ValueError
        result = []
        for entry in value["profiles"]:
            identifier = checked_id(entry["id"])
            name, platform = entry["name"], entry["platform"]
            if (not isinstance(name, str) or not name or len(name) > 255 or
                    platform not in {"windows", "linux", "macos"}):
                raise ValueError
            result.append({"id": identifier, "name": name, "platform": platform})
        return result
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ProfileError("approved-dolphin-pool-contract") from None


def dolphin_list_profiles(headers):
    result = {}
    for page in range(1, 6):
        data = api("GET", DOLPHIN_CLOUD + "/browser_profiles?" + urlencode({"limit": 100, "page": page}),
                   "approved-dolphin-pool-list", headers=headers, timeout=20)
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            raise ProfileError("approved-dolphin-pool-list-contract")
        for profile in data["data"]:
            if not isinstance(profile, dict):
                raise ProfileError("approved-dolphin-pool-list-contract")
            result[checked_id(profile.get("id"))] = profile
        if not data.get("next_page_url"):
            return result
    raise ProfileError("approved-dolphin-pool-list-limit")


def dolphin_settings_hash(profile):
    # Compare configuration only. Session duration, cookies and sync metadata
    # naturally change on a visit and are not profile-setting changes.
    fields = ("platform", "browserType", "useragent", "webrtc", "canvas", "webgl", "webglInfo",
              "clientRect", "timezone", "locale", "geolocation", "doNotTrack", "args", "cpu",
              "memory", "screen", "ports", "osVersion", "webgpu", "audio", "proxyId")
    selected = {key: profile.get(key) for key in fields}
    return hashlib.sha256(json.dumps(selected, sort_keys=True, allow_nan=False).encode()).hexdigest()


def dolphin_saved_browser_present(profile_id):
    """Do not reuse a test profile with a browser outside the app's running map.

    Read OS metadata only, keeping all commands/profile identifiers in memory.
    A busy saved profile is left alone; callers may create a new disposable one.
    """
    if HOST_OS == "linux":
        commands = []
        for path in Path("/proc").iterdir():
            if not path.name.isdecimal():
                continue
            try:
                commands.append((int(path.name), (path / "cmdline").read_bytes().decode().replace("\0", " ")))
            except (OSError, UnicodeError):
                continue
    else:
        try:
            raw = subprocess.check_output(["ps", "-axo", "pid=,command="], text=True)
        except (OSError, subprocess.CalledProcessError):
            raise ProfileError("dedicated-test-profile-process-unverified") from None
        commands = [(int(parts[0]), parts[1]) for line in raw.splitlines()
                    if len(parts := line.strip().split(None, 1)) == 2 and parts[0].isdecimal()]
    for pid, command in commands:
        directory = re.search(r"--user-data-dir[= ](.*?)(?=\s--|$)", command)
        if (directory is None or re.search(r"(?:^|\s)--type=", command) or
                not re.search(r"(?:^|[/\\\s])" + re.escape(str(profile_id)) + r"(?:[/\\\s]|$)", directory[1])):
            continue
        try:
            executable, _ = root_command(pid)
        except (OSError, subprocess.CalledProcessError):
            raise ProfileError("dedicated-test-profile-process-unverified") from None
        if "anty" in executable.lower():
            return True
    return False


def dolphin_owned_inactive(status, profile_id):
    """Accept only the observed running-profile map, never a success envelope."""
    if not isinstance(status, dict) or status.get("success") is False:
        raise ProfileError("owned-profile-inactive-unverified")
    active = status.get("data", status)
    if not isinstance(active, dict) or any(not str(key).isdecimal() for key in active):
        raise ProfileError("owned-profile-inactive-unverified")
    return str(profile_id) not in {str(key) for key in active}


def wait_dolphin_owned_inactive(profile_id, attempts=100):
    # A successful stop can precede the app's removal from its running map.
    # Poll only read-only status; never retry an ambiguous start or stop another
    # profile. Unknown response shapes still fail closed.
    for attempt in range(attempts):
        status = api("GET", DOLPHIN_LOCAL + "/browser_profiles/running",
                     "cleanup-owned-status", timeout=5)
        if dolphin_owned_inactive(status, profile_id):
            return
        if attempt + 1 < attempts:
            time.sleep(0.2)
    raise ProfileError("owned-profile-inactive-unverified")


ADSPOWER_OWNED_TITLE = re.compile(r"ADA owned [0-9a-f]{32}")
ADSPOWER_DEFAULT_TITLE = "ADA owned default " + HOST_OS  # This host's kept default-recipe profile.
ADSPOWER_REFUSED_STARTS = set()  # Earlier-run profiles that refused to start in this process.
ADSPOWER_START_MARKERS = {
    **ADSPOWER_MESSAGE_MARKERS,
    "open": r"open|launch|打开|启动",
    "in_use": r"in use|being used|is using|already open|opened by|another device|other device|正在使用|已打开|其他设备|占用",
    "kernel": r"kernel|sunbrowser|flowerbrowser|download|updat|内核|下载|更新",
    "missing": r"not exist|not found|不存在|未找到",
    "api": r"\bapi\b|接口",
    "rate": r"rate.limit|too frequent|too many request|请求.{0,8}频繁|访问.{0,8}频繁",
}


def adspower_kept_title(profile_os):
    """Name of this host's kept test profile for one OS claim."""
    return ADSPOWER_DEFAULT_TITLE if profile_os == HOST_OS else ADSPOWER_DEFAULT_TITLE + " " + profile_os


def adspower_start_markers(data):
    """Enum-only facts about a refused start; never the vendor's message text."""
    data = data if isinstance(data, dict) else {}
    text = " ".join(value[:2048].lower() for key in ("msg", "message")
                    if isinstance(value := data.get(key), str))
    return sorted(key for key, pattern in ADSPOWER_START_MARKERS.items() if re.search(pattern, text))


def adspower_idle_owned_id(root, headers, title=None):
    """(profile ID or None, short reason): an idle profile this pipeline created.

    With a title, only profiles with exactly that name qualify (this host's
    dedicated default profile) and a busy one gets a few seconds to close.
    Without one, the leftovers of earlier runs ("ADA owned <32 hex>") qualify;
    Linux takes them from the start of the sorted list and the Mac from the
    end, so the two hosts pick different ones. Never a profile the operator
    made. Any unexpected answer means none; the caller then creates as before.
    """
    base = root.split("/api/", 1)[0] + "/api/v1"
    try:
        for attempt in range(4):
            if attempt:
                time.sleep(1.5)  # The app refuses more than about two calls a second.
            listed = api("GET", base + "/user/list?" + urlencode({"page": 1, "page_size": 100}),
                         "reuse-owned-list", headers=headers, timeout=20)
            if listed.get("code") == 0:
                break
        else:
            return None, "list-refused"
        owned = sorted(checked_id(row["user_id"]) for row in listed["data"]["list"]
                       if isinstance(row.get("name"), str) and
                       (row["name"] == title if title else ADSPOWER_OWNED_TITLE.fullmatch(row["name"])))
        if not owned:
            return None, "none-owned"
        if title is None and HOST_OS != "linux":
            owned.reverse()
        usable = [profile_id for profile_id in owned if profile_id not in ADSPOWER_REFUSED_STARTS]
        if not usable:
            return None, "none-idle"  # Each one refused to start earlier in this process.
        for sweep in range(3 if title else 1):
            if sweep:
                time.sleep(2)  # A profile stopped a moment ago can still show as open.
            for profile_id in usable:
                time.sleep(1)  # The local API refuses requests that arrive in a burst.
                status = api("GET", base + "/browser/active?" + urlencode({"user_id": profile_id}),
                             "reuse-owned-status", headers=headers, timeout=20)
                if status.get("code") == 0 and status.get("data", {}).get("status") == "Inactive":
                    return profile_id, "idle-owned-found"
        return None, "none-idle"
    except (ProfileError, KeyError, TypeError, AttributeError):
        return None, "lookup-error"


def checked_port(value):
    if isinstance(value, bool) or not str(value).isdigit() or not 1024 <= int(value) <= 65534:
        raise ProfileError("debug-port-contract")
    return int(value)


def octo_debug_port(data):
    """Accept Octo's loopback WebSocket endpoint when debug_port is omitted."""
    value = data.get("debug_port")
    if value is not None:
        return checked_port(value)
    endpoint = data.get("ws_endpoint")
    if not isinstance(endpoint, str):
        raise ProfileError("debug-port-contract")
    try:
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"ws", "wss"} or parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise ProfileError("debug-port-contract")
        return checked_port(parsed.port)
    except ValueError:
        raise ProfileError("debug-port-contract") from None


def socket_owners(port):
    """Resolve this owned CDP listener, not process titles or wrapper argv."""
    if HOST_OS == "macos":
        try:
            raw = subprocess.check_output(["/usr/sbin/lsof", "-n", "-P", f"-iTCP:{port}",
                                           "-sTCP:LISTEN", "-t"], text=True, stderr=subprocess.DEVNULL)
            return {int(line) for line in raw.splitlines() if line.isdecimal()}
        except (OSError, subprocess.CalledProcessError):
            return set()
    inodes = set()
    for name in ("tcp", "tcp6"):
        try:
            for line in (Path("/proc/net") / name).read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] == "0A" and int(fields[1].rsplit(":", 1)[1], 16) == port:
                    inodes.add(fields[9])
        except (OSError, IndexError, ValueError):
            pass
    owners = set()
    if not inodes:
        return owners
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            for fd in (path / "fd").iterdir():
                try:
                    link = os.readlink(fd)
                except OSError:
                    continue
                if link.startswith("socket:[") and link[8:-1] in inodes:
                    owners.add(int(path.name))
                    break
        except OSError:
            pass
    return owners


def octo_owned_inactive(active, profile_id):
    """A malformed active list is not evidence that an owned profile stopped."""
    if not isinstance(active, list) or any(not isinstance(item, dict) or
            not isinstance(item.get("uuid"), str) or not item["uuid"] for item in active):
        raise ProfileError("owned-profile-inactive-unverified")
    return all(item["uuid"] != profile_id for item in active)


def owned_listener_refused(port):
    """Accept only a definite loopback refusal, not timeout/inspection failure."""
    try:
        with socket.create_connection(("127.0.0.1", checked_port(port)), timeout=2):
            return False
    except ConnectionRefusedError:
        return True
    except OSError:
        raise ProfileError("owned-debug-listener-unverified") from None


def root_command(pid):
    """Keep raw command lines in memory only; exe is kernel/OS metadata."""
    if HOST_OS == "linux":
        p = Path("/proc") / str(pid)
        return (Path(os.readlink(p / "exe")).name,
                (p / "cmdline").read_bytes().decode().replace("\0", " "))
    exe = subprocess.check_output(["ps", "-p", str(pid), "-o", "comm="], text=True).strip()
    command = subprocess.check_output(["ps", "-p", str(pid), "-o", "command="], text=True)
    return Path(exe).name, command


def native_mode(port):
    matches = []
    if HOST_OS == "linux":
        commands = []
        for path in Path("/proc").iterdir():
            if not path.name.isdecimal():
                continue
            try:
                commands.append((int(path.name), (path / "cmdline").read_bytes().decode().replace("\0", " ")))
            except (OSError, UnicodeError):
                pass
    else:
        raw = subprocess.check_output(["ps", "-axo", "pid=,command="], text=True)
        commands = [(int(line.strip().split(None, 1)[0]), line.strip().split(None, 1)[1])
                    for line in raw.splitlines() if len(line.strip().split(None, 1)) == 2]
    for pid, command in commands:
        if not re.search(r"--remote-debugging-port(?:=|\s+)" + str(port) + r"(?:\s|$)", command):
            continue
        if re.search(r"(?:^|\s)--type=", command):
            continue
        if not any(name in command.lower() for name in ("chrome", "chromium", "sunbrowser", "anty", "mimic", "octium", "orbita")):
            continue
        matches.append({"headless_flag": bool(re.search(r"(?:^|\s)--headless(?:=\S+)?(?:\s|$)", command))})
    if len(matches) == 1:
        return {"state": "verified", **matches[0]}
    # Some Chromium derivatives rewrite argv or keep a launcher wrapper with
    # the same flags. The kernel-owned listening socket identifies the browser
    # that actually served this CDP port; never borrow another profile's mode.
    socket_matches = []
    for pid in socket_owners(port):
        try:
            exe, command = root_command(pid)
            if not any(name in exe.lower() for name in
                       ("chrome", "chromium", "sunbrowser", "anty", "mimic", "octium", "orbita")):
                continue
            if re.search(r"(?:^|\s)--type=", command):
                continue
            socket_matches.append({"headless_flag": bool(re.search(
                r"(?:^|\s)--headless(?:=\S+)?(?:\s|$)", command))})
        except (OSError, UnicodeError, subprocess.CalledProcessError):
            continue
    return {"state": "verified", "socket_owner_verified": True, **socket_matches[0]} if len(socket_matches) == 1 else {
        "state": "UNKNOWN", "matching_processes": len(matches), "matching_socket_owners": len(socket_matches)}


class OwnedProfile:
    def __init__(self, vendor, profile_os, journal, client_rects_noise=None,
                 octo_webrtc_mode="disable_non_proxied_udp"):
        if client_rects_noise is not None and (vendor != "octo" or type(client_rects_noise) is not bool):
            raise ProfileError("client-rects-variation-contract")
        self.client_rects_noise = client_rects_noise
        if octo_webrtc_mode not in OCTO_WEBRTC_MODES or (vendor != "octo" and
                octo_webrtc_mode != "disable_non_proxied_udp"):
            raise ProfileError("webrtc-variation-contract")
        self.octo_webrtc_mode = octo_webrtc_mode
        self.vendor, self.profile_os, self.journal = vendor, profile_os, journal
        self.root, self.headers = credentials(vendor)
        self.id = None
        self.running = False
        self.start_pending = False
        self.create_pending = False
        self.sdk = None
        self.port = None
        self.startup_audit = None
        self.profile_create_audit = None
        self.adspower_create_audit = None
        self.title = "ADA owned " + uuid4().hex

    def register(self, value):
        if self.id is not None or self.journal.exists():
            raise ProfileError("ownership-journal-conflict")
        self.id = checked_id(value)
        descriptor = os.open(self.journal, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as out:
            json.dump({"owned_created_id": self.id, "vendor": self.vendor,
                       "owned_title": self.title, "cleanup": "pending"}, out)

    def register_reused_dolphin(self, value):
        """Journal the explicitly configured test profile without claiming creation."""
        if self.vendor != "dolphin_anty" or self.id is not None or self.journal.exists():
            raise ProfileError("ownership-journal-conflict")
        self.id, self.saved = checked_id(value), True
        descriptor = os.open(self.journal, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as out:
            json.dump({"owned_reused_id": self.id, "vendor": self.vendor,
                       "ownership_state": "configured-dedicated-test-profile",
                       "delete_permitted": False, "cleanup": "pending"}, out)

    def take_approved_dolphin(self, pool):
        available = dolphin_list_profiles(self.headers)
        status = api("GET", DOLPHIN_LOCAL + "/browser_profiles/running",
                     "approved-dolphin-pool-status", timeout=10)
        # Prefer prior test profiles, then the operator's other allowlisted ones.
        ordered = sorted(pool, key=lambda entry: not entry["name"].startswith(("ADA owned ", "ADA disposable ")))
        for entry in ordered:
            if entry["platform"] != self.profile_os:
                continue
            profile = available.get(entry["id"])
            if (not profile or profile.get("name") != entry["name"] or
                    profile.get("platform") != self.profile_os or profile.get("browserType") != "anty"):
                continue
            if (not dolphin_owned_inactive(status, entry["id"]) or
                    dolphin_saved_browser_present(entry["id"])):
                continue
            self.dolphin_reuse_settings_hash = dolphin_settings_hash(profile)
            self.dolphin_reuse_kind = "operator-approved-pool"
            self.dolphin_selected_profile_id = entry["id"]
            self.register_reused_dolphin(entry["id"])
            return
        # A reuse-only request must not silently create or mutate a profile.
        raise ProfileError("approved-dolphin-pool-no-idle-match")

    def register_reused_adspower(self, value):
        """Journal a profile an earlier run created; it is stopped, never deleted."""
        if self.vendor != "ads_power" or self.id is not None or self.journal.exists():
            raise ProfileError("ownership-journal-conflict")
        self.id, self.saved = checked_id(value), True
        descriptor = os.open(self.journal, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as out:
            json.dump({"owned_reused_id": self.id, "vendor": self.vendor,
                       "ownership_state": "earlier-run-owned-profile",
                       "delete_permitted": False, "cleanup": "pending"}, out)

    def adspower_reports_closed(self):
        """True only when the app itself shows this profile closed; never on doubt."""
        for attempt in range(2):
            time.sleep(1 + attempt)
            try:
                status = api("GET", self.root.split("/api/", 1)[0] + "/api/v1/browser/active?" +
                             urlencode({"user_id": self.id}), "owned-closed-status",
                             headers=self.headers, timeout=20)
                state = status.get("data", {}).get("status") if status.get("code") == 0 else None
            except (ProfileError, AttributeError):
                state = None
            if state == "Inactive":
                return True
            if state == "Active":
                return False
        return False

    def adspower_start_after_refusal(self, hidden, refusal):
        """Return an accepted start answer after a refused one, or raise.

        Nothing more is tried unless the app shows the refused profile closed:
        then nothing was launched and nothing needs stopping. An account limit
        ends it there, because every other profile would be refused as well.
        Otherwise a reused profile is left alone for the rest of this process
        and the default recipe picks its next profile the usual way.
        """
        self.adspower_start_markers = adspower_start_markers(refusal)
        while self.adspower_reports_closed():
            self.start_pending = False
            marks = set(self.adspower_start_markers)
            account_wide = (("limit" in marks and bool(marks & {"daily", "monthly"})) or
                            bool(marks & {"subscription", "authentication"}))
            if account_wide or not getattr(self, "saved", False) or len(ADSPOWER_REFUSED_STARTS) >= 8:
                break
            ADSPOWER_REFUSED_STARTS.add(self.id)
            self.reuse_start_refusals = getattr(self, "reuse_start_refusals", 0) + 1
            self.journal.unlink()
            self.id, self.saved = None, False
            self.create()
            self.start_pending = True
            data = api("POST", self.root + "/start", "start", headers=self.headers, timeout=240,
                       body={"profile_id": self.id, "headless": "1" if hidden else "0",
                             "last_opened_tabs": "0", "proxy_detection": "0"})
            if data.get("code") == 0:
                return data
            self.adspower_start_markers = adspower_start_markers(data)
        raise ProfileError("start-rejected")

    def create_adspower_profile(self, fingerprint):
        """Create one new AdsPower profile named self.title and journal it."""
        self.create_pending = True
        data = api("POST", self.root + "/create", "create", headers=self.headers, body={
            "name": self.title, "group_id": "0", "user_proxy_config": {"proxy_soft": "no_proxy"},
            "fingerprint_config": fingerprint})
        self.adspower_create_audit = adspower_create_evidence(data)
        if not isinstance(data, dict) or type(data.get("code")) is not int:
            # A malformed acknowledgement cannot establish either success
            # or a definite refusal. Keep the unconfirmed-create journal.
            raise ProfileError("create-response-unverified")
        if data.get("code") != 0:
            self.create_pending = False
            raise ProfileError("create-rejected", reason=adspower_business_failure(data))
        self.register(data.get("data", {}).get("profile_id"))

    def take_default_adspower(self, fingerprint):
        """Find or make the profile for the default recipe, creating as rarely as possible.

        1. This host's dedicated default profile, used exactly as it was created.
        2. If the host has none, create it now; it is kept after a clean start.
           A busy or unusable one gets a throw-away profile, as before reuse.
        3. If the account refuses a new profile, an idle leftover of an earlier
           run. Its settings are whatever that run asked for, so the report
           marks the case as not the standard recipe.
        """
        kept_title = adspower_kept_title(self.profile_os)
        found, self.reuse_lookup = adspower_idle_owned_id(self.root, self.headers, kept_title)
        if found is not None:
            self.register_reused_adspower(found)
            self.reuse_kind = "dedicated"
            return
        self.keep_created = self.reuse_lookup == "none-owned"
        if self.keep_created:
            self.title = kept_title
        try:
            time.sleep(1)  # Space the calls out; the lookup has just used the API.
            self.create_adspower_profile(fingerprint)
            self.reuse_kind = "new-dedicated" if self.keep_created else "new"
            return
        except ProfileError as error:
            if error.stage != "create-rejected":
                raise
            refusal = error
        self.keep_created = False
        # A leftover's OS claim is not known, so it may only stand in for the host's own.
        if not ADS_LEFTOVER_FALLBACK or self.profile_os != HOST_OS:
            raise refusal
        time.sleep(1)  # Space the calls out; the refused create has just used the API.
        found, self.reuse_lookup = adspower_idle_owned_id(self.root, self.headers)
        if found is None:
            raise refusal
        self.adspower_create_audit = None  # The leftover replaces the refused new profile.
        self.register_reused_adspower(found)
        self.reuse_kind = "leftover"

    def record_launch(self, mode):
        """Persist recovery coordinates privately, never commands or credentials."""
        if self.id is None or self.journal.is_symlink() or not self.journal.is_file():
            raise ProfileError("launch-journal-unverified")
        record = json.loads(self.journal.read_text())
        if (record.get("vendor") != self.vendor or
                record.get("owned_created_id", record.get("owned_reused_id")) != self.id):
            raise ProfileError("launch-journal-unverified")
        record.update({"owned_debug_port": checked_port(self.port),
                       "expected_headless": mode == "headless",
                       "launch_recorded_utc": datetime.now(timezone.utc).isoformat(),
                       "listener_owner_pids": sorted(socket_owners(self.port))})
        with tempfile.NamedTemporaryFile(mode="w", dir=self.journal.parent, delete=False) as out:
            os.chmod(out.name, 0o600)
            json.dump(record, out)
            temporary = out.name
        os.replace(temporary, self.journal)

    def preserve_unconfirmed(self, operation):
        if self.journal.exists():
            return
        descriptor = os.open(self.journal, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as out:
            json.dump({"owned_created_id": None, "vendor": self.vendor,
                       "owned_title": self.title, "cleanup": "UNKNOWN",
                       "ownership_state": "unconfirmed-" + operation}, out)

    def create(self):
        try:
            self._create()
            self.create_pending = False
        except (ProfileError, KeyError, ValueError, TypeError, AttributeError, OSError) as error:
            if self.create_pending and self.id is None:
                if (getattr(error, "http", None) in {401, 403, 422, 429} or
                        getattr(error, "reason", None) == "app-not-listening"):
                    self.create_pending = False
                else:
                    self.preserve_unconfirmed("create")
            raise

    def _create(self):
        if self.vendor in {"octo", "multilogin"}:
            return  # One-time/quick creation is part of start().
        if self.vendor == "ads_power":
            ua_os = {"windows": "Windows 11", "linux": "Linux", "macos": "Mac OS X 13"}[self.profile_os]
            fingerprint = {"automatic_timezone": "1", "random_ua": {
                "ua_browser": ["chrome"], "ua_system_version": [ua_os]}}
            if ADS_WEBRTC is None and ADS_SCREEN is None and self.profile_os in (HOST_OS, "windows"):
                # The account allows only so many new profiles a day, so the default
                # recipe keeps one profile per host and reuses it. Settings rows
                # still create their own, so their recipe is never in doubt.
                self.take_default_adspower(fingerprint)
                return
            if ADS_WEBRTC is not None:
                fingerprint["webrtc"] = ADS_WEBRTC
            if ADS_SCREEN is not None:
                fingerprint["screen_resolution"] = ADS_SCREEN
            self.create_adspower_profile(fingerprint)
        elif self.vendor == "dolphin_anty":
            self.profile_create_audit = {"template_attempts": 0, "definite_hardware_refusals": 0,
                                         "masking_changed": False}
            pool = dolphin_reuse_pool()
            if pool is not None:
                self.take_approved_dolphin(pool)
                return
            saved = dolphin_saved_id()
            self.reused_profile_skipped_busy = False
            if saved is not None and self.profile_os == HOST_OS:
                status = api("GET", DOLPHIN_LOCAL + "/browser_profiles/running",
                             "reuse-test-profile-status", timeout=5)
                self.reused_profile_skipped_busy = (not dolphin_owned_inactive(status, saved) or
                                                   dolphin_saved_browser_present(saved))
            if saved is not None and self.profile_os == HOST_OS and not self.reused_profile_skipped_busy:
                # The app can refuse to start a brand-new profile while its cloud
                # sync has nothing to fetch. Reuse this host's dedicated test profile.
                self.register_reused_dolphin(saved)
                return
            for attempt in range(3):
                configured = dolphin_profile_template(self.profile_os, self.headers)
                self.profile_create_audit["template_attempts"] += 1
                self.create_pending = True
                try:
                    data = api("POST", DOLPHIN_CLOUD + "/browser_profiles", "create", headers=self.headers,
                               accepted=(200, 201), body={
                        "name": self.title, "platform": self.profile_os, "browserType": "anty", "mainWebsite": "",
                        **configured,
                        "webrtc": {"mode": "altered", "ipAddress": None}, "canvas": {"mode": "real"},
                        "webgl": {"mode": "real"},
                        "timezone": {"mode": "auto", "value": None}, "locale": {"mode": "auto", "value": None},
                        "screen": {"mode": None, "resolution": None}, "doNotTrack": False})
                    break
                except ProfileError as error:
                    # A definite documented rejection created no profile. Never
                    # replay an ambiguous POST, disable masking or reuse an ID.
                    if error.http != 422 or error.reason != "dolphin-hardware-incompatible":
                        raise
                    self.create_pending = False
                    self.profile_create_audit["definite_hardware_refusals"] += 1
                    if attempt == 2:
                        raise
            if data.get("success") is False:
                self.create_pending = False
                raise ProfileError("create-rejected")
            self.register((data.get("data") or data).get("id"))
        else:
            claim = {"windows": "win", "linux": "lin", "macos": "mac"}[self.profile_os]
            self.create_pending = True
            data = api("POST", "https://api.gologin.com/browser/custom", "create", headers=self.headers,
                       accepted=(200, 201), body={"name": self.title, "os": claim,
                       **({"osSpec": "win11"} if claim == "win" else {}), "createProxy": False})
            self.register(data.get("id"))

    def start(self, mode):
        if mode not in {"headed", "headless"}:
            raise ProfileError("mode-contract")
        if self.vendor not in {"multilogin", "octo"} and self.id is None:
            raise ProfileError("unowned-start")
        if self.running or self.start_pending:
            raise ProfileError("already-owned-running-or-unconfirmed")
        self.start_pending = True
        try:
            self.port = self._start(mode)
            self.record_launch(mode)
            return self.port
        except (ProfileError, KeyError, ValueError, TypeError, AttributeError, OSError) as error:
            # An explicit authentication/validation/rate refusal is not an
            # ambiguous launch. Never infer the same from a timeout or 5xx.
            refused = (getattr(error, "http", None) in {401, 403, 422, 429} or
                       getattr(error, "reason", None) == "app-not-listening")
            if self.vendor in {"multilogin", "octo"} and self.id is None:
                if refused:
                    self.start_pending = False
                else:
                    self.preserve_unconfirmed("start")
            elif self.vendor == "gologin" and self.sdk is None:
                self.start_pending = False  # No child launcher was spawned.
            raise

    def _start(self, mode):
        if mode not in {"headed", "headless"}:
            raise ProfileError("mode-contract")
        if self.vendor not in {"multilogin", "octo"} and self.id is None:
            raise ProfileError("unowned-start")
        hidden = mode == "headless"
        if self.running:
            raise ProfileError("already-owned-running")
        if self.vendor == "ads_power":
            data = api("POST", self.root + "/start", "start", headers=self.headers, timeout=240,
                       body={"profile_id": self.id, "headless": "1" if hidden else "0",
                             "last_opened_tabs": "0", "proxy_detection": "0"})
            if data.get("code") != 0:
                data = self.adspower_start_after_refusal(hidden, data)
            self.running = True
            self.started_once = True
            return checked_port(data.get("data", {}).get("debug_port"))
        if self.vendor == "dolphin_anty":
            # Token only enters the local app, not CLI args/page code/artifacts.
            token = self.headers["Authorization"][7:]
            login = api("POST", DOLPHIN_LOCAL + "/auth/login-with-token", "local-auth", body={"token": token})
            if login.get("success") is not True:
                raise ProfileError("local-auth-rejected")
            data = None
            for attempt in range(3):
                try:
                    data = api("GET", f"{DOLPHIN_LOCAL}/browser_profiles/{self.id}/start?automation=1&headless={int(hidden)}",
                               "start", timeout=240)
                    break
                except ProfileError as error:
                    # The local app can answer 500 for a profile created moments
                    # ago. Retry only that answer, at most twice, and only after
                    # both the app's map and OS metadata show this owned profile
                    # is idle. A stale running map alone cannot justify a replay.
                    if error.http != 500 or attempt == 2:
                        raise
                    status = api("GET", DOLPHIN_LOCAL + "/browser_profiles/running",
                                 "start-retry-status", timeout=5)
                    if (not dolphin_owned_inactive(status, self.id) or
                            dolphin_saved_browser_present(self.id)):
                        raise
                    time.sleep(8)
            if data.get("success") is not True:
                raise ProfileError("start-rejected")
            self.running = True
            return checked_port(data.get("automation", {}).get("port"))
        if self.vendor == "multilogin":
            payload = {"browser_type": "mimic", "os_type": self.profile_os,
                       "automation": "playwright", "is_headless": hidden,
                       "parameters": {"flags": {
                           "navigator_masking": "mask", "audio_masking": "mask", "localization_masking": "mask",
                           "geolocation_popup": "prompt", "geolocation_masking": "mask", "timezone_masking": "mask",
                           "canvas_noise": "natural", "graphics_noise": "natural", "graphics_masking": "mask",
                           "webrtc_masking": "natural", "fonts_masking": "mask", "media_devices_masking": "mask",
                           "screen_masking": "mask", "proxy_masking": "custom", "ports_masking": "mask"}}}
            try:
                data = api("POST", ML_LOCAL + "/v3/profile/quick", "quick-start", headers=self.headers, body=payload, timeout=240)
            except ProfileError as error:
                # A definite 401 cannot have launched this authenticated profile.
                # Do not retry network timeouts/ambiguous start responses.
                if error.http != 401 or self.headers["Authorization"].startswith("Bearer "):
                    raise
                self.headers = {**self.headers, "Authorization": "Bearer " + self.headers["Authorization"]}
                data = api("POST", ML_LOCAL + "/v3/profile/quick", "quick-start-bearer", headers=self.headers, body=payload, timeout=240)
            if (data.get("status") or {}).get("http_code") != 200:
                raise ProfileError("quick-start-rejected")
            self.register((data.get("data") or {}).get("id"))
            self.running = True
            return checked_port(data["data"].get("port"))
        if self.vendor == "octo":
            claim = "win" if self.profile_os == "windows" else "mac"
            body = {
                "profile_data": {"fingerprint": {"os": claim, "screen": OCTO_SCREEN,
                    "languages": {"type": "manual", "data": ["en-US", "en"]},
                    "timezone": {"type": "manual", "data": "America/New_York"},
                    **({} if self.octo_webrtc_mode == "default" else {"webrtc": {"type": self.octo_webrtc_mode}}),
                    "cpu": 4, "ram": 8},
                    "proxy": None, "start_pages": ["about:blank"]},
                "headless": hidden, "debug_port": True, "only_local": True, "timeout": 180, "flags": []}
            if OCTO_MINIMAL:
                # Only the OS claim: screen, languages, time zone, CPU, RAM and
                # WebRTC are whatever Octo itself gives a new profile.
                body["profile_data"]["fingerprint"] = {"os": claim}
            if OCTO_NOISE is not None:
                body["profile_data"]["fingerprint"]["noise"] = {
                    name: OCTO_NOISE for name in ("webgl", "canvas", "audio", "client_rects")}
            if self.client_rects_noise is not None:
                body["profile_data"]["fingerprint"]["noise"] = {"client_rects": self.client_rects_noise}
            try:
                data = api("POST", LOCAL_OCTO + "/one_time/start", "one-time-start", timeout=240, body=body)
            except ProfileError as error:
                # Exactly one retry only after a definitive rate refusal. No
                # Octo calls while waiting, and never retry an ambiguous launch.
                if error.http != 429 or error.retry_after is None or error.retry_after > 120:
                    raise
                delay = max(error.retry_after, 1) + 2
                print(json.dumps({"vendor": "octo", "rate_limit_wait_seconds": delay}), flush=True)
                while delay > 0:
                    interval = min(delay, 30)
                    time.sleep(interval)
                    delay -= interval
                data = api("POST", LOCAL_OCTO + "/one_time/start", "one-time-start-after-backoff", timeout=240, body=body)
            if data.get("state") != "STARTED":
                raise ProfileError("one-time-start-contract")
            self.register(data.get("uuid"))
            self.running = True
            return octo_debug_port(data)
        return self.start_gologin(mode)

    def start_gologin(self, mode):
        self.startup_audit = None
        if HOST_OS == "linux":
            command = [node_path(), str(ROOT / "scripts/owned_gologin_session.mjs")]
            if mode == "headed" and not os.environ.get("DISPLAY"):
                # The Node SDK spawns a GUI browser itself, unlike vendors
                # whose already-running desktop app supplies its display.
                wrapper = shutil.which("xvfb-run")
                if not wrapper:
                    raise ProfileError("gologin-headed-display-unavailable")
                command = [wrapper, "-a", *command]
        else:
            python = Path.home() / ".ada-gologin-sdk/bin/python"
            if not python.is_file():
                raise ProfileError("gologin-python-sdk-unavailable")
            command = [str(python), str(ROOT / "scripts/owned_gologin_session.py")]
        launch_request = {"owned_profile_id": self.id, "mode": mode}
        if HOST_OS == 'macos':
            ownership = json.loads(self.journal.read_text())
            if (ownership.get('vendor') != 'gologin' or
                    ownership.get('owned_created_id') != self.id or
                    'owned_reused_id' in ownership):
                raise ProfileError('disposable-session-ownership-unverified')
            launch_request['discard_test_profile'] = True
        if getattr(self, "diagnostic_netlog_path", None) is not None:
            if HOST_OS != "macos":
                raise ProfileError("private-trace-host-contract")
            launch_request["private_netlog_path"] = str(self.diagnostic_netlog_path)
        self.sdk = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    env={**os.environ, "DISABLE_TELEMETRY": "true"})
        self.sdk.stdin.write(json.dumps(launch_request) + "\n")
        self.sdk.stdin.flush()
        deadline = time.monotonic() + 240
        pending = b""
        while time.monotonic() < deadline:
            readable, _, _ = select.select([self.sdk.stdout], [], [], 0.5)
            if not readable:
                continue
            chunk = os.read(self.sdk.stdout.fileno(), 4096)
            if not chunk and self.sdk.poll() is not None:
                raise ProfileError("gologin-sdk-start-failed")
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                if line.startswith(b"ADA_OWNED_SESSION="):
                    info = json.loads(line.partition(b"=")[2])
                    if "startup" in info:
                        self.startup_audit = sanitize_gologin_startup(info["startup"])
                    if "port" not in info:
                        allowed = {"debugger-address-invalid", "owned-child-unverified", "debug-listener-not-owned",
                                   "browser-exited-before-readiness", "debugger-not-ready", "debugger-port-mismatch",
                                   "listener-audit-unavailable", "sdk-start-exception", "multiple-owned-browser-spawns",
                                   "installed-browser-version-unverified", "secured-config-contract-invalid",
                                   "secured-profile-config-missing"}
                        reason = info.get("reason")
                        self.startup_audit = sanitize_gologin_startup(info.get("startup"))
                        raise ProfileError("gologin-sdk-start-failed", reason=reason if reason in allowed else "UNKNOWN")
                    if HOST_OS == "macos" and info.get("ready") is not True:
                        raise ProfileError("gologin-sdk-start-failed", reason="debugger-not-ready")
                    self.running = True
                    return checked_port(info["port"])
            if len(pending) > 65536:
                pending = b""  # SDK chatter is never logged/exported.
        raise ProfileError("gologin-sdk-start-timeout")

    def stop(self):
        if not self.running and self.sdk is None and not self.start_pending:
            return {"cleanup_confirmed": True}
        if self.id is None:
            # No known owned ID: do not stop an arbitrary active profile, and
            # retain the private journal so the dispatcher pauses creation.
            raise ProfileError("unconfirmed-start-cleanup", reason="UNKNOWN")
        if self.vendor == "ads_power":
            data = api("POST", self.root + "/stop", "stop", headers=self.headers, body={"profile_id": self.id})
            # The app refuses to stop a profile that is not open. Accept that only
            # when it shows the profile closed; the debug-port check still follows.
            if data.get("code") != 0 and not self.adspower_reports_closed():
                raise ProfileError("stop-rejected")
            if self.port is None:
                # Failed starts may have launched without returning a port.
                # An accepted stop is insufficient without an inactive status.
                status = api("GET", self.root.split("/api/", 1)[0] + "/api/v1/browser/active?" +
                             urlencode({"user_id": self.id}), "cleanup-owned-status", headers=self.headers)
                if status.get("code") != 0 or status.get("data", {}).get("status") != "Inactive":
                    raise ProfileError("owned-profile-inactive-unverified")
        elif self.vendor == "dolphin_anty":
            data = api("GET", f"{DOLPHIN_LOCAL}/browser_profiles/{self.id}/stop", "stop")
            if data.get("success") is False:
                raise ProfileError("stop-rejected")
            wait_dolphin_owned_inactive(self.id)
            if self.port is None and dolphin_saved_browser_present(self.id):
                # An ambiguous start may have spawned a browser without
                # returning a CDP port. Do not delete its profile merely
                # because the app no longer lists it as running.
                raise ProfileError("owned-profile-native-exit-unverified")
            if getattr(self, "dolphin_reuse_kind", None) == "operator-approved-pool":
                profile = dolphin_list_profiles(self.headers).get(self.id)
                if not profile or dolphin_settings_hash(profile) != self.dolphin_reuse_settings_hash:
                    raise ProfileError("reused-dolphin-settings-changed")
        elif self.vendor == "multilogin":
            api("GET", f"{ML_LOCAL}/v1/profile/stop/p/{self.id}", "stop", headers=self.headers)
        elif self.vendor == "octo":
            redundant_stop = False
            try:
                api("POST", LOCAL_OCTO + "/stop", "stop", body={"uuid": self.id})
            except ProfileError as error:
                # Closing the owned last tab can already stop a one-time
                # profile. A 400 alone proves nothing: require both inactive
                # status and independently closed known debug transport.
                if error.http != 400 or self.port is None:
                    raise
                redundant_stop = True
            active = api("GET", LOCAL_OCTO + "/active", "cleanup-active")
            if not octo_owned_inactive(active, self.id):
                raise ProfileError("owned-profile-still-active")
            if redundant_stop and (socket_owners(self.port) or
                                   not owned_listener_refused(self.port)):
                raise ProfileError("owned-debug-listener-still-active")
        else:
            try:
                self.sdk.stdin.write("STOP\n")
                self.sdk.stdin.flush()
            except BrokenPipeError:
                pass
            try:
                output, _ = self.sdk.communicate(timeout=90)
            except subprocess.TimeoutExpired:
                # Stop only the helper we own, never kill a global browser class.
                self.sdk.terminate()
                raise ProfileError("gologin-sdk-cleanup-timeout") from None
            if self.sdk.returncode or "ADA_OWNED_STOPPED" not in output:
                raise ProfileError("gologin-sdk-cleanup-unverified")
            self.sdk = None
        self.running = False
        if self.port is not None:
            # An app's running map can clear before its browser exits. Require
            # both OS socket absence and a definite loopback refusal. Retain
            # the recovery journal on any unknown result; never force-kill.
            attempts = 150 if self.vendor == "dolphin_anty" else 50
            for _ in range(attempts):
                if not socket_owners(self.port) and owned_listener_refused(self.port):
                    break
                time.sleep(0.2)
            else:
                raise ProfileError("owned-debug-listener-still-active")
            self.port = None
        self.start_pending = False
        if self.vendor in {"multilogin", "octo"}:
            self.journal.unlink()
            self.id = None
        return {"cleanup_confirmed": True}

    def delete_created(self):
        if self.id is None:
            if self.create_pending:
                raise ProfileError("unconfirmed-create-cleanup", reason="UNKNOWN")
            return
        if self.running or self.sdk is not None or self.start_pending:
            self.stop()
        if getattr(self, "saved", False):
            self.journal.unlink()
            self.id = None  # A reused test profile is stopped, never deleted.
            return
        if self.vendor == "ads_power":
            if getattr(self, "keep_created", False) and getattr(self, "started_once", False):
                self.journal.unlink()
                self.id = None  # This host's dedicated default profile stays for the next case.
                return
            data = api("POST", self.root + "/delete", "delete-owned", headers=self.headers,
                       body={"profile_id": [self.id]})
            if data.get("code") != 0:
                raise ProfileError("delete-owned-rejected")
        elif self.vendor == "dolphin_anty":
            data = api("DELETE", f"{DOLPHIN_CLOUD}/browser_profiles/{self.id}", "delete-owned",
                       headers=self.headers, accepted=(200, 204))  # Default soft delete, no forceDelete.
            if data.get("success") is False:
                raise ProfileError("delete-owned-rejected")
        elif self.vendor == "gologin":
            api("DELETE", f"https://api.gologin.com/browser/{self.id}", "delete-owned",
                headers=self.headers, accepted=(200, 204))
        else:
            raise ProfileError("quick-profile-cleanup-unverified")
        self.journal.unlink()
        self.id = None


def node_path():
    # The observer uses the global WebSocket constructor. Ubuntu's Node 18
    # does not have it; prefer a newer binary when one is installed.
    candidates = []
    found = shutil.which("node")
    if found:
        candidates.append(found)
    for p in ("/opt/homebrew/bin/node", "/usr/local/bin/node"):
        if Path(p).is_file():
            candidates.append(p)
    nvm = Path.home() / ".nvm/versions/node"
    if nvm.is_dir():
        candidates.extend(str(path) for path in sorted(nvm.glob("v*/bin/node")))
    seen = []
    for candidate in candidates:
        if candidate not in seen:
            seen.append(candidate)
    for candidate in seen:
        try:
            probe = subprocess.run([candidate, "-e", "process.exit(typeof WebSocket==='function'?0:1)"],
                                    capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    if seen:
        return seen[0]
    raise ProfileError("node-unavailable")


def usable(row, manifest, preload):
    result, audit = row.get("result", {}), row.get("launch_audit", {})
    verdict = result.get("verdict", {})
    return (row.get("detector_sha256") == manifest and row.get("cleanup_confirmed") is True and
            audit.get("state") == "verified" and audit.get("headless_flag") is (row["mode"] == "headless") and
            result.get("pageTitle") == "Example Domain" and result.get("documentReadyState") == "complete" and
            result.get("testSetup") == {"preload": "challenge", "preloadSha256": preload} and
            set(verdict) == set(NAMES) and all(type(v) is bool for v in verdict.values()))


def print_outcome(row):
    """Experimental counts cannot turn an UNKNOWN or wrong-mode launch into a pass."""
    result = {"print_complete": False, "print_mode_correct": False}
    payload, audit = row.get("result"), row.get("launch_audit")
    if not isinstance(payload, dict) or not isinstance(audit, dict):
        return result
    value, mode = payload.get("ownedPrint"), row.get("mode")
    if not isinstance(value, dict) or mode not in ("headed", "headless"):
        return result
    fields = ("ready", "before", "after", "returned", "pong", "threw", "frameRemoved", "urlRestored", "historyUnchanged")
    if (row.get("usable") is not True or row.get("cleanup_confirmed") is not True or
            audit.get("state") != "verified" or audit.get("headless_flag") is not (mode == "headless") or
            value.get("state") != "complete" or any(type(value.get(key)) is not bool for key in fields) or
            not all(value[key] for key in ("ready", "frameRemoved", "urlRestored", "historyUnchanged")) or
            type(value.get("hypothesis")) is not bool):
        return result
    expected_hypothesis = value["returned"] and value["pong"] and not value["after"] and value["before"] and not value["threw"]
    if value["hypothesis"] is not expected_hypothesis:
        return result
    if not value["before"] or not value["returned"] or value["threw"] or not (value["after"] or value["pong"]):
        return result
    return {"print_complete": True, "print_mode_correct": value["hypothesis"] is (mode == "headless")}


def main():
    global ML_TOKEN_STORE, ADS_WEBRTC, ADS_SCREEN, OCTO_SCREEN, ADS_LEFTOVER_FALLBACK, OCTO_MINIMAL, OCTO_NOISE
    ADS_LEFTOVER_FALLBACK = False  # Each row here states its OS claim; a leftover may carry another.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor", choices=tuple(OS_CLAIMS), required=True)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile-os", nargs="+", choices=("windows", "linux", "macos"))
    parser.add_argument("--multilogin-token-store", choices=("auto", "runner"), default="auto")
    parser.add_argument("--create-owned-profiles", action="store_true")
    parser.add_argument("--activated-popup-diagnostic", action="store_true")
    parser.add_argument("--print-mode-diagnostic", action="store_true")
    parser.add_argument("--product-artifact-diagnostic", action="store_true")
    parser.add_argument("--geometry-contract-diagnostic", action="store_true",
                        help="Owned geometry serialization and opaque-value API contract study")
    parser.add_argument("--octo-bridge-diagnostic", action="store_true",
                        help="Descriptor-only native Octo bridge leads; not a classifier")
    parser.add_argument("--octo-client-rects-noise", choices=("default", "on", "off"), default="default")
    parser.add_argument("--adspower-webrtc-mode", choices=("default", "disabled", "proxy", "local", "forward"), default="default")
    parser.add_argument("--adspower-screen", help="width_height for new owned AdsPower profiles")
    parser.add_argument("--octo-screen", help="WIDTHxHEIGHT for new owned Octo profiles")
    parser.add_argument("--octo-minimal", action="store_true",
                        help="New owned Octo profiles carry only the OS claim; all else Octo defaults")
    parser.add_argument("--octo-noise", choices=("default", "on", "off"), default="default",
                        help="New owned Octo profiles: set all four noise switches on or off together")
    parser.add_argument("--octo-webrtc-mode", choices=OCTO_WEBRTC_MODES,
                        default="disable_non_proxied_udp",
                        help="New owned Octo profiles only; 'default' omits fingerprint.webrtc")
    parser.add_argument("--candidate-branch-diagnostic", action="store_true")
    parser.add_argument("--valid-api-diagnostic", action="store_true",
                        help="Fixed-input valid API contracts and Octo tracing in owned sessions")
    parser.add_argument("--sdp-contract-diagnostic", action="store_true",
                        help="Fixed synthetic remote-description lifecycle study in owned sessions")
    parser.add_argument("--joint-contract-diagnostic", action="store_true",
                        help="Three fixed-input API families measured after verdicts; not a classifier")
    parser.add_argument("--extended-contract-diagnostic", action="store_true",
                        help="Four further fixed-input API families; not a classifier")
    args = parser.parse_args()
    if not args.create_owned_profiles or not 1 <= args.repeats <= 3:
        parser.error("Explicit owned creation required; repeats must be 1–3")
    if args.octo_client_rects_noise != "default" and args.vendor != "octo":
        parser.error("Client Rects variation applies only to owned Octo profiles")
    if args.octo_webrtc_mode != "disable_non_proxied_udp" and args.vendor != "octo":
        parser.error("WebRTC variation applies only to owned Octo profiles")
    claims = tuple(dict.fromkeys(args.profile_os or OS_CLAIMS[args.vendor]))
    if not set(claims).issubset(OS_CLAIMS[args.vendor]):
        parser.error("Selected OS claim is not supported by this vendor recipe")
    ML_TOKEN_STORE = args.multilogin_token_store
    ADS_WEBRTC = None if args.adspower_webrtc_mode == "default" else args.adspower_webrtc_mode
    if args.adspower_screen is not None:
        if args.vendor != "ads_power" or not re.fullmatch(r"\d{3,4}_\d{3,4}", args.adspower_screen):
            parser.error("AdsPower screen must be width_height on an AdsPower run")
        ADS_SCREEN = args.adspower_screen
    if args.octo_screen is not None:
        if args.vendor != "octo" or not re.fullmatch(r"\d{3,4}x\d{3,4}", args.octo_screen):
            parser.error("Octo screen must be WIDTHxHEIGHT on an Octo run")
        OCTO_SCREEN = args.octo_screen
    if args.octo_minimal:
        if args.vendor != "octo" or args.octo_webrtc_mode != "default" or args.octo_screen is not None:
            parser.error("--octo-minimal needs an Octo run with --octo-webrtc-mode default and no --octo-screen")
        OCTO_MINIMAL = True
    if args.octo_noise != "default":
        if args.vendor != "octo":
            parser.error("--octo-noise applies only to an Octo run")
        OCTO_NOISE = args.octo_noise == "on"
    node = node_path()
    directory = ROOT / "src/ada_challenge/challenge/templates/static/detections"
    manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.glob("*.js"))}
    if set(manifest) != {n + ".js" for n in NAMES}:
        raise ProfileError("candidate-roster")
    preload = hashlib.sha256((ROOT / "src/ada_challenge/challenge/templates/static/js/user-agent-spoof.js").read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    total, usable_count, mode_count, product_count = 0, 0, 0, 0
    blocked = False
    last_octo_start = None
    with args.output.open("x", encoding="utf-8") as output:
        os.chmod(args.output, 0o600)
        for profile_os in claims:
            for repeat in range(1, args.repeats + 1):
                owner = OwnedProfile(args.vendor, profile_os,
                    args.output.with_name(f"{args.output.name}.{profile_os}.{repeat}.private-owner.json"),
                    client_rects_noise=None if args.octo_client_rects_noise == "default" else args.octo_client_rects_noise == "on",
                    octo_webrtc_mode=args.octo_webrtc_mode)
                try:
                    owner.create()
                    modes = ("headed", "headless") if repeat % 2 else ("headless", "headed")
                    for mode in modes:
                        row = {"observed_at": datetime.now(timezone.utc).isoformat(), "vendor": args.vendor,
                               "host_os": HOST_OS, "profile_os": profile_os, "repeat": repeat, "mode": mode,
                               "profile_route": "quick" if args.vendor == "multilogin" else
                               "one-time" if args.vendor == "octo" else "new-owned-saved",
                               "detector_sha256": manifest, "submission_ready": False}
                        if getattr(owner, "saved", False):
                            row["profile_reused"] = True
                            row["profile_reuse_kind"] = getattr(owner, "reuse_kind", None)
                        if args.vendor == "octo":
                            row["requested_client_rects_noise"] = args.octo_client_rects_noise
                            row["requested_webrtc_mode"] = args.octo_webrtc_mode
                            row["requested_octo_noise"] = args.octo_noise
                        port = None
                        try:
                            if args.vendor == "octo":
                                # Base plan: 50 points/minute; one-time start
                                # costs 4 and stop costs 1, team-wide. Keep a
                                # margin, even when the next host starts a job.
                                if last_octo_start is not None:
                                    delay = 8 - (time.monotonic() - last_octo_start)
                                    if delay > 0:
                                        time.sleep(delay)
                                last_octo_start = time.monotonic()
                            port = owner.start(mode)
                            owner.port = port
                            env = {**os.environ, "ADA_CDP_PORT": str(port), "ADA_PROBE_URL": "https://example.com/",
                                   "ADA_EXPECT_TITLE": "Example Domain", "ADA_PROBE_PRELOAD": "challenge"}
                            if args.activated_popup_diagnostic:
                                env.update(ADA_OWNED_ACTIVATED_POPUP="1", ADA_OWNED_TEST_SESSION="1")
                            if args.print_mode_diagnostic:
                                env.update(ADA_OWNED_PRINT_DIAGNOSTIC="1", ADA_OWNED_TEST_SESSION="1")
                            if args.product_artifact_diagnostic:
                                env.update(ADA_PRODUCT_ARTIFACT_DIAGNOSTIC="1", ADA_OWNED_TEST_SESSION="1")
                            if args.geometry_contract_diagnostic:
                                env.update(ADA_GEOMETRY_CONTRACT_DIAGNOSTIC="1", ADA_OWNED_TEST_SESSION="1")
                            if args.octo_bridge_diagnostic:
                                env.update(ADA_OCTO_BRIDGE_DIAGNOSTIC="1", ADA_OWNED_TEST_SESSION="1")
                            if args.candidate_branch_diagnostic:
                                env.update(ADA_CANDIDATE_BRANCH_DIAGNOSTIC="1", ADA_OWNED_TEST_SESSION="1")
                            if args.valid_api_diagnostic:
                                env.update(ADA_VALID_API_DIAGNOSTIC="1", ADA_OWNED_TEST_SESSION="1")
                            if args.sdp_contract_diagnostic:
                                env.update(ADA_SDP_CONTRACT_DIAGNOSTIC="1", ADA_OWNED_TEST_SESSION="1")
                            if args.joint_contract_diagnostic:
                                env.update(ADA_JOINT_CONTRACT_DIAGNOSTIC="1", ADA_OWNED_TEST_SESSION="1")
                            if args.extended_contract_diagnostic:
                                env.update(ADA_EXTENDED_CONTRACT_DIAGNOSTIC="1", ADA_OWNED_TEST_SESSION="1")
                            row["result"] = run_page_probe(
                                [node, str(ROOT / "scripts/probe_real_browser.mjs")], env)
                            # Some vendor APIs return before the browser root is
                            # discoverable. CDP/page readiness is the boundary,
                            # not the HTTP start response. No expected mode is
                            # used to manufacture this independent flag audit.
                            row["launch_audit"] = native_mode(port)
                            if owner.startup_audit is not None:
                                row["startup_audit"] = owner.startup_audit
                        except (ProfileError, KeyError, ValueError, TypeError, AttributeError, OSError, subprocess.TimeoutExpired) as error:
                            row["failure"] = {"stage": getattr(error, "stage", "probe"),
                                              "http": getattr(error, "http", None),
                                              "reason": getattr(error, "reason", "UNKNOWN")}
                            if owner.startup_audit is not None:
                                row["startup_audit"] = owner.startup_audit
                        finally:
                            # Failure evidence is independent of the expected
                            # mode and is collected before this owned stop.
                            preserve_native_audit(row, port)
                            try:
                                row.update(owner.stop())
                            except (ProfileError, OSError) as error:
                                row["cleanup_confirmed"] = False
                                row["cleanup_failure"] = {"stage": getattr(error, "stage", "cleanup"),
                                                          "http": getattr(error, "http", None),
                                                          "reason": getattr(error, "reason", "UNKNOWN")}
                        row["usable"] = usable(row, manifest, preload)
                        verdict = row.get("result", {}).get("verdict", {})
                        row["mode_correct"] = row["usable"] and verdict.get("headless") is (mode == "headless")
                        row["product_correct"] = row["usable"] and [n for n in NAMES if n != "headless" and verdict.get(n) is True] == [args.vendor]
                        total += 1
                        usable_count += int(row["usable"])
                        mode_count += int(row["mode_correct"])
                        product_count += int(row["product_correct"])
                        output.write(json.dumps(row) + "\n"); output.flush()
                        print(json.dumps({k: row[k] for k in ("vendor", "host_os", "profile_os", "repeat", "mode", "usable", "mode_correct", "product_correct")} |
                                         {"failure": row.get("failure")}), flush=True)
                        if row.get("failure") or row.get("cleanup_failure"):
                            raise ProfileError("unusable-case")
                except (ProfileError, KeyError, OSError) as error:
                    failure = {"vendor_blocked": args.vendor, "host_os": HOST_OS, "profile_os": profile_os,
                               "repeat": repeat, "stage": getattr(error, "stage", "configuration"),
                               "http": getattr(error, "http", None), "reason": getattr(error, "reason", "UNKNOWN")}
                    output.write(json.dumps(failure) + "\n"); output.flush()
                    print(json.dumps(failure), flush=True)
                    blocked = True
                finally:
                    owner.delete_created()
                if blocked:
                    break
            if blocked:
                break
        unchanged = manifest == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.glob("*.js"))}
        summary = {"vendor": args.vendor, "host_os": HOST_OS, "planned": len(claims) * 2 * args.repeats,
                   "observed": total, "usable": usable_count, "mode_correct": mode_count,
                   "product_correct": product_count, "blocked": blocked, "sources_unchanged": unchanged,
                   "submission_ready": False}
        output.write(json.dumps({"summary": summary}) + "\n")
        print(json.dumps(summary), flush=True)
    return 1 if blocked or not unchanged else 0 if mode_count == total and product_count == total else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ProfileError as error:
        print(json.dumps({"fatal_stage": error.stage, "http": error.http, "reason": error.reason,
                          "submission_ready": False}), flush=True)
        sys.exit(1)

# Candidate-test capacity policy: reuse existing dedicated AdsPower/Dolphin
# profiles only. This alters launch allocation, never submitted JS or grading.
_original_api_for_capacity_policy = api
def api(method, url, stage, **options):
    if method == "POST" and url == DOLPHIN_CLOUD + "/browser_profiles":
        raise ProfileError(stage, http=403, reason="reuse-only-capacity-preserved")
    return _original_api_for_capacity_policy(method, url, stage, **options)
def _reuse_only_adspower_create(self, fingerprint):
    raise ProfileError("reuse-only-profile-unavailable", http=403,
                       reason="reuse-only-capacity-preserved")
OwnedProfile.create_adspower_profile = _reuse_only_adspower_create
