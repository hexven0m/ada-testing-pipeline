#!/usr/bin/env python3
"""Visit one scheduled ADA page using an owned test vendor profile.

This is a runner adapter, not a scorer and never a human-verification tool.
Native launch flags stay outside page JavaScript. Only new profiles, an idle,
host-configured dedicated Dolphin test profile, or an idle AdsPower profile an
earlier run created are selected; reused profiles are never deleted and all
other existing profiles are left untouched.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from urllib.parse import parse_qsl, urlsplit

if __package__:
    from . import run_owned_vendor_profiles as profiles
else:
    import run_owned_vendor_profiles as profiles

ROOT = Path(__file__).resolve().parents[1]
PRODUCTS = tuple(name for name in profiles.NAMES if name != "headless")


def failure_evidence(error, fallback):
    """Keep diagnostic categories, never exception text or remote values."""
    stage = getattr(error, "stage", fallback)
    if not isinstance(stage, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,95}", stage):
        stage = fallback
    status = getattr(error, "http", None)
    delay = getattr(error, "retry_after", None)
    reason = getattr(error, "reason", "UNKNOWN")
    allowed = {"UNKNOWN", "response-limit", "authorization-refused", "access-or-quota-refused",
               "rate-limited", "profile-quota-exhausted", "network-or-client-error",
               "daily-create-quota-exhausted",
               "app-not-listening",
               "dolphin-hardware-incompatible", "debugger-not-ready", "child-exited",
               "startup-timeout", "invalid-launch-output"}
    # These strings are constructed from field-name enums by profiles.api().
    # Recheck at this reporting boundary, even when supplied by another caller.
    fields = ("platform", "useragent", "webglInfo", "cpu", "memory", "osVersion")
    if isinstance(reason, str) and reason.startswith("validation-mentions-"):
        mentioned = reason.removeprefix("validation-mentions-").split("-")
        safe = (bool(mentioned) and len(set(mentioned)) == len(mentioned) and
                all(field in fields for field in mentioned))
    else:
        safe = isinstance(reason, str) and reason in allowed
    return {"stage": stage, "http": status if type(status) is int and 100 <= status <= 599 else None,
            "reason": reason if safe else "UNKNOWN",
            "retry_after": delay if type(delay) is int and 0 <= delay <= 3600 else None}


def target_order(url, allowed_origin, collector_contract="session-bound"):
    """Bind one page to exactly one approved private collector origin/task."""
    try:
        target, origin = urlsplit(url), urlsplit(allowed_origin)
        # These are exact owned authorities, not general DNS exemptions.
        # The HTTPS hostname is the existing private Linux tailnet node;
        # certificates are verified by the browser, never ignored by this tool.
        known_https = (origin.scheme == "https" and
                       origin.hostname == os.environ.get("ADA_PRIVATE_HTTPS_HOST") and
                       origin.port in {None, 443, 18443})
        try:
            address = ipaddress.ip_address("127.0.0.1" if origin.hostname == "localhost" else (origin.hostname or ""))
        except ValueError:
            address = None
        private_http = (origin.scheme == "http" and address is not None and
                        not (address.is_global or address.is_unspecified or address.is_multicast) and
                        origin.port is not None)
        pairs = parse_qsl(target.query, keep_blank_values=True, strict_parsing=True)
        query = dict(pairs)
        if collector_contract not in {"session-bound", "legacy-order"}:
            raise ValueError
        expected = {"order_number", "session_id"} if collector_contract == "session-bound" else {"order_number"}
        if (not (private_http or known_https) or
                origin.username is not None or origin.password is not None or
                origin.path not in {"", "/"} or origin.query or origin.fragment or
                target.scheme != origin.scheme or target.netloc != origin.netloc or
                target.path != "/_web" or target.fragment or len(pairs) != len(expected) or
                set(query) != expected or
                not re.fullmatch(r"0|[1-9][0-9]*", query["order_number"]) or
                int(query["order_number"]) > 22 or
                (collector_contract == "session-bound" and
                 not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", query["session_id"]))):
            raise ValueError
        return int(query["order_number"])
    except (ValueError, TypeError, IndexError, AttributeError):
        raise profiles.ProfileError("task-url-contract") from None


def candidate_hashes(directory):
    paths = sorted(directory.glob("*.js"))
    expected = {name + ".js" for name in profiles.NAMES}
    if {path.name for path in paths} != expected or any(path.is_symlink() for path in paths):
        raise profiles.ProfileError("candidate-contract")
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def frontend_mode_evidence(frontend, mode):
    """Separate untouched collector payloads from detector completion proof.

    The frontend catches/coerces detector failures and non-Booleans. Some
    kernels omit caught console errors. No matching payload alone is a pass;
    strict raw-return diagnostics supply a separate completion observation.
    """
    if (not isinstance(frontend, dict) or mode not in {"headed", "headless"} or
            type(frontend.get("headless")) is not bool):
        raise profiles.ProfileError("frontend-mode-evidence-mismatch")
    errors = frontend.get("detector_errors", [])
    if not isinstance(errors, list) or any(not isinstance(item, dict) for item in errors):
        raise profiles.ProfileError("frontend-mode-evidence-mismatch")
    failed = any(item.get("detector") == "headless" for item in errors)
    matches = frontend["headless"] is (mode == "headless")
    return {"mode_error_observed": failed, "mode_payload_matches": matches,
            "mode_observation_state": "ERROR" if failed else "UNVERIFIED",
            "mode_correct": False if failed or not matches else None}


def octium_sandbox_helper_broken():
    """Octium aborts when chrome-sandbox exists but is not setuid root.

    The local API then returns HTTP 400, profiles.start_failed. A missing
    helper is left alone; only a present, wrongly installed helper is bypassed.
    """
    root = Path.home() / ".Octo Browser" / "bin" / "Octium"
    if not root.is_dir():
        return False
    helpers = list(root.glob("*/chrome-sandbox"))
    if not helpers:
        return False
    for helper in helpers:
        try:
            info = helper.stat()
        except OSError:
            return True
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o4755:
            return True
    return False


class SavedOctoProfile(profiles.OwnedProfile):
    """Use the saved start route, but ONLY with this invocation's new empty ID."""
    def _create(self):
        if self.id is not None or self.journal.exists():
            raise profiles.ProfileError("ownership-journal-conflict")
        self.create_pending = True
        claim = "win" if self.profile_os == "windows" else "mac"
        body = {
            "title": self.title, "fingerprint": {"os": claim, "screen": "1920x1080",
                "languages": {"type": "manual", "data": ["en-US", "en"]},
                "timezone": {"type": "manual", "data": "America/New_York"},
                "webrtc": {"type": self.octo_webrtc_mode}, "cpu": 4, "ram": 8},
            "proxy": None, "start_pages": ["about:blank"], "launch_args": [],
            "storage_options": {name: False for name in
                ("cookies", "passwords", "localstorage", "history", "bookmarks", "serviceworkers")}}
        if profiles.OCTO_MINIMAL:
            # Only the OS claim; every other fingerprint field is Octo's own default.
            body["fingerprint"] = {"os": claim}
        try:
            data = profiles.api("POST", profiles.OCTO_CLOUD, "saved-create", headers=self.headers,
                                accepted=(200, 201), body=body)
        except profiles.ProfileError as error:
            # Only a definitive HTTP refusal may be replayed. A lost response
            # could already have created a profile; never retry that case.
            delay = error.retry_after
            if error.http != 429 or type(delay) is not int or not 0 <= delay <= 300:
                raise
            remaining = max(delay, 1) + 2
            self.rate_backoff_audit = {"stage": "saved-create", "wait_seconds": remaining,
                                       "replays": 1, "definite_http_refusal": True}
            print(json.dumps({"vendor": "octo", "stage": "saved-create",
                              "rate_limit_wait_seconds": remaining}), flush=True)
            while remaining:
                interval = min(remaining, 30)
                time.sleep(interval)
                remaining -= interval
            data = profiles.api("POST", profiles.OCTO_CLOUD, "saved-create-after-backoff",
                                headers=self.headers, accepted=(200, 201), body=body)
        if data.get("success") is not True:
            raise profiles.ProfileError("saved-create-contract")
        self.register(data.get("data", {}).get("uuid"))

    def _start(self, mode):
        if self.id is None:
            raise profiles.ProfileError("unowned-start")
        body = {"uuid": self.id, "headless": mode == "headless", "debug_port": True,
                "only_local": True, "timeout": 180}
        if octium_sandbox_helper_broken():
            body["flags"] = ["--no-sandbox"]
        data = profiles.api("POST", profiles.LOCAL_OCTO + "/start", "saved-start", body=body, timeout=240)
        if data.get("uuid") != self.id or data.get("state") != "STARTED":
            raise profiles.ProfileError("saved-start-contract")
        self.running = True
        return profiles.checked_port(data.get("debug_port"))

    def stop(self):
        if self.id is None:
            return super().stop()
        # Generic quick/one-time cleanup unlinks its ID. Saved cleanup must keep
        # the known ID/journal until a separate recoverable cloud Trash succeeds.
        if self.running or self.start_pending:
            try:
                profiles.api("POST", profiles.LOCAL_OCTO + "/stop", "saved-stop", body={"uuid": self.id})
            except profiles.ProfileError as error:
                # A start that never launched also answers 400. Inactivity is
                # checked below; a profile that is still open still fails cleanup.
                if error.http != 400:
                    raise
        for _ in range(20):
            active = profiles.api("GET", profiles.LOCAL_OCTO + "/active", "saved-inactive")
            if not isinstance(active, list) or any(not isinstance(item, dict) for item in active):
                raise profiles.ProfileError("saved-inactive-contract")
            if not any(item.get("uuid") == self.id for item in active):
                break
            time.sleep(1)
        else:
            raise profiles.ProfileError("owned-profile-still-active")
        if self.port is not None:
            for _ in range(50):
                if not profiles.socket_owners(self.port):
                    break
                time.sleep(0.2)
            else:
                raise profiles.ProfileError("owned-debug-listener-still-active")
        self.running = self.start_pending = False
        self.port = None
        return {"cleanup_confirmed": True}

    def delete_created(self):
        if self.id is None:
            return super().delete_created()
        self.stop()
        data = profiles.api("DELETE", profiles.OCTO_CLOUD, "saved-trash", headers=self.headers,
                            body={"uuids": [self.id], "skip_trash_bin": False})
        if data.get("success") is not True or self.id not in data.get("data", {}).get("deleted_uuids", []):
            raise profiles.ProfileError("saved-trash-contract")
        self.journal.unlink()
        self.id = None


def run_task(*, vendor, mode, url, allowed_origin, candidate_directory, artifacts,
             octo_route="one-time", owner_factory=None, observer=None, collector_contract="session-bound",
             diagnostic_go_netlog=False, profile_os=None):
    order = target_order(url, allowed_origin, collector_contract)
    if vendor not in PRODUCTS or mode not in {"headed", "headless"} or octo_route not in {"saved", "one-time"}:
        raise profiles.ProfileError("task-contract")
    manifest = candidate_hashes(candidate_directory)
    if type(diagnostic_go_netlog) is not bool or (diagnostic_go_netlog and
            (vendor != "gologin" or profiles.HOST_OS != "macos" or
             not re.fullmatch(r"ada-mode-diagnostic-[A-Za-z0-9]{8}", ROOT.name))):
        raise profiles.ProfileError("private-trace-task-contract")
    artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    journal = artifacts / "private-owner.json"
    owner_class = SavedOctoProfile if vendor == "octo" and octo_route == "saved" else profiles.OwnedProfile
    # Production results point to a Windows claim with Octo's own defaults
    # (WebRTC included). The old macOS / UDP-disabled preset passed an Octo
    # rule in the lab that production missed on every task.
    if profile_os is None:
        profile_os = "windows" if vendor == "octo" else profiles.HOST_OS
    elif profile_os not in profiles.OS_CLAIMS.get(vendor, ()):
        raise profiles.ProfileError("task-contract")
    if vendor == "octo" and owner_factory is None:
        profiles.OCTO_MINIMAL = True
        owner = owner_class(vendor, profile_os, journal, octo_webrtc_mode="default")
    else:
        owner = (owner_factory or owner_class)(vendor, profile_os, journal)
    if diagnostic_go_netlog:
        owner.diagnostic_netlog_path = artifacts / "private-netlog.json"
    report = {"state": "UNKNOWN", "vendor": vendor, "mode": mode, "order_number": order,
              "host_os": profiles.HOST_OS, "profile_os": profile_os,
              "collector_contract": collector_contract,
              "navigation_origin": allowed_origin,
              "octo_route": octo_route if vendor == "octo" else None,
              "expected_detector_sha256": manifest, "cleanup_confirmed": False}
    try:
        owner.create()
        port = owner.start(mode)
        audit = profiles.native_mode(port)
        report["native_launch_audit"] = audit
        if audit.get("state") != "verified" or audit.get("headless_flag") is not (mode == "headless"):
            raise profiles.ProfileError("native-mode-unverified")
        if observer is not None:
            result = observer(port, url)
        else:
            completed = subprocess.run([profiles.node_path(), str(ROOT / "scripts/observe_ada_frontend.mjs"),
                                        str(port), url, "45000", collector_contract], capture_output=True, text=True,
                                       timeout=65, check=False)
            if completed.returncode:
                # Do not export raw Node/SDK responses or exception text.
                stage = "frontend-observation-failed"
                try:
                    observation = json.loads(completed.stdout)
                    reason = observation.get("reason", "")
                    diagnostics = observation.get("diagnostics")
                    if isinstance(diagnostics, dict):
                        report["frontend_observation_diagnostics"] = diagnostics
                    if re.fullmatch(r"(?:frontend|collector|owned|detector-source|cdp)-[a-z-]+(?:-\d+)?", reason):
                        stage = reason
                    elif re.fullmatch(r"observer-failed|non-owned-cdp-endpoint|cdp-[a-z-]+:[A-Za-z.]+", reason):
                        # Keep the observer's own category; ":" and "." cannot be in a stage name.
                        stage = "frontend-" + reason.replace(":", "-").replace(".", "-")
                except (ValueError, AttributeError, TypeError):
                    pass
                raise profiles.ProfileError(stage)
            result = json.loads(completed.stdout)
        report["frontend"] = result
        if (result.get("state") != "collector-confirmed" or result.get("order_number") != order or
                type(result.get("headless")) is not bool or
                result.get("detector_sha256") != manifest or
                type(result.get("http_status")) is not int or not 200 <= result["http_status"] < 300):
            raise profiles.ProfileError("frontend-evidence-mismatch")
        # A wrong verdict is still a delivered result, not an infrastructure error.
        # The original scorer, not this adapter, applies its headless/human gates.
        report.update(frontend_mode_evidence(result, mode))
        report["state"] = "delivered"
    except (profiles.ProfileError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        report["failure"] = failure_evidence(error, "task-UNKNOWN")
    finally:
        if vendor == "ads_power":
            audit = profiles.sanitize_adspower_create_evidence(getattr(owner, "adspower_create_audit", None))
            if audit is not None:
                report["adspower_create_audit"] = audit
        backoff = getattr(owner, "rate_backoff_audit", None)
        if (isinstance(backoff, dict) and backoff.get("stage") == "saved-create" and
                type(backoff.get("wait_seconds")) is int and 3 <= backoff["wait_seconds"] <= 302 and
                type(backoff.get("replays")) is int and backoff["replays"] == 1 and
                backoff.get("definite_http_refusal") is True):
            report["rate_backoff_audit"] = {key: backoff[key] for key in
                ("stage", "wait_seconds", "replays", "definite_http_refusal")}
        if vendor == "ads_power":
            kind = getattr(owner, "reuse_kind", None)
            report["profile_ownership"] = ("dedicated-default-reuse" if kind == "dedicated" else
                                           "new-dedicated-default" if kind == "new-dedicated" else
                                           "earlier-run-owned-reuse" if kind == "leftover" else "new-disposable")
            lookup = getattr(owner, "reuse_lookup", None)
            if lookup in ("idle-owned-found", "list-refused", "none-owned", "none-idle", "lookup-error"):
                report["reuse_lookup"] = lookup
            refusals = getattr(owner, "reuse_start_refusals", 0)
            if type(refusals) is int and 0 < refusals <= 8:
                report["reuse_start_refusals"] = refusals
            words = getattr(owner, "adspower_start_markers", None)
            if isinstance(words, list) and all(word in profiles.ADSPOWER_START_MARKERS for word in words):
                report["adspower_start_audit"] = {"message_markers": sorted(set(words))}
        if vendor == "dolphin_anty":
            pool_reused = getattr(owner, "dolphin_reuse_kind", None) == "operator-approved-pool"
            report["profile_ownership"] = ("operator-approved-pool-reuse" if pool_reused else
                                           "configured-dedicated-reuse" if getattr(owner, "saved", False)
                                           else "new-disposable")
            report["reused_profile_skipped_busy"] = getattr(owner, "reused_profile_skipped_busy", False) is True
        create_audit = getattr(owner, "profile_create_audit", None)
        if (isinstance(create_audit, dict) and set(create_audit) ==
                {"template_attempts", "definite_hardware_refusals", "masking_changed"} and
                all(type(create_audit[key]) is int and 0 <= create_audit[key] <= 3
                    for key in ("template_attempts", "definite_hardware_refusals")) and
                create_audit["masking_changed"] is False):
            report["profile_create_audit"] = create_audit.copy()
        if isinstance(getattr(owner, "startup_audit", None), dict):
            report["startup_audit"] = profiles.sanitize_gologin_startup(owner.startup_audit)
        try:
            owner.stop()
            owner.delete_created()
            report["cleanup_confirmed"] = not journal.exists()
        except (profiles.ProfileError, OSError, ValueError, KeyError, TypeError) as error:
            report["cleanup_failure"] = failure_evidence(error, "cleanup-UNKNOWN")
            if vendor == "multilogin" and sys.platform.startswith("linux"):
                if __package__:
                    from .owned_ml_exit_reconciliation import reconcile_owned_ml_exit
                else:
                    from owned_ml_exit_reconciliation import reconcile_owned_ml_exit
                proof = reconcile_owned_ml_exit(journal, ROOT, profiles, mode == "headless")
                if proof is not None:
                    report["cleanup_native_exit_reconciliation"] = proof
                    report["cleanup_confirmed"] = True
        if not report["cleanup_confirmed"]:
            report["state"] = "UNKNOWN"
        if diagnostic_go_netlog:
            if __package__:
                from .owned_network_trace import read_summary
            else:
                from owned_network_trace import read_summary
            report["diagnostic_network_trace"] = read_summary(artifacts / "private-netlog.json")
        with (artifacts / "report.json").open("x", encoding="utf-8") as output:
            os.chmod(output.name, 0o600)
            json.dump(report, output, indent=2)
            output.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor", choices=PRODUCTS, required=True)
    parser.add_argument("--mode", choices=("headed", "headless"), required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--allowed-origin", required=True)
    parser.add_argument("--candidate-directory", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--octo-route", choices=("saved", "one-time"), default="one-time")
    parser.add_argument("--create-owned-profiles", action="store_true")
    args = parser.parse_args()
    if not args.create_owned_profiles:
        parser.error("Explicit owned disposable profile creation required")
    options = vars(args)
    options.pop("create_owned_profiles")
    try:
        result = run_task(**options)
    except (profiles.ProfileError, OSError, ValueError, KeyError):
        print(json.dumps({"state": "UNKNOWN", "failure": {"stage": "preflight-failed"}}))
        return 1
    print(json.dumps(result), flush=True)
    return 0 if result["state"] == "delivered" else 1


if __name__ == "__main__":
    sys.exit(main())
