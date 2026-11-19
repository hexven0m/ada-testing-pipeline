#!/usr/bin/env python3
"""Repeat actual React execution in new owned profiles; not a scored round.

Loopback collector/template diagnostics never substitute for /score or human
verification. Each remote stage is private and immutable for the entire batch.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
HOSTS = ("macos", "linux")
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in
                         ("100.64.0.0/10", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                          "127.0.0.0/8"))


def private_ipv4(value):
    address = ipaddress.IPv4Address(value)
    if not any(address in network for network in PRIVATE_NETWORKS):
        raise ValueError("private-worker-address-required")
    return str(address)
SCRIPTS = ("run_frontend_mode_diagnostic_matrix.py", "serve_frontend_mode_diagnostic.py", "owned_network_trace.py",
           "run_owned_chrome_frontend.py",
           "run_owned_frontend_task.py", "run_owned_vendor_profiles.py", "observe_ada_frontend.mjs",
           "frontend_error_evidence.mjs", "cdp_rpc.mjs", "owned_gologin_session.py",
           "owned_gologin_session.mjs", "gologin_session_support.py", "diagnose_owned_navigation.mjs",
           "observe_product_callsite_study.mjs", "product_callsite_probe.mjs", "product_callsite_helper.js",
           "owned_callsite_realms.mjs", "owned_formatter_counterexample.mjs", "owned_product_caller_controls.mjs")
SCRIPTS += ("observe_rtc_contract_study.mjs", "owned_rtc_contract_probe.mjs")
SCRIPTS += ("owned_candidate_research_probe.mjs",)
SCRIPTS += ("owned_independent_contract_probe.mjs",)
SCRIPTS += ("observe_input_contract_study.mjs", "owned_input_contract_probe.mjs", "observe_assistant_control.mjs")
SCRIPTS += ("observe_ads_resource_study.mjs",)
SCRIPTS += ("observe_headless_repeat_study.mjs",)
SCRIPTS += ("observe_headless_first_call_study.mjs", "owned_ml_exit_reconciliation.py", "owned_script_source_binding.mjs")
SCRIPTS += ("observe_resize_contract_study.mjs", "owned_resize_contract_probe.mjs")


ASSET_FILES = ("index.html", "static/js/main.3256c9f3.js", "static/js/user-agent-spoof.js", "static/css/main.c1e9ffb3.css")


def evidence_directory(output_root=None):
    """Create private local evidence under the operator's explicit run root."""
    evidence = Path(output_root) if output_root is not None else ROOT / "experiments"
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="frontend-mode-diagnostic-", dir=evidence))


def stage_archive(directory, assets_directory=None):
    """Build the unchanged remote stage recipe from explicit frozen inputs."""
    templates = (Path(assets_directory) if assets_directory is not None else
                 ROOT / "src/ada_challenge/challenge/templates")
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        for script in SCRIPTS:
            tar.add(ROOT / "scripts" / script, arcname="scripts/" + script, recursive=False)
        for name in ("ads_power.js", "dolphin_anty.js", "gologin.js", "headless.js", "multilogin.js", "octo.js"):
            tar.add(directory / name, arcname="candidate/" + name, recursive=False)
        for name in ASSET_FILES:
            tar.add(templates / name, arcname="templates/" + name, recursive=False)
    return archive.getvalue()


def ssh_connection(host_os, worker=None, control_path=None):
    """Use an operator-supplied owned socket for Linux dispatch only.

    Passwords and private keys are never accepted, stored, or forwarded here.
    """
    if host_os not in HOSTS or (host_os != "linux" and control_path is not None):
        raise ValueError("ssh-host-contract")
    host = worker
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*@[0-9.]+", host):
        raise ValueError("Specify --worker user@private-IPv4")
    private_ipv4(host.split("@", 1)[1])
    options = ()
    if control_path is not None:
        path = Path(control_path).resolve()
        try:
            metadata = path.stat()
        except OSError:
            raise ValueError("ssh-control-socket-unavailable") from None
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError("ssh-control-socket-not-owned")
        options = ("-o", "ControlMaster=auto", "-o", f"ControlPath={path}")
    return host, options


def require_host_platform(host, options, expected):
    code = ("import sys; print('linux' if sys.platform.startswith('linux') "
            "else 'macos' if sys.platform == 'darwin' else 'other')")
    checked = subprocess.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        *options, host, shlex.join(["python3", "-c", code])],
        capture_output=True, text=True, timeout=20, check=False)
    if checked.returncode or checked.stdout.strip() != expected:
        raise ValueError("ssh-platform-unverified; no profiles started")


def record(path, value):
    with path.open("x") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, indent=2)
        output.write("\n")


def diagnostic_plan(host_os, vendors, repeats, source_sha256):
    """Pin the full roster BEFORE browser starts, so early stops stay missing."""
    if (host_os not in HOSTS or type(repeats) is not int or not 1 <= repeats <= 5 or
            not isinstance(vendors, list) or not vendors or
            any(not isinstance(v, str) or v not in {"ads_power", "dolphin_anty", "gologin", "multilogin", "octo", "chrome_control"} for v in vendors) or
            len(set(vendors)) != len(vendors) or
            2 * repeats * len(vendors) > 23 or not isinstance(source_sha256, dict) or
            set(source_sha256) != {v + ".js" for v in ("ads_power", "dolphin_anty", "gologin", "multilogin", "octo", "headless")} or
            any(not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) for digest in source_sha256.values())):
        raise ValueError("diagnostic-plan-contract")
    cases = []
    for product in vendors:
        for repeat in range(repeats):
            for mode in ("headed", "headless"):
                cases.append({"case_id": f"{host_os}-{product}-{mode}-{repeat}", "order_number": len(cases),
                              "host_os": host_os, "product": product, "mode": mode, "repeat": repeat})
    return {"schema_version": 1, "challenge": "ada_v3", "evaluation_request_id": uuid4().hex,
            "source_sha256": dict(source_sha256), "expected_cases": cases,
            "diagnostic_only": True, "submission_certified": False}


def diagnostic_transport(vendors, host_os, tailnet_origin=False, localhost_origin=False, private_address=None):
    """Keep Mimic's default local-port masking intact; route the collector instead.

    Bind only the configured private interface or loopback. HTTP on a tailnet address is NOT a secure
    context: media-dependent detector comparisons must use a trusted HTTPS
    diagnostic or an explicitly controlled loopback origin. The observer
    records actual API availability; do not infer product absence from an
    unavailable API. Explicit localhost is an opt-in transport control.
    """
    if (host_os not in HOSTS or type(tailnet_origin) is not bool or
            type(localhost_origin) is not bool or (tailnet_origin and localhost_origin)):
        raise ValueError("diagnostic-origin-contract")
    uses_tailnet = tailnet_origin or ("multilogin" in vendors and not localhost_origin)
    if uses_tailnet and not private_address:
        raise ValueError("private-worker-address-required")
    bind_host = private_ipv4(private_address) if uses_tailnet else "127.0.0.1"
    selection = ("explicit-tailnet" if tailnet_origin else "explicit-localhost" if localhost_origin
                 else "automatic-multilogin-tailnet" if uses_tailnet else "default-loopback")
    return {"bind_host": bind_host, "origin_host": "localhost" if localhost_origin else bind_host,
            "uses_tailnet": uses_tailnet, "selection": selection}


def diagnostic_batch_transport(vendors, host_os, tailnet_origin=False, localhost_origin=False,
                               navigation_only=False, private_address=None):
    """Use observed compatible authorities without changing browser policies.

    Mac Orbita delivered the unchanged frontend at exact localhost, whereas
    numeric private addresses failed before detector loading. Mimic still
    needs its private-network route with default loopback masking intact.
    A mixed batch therefore shares immutable assets, capability and collector
    across two task-owned listeners, not across two supposed scoring runs.
    Explicit route controls and navigation studies remain unchanged.
    """
    if type(navigation_only) is not bool:
        raise ValueError("diagnostic-origin-contract")
    transport = diagnostic_transport(vendors, host_os, tailnet_origin, localhost_origin, private_address)
    transport["origin_hosts"] = {vendor: transport["origin_host"] for vendor in vendors}
    transport["secondary_bind_host"] = None
    if (host_os == "macos" and "gologin" in vendors and not tailnet_origin and
            not localhost_origin and not navigation_only):
        transport["origin_hosts"]["gologin"] = "localhost"
        if transport["uses_tailnet"]:
            transport["secondary_bind_host"] = "127.0.0.1"
            transport["selection"] = "automatic-vendor-authorities"
        else:
            transport["selection"] = "automatic-gologin-localhost"
    return transport


def correlate_diagnostic_receipt(result, receipt):
    """Correlate actual server evidence without upgrading UNKNOWN to a pass.

    Vendor observers store failure diagnostics at the top level; the stock
    Chrome observer stores the same data inside frontend_observation.
    """
    diagnostics = result.get("frontend_observation_diagnostics")
    if diagnostics is None:
        observation = result.get("frontend_observation", {})
        diagnostics = observation.get("diagnostics") if isinstance(observation, dict) else None
    if not isinstance(diagnostics, dict) or not isinstance(receipt, dict):
        return {}
    expected = result.get("expected_detector_sha256")
    names = {"headless.js", "ads_power.js", "dolphin_anty.js", "gologin.js", "multilogin.js", "octo.js"}
    announced = diagnostics.get("header_confirmed_verdicts", [])
    if (not isinstance(expected, dict) or set(expected) != names or
            diagnostics.get("detector_sha256") != expected or
            not isinstance(announced, list) or len(announced) != 1 or
            not isinstance(announced[0], dict) or
            receipt.get("diagnostic_only") is not True or receipt.get("submission_certified") is not False or
            type(receipt.get("headless")) is not bool or
            result.get("mode") not in {"headed", "headless"} or
            type(receipt.get("order_number")) is not int or
            receipt["order_number"] != result.get("order_number") or
            announced[0].get("order_number") != receipt["order_number"] or
            announced[0].get("headless") is not receipt["headless"] or
            not isinstance(receipt.get("submitted_framework"), list) or
            announced[0].get("submitted_framework") != receipt["submitted_framework"]):
        return {}
    return {"diagnostic_server_receipt": receipt,
            "diagnostic_mode_matches": receipt["headless"] is (result["mode"] == "headless")}


def remote(vendors, repeats, tailnet_origin=False, collector_response_drain=False, navigation_only=False, localhost_origin=False,
           diagnostic_go_netlog=False, callsite_study=False, collector_cache_control="omit", rtc_contract_study=False,
           input_contract_study=False, headless_repeat_study=False, headless_first_call_study=False,
           resize_contract_study=False, vary_claims=False, private_address=None):
    if __package__:
        from .run_owned_frontend_task import run_task, candidate_hashes
        from .run_owned_vendor_profiles import NAMES
    else:
        from run_owned_frontend_task import run_task, candidate_hashes
        from run_owned_vendor_profiles import NAMES
    if type(headless_first_call_study) is not bool or (headless_first_call_study and
            (headless_repeat_study or input_contract_study or rtc_contract_study or callsite_study or
             collector_response_drain or navigation_only or diagnostic_go_netlog or resize_contract_study)):
        raise ValueError("headless-first-study-contract")
    if type(headless_repeat_study) is not bool or (headless_repeat_study and
            (input_contract_study or rtc_contract_study or callsite_study or collector_response_drain or
             navigation_only or diagnostic_go_netlog)):
        raise ValueError("headless-repeat-study-contract")
    if type(resize_contract_study) is not bool or (resize_contract_study and
            (headless_repeat_study or input_contract_study or rtc_contract_study or callsite_study or
             collector_response_drain or navigation_only or diagnostic_go_netlog)):
        raise ValueError("resize-study-batch-contract")
    if (type(input_contract_study) is not bool or (input_contract_study and
            (rtc_contract_study or callsite_study or collector_response_drain or navigation_only or diagnostic_go_netlog)) or
            type(rtc_contract_study) is not bool or (rtc_contract_study and
            (callsite_study or collector_response_drain or navigation_only or diagnostic_go_netlog)) or
            collector_cache_control not in {"omit", "no-store"} or
            type(callsite_study) is not bool or not 1 <= repeats <= 5 or not vendors or any(v not in (*NAMES, "chrome_control") or v == "headless" for v in vendors) or
            2 * repeats * len(vendors) > 23 or (tailnet_origin and localhost_origin) or
            (diagnostic_go_netlog and (sys.platform != "darwin" or vendors != ["gologin"] or not navigation_only)) or
            (callsite_study and (collector_response_drain or navigation_only or diagnostic_go_netlog or
                                not set(vendors).issubset({"multilogin", "chrome_control"})))):
        raise ValueError("batch-contract")
    manifest = candidate_hashes(ROOT / "candidate")
    plan = diagnostic_plan("linux" if sys.platform.startswith("linux") else "macos", vendors, repeats, manifest)
    artifacts = ROOT / "artifacts"
    artifacts.mkdir(mode=0o700, exist_ok=False)
    record(artifacts / "evaluation-plan.json", plan)
    log = (artifacts / "server.log").open("x")
    os.chmod(log.name, 0o600)
    transport = diagnostic_batch_transport(vendors, "linux" if sys.platform.startswith("linux") else "macos",
                                           tailnet_origin, localhost_origin, navigation_only, private_address)
    bind_host = transport["bind_host"]
    process = subprocess.Popen([sys.executable, str(ROOT / "scripts/serve_frontend_mode_diagnostic.py"),
        "--candidate", str(ROOT / "candidate"), "--templates", str(ROOT / "templates"),
        "--state", str(artifacts / "server"), *(["--drain-collector-response"] if collector_response_drain else []),
        "--host", bind_host, "--port", "0", "--collector-cache-control", collector_cache_control,
        *(["--secondary-loopback"] if transport["secondary_bind_host"] else []),
        *(["--headless-first-call-study"] if headless_first_call_study else []),
        *(["--callsite-study"] if callsite_study else [])],
        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    log.close()
    record(artifacts / "server-process.json", {"pid": process.pid})
    rows = []
    try:
        private = artifacts / "server/private-session.json"
        for _ in range(100):
            if private.exists() and (artifacts / "server/manifest.json").exists():
                try:
                    session = json.loads(private.read_text())
                    break
                except json.JSONDecodeError:
                    pass  # A readiness file is not ready until fully written.
            if process.poll() is not None:
                raise ValueError("diagnostic-server-failed")
            time.sleep(0.1)
        else:
            raise ValueError("diagnostic-server-not-ready")
        for vendor in vendors:
            origin = "http://" + transport["origin_hosts"][vendor] + ":" + str(session["port"])
            for repeat in range(repeats):
                for mode in ("headed", "headless"):
                    order = len(rows)
                    options = dict(mode=mode,
                        url=origin + "/_web?order_number=" + str(order) + "&session_id=" + session["session_id"],
                        allowed_origin=origin, candidate_directory=ROOT / "candidate", artifacts=artifacts / f"task-{order}")
                    if headless_repeat_study:
                        from run_owned_vendor_profiles import node_path
                        def observe_repeat(port, url):
                            completed = subprocess.run([node_path(), str(ROOT / "scripts/observe_headless_repeat_study.mjs"),
                                str(port), url], capture_output=True, text=True, timeout=120)
                            return json.loads(completed.stdout)
                        options["observer"] = observe_repeat
                    if headless_first_call_study:
                        from run_owned_vendor_profiles import node_path
                        def observe_first(port, url):
                            preload = hashlib.sha256((ROOT / "templates/static/js/user-agent-spoof.js").read_bytes()).hexdigest()
                            completed = subprocess.run([node_path(), str(ROOT / "scripts/observe_headless_first_call_study.mjs"),
                                str(port), url, preload], capture_output=True, text=True, timeout=120)
                            return json.loads(completed.stdout)
                        options["observer"] = observe_first
                    if resize_contract_study:
                        from run_owned_vendor_profiles import node_path
                        def observe_resize(port, url):
                            completed = subprocess.run([node_path(), str(ROOT / "scripts/observe_resize_contract_study.mjs"),
                                str(port), url], capture_output=True, text=True, timeout=120)
                            return json.loads(completed.stdout)
                        options["observer"] = observe_resize
                    if callsite_study:
                        from run_owned_vendor_profiles import node_path
                        def observe_callsites(port, url):
                            completed = subprocess.run([node_path(), str(ROOT / "scripts/observe_product_callsite_study.mjs"),
                                str(port), url, str(ROOT / "candidate")], capture_output=True, text=True, timeout=120)
                            return json.loads(completed.stdout)
                        options["observer"] = observe_callsites
                    if rtc_contract_study:
                        from run_owned_vendor_profiles import node_path
                        def observe_rtc(port, url):
                            completed = subprocess.run([node_path(), str(ROOT / "scripts/observe_rtc_contract_study.mjs"),
                                str(port), url], capture_output=True, text=True, timeout=120)
                            return json.loads(completed.stdout)
                        options["observer"] = observe_rtc
                    if input_contract_study:
                        from run_owned_vendor_profiles import node_path
                        def observe_inputs(port, url):
                            completed = subprocess.run([node_path(), str(ROOT / "scripts/observe_input_contract_study.mjs"),
                                str(port), url], capture_output=True, text=True, timeout=120)
                            return json.loads(completed.stdout)
                        options["observer"] = observe_inputs
                    if vendor == "chrome_control":
                        from run_owned_chrome_frontend import run_control
                        result = run_control(**options)
                    else:
                        if navigation_only:
                            from run_owned_vendor_profiles import node_path
                            def observe_navigation(port, url):
                                completed = subprocess.run([node_path(), str(ROOT / "scripts/diagnose_owned_navigation.mjs"),
                                    str(port), url], capture_output=True, text=True, timeout=90, check=False)
                                return json.loads(completed.stdout)
                            options["observer"] = observe_navigation
                        claim = None
                        if vary_claims:
                            # Each repeat is another profile: Windows claim first, then the
                            # host's own OS (Octo has no Linux claim, so macOS there).
                            here = "linux" if sys.platform.startswith("linux") else "macos"
                            claim = ("windows", "macos" if vendor == "octo" else here)[repeat % 2]
                        result = run_task(vendor=vendor, **options,
                            octo_route="saved" if sys.platform.startswith("linux") else "one-time",
                            diagnostic_go_netlog=diagnostic_go_netlog, profile_os=claim)
                    result["repeat"] = repeat
                    result["case_id"] = plan["expected_cases"][order]["case_id"]
                    result["evaluation_request_id"] = plan["evaluation_request_id"]
                    result["diagnostic_origin"] = origin
                    if callsite_study:
                        study = result.get("frontend", result.get("frontend_observation", {}))
                        result["callsite_study_complete"] = (study.get("state") == "callsite-study" and
                            study.get("diagnostic_only") is True and study.get("submission_certified") is False and
                            study.get("detector_sha256") == result["expected_detector_sha256"])
                    receipt = artifacts / "server" / f"payload-{order}.json"
                    # Diagnostic evidence only. Never rewrite UNKNOWN or
                    # promote a receipt into official/full transport completion.
                    if receipt.exists():
                        result.update(correlate_diagnostic_receipt(result, json.loads(receipt.read_text())))
                    rows.append(result)
                    print(json.dumps({"vendor": vendor, "mode": mode, "repeat": repeat,
                        "state": result["state"], "headless": result.get("frontend", {}).get("headless"),
                        "submitted_framework": result.get("frontend", {}).get("submitted_framework"),
                        "mode_correct": result.get("mode_correct"),
                        "mode_payload_matches": result.get("mode_payload_matches"),
                        "mode_observation_state": result.get("mode_observation_state"),
                        "detector_errors": result.get("frontend", {}).get("detector_errors"),
                        "diagnostic_mode_matches": result.get("diagnostic_mode_matches"),
                        "callsite_study_complete": result.get("callsite_study_complete"),
                        "cleanup_confirmed": result.get("cleanup_confirmed")}), flush=True)
                    if result.get("failure", {}).get("http") in {401, 402, 403, 429}:
                        raise ValueError("definite-vendor-api-refusal; batch stopped")
                    if not result.get("cleanup_confirmed"):
                        raise ValueError("owned-cleanup-unverified; batch stopped")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        record(artifacts / "summary.json", {"diagnostic_only": True, "submission_certified": False,
            "collector_response_drain": collector_response_drain,
            "collector_cache_control": collector_cache_control,
            "navigation_only": navigation_only,
            "tailnet_origin": transport["uses_tailnet"],
            "transport_selection": transport["selection"],
            "origin_hosts": transport["origin_hosts"],
            "secondary_bind_host": transport["secondary_bind_host"],
            "localhost_origin": localhost_origin,
            "diagnostic_go_netlog": diagnostic_go_netlog,
            "callsite_study": callsite_study,
            "rtc_contract_study": rtc_contract_study,
            "input_contract_study": input_contract_study,
            "resize_contract_study": resize_contract_study,
            "resize_probe_sha256": hashlib.sha256((ROOT / "scripts/owned_resize_contract_probe.mjs").read_bytes()).hexdigest()
                if resize_contract_study else None,
            "headless_repeat_study": headless_repeat_study,
            "headless_first_call_study": headless_first_call_study,
            "input_probe_sha256": hashlib.sha256((ROOT / "scripts/owned_input_contract_probe.mjs").read_bytes()).hexdigest()
                if input_contract_study else None,
            "rtc_probe_sha256": hashlib.sha256((ROOT / "scripts/owned_rtc_contract_probe.mjs").read_bytes()).hexdigest()
                if rtc_contract_study else None,
            "server_stopped": process.poll() is not None, "rows": rows})


def local(host_os, directory, vendors, repeats, tailnet_origin=False, collector_response_drain=False, navigation_only=False, localhost_origin=False,
          diagnostic_go_netlog=False, callsite_study=False, collector_cache_control="omit", rtc_contract_study=False,
          worker=None, ssh_control_path=None, input_contract_study=False, headless_repeat_study=False,
          headless_first_call_study=False, resize_contract_study=False, vary_claims=False,
          output_root=None, assets_directory=None):
    from scripts.run_owned_frontend_task import candidate_hashes
    hashes = candidate_hashes(directory)
    if type(headless_first_call_study) is not bool or (headless_first_call_study and
            (headless_repeat_study or input_contract_study or rtc_contract_study or callsite_study or
             collector_response_drain or navigation_only or diagnostic_go_netlog or resize_contract_study)):
        raise ValueError("headless-first-study-contract")
    if type(headless_repeat_study) is not bool or (headless_repeat_study and
            (input_contract_study or rtc_contract_study or callsite_study or collector_response_drain or
             navigation_only or diagnostic_go_netlog)):
        raise ValueError("headless-repeat-study-contract")
    if type(resize_contract_study) is not bool or (resize_contract_study and
            (headless_repeat_study or input_contract_study or rtc_contract_study or callsite_study or
             collector_response_drain or navigation_only or diagnostic_go_netlog)):
        raise ValueError("resize-study-batch-contract")
    if type(input_contract_study) is not bool or (input_contract_study and
            (rtc_contract_study or callsite_study or collector_response_drain or navigation_only or diagnostic_go_netlog)):
        raise ValueError("input-study-batch-contract")
    if type(rtc_contract_study) is not bool or (rtc_contract_study and
            (callsite_study or collector_response_drain or navigation_only or diagnostic_go_netlog)):
        raise ValueError("rtc-study-batch-contract")
    if collector_cache_control not in {"omit", "no-store"}:
        raise ValueError("collector-cache-control-contract")
    host, ssh_options = ssh_connection(host_os, worker, ssh_control_path)
    private_address = host.split("@", 1)[1]
    if diagnostic_go_netlog and (host_os != "macos" or vendors != ["gologin"] or not navigation_only):
        raise ValueError("private-trace-batch-contract")
    if type(callsite_study) is not bool or (callsite_study and
            (collector_response_drain or navigation_only or diagnostic_go_netlog or
             not set(vendors).issubset({"multilogin", "chrome_control"}))):
        raise ValueError("callsite-batch-contract")
    diagnostic_plan(host_os, vendors, repeats, hashes)  # Validate roster before SSH/staging.
    diagnostic_batch_transport(vendors, host_os, tailnet_origin, localhost_origin, navigation_only, private_address)
    def ssh(command, data=None, timeout=30):
        return subprocess.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            *ssh_options, host, shlex.join(command)], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=True, timeout=timeout).stdout
    require_host_platform(host, ssh_options, host_os)
    stage = ssh(["mktemp", "-d", "/tmp/ada-mode-diagnostic-XXXXXXXX"]).decode().strip()
    if not re.fullmatch(r"/tmp/ada-mode-diagnostic-[A-Za-z0-9]{8}", stage):
        raise ValueError("remote-stage-contract")
    artifacts = evidence_directory(output_root)
    record(artifacts / "stage.json", {"host": host, "host_os": host_os, "stage": stage, "candidate_sha256": hashes,
        "diagnostic_only": True, "submission_certified": False,
        "navigation_only": navigation_only,
        "collector_response_drain": collector_response_drain,
        "collector_cache_control": collector_cache_control,
        "callsite_study": callsite_study,
        "rtc_contract_study": rtc_contract_study,
        "input_contract_study": input_contract_study,
        "resize_contract_study": resize_contract_study,
        "resize_probe_sha256": hashlib.sha256((ROOT / "scripts/owned_resize_contract_probe.mjs").read_bytes()).hexdigest()
            if resize_contract_study else None,
        "headless_repeat_study": headless_repeat_study,
        "headless_first_call_study": headless_first_call_study,
        "input_probe_sha256": hashlib.sha256((ROOT / "scripts/owned_input_contract_probe.mjs").read_bytes()).hexdigest()
            if input_contract_study else None,
        "rtc_probe_sha256": hashlib.sha256((ROOT / "scripts/owned_rtc_contract_probe.mjs").read_bytes()).hexdigest()
            if rtc_contract_study else None,
        "diagnostic_go_netlog": diagnostic_go_netlog})
    ssh(["tar", "-xf", "-", "-C", stage], stage_archive(directory, assets_directory))
    print("Private diagnostic stage: " + stage + "; local evidence: " + str(artifacts), flush=True)
    remote_command = [
        "python3", stage + "/scripts/run_frontend_mode_diagnostic_matrix.py", "--remote"]
    if host_os == "linux":
        remote_command = ["env", "DISPLAY=:20", *remote_command]
    process = subprocess.Popen(["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        *ssh_options, host, shlex.join(remote_command + [
        "--vendors", *vendors, "--repeats", str(repeats), "--collector-cache-control", collector_cache_control,
        "--private-address", private_address,
        *(["--tailnet-origin"] if tailnet_origin else []),
        *(["--collector-response-drain"] if collector_response_drain else []),
        *(["--navigation-only"] if navigation_only else []),
        *(["--localhost-origin"] if localhost_origin else []),
        *(["--diagnostic-go-netlog"] if diagnostic_go_netlog else []),
        *(["--callsite-study"] if callsite_study else []),
        *(["--rtc-contract-study"] if rtc_contract_study else []),
        *(["--input-contract-study"] if input_contract_study else []),
        *(["--headless-repeat-study"] if headless_repeat_study else []),
        *(["--headless-first-call-study"] if headless_first_call_study else []),
        *(["--resize-contract-study"] if resize_contract_study else []),
        *(["--vary-claims"] if vary_claims else [])])])
    process.wait()
    summary = json.loads(ssh(["python3", "-c", "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())",
                              stage + "/artifacts/summary.json"]))
    record(artifacts / "summary.json", summary)
    plan = json.loads(ssh(["python3", "-c", "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())",
                           stage + "/artifacts/evaluation-plan.json"]))
    record(artifacts / "evaluation-plan.json", plan)
    # A server failure still has a pinned plan and empty/partial summary.
    # Do not lose those results by raising while fetching an absent manifest.
    manifest = json.loads(ssh(["python3", "-c", "from pathlib import Path; import sys; p=Path(sys.argv[1]); "
                              "print(p.read_text() if p.is_file() else '{\"state\":\"UNAVAILABLE\"}')",
                              stage + "/artifacts/server/manifest.json"]))
    record(artifacts / "server-manifest.json", manifest)
    print("Diagnostic evidence saved: " + str(artifacts / "summary.json"), flush=True)
    return process.returncode


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote", action="store_true")
    parser.add_argument("--host", choices=tuple(HOSTS))
    parser.add_argument("--worker", help="SSH destination user@private-IPv4 for local dispatch.")
    parser.add_argument("--private-address", help=argparse.SUPPRESS)
    parser.add_argument("--ssh-control-path", type=Path,
                        help="Existing owned Linux SSH control socket; no password is stored.")
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--output-root", type=Path, help="Local evidence parent; never forwarded to the worker.")
    parser.add_argument("--assets-directory", type=Path, help="Explicit frozen frontend assets for local staging.")
    parser.add_argument("--vendors", nargs="+", required=True)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--tailnet-origin", action="store_true",
                        help="Use the configured private test-host interface. Automatic for Multilogin batches.")
    parser.add_argument("--collector-response-drain", action="store_true",
                        help="Test-only template modification; disabled by default. Never scorer certification.")
    parser.add_argument("--navigation-only", action="store_true", help="Owned route isolation; never mode scoring.")
    parser.add_argument("--localhost-origin", action="store_true", help="Use the explicit localhost authority; bind stays loopback-only.")
    parser.add_argument("--diagnostic-go-netlog", action="store_true",
                        help="Private, bounded network trace; Mac GoLogin route isolation only. Raw traces never exported.")
    parser.add_argument("--callsite-study", action="store_true",
                        help="Owned post-prediction script-origin comparison. Never scorer qualification.")
    parser.add_argument("--rtc-contract-study", action="store_true",
                        help="Post-prediction fixed-input RTC contract research; no device/IP values exported.")
    parser.add_argument("--input-contract-study", action="store_true",
                        help="Post-prediction conversion, cross-realm and lifecycle research; enum-only output.")
    parser.add_argument("--headless-repeat-study", action="store_true",
                        help="Observe a second raw headless call after submission; never original-call certification.")
    parser.add_argument("--headless-first-call-study", action="store_true",
                        help="Separate source-pinned first-call page after the unchanged frontend; diagnostic only.")
    parser.add_argument("--resize-contract-study", action="store_true",
                        help="Post-prediction fixed receiver/error semantics; no classification or identity reads.")
    parser.add_argument("--vary-claims", action="store_true",
                        help="Give each repeat of a product another profile: Windows claim, then the host OS.")
    parser.add_argument("--collector-cache-control", choices=("omit", "no-store"), default="omit",
                        help="Default matches the checked-in collector; no-store reproduces the old diagnostic header")
    args = parser.parse_args()
    if args.ssh_control_path is not None and (args.remote or args.host != "linux"):
        parser.error("SSH control socket requires local dispatch with --host linux")
    if (args.remote and args.worker is not None) or (not args.remote and args.private_address is not None):
        parser.error("Specify --worker on the controller")
    if args.remote and (args.output_root is not None or args.assets_directory is not None):
        parser.error("Local output/assets arguments cannot be used with --remote")
    if args.remote:
        import fcntl
        ownership_lock = open('/tmp/adatest.lock', 'a')
        fcntl.flock(ownership_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        remote(args.vendors, args.repeats, args.tailnet_origin, args.collector_response_drain, args.navigation_only,
               args.localhost_origin, args.diagnostic_go_netlog, args.callsite_study, args.collector_cache_control,
               args.rtc_contract_study, args.input_contract_study, args.headless_repeat_study, args.headless_first_call_study,
               args.resize_contract_study, args.vary_claims, args.private_address)
    else:
        sys.path.insert(0, str(ROOT))
        if not args.host or not args.directory:
            parser.error("--host and previously validated --directory required")
        sys.exit(local(args.host, args.directory.resolve(), args.vendors, args.repeats, args.tailnet_origin,
                       args.collector_response_drain, args.navigation_only, args.localhost_origin, args.diagnostic_go_netlog,
                       args.callsite_study, args.collector_cache_control, args.rtc_contract_study,
                       args.worker, args.ssh_control_path, args.input_contract_study, args.headless_repeat_study,
                       args.headless_first_call_study, args.resize_contract_study, args.vary_claims,
                       args.output_root, args.assets_directory))
