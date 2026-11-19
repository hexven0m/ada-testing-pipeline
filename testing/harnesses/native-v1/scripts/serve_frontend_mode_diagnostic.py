#!/usr/bin/env python3
"""Private-interface React-page diagnosis, NOT /score or human-gate qualification.

Serves the existing template/bundle/preload and an immutable six-file candidate.
The collector records actual page answers, not expected labels. No scoring API
is implemented and no detector is called or modified by this server.
"""
from __future__ import annotations
import argparse
import errno
import hashlib
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import signal
import ssl
import threading
from urllib.parse import parse_qs, urlsplit

PRODUCTS = ("ads_power", "dolphin_anty", "gologin", "multilogin", "octo")
FILES = ("headless.js", *(p + ".js" for p in PRODUCTS))


class DiagnosticHTTPServer(ThreadingHTTPServer):
    # Chrome opens the template, bundle, CSS and six detector connections in
    # one burst. Python 3.12's default five-entry listen queue can reset the
    # last connection on macOS before a handler accepts it.
    request_queue_size = 128


COLLECTOR_DRAIN = """<script>(function () {
  const originalFetch = window.fetch;
  window.fetch = function (input, options) {
    const pending = originalFetch.call(this, input, options);
    if (input !== "/_payload") return pending;
    return pending.then(async function (response) {
      await response.arrayBuffer();
      return response;
    });
  };
}());</script>"""
RAW_HEADLESS_PAGE = b'''<!doctype html><html><head><meta charset="utf-8">
<title>ADA raw mode diagnostic</title>
<script src="/static/js/user-agent-spoof.js"></script>
<script src="/static/detections/headless.js"></script>
</head><body>Dedicated raw mode diagnostic; not a scorer or human check.</body></html>'''


def render(template, session_id, order):
    replacements = {
        "{{ ada_result_endpoint }}": "/_payload",
        "{{ ada_session_order_number }}": str(order),
        "{{ ada_session_id }}": session_id,
        "{{ ada_framework_names | tojson | safe }}": json.dumps(list(PRODUCTS)),
    }
    for old, new in replacements.items():
        if old not in template:
            raise ValueError("template-contract")
        template = template.replace(old, new)
    if "{{" in template:
        raise ValueError("unrendered-template")
    return template.encode()


def accepted_payload(value, session_id):
    if not isinstance(value, dict) or value.get("session_id") != session_id:
        return False
    order = str(value.get("order_number", ""))
    rows = value.get("results")
    return (re.fullmatch(r"(?:[0-9]|1[0-9]|2[0-2])", order) is not None and
            type(value.get("headless")) is bool and isinstance(rows, list) and
            len(rows) == 5 and all(isinstance(x, dict) and
                x.get("framework_name") in PRODUCTS and type(x.get("detected")) is bool for x in rows) and
            len({x["framework_name"] for x in rows}) == 5)


def diagnostic_tls(certificate, private_key):
    """Use an existing operator-owned certificate; never disable peer checks.

    This listener does not issue certificates or alter an existing HTTPS route.
    Certificate/key contents and paths are not included in evidence manifests.
    """
    if certificate is None and private_key is None:
        return None
    if certificate is None or private_key is None:
        raise ValueError("diagnostic-tls-pair-required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    return context


def listener_hosts(host, secondary_loopback=False, tls=False):
    """Never add a public/listen-all route or an uncertified TLS authority."""
    address = ipaddress.ip_address(host)
    if (address.version != 4 or address.is_global or address.is_unspecified or
            address.is_multicast):
        raise ValueError("private-ipv4-bind-required")
    if type(secondary_loopback) is not bool or (secondary_loopback and
            (host == "127.0.0.1" or tls)):
        raise ValueError("secondary-loopback-contract")
    return [host, "127.0.0.1"] if secondary_loopback else [host]


def bind_listeners(hosts, port, handler, tls=None):
    """Bind every interface before readiness; close all on partial failure."""
    requested = port
    for attempt in range(5):
        servers = []
        port = requested
        try:
            for host in hosts:
                server = DiagnosticHTTPServer((host, port), handler)
                servers.append(server)
                server.daemon_threads = True
                if tls is not None:
                    server.socket = tls.wrap_socket(server.socket, server_side=True)
                port = server.server_port  # Share one port across private interfaces.
            return servers
        except BaseException as error:
            for server in servers:
                server.server_close()  # Not yet serving: shutdown() would deadlock.
            # An ephemeral port free on the first interface may already be
            # occupied on the second. Never close another process's listener.
            if (requested != 0 or not servers or not isinstance(error, OSError) or
                    error.errno != errno.EADDRINUSE or attempt == 4):
                raise


def serve(candidate, templates, state, port, drain_collector_response=False, host="127.0.0.1", callsite_study=False,
          collector_cache_control="omit", tls_certificate=None, tls_private_key=None, secondary_loopback=False,
          headless_first_call_study=False):
    if type(headless_first_call_study) is not bool or (headless_first_call_study and
            (callsite_study or drain_collector_response)):
        raise ValueError("headless-first-study-contract")
    if collector_cache_control not in {"omit", "no-store"}:
        raise ValueError("collector-cache-control-contract")
    hosts = listener_hosts(host, secondary_loopback, tls_certificate is not None or tls_private_key is not None)
    tls = diagnostic_tls(tls_certificate, tls_private_key)
    state.mkdir(mode=0o700, exist_ok=False)
    if {p.name for p in candidate.glob("*.js")} != set(FILES):
        raise ValueError("candidate-contract")
    sources = {"/static/detections/" + name: (candidate / name).read_bytes() for name in FILES}
    for asset in ("js/user-agent-spoof.js", "js/main.3256c9f3.js", "css/main.c1e9ffb3.css"):
        sources["/static/" + asset] = (templates / "static" / asset).read_bytes()
    if type(callsite_study) is not bool or (callsite_study and drain_collector_response):
        raise ValueError("callsite-study-contract")
    if callsite_study:
        # Never a submission file or an injected script in the native template.
        # An explicit owned study loads this asset AFTER original predictions.
        sources["/__callsite.js"] = Path(__file__).with_name("product_callsite_helper.js").read_bytes()
    template = (templates / "index.html").read_text()
    original_template_hash = hashlib.sha256(template.encode()).hexdigest()
    if drain_collector_response:
        # Test-only capture change AFTER predictions. React ignores its fetch
        # body; consume that body to observe completed transport. Never ship
        # this hook in detector files or claim this template is unmodified.
        template = template.replace('<script defer="defer"', COLLECTOR_DRAIN + '\n<script defer="defer"')
    session_id = secrets.token_urlsafe(32)
    render(template, session_id, 0)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *_args):
            pass  # Task URLs contain a private diagnostic-session capability.

        def respond(self, code, body, kind="application/json", cache_control="no-store"):
            self.send_response(code)
            self.send_header("Content-Type", kind)
            if cache_control != "omit":
                self.send_header("Cache-Control", cache_control)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            self.close_connection = True

        def do_GET(self):
            url = urlsplit(self.path)
            if url.path in sources and not url.query:
                kind = "text/css" if url.path.endswith(".css") else "text/javascript"
                return self.respond(200, sources[url.path], kind)
            query = parse_qs(url.query, keep_blank_values=True)
            if (url.path in {"/_web", "/__headless_first"} and set(query) == {"order_number", "session_id"} and
                    query["session_id"] == [session_id] and len(query["order_number"]) == 1 and
                    re.fullmatch(r"(?:[0-9]|1[0-9]|2[0-2])", query["order_number"][0])):
                if url.path == "/__headless_first":
                    if headless_first_call_study:
                        return self.respond(200, RAW_HEADLESS_PAGE, "text/html")
                else:
                    return self.respond(200, render(template, session_id, int(query["order_number"][0])), "text/html")
            self.respond(404, b'{}')

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if self.path != "/_payload" or not 0 < length <= 16384:
                    raise ValueError
                value = json.loads(self.rfile.read(length))
                if not accepted_payload(value, session_id):
                    raise ValueError
                order = int(value["order_number"])
                record = {"diagnostic_only": True, "submission_certified": False, "order_number": order,
                          "headless": value["headless"], "submitted_framework":
                          [x["framework_name"] for x in value["results"] if x["detected"]]}
                with (state / f"payload-{order}.json").open("x") as output:
                    os.chmod(output.name, 0o600)
                    json.dump(record, output)
                # The checked-in collector's success path adds no Cache-Control.
                # Adding no-store here prevents Chromium's
                # fetch body buffering; React does not consume this response body.
                # Keep assets no-store, and retain the old header only as an
                # explicit transport-regression variant. Never rewrite verdicts.
                self.respond(200, b'null', cache_control=collector_cache_control)
            except (ValueError, TypeError, OSError):
                self.respond(422, b'{}')

    servers = bind_listeners(hosts, port, Handler, tls)
    serving = []
    previous_handlers = {}
    stop = threading.Event()
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[signum] = signal.signal(signum, lambda *_args: stop.set())
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            serving.append(server)
        with (state / "manifest.json").open("x") as output:
            os.chmod(output.name, 0o600)
            json.dump({"diagnostic_only": True, "submission_certified": False,
                   "source_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()},
                   "listener_hosts": hosts,
                   "collector_response_drain": drain_collector_response,
                   "collector_cache_control": collector_cache_control,
                   "callsite_study": callsite_study,
                   "headless_first_call_study": headless_first_call_study,
                   "tls": tls is not None,
                   "original_template_sha256": original_template_hash,
                   "template_sha256": hashlib.sha256(template.encode()).hexdigest()}, output, indent=2)
        with (state / "private-session.json").open("x") as output:
            os.chmod(output.name, 0o600)
            json.dump({"session_id": session_id, "port": servers[0].server_port}, output)
        print("Private frontend diagnostic ready; not a scorer.", flush=True)
        stop.wait()
    finally:
        for server in serving:
            server.shutdown()
        for server in servers:
            server.server_close()
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--templates", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--port", type=int, default=18094)
    parser.add_argument("--drain-collector-response", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--secondary-loopback", action="store_true",
                        help="Same private diagnostic on 127.0.0.1; no TLS or public binding")
    parser.add_argument("--callsite-study", action="store_true")
    parser.add_argument("--headless-first-call-study", action="store_true",
                        help="Separate source-pinned raw mode page; the React page stays unchanged.")
    parser.add_argument("--tls-certificate", type=Path, help="Existing trusted certificate; diagnostic only")
    parser.add_argument("--tls-private-key", type=Path, help="Local key path; never staged to another host")
    parser.add_argument("--collector-cache-control", choices=("omit", "no-store"), default="omit",
                        help="Default matches the checked-in collector; no-store reproduces the old diagnostic header")
    args = parser.parse_args()
    serve(args.candidate, args.templates, args.state, args.port, args.drain_collector_response, args.host,
          args.callsite_study, args.collector_cache_control, args.tls_certificate, args.tls_private_key,
          args.secondary_loopback, args.headless_first_call_study)
