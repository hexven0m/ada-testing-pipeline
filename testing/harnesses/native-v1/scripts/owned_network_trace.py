"""Bounded, private NetLog diagnostics for fresh owned GoLogin sessions only.

Raw traces stay on the browser host. Summaries omit URLs, headers, hostnames,
addresses, profile IDs and arbitrary event data. Nothing here is a detector.
"""
from collections import Counter, defaultdict
import ipaddress
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

OWNED_HOST = os.environ.get("ADA_PRIVATE_HTTPS_HOST")
MAX_BYTES = 20 * 1024 * 1024
EVENTS = {
    "URL_REQUEST_START_JOB", "URL_REQUEST_DELEGATE_CONNECTED", "PROXY_RESOLUTION_SERVICE",
    "PROXY_RESOLUTION_SERVICE_RESOLVED_PROXY_LIST", "HOST_RESOLVER_MANAGER_REQUEST",
    "HOST_RESOLVER_MANAGER_JOB", "HOST_RESOLVER_MANAGER_CACHE_HIT", "HOST_RESOLVER_MANAGER_HOSTS_HIT",
    "HOST_RESOLVER_SYSTEM_TASK", "HOST_RESOLVER_DNS_TASK", "HOST_RESOLVER_SERVICE_ENDPOINTS_UPDATED",
    "TCP_CONNECT", "TCP_CONNECT_ATTEMPT", "SSL_CONNECT", "FAILED", "CANCELLED",
}


def reserve_capture(root, value):
    """Never overwrite a file or accept a capture path outside this private stage."""
    root = root.resolve()
    path = Path(value)
    if (not re.fullmatch(r"ada-mode-diagnostic-[A-Za-z0-9]{8}", root.name) or
            path.name != "private-netlog.json" or not re.fullmatch(r"task-(?:[0-9]|1[0-9]|2[0-2])", path.parent.name) or
            path.parent.resolve().parent != root / "artifacts" or
            path.is_symlink() or path.parent.is_symlink() or path.parent.stat().st_mode & 0o077):
        raise ValueError("private-capture-contract")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    # Default capture mode strips private information. Never request sensitive
    # capture modes, raw bytes, a resolver override or security-disabled mode.
    return path, ["--log-net-log=" + str(path), "--net-log-max-size-mb=8", "--net-log-duration=20"]


def _host(value):
    if not isinstance(value, str) or len(value) > 8192:
        return None
    try:
        return urlsplit(value if "://" in value else "http://" + value).hostname
    except ValueError:
        return None


def _addresses(value, depth=0):
    if depth > 8:
        return []
    if isinstance(value, dict):
        return [item for key in ("address_list", "addresses", "address", "ip_endpoints", "ipv4_endpoints",
                                "ipv6_endpoints", "endpoints", "results")
                if key in value for item in _addresses(value[key], depth + 1)]
    if isinstance(value, list) and len(value) <= 200:
        return [item for row in value for item in _addresses(row, depth + 1)]
    if isinstance(value, str) and len(value) <= 128:
        try:
            return [ipaddress.ip_address(value)]
        except ValueError:
            try:
                return [ipaddress.ip_address(urlsplit("http://" + value).hostname)]
            except (ValueError, TypeError):
                pass
    return []


def summarize(trace):
    """Correlate source dependencies for only the exact owned tailnet hostname."""
    constants = trace.get("constants", {}) if isinstance(trace, dict) else {}
    kinds = constants.get("logEventTypes", {}) if isinstance(constants, dict) else {}
    events = trace.get("events") if isinstance(trace, dict) else None
    if (not isinstance(kinds, dict) or not kinds or not isinstance(events, list) or
            len(events) > 200000):
        return {"state": "UNKNOWN", "reason": "trace-contract", "diagnostic_only": True}
    names = {value: key for key, value in kinds.items() if type(value) is int}
    indexed, links, seeds = defaultdict(list), defaultdict(set), set()
    for event in events:
        if not isinstance(event, dict):
            continue
        source, params = event.get("source"), event.get("params", {})
        if not isinstance(source, dict) or type(source.get("id")) is not int or not isinstance(params, dict):
            continue
        sid = source["id"]
        kind = event.get("type")
        indexed[sid].append((names.get(kind) if type(kind) is int else None, params))
        if OWNED_HOST and any(_host(params.get(key)) == OWNED_HOST for key in ("host", "hostname", "url")):
            seeds.add(sid)
        dependency = params.get("source_dependency")
        if isinstance(dependency, dict) and type(dependency.get("id")) is int:
            other = dependency["id"]
            links[sid].add(other)
            links[other].add(sid)
    scoped, todo = set(seeds), list(seeds)
    while todo:
        for sid in links[todo.pop()]:
            if sid not in scoped:
                scoped.add(sid)
                todo.append(sid)
                if len(scoped) > 256:
                    return {"state": "UNKNOWN", "reason": "trace-graph-limit", "diagnostic_only": True}
    counts, errors, addresses, proxy = Counter(), Counter(), Counter(), Counter()
    for sid in scoped:
        for name, params in indexed[sid]:
            if name not in EVENTS:
                continue
            counts[name] += 1
            code = params.get("net_error")
            if type(code) is int and -999 <= code <= 0:
                errors[str(code)] += 1
            if name.startswith("HOST_RESOLVER") or name.startswith("TCP_CONNECT"):
                for address in _addresses(params):
                    category = ("expected-tailnet" if address in ipaddress.ip_network("100.64.0.0/10") else
                                "loopback" if address.is_loopback else
                                "other-private" if not address.is_global else "public")
                    addresses[category] += 1
            if name == "PROXY_RESOLUTION_SERVICE_RESOLVED_PROXY_LIST":
                value = params.get("pac_string")
                proxy["direct" if value == "DIRECT" else "other-or-unknown"] += 1
    return {"state": "observed" if seeds else "UNKNOWN", "diagnostic_only": True,
            "owned_host_sources": len(seeds), "scoped_sources": len(scoped),
            "event_counts": dict(sorted(counts.items())), "net_error_counts": dict(sorted(errors.items())),
            "address_classes": dict(sorted(addresses.items())), "proxy_classes": dict(sorted(proxy.items()))}


def read_summary(path):
    def unknown(reason):
        return {"state": "UNKNOWN", "reason": reason, "diagnostic_only": True}

    try:
        if path.is_symlink():
            return unknown("private-trace-path-rejected")
        meta = path.stat()
        if meta.st_mode & 0o077:
            return unknown("private-trace-permissions-rejected")
        if meta.st_size > MAX_BYTES:
            return unknown("private-trace-size-rejected")
        if meta.st_size == 0:
            return unknown("private-trace-empty")
        text = path.read_text()
    except (OSError, ValueError, TypeError):
        return unknown("private-trace-unavailable")
    try:
        return summarize(json.loads(text))
    except (ValueError, TypeError):
        return unknown("private-trace-json-incomplete")
