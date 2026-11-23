#!/usr/bin/env python3
"""
Sycope Monitoring - Zabbix External Check Script
Version: 2.0
Tested with Sycope 3.x API

Usage:
  sycope_check.py <sycope_ip> <check_type> <monitored_ip> [extra_args...]

Check types for a monitored host (template "Sycope Monitoring", <monitored_ip> = host IP):
  host_alerts       <last_minutes> [alert_name...]  all alerts of the host in one query: totals,
                                                    severity counts and per-name counts
  active_services   <last_days> <disable_nat_ports>
  matched_ips       <last_minutes>
  connections       <last_minutes>
  alert_count       <alert_name> <include_client_ip> <last_minutes>   (1.x, one alert name)
  any_alerts        <last_minutes>                                    (1.x, severity counts)

Check types for the Sycope appliance itself, no IP filter (template "Sycope Appliance",
<monitored_ip> is not used, pass "-"):
  appliance_health  <last_minutes>   CPU, memory, disks, flow collection, indexing, event bus
  appliance_traffic <last_minutes> <exporter_hours>   total traffic and flow exporters
  appliance_alerts  <last_minutes>   alerts in the whole network and Sycope notifications

Each check prints one JSON document. The templates read it with one master item per check and
dependent items, so one check run feeds all its items.

Credentials via environment variables (or /etc/zabbix/sycope.conf):
  SYCOPE_USER
  SYCOPE_PASSWORD

Session reuse (optional settings, same places):
  SYCOPE_SESSION_TTL   seconds a Sycope session is reused by all checks (default 600, 0 = log in
                       and out on every check, the behaviour of version 1.0)
  SYCOPE_SESSION_DIR   directory of the session cache file (default: system temp directory)
  SYCOPE_HTTP_TIMEOUT  seconds to wait for each Sycope API response (default 5), so a stalled
                       appliance fails the check before the Zabbix item timeout

Returns JSON: {"value": <int>, "message": "<str>"}
"""

import sys
import os
import json
import time
import hashlib
import tempfile
import urllib.request
import urllib.error
import ssl
import datetime

def load_config_file(path='/etc/zabbix/sycope.conf'):
    """Parse a simple KEY=VALUE config file into environment variables."""
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)

load_config_file()

def get_credentials():
    user = os.environ.get('SYCOPE_USER', '')
    password = os.environ.get('SYCOPE_PASSWORD', '')
    if not user or not password:
        print(json.dumps({"error": "SYCOPE_USER or SYCOPE_PASSWORD env vars not set"}))
        sys.exit(1)
    return user, password

def http_timeout():
    try:
        return float(os.environ.get('SYCOPE_HTTP_TIMEOUT', '5'))
    except ValueError:
        return 5.0

def make_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def api_post(base_url, path, payload, cookie=None):
    ctx = make_ssl_context()
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        f"{base_url}{path}",
        data=data,
        headers={'Content-Type': 'application/json'}
    )
    if cookie:
        req.add_header('Cookie', cookie)
    with urllib.request.urlopen(req, context=ctx, timeout=http_timeout()) as resp:
        body = resp.read().decode('utf-8')
        # capture Set-Cookie header for session
        set_cookie = resp.getheader('Set-Cookie', '')
        return json.loads(body), set_cookie

def api_get(base_url, path, cookie=None):
    ctx = make_ssl_context()
    req = urllib.request.Request(f"{base_url}{path}")
    if cookie:
        req.add_header('Cookie', cookie)
    with urllib.request.urlopen(req, context=ctx, timeout=http_timeout()) as resp:
        return resp.read().decode('utf-8')

def login(base_url, user, password):
    payload = {"username": user, "password": password}
    try:
        resp, set_cookie = api_post(base_url, "/npm/api/v1/login", payload)
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode('utf-8', 'replace')).get('message', '')
        except Exception:
            detail = ''
        raise RuntimeError(f"Sycope login failed (HTTP {e.code}) {detail}".strip())
    # Extract session cookie
    cookie = None
    if set_cookie:
        cookie = set_cookie.split(';')[0]
    return cookie

def session_ttl():
    try:
        return max(0, int(os.environ.get('SYCOPE_SESSION_TTL', '600')))
    except ValueError:
        return 600

def session_cache_path(base_url, user):
    key = hashlib.sha256(f"{base_url}|{user}".encode('utf-8')).hexdigest()[:16]
    directory = os.environ.get('SYCOPE_SESSION_DIR') or tempfile.gettempdir()
    return os.path.join(directory, f"sycope_check_{key}.session")

def load_cached_cookie(path, ttl):
    """Session cookie saved by a previous check, or None when missing/expired/unreadable."""
    try:
        if time.time() - os.path.getmtime(path) >= ttl:
            return None
        with open(path) as f:
            return f.read().strip() or None
    except OSError:
        return None

def save_cookie(path, cookie):
    """Store the cookie atomically, readable only by the Zabbix user (it is a session token)."""
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(cookie)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass

def drop_cookie(path):
    try:
        os.unlink(path)
    except OSError:
        pass

def is_auth_error(exc):
    """True when Sycope rejected the request because the session is no longer valid.
    An expired session gets HTTP 401; the first request after it was invalidated may get
    HTTP 400 "Invalid username or password."."""
    if not isinstance(exc, urllib.error.HTTPError):
        return False
    if exc.code == 401:
        return True
    if exc.code == 400:
        try:
            return 'invalid username or password' in exc.read().decode('utf-8', 'replace').lower()
        except Exception:
            return False
    return False

def logout(base_url, cookie):
    try:
        api_get(base_url, "/npm/api/v1/logout", cookie=cookie)
    except Exception:
        pass

def make_timestamps(minutes_back=None, days_back=None):
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    end_time = "@" + now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if minutes_back is not None:
        start = now - datetime.timedelta(minutes=int(minutes_back))
    elif days_back is not None:
        start = now - datetime.timedelta(days=int(days_back))
    else:
        start = now - datetime.timedelta(minutes=15)
    start_time = "@" + start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return start_time, end_time

def run_nql(base_url, cookie, nql, start_time, end_time, limit=50000):
    """Run an NQL query and return all result rows."""
    payload = {
        "startTime": start_time,
        "endTime": end_time,
        "nql": nql,
        "fsActive": False,
        "waitTime": 30000,
        "limit": limit
    }
    resp, _ = api_post(base_url, "/npm/api/v1/pipeline/run", payload, cookie=cookie)
    job_id = resp.get("jobId")
    total = resp.get("data", {}).get("total", 0) or 0

    all_data = []
    import math
    pages = math.ceil(total / limit) if total > 0 else 1
    for offset_idx in range(pages):
        data_payload = {"limit": limit, "offset": offset_idx * limit}
        data_resp, _ = api_post(base_url, f"/npm/api/v1/pipeline/{job_id}/data", data_payload, cookie=cookie)
        chunk = data_resp.get("data", []) or []
        all_data.extend(chunk)
    return all_data

def check_alert_count(base_url, cookie, ip, alert_name, include_client, last_minutes):
    start_time, end_time = make_timestamps(minutes_back=last_minutes)
    if include_client in ('true', '1', 'True', True):
        nql = f'src stream="alerts" | clientIp = "{ip}" or serverIp = "{ip}" | alertName = "{alert_name}"'
    else:
        nql = f'src stream="alerts" | serverIp = "{ip}" | alertName = "{alert_name}"'

    rows = run_nql(base_url, cookie, nql, start_time, end_time)
    total = len(rows)
    seen = sum(1 for r in rows if str(r.get("alertSeen", "")).lower() == "true")
    false_pos = sum(1 for r in rows if str(r.get("alertFalsePositive", "")).lower() == "true")
    return {
        "value": total,
        "message": f"Total: {total}, Acknowledged: {seen}, False Positive: {false_pos}"
    }

def check_any_alerts(base_url, cookie, ip, last_minutes):
    start_time, end_time = make_timestamps(minutes_back=last_minutes)
    nql = (
        f'src stream="alerts" | clientIp = "{ip}" or serverIp = "{ip}" | '
        'aggr count=count(1) by alertName, alertSeverity unwind=true | '
        'sort count desc | limit 100'
    )
    rows = run_nql(base_url, cookie, nql, start_time, end_time)

    total = sum(int(r.get("count", 0) or 0) for r in rows)

    severity_counts = {}
    for r in rows:
        sev = str(r.get("alertSeverity") or "Unknown").capitalize()
        severity_counts[sev] = severity_counts.get(sev, 0) + int(r.get("count", 0) or 0)

    alert_parts = []
    for r in rows:
        name = r.get("alertName", "Unknown")
        cnt = int(r.get("count", 0) or 0)
        sev = str(r.get("alertSeverity") or "?").capitalize()
        alert_parts.append(f"{name} [{sev}]: {cnt}")

    sev_summary = ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))
    alert_summary = " | ".join(alert_parts) if alert_parts else "No alerts"

    return {
        "value": total,
        "severity_critical": severity_counts.get("Critical", 0),
        "severity_high":     severity_counts.get("High", 0),
        "severity_medium":   severity_counts.get("Medium", 0),
        "severity_low":      severity_counts.get("Low", 0),
        "severity_info":     severity_counts.get("Info", 0),
        "message": f"Total: {total} | {sev_summary} | {alert_summary}"
    }

def check_active_services(base_url, cookie, ip, last_days, disable_nat_ports):
    start_time, end_time = make_timestamps(days_back=last_days)
    nql = (
        f'src stream="assetNetflowAggr" | serverIp="{ip}" | '
        'aggr total=count(1) by serverPort as serverPortName, '
        'lookup("app", "name", {"ip": serverIp, "port": serverPort}) as appName unwind=true | '
        'sort serverPortName asc | limit 1000'
    )
    rows = run_nql(base_url, cookie, nql, start_time, end_time)
    if disable_nat_ports in ('true', '1', 'True', True):
        rows = [r for r in rows if int(r.get("serverPortName", 0)) < 49152]

    parts = []
    for r in rows:
        port = r.get("serverPortName", "?")
        app = r.get("appName") or "not defined"
        parts.append(f"{port} ({app})")
    count = len(rows)
    return {
        "value": count,
        "message": ", ".join(parts) if parts else "No active services found"
    }

def check_matched_ips(base_url, cookie, ip, last_minutes):
    """Distinct client and server IPs of the host's inbound traffic, split by whether the traffic
    matches a traffic profile and by the privacy of the address.

    Two queries (matched, unmatched) grouped by client and server privacy; version 1.x ran one
    query per output field (8). The server side has a single address (the host), so the server
    counts are 0 or 1."""
    start_time, end_time = make_timestamps(minutes_back=last_minutes)
    privacy = 'if(eq(lookup("hosts & subnets", "privacy", {{"cidr": {0}}}), "Private"): "Private", "Public")'
    results = {}
    for label, cond in (("Matched", "!="), ("Unmatched", "=")):
        nql = (
            'src stream="assetNetflowAggr" | set assetProfileNames=matchingTrafficProfiles(clientIp,serverIp,'
            f'serverPort,protocol,name=true includeAny=true) | assetProfileNames {cond} [] | serverIp = "{ip}" | '
            f'set clientPrivacy={privacy.format("clientIp")} | set serverPrivacy={privacy.format("serverIp")} | '
            'aggr dcClientIp=dc(clientIp) by clientPrivacy, serverPrivacy unwind=true | limit 1000'
        )
        rows = run_nql(base_url, cookie, nql, start_time, end_time)
        for side in ("Public", "Private"):
            results[f"{label}_Client_{side}_IPs"] = sum(
                int(_num(r.get("dcClientIp"))) for r in rows if r.get("clientPrivacy") == side)
            results[f"{label}_Server_{side}_IPs"] = 1 if any(r.get("serverPrivacy") == side for r in rows) else 0
    return results

def check_connections(base_url, cookie, ip, last_minutes):
    start_time, end_time = make_timestamps(minutes_back=last_minutes)
    queries = [
        ("Connections_From_Node",
         f'src stream="assetNetflowAggr" | clientIp = "{ip}" | set Privacy=if(eq(lookup("hosts & subnets", "privacy", {{"cidr": serverIp}}), "Private"): "Private", "Public") | aggr Counter=dc(serverIp) by Privacy as Privacy unwind=true | limit 1000'),
        ("Connections_To_Node",
         f'src stream="assetNetflowAggr" | serverIp="{ip}" | aggr Counter=dc(clientIp), Privacy=first(if(eq(lookup("hosts & subnets", "privacy", {{"cidr": clientIp}}), "Private"): "Private", "Public")) unwind=true | limit 1000'),
    ]
    results = {}
    for name, nql in queries:
        rows = run_nql(base_url, cookie, nql, start_time, end_time)
        priv = next((int(r.get("Counter", 0) or 0) for r in rows if r.get("Privacy") == "Private"), 0)
        pub = next((int(r.get("Counter", 0) or 0) for r in rows if r.get("Privacy") == "Public"), 0)
        results[f"Private_{name}"] = priv
        results[f"Public_{name}"] = pub
    return results


def check_host_alerts(base_url, cookie, ip, last_minutes, alert_names):
    """All alerts of the host (client or server side) in one query.

    Replaces one alert_count query per alert name plus the any_alerts query of version 1.x.
    by_name holds every requested name (0 when absent) and every name seen in the window."""
    start_time, end_time = make_timestamps(minutes_back=last_minutes)
    nql = (
        f'src stream="alerts" | clientIp = "{ip}" or serverIp = "{ip}" | '
        'aggr count=count(1) by alertName, alertSeverity, alertSeen, alertFalsePositive unwind=true | '
        'limit 10000'
    )
    rows = run_nql(base_url, cookie, nql, start_time, end_time)

    by_name = {n: {"value": 0, "seen": 0, "false_positive": 0, "severity": {}} for n in alert_names}
    severity_counts = {}
    for r in rows:
        cnt = int(r.get("count", 0) or 0)
        name = r.get("alertName") or "Unknown"
        sev = str(r.get("alertSeverity") or "Unknown").capitalize()
        entry = by_name.setdefault(name, {"value": 0, "seen": 0, "false_positive": 0, "severity": {}})
        entry["value"] += cnt
        if str(r.get("alertSeen", "")).lower() == "true":
            entry["seen"] += cnt
        if str(r.get("alertFalsePositive", "")).lower() == "true":
            entry["false_positive"] += cnt
        entry["severity"][sev] = entry["severity"].get(sev, 0) + cnt
        severity_counts[sev] = severity_counts.get(sev, 0) + cnt

    for entry in by_name.values():
        entry["message"] = (f"Total: {entry['value']}, Acknowledged: {entry['seen']}, "
                            f"False Positive: {entry['false_positive']}")

    total = sum(severity_counts.values())
    seen_names = sorted(((n, e) for n, e in by_name.items() if e["value"]),
                        key=lambda x: (-x[1]["value"], x[0]))
    alert_parts = [f"{n} [{'/'.join(sorted(e['severity']))}]: {e['value']}" for n, e in seen_names]
    sev_summary = ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))
    return {
        "value": total,
        "severity_critical": severity_counts.get("Critical", 0),
        "severity_high":     severity_counts.get("High", 0),
        "severity_medium":   severity_counts.get("Medium", 0),
        "severity_low":      severity_counts.get("Low", 0),
        "severity_info":     severity_counts.get("Info", 0),
        "by_name": by_name,
        "message": f"Total: {total} | {sev_summary} | " + (" | ".join(alert_parts) if alert_parts else "No alerts"),
    }


# ---------------------------------------------------------------------------
# Sycope appliance (template "Sycope Appliance"): whole-system data, no IP filter
# ---------------------------------------------------------------------------

def minute_window(last_minutes, now=None):
    """Window of whole minutes that ends one minute before the current minute, so the 1-minute
    aggregates and per-minute metrics in it are complete. Returns (start, end, seconds)."""
    now = now or datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    end = now.replace(second=0, microsecond=0) - datetime.timedelta(minutes=1)
    minutes = max(1, int(last_minutes))
    start = end - datetime.timedelta(minutes=minutes)
    fmt = lambda t: "@" + t.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return fmt(start), fmt(end), minutes * 60


def _num(v):
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def _latest(rows, key_field):
    """Newest row per value of key_field."""
    out = {}
    for r in rows:
        k = r.get(key_field)
        if k is None:
            continue
        if k not in out or _num(r.get("timestamp")) > _num(out[k].get("timestamp")):
            out[k] = r
    return out


# metrics stream: per-minute counters (duration 60000 ms) and point-in-time gauges (duration -1)
GAUGE_SETS = ("osCpuUtil", "devMemUtil", "osDisksUtil", "assetDnsResolver")


def summarize_health(counter_rows, gauge_rows, index_totals, index_error_rows, seconds, now_ms):
    """Build the appliance_health result from rows of the Sycope "metrics" stream."""
    by_set = {}
    for r in counter_rows:
        by_set.setdefault(r.get("metaSetName"), []).append(r)

    def total(meta, field, where=None):
        return sum(_num(r.get(field)) for r in by_set.get(meta, []) if where is None or where(r))

    decoder_total = lambda r: r.get("exporterIp") == "total"
    flows_decoded = sum(total("netflowDecoder", f, decoder_total) for f in ("v5flows", "v9flows", "v10flows", "sflows"))
    analyzed = total("netflowAnalyzer", "flowsAnalyzed", lambda r: r.get("serviceName") == "flowAnalyzer")
    eventbus = by_set.get("eventBus", [])

    gauges = {}
    for r in gauge_rows:
        gauges.setdefault(r.get("metaSetName"), []).append(r)

    cpu_rows = list(_latest(gauges.get("osCpuUtil", []), "cpuName").values())
    cpu_util = round(100 * sum(_num(r.get("cpuUsed")) for r in cpu_rows) / len(cpu_rows), 2) if cpu_rows else -1

    mem = max(gauges.get("devMemUtil", []), key=lambda r: _num(r.get("timestamp")), default=None)
    mem_total = _num(mem.get("size")) * 1024 if mem else -1    # Sycope reports KiB
    mem_used = _num(mem.get("used")) * 1024 if mem else -1
    mem_util = round(100 * mem_used / mem_total, 2) if mem and mem_total > 0 else -1

    disks = []
    for name, r in sorted(_latest(gauges.get("osDisksUtil", []), "diskName").items()):
        size, used, avail = (_num(r.get(f)) * 1024 for f in ("diskTotalSize", "diskUsed", "diskAvail"))
        disks.append({
            "name": name, "total": size, "used": used, "free": avail,
            # like df: used / (used + available), the reserved blocks do not count as free
            "pused": round(100 * used / (used + avail), 2) if used + avail > 0 else 0,
        })

    dns = max(gauges.get("assetDnsResolver", []), key=lambda r: _num(r.get("timestamp")), default={})

    newest = max((_num(r.get("timestamp")) for r in counter_rows + gauge_rows), default=0)
    idx = index_totals[0] if index_totals else {}
    index_errors = sorted(index_error_rows, key=lambda r: -_num(r.get("errors")))
    rate = lambda v: round(v / seconds, 3)

    result = {
        "cpu_util": cpu_util,
        "memory_total": mem_total,
        "memory_used": mem_used,
        "memory_util": mem_util,
        "disks": disks,
        "netflow_udp_pps": rate(total("netflowServer", "udpPackets")),
        "netflow_udp_dropped": total("netflowServer", "udpDropped"),
        "netflow_udp_errors": total("netflowServer", "errors"),
        "flows_decoded_ps": rate(flows_decoded),
        "flows_analyzed_ps": rate(analyzed),
        "flows_filtered_out": total("netflowFilter", "filteredOut"),
        "decoder_dropped": total("netflowDecoder", "dropped", decoder_total),
        "decoder_missed_templates": total("netflowDecoder", "missedTemplates", decoder_total),
        "decoder_errors": total("netflowDecoder", "errors", decoder_total),
        "forwarder_dropped": total("netflowForwarder", "packetsDropped"),
        "index_writes_ps": rate(_num(idx.get("writes"))),
        "index_write_errors": _num(idx.get("writeErrors")),
        "index_delete_errors": _num(idx.get("deleteErrors")),
        "eventbus_rejected": sum(_num(r.get("rejected")) for r in eventbus),
        "eventbus_dead_events": sum(_num(r.get("deadEvents")) for r in eventbus),
        "eventbus_errors": sum(_num(r.get("errors")) for r in eventbus),
        "eventbus_max_queue": max((_num(r.get("maxQueueSize")) for r in eventbus), default=0),
        "source_errors": total("nettySource", "errors") + total("nettyAnalyzer", "errors"),
        "dns_servers_failed": _num(dns.get("serversFailed")) if dns else -1,
        "metrics_age": round((now_ms - newest) / 1000) if newest else -1,
    }
    problems = [f"{k}={v:g}" for k, v in result.items()
                if k in ("netflow_udp_dropped", "netflow_udp_errors", "decoder_dropped", "decoder_errors",
                         "forwarder_dropped", "index_write_errors", "index_delete_errors", "eventbus_rejected",
                         "eventbus_dead_events", "eventbus_errors", "source_errors") and v]
    if index_errors:
        problems.append("index errors: " + ", ".join(f"{r.get('indexName')}={_num(r.get('errors')):g}" for r in index_errors[:10]))
    result["message"] = ("Problems: " + "; ".join(problems)) if problems else "No collection, indexing or event bus errors"
    return result


def check_appliance_health(base_url, cookie, last_minutes):
    start_time, end_time, seconds = minute_window(last_minutes)
    counter_rows = run_nql(
        base_url, cookie,
        'src stream="metrics" | metaSetName != "indexIndexing" | '
        + " | ".join(f'metaSetName != "{m}"' for m in GAUGE_SETS) + ' | limit 50000',
        start_time, end_time)
    # gauges are written every few minutes: read a longer window and keep the newest value
    g_start, g_end = make_timestamps(minutes_back=max(15, int(last_minutes)))
    gauge_rows = run_nql(
        base_url, cookie,
        'src stream="metrics" | ' + " or ".join(f'metaSetName = "{m}"' for m in GAUGE_SETS) + ' | limit 5000',
        g_start, g_end)
    index_totals = run_nql(
        base_url, cookie,
        'src stream="metrics" | metaSetName = "indexIndexing" | aggr writes=sum(writeNum), '
        'writeErrors=sum(writeErrors), deleteErrors=sum(deleteErrors) unwind=true',
        start_time, end_time)
    index_error_rows = []
    if index_totals and (_num(index_totals[0].get("writeErrors")) or _num(index_totals[0].get("deleteErrors"))):
        index_error_rows = run_nql(
            base_url, cookie,
            'src stream="metrics" | metaSetName = "indexIndexing" | writeErrors > 0 or deleteErrors > 0 | '
            'aggr writeErrors=sum(writeErrors), deleteErrors=sum(deleteErrors) by indexName unwind=true | limit 100',
            start_time, end_time)
        for r in index_error_rows:
            r["errors"] = _num(r.get("writeErrors")) + _num(r.get("deleteErrors"))
    now_ms = time.time() * 1000
    return summarize_health(counter_rows, gauge_rows, index_totals, index_error_rows, seconds, now_ms)


def summarize_traffic(total_rows, active_rows, known_rows, seconds):
    t = total_rows[0] if total_rows else {}
    nbytes = _num(t.get("clientBytes")) + _num(t.get("serverBytes"))
    packets = _num(t.get("clientPackets")) + _num(t.get("serverPackets"))
    active = {r.get("exporterIp"): r for r in active_rows if r.get("exporterIp")}
    known = sorted({r.get("exporterIp") for r in known_rows if r.get("exporterIp")} | set(active))
    exporters = []
    for ip in known:
        r = active.get(ip, {})
        exporters.append({
            "ip": ip,
            "bps": round(8 * _num(r.get("bytes")) / seconds, 3),
            "pps": round(_num(r.get("packets")) / seconds, 3),
            "fps": round(_num(r.get("flows")) / seconds, 3),
            "active": 1 if ip in active else 0,
        })
    silent = [e["ip"] for e in exporters if not e["active"]]
    return {
        "bps": round(8 * nbytes / seconds, 3),
        "pps": round(packets / seconds, 3),
        "flows_ps": round(_num(t.get("flows")) / seconds, 3),
        "sessions_ps": round(_num(t.get("sessions")) / seconds, 3),
        "exporters_active": len(active),
        "exporters_known": len(known),
        "exporters_silent": len(silent),
        "exporters": exporters,
        "message": ("Silent exporters: " + ", ".join(silent)) if silent else f"All {len(known)} exporters sending",
    }


def check_appliance_traffic(base_url, cookie, last_minutes, exporter_hours):
    start_time, end_time, seconds = minute_window(last_minutes)
    total_rows = run_nql(
        base_url, cookie,
        'src stream="netflowTotalAggr" | aggr clientBytes=sum(clientBytes), serverBytes=sum(serverBytes), '
        'clientPackets=sum(clientPackets), serverPackets=sum(serverPackets), flows=sum(flows), '
        'sessions=sum(sessions) unwind=true',
        start_time, end_time)
    by_exporter = ('src stream="netflowByExporterAggr" | aggr bytes=sum(bytes), packets=sum(packets), '
                   'flows=sum(flows) by exporterIp unwind=true | limit 10000')
    active_rows = run_nql(base_url, cookie, by_exporter, start_time, end_time)
    k_start, k_end = make_timestamps(minutes_back=max(1, int(exporter_hours)) * 60)
    known_rows = run_nql(
        base_url, cookie,
        'src stream="netflowByExporterAggr" | aggr flows=sum(flows) by exporterIp unwind=true | limit 10000',
        k_start, k_end)
    return summarize_traffic(total_rows, active_rows, known_rows, seconds)


def summarize_alerts(alert_rows, notification_rows, top=10):
    severity_counts, by_name = {}, {}
    for r in alert_rows:
        cnt = int(_num(r.get("count")))
        sev = str(r.get("alertSeverity") or "Unknown").capitalize()
        severity_counts[sev] = severity_counts.get(sev, 0) + cnt
        name = r.get("alertName") or "Unknown"
        by_name[name] = by_name.get(name, 0) + cnt
    levels, notes = {}, []
    for r in notification_rows:
        cnt = int(_num(r.get("count")))
        level = str(r.get("level") or "Unknown").capitalize()
        levels[level] = levels.get(level, 0) + cnt
        if level in ("Error", "Critical", "Warning"):
            notes.append(f"[{level}] {r.get('source') or '?'}: {r.get('message') or ''}")
    total = sum(severity_counts.values())
    top_names = sorted(by_name.items(), key=lambda x: (-x[1], x[0]))[:top]
    return {
        "value": total,
        "severity_critical": severity_counts.get("Critical", 0),
        "severity_high":     severity_counts.get("High", 0),
        "severity_medium":   severity_counts.get("Medium", 0),
        "severity_low":      severity_counts.get("Low", 0),
        "severity_info":     severity_counts.get("Info", 0),
        "alert_names": len(by_name),
        "message": f"Total: {total} | " + ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))
                   + " | " + (" | ".join(f"{n}: {c}" for n, c in top_names) if top_names else "No alerts"),
        "notifications_error": levels.get("Error", 0) + levels.get("Critical", 0),
        "notifications_warning": levels.get("Warning", 0),
        "notifications_info": levels.get("Info", 0),
        "notifications_message": " | ".join(sorted(set(notes))) if notes else "No warnings or errors",
    }


def check_appliance_alerts(base_url, cookie, last_minutes):
    start_time, end_time = make_timestamps(minutes_back=last_minutes)
    alert_rows = run_nql(
        base_url, cookie,
        'src stream="alerts" | aggr count=count(1) by alertName, alertSeverity unwind=true | limit 10000',
        start_time, end_time)
    notification_rows = run_nql(
        base_url, cookie,
        'src stream="notifications" | aggr count=count(1) by level, source, message unwind=true | limit 1000',
        start_time, end_time)
    return summarize_alerts(alert_rows, notification_rows)


def run_check(base_url, cookie, check_type, monitored_ip, extra):
    if check_type in ("alert_count", "alert_count_msg"):
        alert_name = extra[0] if len(extra) > 0 else ""
        include_client = extra[1] if len(extra) > 1 else "true"
        last_minutes = int(extra[2]) if len(extra) > 2 else 15
        result = check_alert_count(base_url, cookie, monitored_ip, alert_name, include_client, last_minutes)
        return result

    elif check_type in ("active_services", "active_services_msg"):
        last_days = int(extra[0]) if len(extra) > 0 else 7
        disable_nat = extra[1] if len(extra) > 1 else "true"
        result = check_active_services(base_url, cookie, monitored_ip, last_days, disable_nat)
        return result

    elif check_type == "matched_ips":
        last_minutes = int(extra[0]) if len(extra) > 0 else 60
        result = check_matched_ips(base_url, cookie, monitored_ip, last_minutes)
        return result

    elif check_type == "connections":
        last_minutes = int(extra[0]) if len(extra) > 0 else 30
        result = check_connections(base_url, cookie, monitored_ip, last_minutes)
        return result

    elif check_type == "host_alerts":
        last_minutes = int(extra[0]) if len(extra) > 0 and extra[0].isdigit() else 15
        names = [n for n in extra[1:] if n]
        return check_host_alerts(base_url, cookie, monitored_ip, last_minutes, names)

    elif check_type == "appliance_health":
        last_minutes = int(extra[0]) if len(extra) > 0 and extra[0].isdigit() else 5
        return check_appliance_health(base_url, cookie, last_minutes)

    elif check_type == "appliance_traffic":
        last_minutes = int(extra[0]) if len(extra) > 0 and extra[0].isdigit() else 5
        exporter_hours = int(extra[1]) if len(extra) > 1 and extra[1].isdigit() else 24
        return check_appliance_traffic(base_url, cookie, last_minutes, exporter_hours)

    elif check_type == "appliance_alerts":
        last_minutes = int(extra[0]) if len(extra) > 0 and extra[0].isdigit() else 5
        return check_appliance_alerts(base_url, cookie, last_minutes)

    elif check_type in ("any_alerts", "any_alerts_msg"):
        # extra[0] = minutes, extra[1] = optional severity suffix (ignored - preprocessing handles extraction)
        last_minutes = int(extra[0]) if len(extra) > 0 and extra[0].isdigit() else 15
        result = check_any_alerts(base_url, cookie, monitored_ip, last_minutes)
        return result

    else:
        raise ValueError(f"Unknown check_type: {check_type}")



def main():
    if len(sys.argv) < 4:
        print(json.dumps({"error": "Usage: sycope_check.py <sycope_ip> <check_type> <monitored_ip> [args...]"}))
        sys.exit(1)

    sycope_ip = sys.argv[1]
    check_type = sys.argv[2]
    monitored_ip = sys.argv[3]
    extra = sys.argv[4:]

    base_url = f"https://{sycope_ip}"
    user, password = get_credentials()

    ttl = session_ttl()
    cache = session_cache_path(base_url, user)
    cookie = None
    try:
        cookie = load_cached_cookie(cache, ttl) if ttl else None
        cached = cookie is not None
        if not cached:
            cookie = login(base_url, user, password)
            if ttl and cookie:
                save_cookie(cache, cookie)
        try:
            result = run_check(base_url, cookie, check_type, monitored_ip, extra)
        except Exception as e:
            if not (cached and is_auth_error(e)):
                raise
            # cached session expired or was invalidated: log in again once and repeat the check
            drop_cookie(cache)
            cookie = login(base_url, user, password)
            if cookie:
                save_cookie(cache, cookie)
            result = run_check(base_url, cookie, check_type, monitored_ip, extra)
        print(json.dumps(result))

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    finally:
        # a cached session stays open for the next checks; without caching, log out as before
        if cookie and not ttl:
            logout(base_url, cookie)

if __name__ == "__main__":
    main()
