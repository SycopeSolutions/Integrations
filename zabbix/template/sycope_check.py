#!/usr/bin/env python3
"""
Sycope Monitoring - Zabbix External Check Script
Version: 1.0
Tested with Sycope 3.x API

Usage:
  sycope_check.py <sycope_ip> <check_type> <monitored_ip> [extra_args...]

Check types:
  alert_count       <alert_name> <include_client_ip> <last_minutes>
  active_services   <last_days> <disable_nat_ports>
  matched_ips       <last_minutes>
  connections       <last_minutes>

Credentials via environment variables:
  SYCOPE_USER
  SYCOPE_PASSWORD

Returns JSON: {"value": <int>, "message": "<str>"}
"""

import sys
import os
import json
import time
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
    with urllib.request.urlopen(req, context=ctx) as resp:
        body = resp.read().decode('utf-8')
        # capture Set-Cookie header for session
        set_cookie = resp.getheader('Set-Cookie', '')
        return json.loads(body), set_cookie

def api_get(base_url, path, cookie=None):
    ctx = make_ssl_context()
    req = urllib.request.Request(f"{base_url}{path}")
    if cookie:
        req.add_header('Cookie', cookie)
    with urllib.request.urlopen(req, context=ctx) as resp:
        return resp.read().decode('utf-8')

def login(base_url, user, password):
    payload = {"username": user, "password": password}
    resp, set_cookie = api_post(base_url, "/npm/api/v1/login", payload)
    # Extract session cookie
    cookie = None
    if set_cookie:
        cookie = set_cookie.split(';')[0]
    return cookie

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
    start_time, end_time = make_timestamps(minutes_back=last_minutes)
    results = {}
    queries = [
        ("Matched_Client_Public_IPs",
         f'src stream="assetNetflowAggr" | set assetProfileNames=matchingTrafficProfiles(clientIp,serverIp,serverPort,protocol,name=true includeAny=true) | assetProfileNames != [] | serverIp = "{ip}" | set clientPrivacy=if(eq(lookup("hosts & subnets", "privacy", {{"cidr": clientIp}}), "Private"): "Private", "Public") | clientPrivacy = "Public" | aggr dcClientIp=dc(clientIp) unwind=true | limit 1000'),
        ("Matched_Client_Private_IPs",
         f'src stream="assetNetflowAggr" | set assetProfileNames=matchingTrafficProfiles(clientIp,serverIp,serverPort,protocol,name=true includeAny=true) | assetProfileNames != [] | serverIp = "{ip}" | set clientPrivacy=if(eq(lookup("hosts & subnets", "privacy", {{"cidr": clientIp}}), "Private"): "Private", "Public") | clientPrivacy = "Private" | aggr dcClientIp=dc(clientIp) unwind=true | limit 1000'),
        ("Matched_Server_Public_IPs",
         f'src stream="assetNetflowAggr" | set assetProfileNames=matchingTrafficProfiles(clientIp,serverIp,serverPort,protocol,name=true includeAny=true) | assetProfileNames != [] | serverIp = "{ip}" | set serverPrivacy=if(eq(lookup("hosts & subnets", "privacy", {{"cidr": serverIp}}), "Private"): "Private", "Public") | serverPrivacy = "Public" | aggr dcServerIp=dc(serverIp) unwind=true | limit 1000'),
        ("Matched_Server_Private_IPs",
         f'src stream="assetNetflowAggr" | set assetProfileNames=matchingTrafficProfiles(clientIp,serverIp,serverPort,protocol,name=true includeAny=true) | assetProfileNames != [] | serverIp = "{ip}" | set serverPrivacy=if(eq(lookup("hosts & subnets", "privacy", {{"cidr": serverIp}}), "Private"): "Private", "Public") | serverPrivacy = "Private" | aggr dcServerIp=dc(serverIp) unwind=true | limit 1000'),
        ("Unmatched_Client_Public_IPs",
         f'src stream="assetNetflowAggr" | set assetProfileNames=matchingTrafficProfiles(clientIp,serverIp,serverPort,protocol,name=true includeAny=true) | assetProfileNames = [] | serverIp = "{ip}" | set clientPrivacy=if(eq(lookup("hosts & subnets", "privacy", {{"cidr": clientIp}}), "Private"): "Private", "Public") | clientPrivacy = "Public" | aggr dcClientIp=dc(clientIp) unwind=true | limit 1000'),
        ("Unmatched_Client_Private_IPs",
         f'src stream="assetNetflowAggr" | set assetProfileNames=matchingTrafficProfiles(clientIp,serverIp,serverPort,protocol,name=true includeAny=true) | assetProfileNames = [] | serverIp = "{ip}" | set clientPrivacy=if(eq(lookup("hosts & subnets", "privacy", {{"cidr": clientIp}}), "Private"): "Private", "Public") | clientPrivacy = "Private" | aggr dcClientIp=dc(clientIp) unwind=true | limit 1000'),
        ("Unmatched_Server_Public_IPs",
         f'src stream="assetNetflowAggr" | set assetProfileNames=matchingTrafficProfiles(clientIp,serverIp,serverPort,protocol,name=true includeAny=true) | assetProfileNames = [] | set serverPrivacy=if(eq(lookup("hosts & subnets", "privacy", {{"cidr": serverIp}}), "Private"): "Private", "Public") | serverPrivacy = "Public" | serverIp = "{ip}" | aggr dcServerIp=dc(serverIp) unwind=true | limit 1000'),
        ("Unmatched_Server_Private_IPs",
         f'src stream="assetNetflowAggr" | set assetProfileNames=matchingTrafficProfiles(clientIp,serverIp,serverPort,protocol,name=true includeAny=true) | assetProfileNames = [] | serverIp = "{ip}" | set serverPrivacy=if(eq(lookup("hosts & subnets", "privacy", {{"cidr": serverIp}}), "Private"): "Private", "Public") | serverPrivacy = "Private" | aggr dcServerIp=dc(serverIp) unwind=true | limit 1000'),
    ]
    for name, nql in queries:
        rows = run_nql(base_url, cookie, nql, start_time, end_time)
        val = 0
        if rows:
            first_row = rows[0]
            first_key = list(first_row.keys())[0] if first_row else None
            if first_key:
                val = int(first_row[first_key] or 0)
        results[name] = val
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

    cookie = None
    try:
        cookie = login(base_url, user, password)
        if check_type in ("alert_count", "alert_count_msg"):
            alert_name = extra[0] if len(extra) > 0 else ""
            include_client = extra[1] if len(extra) > 1 else "true"
            last_minutes = int(extra[2]) if len(extra) > 2 else 15
            result = check_alert_count(base_url, cookie, monitored_ip, alert_name, include_client, last_minutes)
            print(json.dumps(result))

        elif check_type in ("active_services", "active_services_msg"):
            last_days = int(extra[0]) if len(extra) > 0 else 7
            disable_nat = extra[1] if len(extra) > 1 else "true"
            result = check_active_services(base_url, cookie, monitored_ip, last_days, disable_nat)
            print(json.dumps(result))

        elif check_type == "matched_ips":
            last_minutes = int(extra[0]) if len(extra) > 0 else 60
            result = check_matched_ips(base_url, cookie, monitored_ip, last_minutes)
            print(json.dumps(result))

        elif check_type == "connections":
            last_minutes = int(extra[0]) if len(extra) > 0 else 30
            result = check_connections(base_url, cookie, monitored_ip, last_minutes)
            print(json.dumps(result))

        elif check_type in ("any_alerts", "any_alerts_msg"):
            # extra[0] = minutes, extra[1] = optional severity suffix (ignored - preprocessing handles extraction)
            last_minutes = int(extra[0]) if len(extra) > 0 and extra[0].isdigit() else 15
            result = check_any_alerts(base_url, cookie, monitored_ip, last_minutes)
            print(json.dumps(result))

        else:
            print(json.dumps({"error": f"Unknown check_type: {check_type}"}))
            sys.exit(1)

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    finally:
        if cookie:
            logout(base_url, cookie)

if __name__ == "__main__":
    main()
