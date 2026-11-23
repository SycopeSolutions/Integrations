#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for template/sycope_check.py with a fake Sycope NQL API (stdlib only). Run: python3 -m pytest zabbix/tests"""

import datetime
import os
import sys

TEMPLATE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "template"))
sys.path.insert(0, TEMPLATE_DIR)

import sycope_check as sc  # noqa: E402


class FakeNql:
    """Replaces sycope_check.run_nql: answers by the first matching substring and records the queries."""

    def __init__(self, answers):
        self.answers = answers
        self.queries = []

    def __call__(self, base_url, cookie, nql, start_time, end_time, limit=50000):
        self.queries.append(nql)
        for needle, rows in self.answers:
            if needle in nql:
                return rows
        return []


def test_host_alerts_one_query_with_names_and_severities(monkeypatch):
    fake = FakeNql([('stream="alerts"', [
        {"alertName": "Horizontal Scan", "alertSeverity": "High", "count": 3, "alertSeen": "true"},
        {"alertName": "Horizontal Scan", "alertSeverity": "High", "count": 2},
        {"alertName": "Only SYN Client TCP Flag", "alertSeverity": "medium", "count": 4, "alertFalsePositive": True},
    ])])
    monkeypatch.setattr(sc, "run_nql", fake)
    r = sc.check_host_alerts("https://s", "c", "10.0.0.5", 15, ["Vertical Scan", "Horizontal Scan"])
    assert len(fake.queries) == 1
    assert 'clientIp = "10.0.0.5" or serverIp = "10.0.0.5"' in fake.queries[0]
    assert r["value"] == 9 and r["severity_high"] == 5 and r["severity_medium"] == 4
    assert r["by_name"]["Vertical Scan"]["value"] == 0
    assert r["by_name"]["Horizontal Scan"] == {
        "value": 5, "seen": 3, "false_positive": 0, "severity": {"High": 5},
        "message": "Total: 5, Acknowledged: 3, False Positive: 0"}
    assert r["by_name"]["Only SYN Client TCP Flag"]["false_positive"] == 4
    assert r["message"].startswith("Total: 9 | High: 5, Medium: 4 | Horizontal Scan [High]: 5")


def test_matched_ips_two_queries_same_fields(monkeypatch):
    fake = FakeNql([
        ("assetProfileNames != []", [{"clientPrivacy": "Public", "serverPrivacy": "Private", "dcClientIp": 7}]),
        ("assetProfileNames = []", [{"clientPrivacy": "Private", "serverPrivacy": "Private", "dcClientIp": 3},
                                    {"clientPrivacy": "Public", "serverPrivacy": "Private", "dcClientIp": 12}]),
    ])
    monkeypatch.setattr(sc, "run_nql", fake)
    r = sc.check_matched_ips("https://s", "c", "10.0.0.5", 60)
    assert len(fake.queries) == 2
    assert r == {
        "Matched_Client_Public_IPs": 7, "Matched_Server_Public_IPs": 0,
        "Matched_Client_Private_IPs": 0, "Matched_Server_Private_IPs": 1,
        "Unmatched_Client_Public_IPs": 12, "Unmatched_Server_Public_IPs": 0,
        "Unmatched_Client_Private_IPs": 3, "Unmatched_Server_Private_IPs": 1,
    }


def test_minute_window_whole_minutes_before_current():
    now = datetime.datetime(2026, 11, 23, 10, 7, 42)
    start, end, seconds = sc.minute_window(5, now=now)
    assert (start, end, seconds) == ("@2026-11-23T10:01:00.000Z", "@2026-11-23T10:06:00.000Z", 300)


def test_summarize_health():
    counters = [
        {"metaSetName": "netflowServer", "serviceName": "netflow", "udpPackets": 600, "udpDropped": 2, "timestamp": 1000},
        {"metaSetName": "netflowServer", "serviceName": "sflow", "udpPackets": 0, "udpDropped": 0, "timestamp": 1000},
        {"metaSetName": "netflowDecoder", "exporterIp": "total", "v9flows": 300, "v10flows": 300, "dropped": 1, "timestamp": 1000},
        {"metaSetName": "netflowDecoder", "exporterIp": "10.0.0.1", "v9flows": 300, "dropped": 1, "timestamp": 1000},
        {"metaSetName": "netflowAnalyzer", "serviceName": "flowAnalyzer", "flowsAnalyzed": 540, "timestamp": 1000},
        {"metaSetName": "netflowAnalyzer", "serviceName": "assetNetflowAnalyzer", "flowsAnalyzed": 999, "timestamp": 1000},
        {"metaSetName": "eventBus", "name": "netflow", "rejected": 0, "maxQueueSize": 12, "timestamp": 1000},
        {"metaSetName": "eventBus", "name": "alert", "rejected": 4, "maxQueueSize": 40, "timestamp": 50_000},
    ]
    gauges = [
        {"metaSetName": "osCpuUtil", "cpuName": "0", "cpuUsed": 0.5, "timestamp": 1},
        {"metaSetName": "osCpuUtil", "cpuName": "0", "cpuUsed": 0.25, "timestamp": 2},
        {"metaSetName": "devMemUtil", "size": 1000, "used": 250, "timestamp": 2},
        {"metaSetName": "osDisksUtil", "diskName": "/var", "diskTotalSize": 100, "diskUsed": 45, "diskAvail": 45, "timestamp": 2},
        {"metaSetName": "assetDnsResolver", "serversFailed": 1, "timestamp": 2},
    ]
    r = sc.summarize_health(counters, gauges, [{"writes": 600, "writeErrors": 3}],
                            [{"indexName": "netflow", "errors": 3}], 60, now_ms=80_000)
    assert r["cpu_util"] == 25.0
    assert r["memory_total"] == 1024000 and r["memory_util"] == 25.0
    assert r["disks"] == [{"name": "/var", "total": 102400, "used": 46080, "free": 46080, "pused": 50.0}]
    assert r["netflow_udp_pps"] == 10.0 and r["netflow_udp_dropped"] == 2
    assert r["flows_decoded_ps"] == 10.0          # only the "total" decoder row
    assert r["decoder_dropped"] == 1
    assert r["flows_analyzed_ps"] == 9.0           # only the flowAnalyzer service
    assert r["index_writes_ps"] == 10.0 and r["index_write_errors"] == 3
    assert r["eventbus_rejected"] == 4 and r["eventbus_max_queue"] == 40
    assert r["dns_servers_failed"] == 1
    assert r["metrics_age"] == 30
    assert "index errors: netflow=3" in r["message"] and "eventbus_rejected=4" in r["message"]


def test_summarize_health_without_data():
    r = sc.summarize_health([], [], [], [], 300, now_ms=1)
    assert r["cpu_util"] == -1 and r["memory_util"] == -1 and r["metrics_age"] == -1 and r["disks"] == []
    assert r["message"] == "No collection, indexing or event bus errors"


def test_summarize_traffic_and_silent_exporters():
    total = [{"clientBytes": 1500, "serverBytes": 1500, "clientPackets": 30, "serverPackets": 30, "flows": 60, "sessions": 6}]
    active = [{"exporterIp": "10.0.0.1", "bytes": 3000, "packets": 60, "flows": 60}]
    known = [{"exporterIp": "10.0.0.1"}, {"exporterIp": "10.0.0.2"}]
    r = sc.summarize_traffic(total, active, known, 60)
    assert (r["bps"], r["pps"], r["flows_ps"], r["sessions_ps"]) == (400.0, 1.0, 1.0, 0.1)
    assert (r["exporters_active"], r["exporters_known"], r["exporters_silent"]) == (1, 2, 1)
    assert r["exporters"][1] == {"ip": "10.0.0.2", "bps": 0.0, "pps": 0.0, "fps": 0.0, "active": 0}
    assert r["message"] == "Silent exporters: 10.0.0.2"


def test_summarize_alerts_and_notifications():
    alerts = [{"alertName": "A", "alertSeverity": "High", "count": 2}, {"alertName": "B", "alertSeverity": "Low", "count": 5}]
    notes = [{"level": "Warning", "source": "LicenseAgent", "message": "expires", "count": 3},
             {"level": "Error", "source": "Indexer", "message": "disk", "count": 1}]
    r = sc.summarize_alerts(alerts, notes)
    assert r["value"] == 7 and r["severity_high"] == 2 and r["severity_low"] == 5 and r["alert_names"] == 2
    assert r["message"] == "Total: 7 | High: 2, Low: 5 | B: 5 | A: 2"
    assert (r["notifications_error"], r["notifications_warning"]) == (1, 3)
    assert r["notifications_message"] == "[Error] Indexer: disk | [Warning] LicenseAgent: expires"


def test_run_check_dispatch(monkeypatch):
    monkeypatch.setattr(sc, "run_nql", FakeNql([]))
    assert sc.run_check("https://s", "c", "host_alerts", "10.0.0.5", ["15", "X"])["by_name"]["X"]["value"] == 0
    assert sc.run_check("https://s", "c", "appliance_traffic", "-", ["5", "24"])["exporters_known"] == 0
    assert sc.run_check("https://s", "c", "appliance_alerts", "-", ["5"])["value"] == 0
    assert sc.run_check("https://s", "c", "appliance_health", "-", ["5"])["cpu_util"] == -1
