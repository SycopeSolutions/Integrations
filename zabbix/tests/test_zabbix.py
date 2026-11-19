#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for the Zabbix scripts with a fake Zabbix API (needs polars). Run: python3 -m pytest zabbix/tests"""

import os
import sys
import tempfile
from datetime import datetime, timezone

import pytest

ZABBIX_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(ZABBIX_DIR))
sys.path.insert(0, ZABBIX_DIR)

import zabbix_api  # noqa: E402
import zabbix_lookup_sync as lookup_sync  # noqa: E402
import zabbix_statistics as stats  # noqa: E402

T0 = int(datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp())


class FakeZabbix:
    """Answers host.get, item.get and history.get from in-memory data and records the calls."""

    def __init__(self, hosts=(), items=(), history=()):
        self.hosts, self.items, self.history = list(hosts), list(items), list(history)
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "host.get":
            return self.hosts
        if method == "item.get":
            hostids = set(params["hostids"])
            return [i for i in self.items if i["hostid"] in hostids]
        if method == "history.get":
            ids = set(params["itemids"])
            return [
                h
                for h in self.history
                if h["itemid"] in ids and params["time_from"] <= int(h["clock"]) <= params["time_till"]
            ]
        raise AssertionError(method)


def item(itemid, hostid, key, name="", value_type="0", preprocessing=()):
    return {
        "itemid": itemid,
        "hostid": hostid,
        "key_": key,
        "name": name,
        "value_type": value_type,
        "preprocessing": list(preprocessing),
    }


def grid(minutes=5):
    return stats.create_minute_df_pl(
        datetime.fromtimestamp(T0 + 30, timezone.utc), datetime.fromtimestamp(T0 + 30 + 60 * (minutes - 1), timezone.utc)
    )


# --- hostname --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host, expected",
    [
        ({"host": "dc02", "name": "DC02", "inventory": []}, "DC02"),  # inventory disabled
        ({"host": "z", "name": "Zabbix server", "inventory": {"name": "app2", "hostname": ""}}, "app2"),
        ({"host": "h", "name": "Visible", "inventory": {"name": "", "hostname": ""}}, "Visible"),
        ({"host": "h", "name": "", "inventory": {"name": "", "hostname": "inv"}}, "inv"),
        ({"host": "tech", "name": ""}, "tech"),
    ],
)
def test_resolve_hostname(host, expected):
    assert stats.resolve_hostname(host) == expected


# --- item selection ---------------------------------------------------------------------------------


def keys(metric, items, cfg=None):
    selected, aggregate, _ = stats.select_items(items, stats.metric_rules(cfg or {}, metric))
    return [i["key_"] for i in selected], aggregate


def test_select_agent_templates():
    linux = [
        item("1", "h", "system.cpu.load[all,avg1]"),
        item("2", "h", "system.cpu.util"),
        item("3", "h", "system.cpu.util[,user]"),
        item("4", "h", "vm.memory.utilization"),
    ]
    assert keys("cpu_load", linux)[0] == ["system.cpu.util"]  # never load average
    assert keys("memory_usage", linux)[0] == ["vm.memory.utilization"]
    windows = [item("1", "h", "system.cpu.util"), item("2", "h", "vm.memory.util")]
    assert keys("memory_usage", windows)[0] == ["vm.memory.util"]


def test_select_cisco_instances():
    cisco = [
        item("1", "h", "system.cpu.util[cpmCPUTotal5minRev.1]", "#1: CPU utilization"),
        item("2", "h", "system.cpu.util[cpmCPUTotal5minRev.7]", "#7: CPU utilization"),
        item("3", "h", "vm.memory.util[vm.memory.util.1]", "Processor: Memory utilization"),
        item("4", "h", "vm.memory.util[vm.memory.util.11]", "reserve Processor: Memory utilization"),
        item("5", "h", "vm.memory.util[vm.memory.util.2]", "I/O: Memory utilization"),
    ]
    assert keys("cpu_load", cisco) == (
        ["system.cpu.util[cpmCPUTotal5minRev.1]", "system.cpu.util[cpmCPUTotal5minRev.7]"],
        "avg",
    )
    assert keys("memory_usage", cisco) == (["vm.memory.util[vm.memory.util.1]"], "max")
    pools = [cisco[4], item("6", "h", "vm.memory.util[vm.memory.util.3]", "Other: Memory utilization")]
    assert len(keys("memory_usage", pools)[0]) == 2  # no Processor pool: all pools, max


def test_item_keys_override_and_literal_patterns():
    items = [item("1", "h", "system.cpu.util"), item("2", "h", "custom.cpu[x]")]
    cfg = {"item_keys": {"cpu_load": [{"key": "custom.cpu[*]", "aggregate": "max"}]}}
    assert keys("cpu_load", items, cfg) == (["custom.cpu[x]"], "max")
    assert not stats.key_matches("vm.memory.util[*]", "vm.memory.utilXX")
    assert not stats.key_matches("system.cpu.util", "system.cpu.util[,user]")


def test_rule_key_prefixes():
    assert stats.rule_key_prefixes({}) == [
        "icmppingloss",
        "icmppingsec",
        "system.cpu.util",
        "vm.memory.util",
        "vm.memory.utilization",
    ]


# --- value validity ---------------------------------------------------------------------------------


def test_value_max_age():
    heartbeat = [{"type": "20", "params": "5m"}]
    assert stats.value_max_age_seconds({}, {"preprocessing": heartbeat}) == 300
    assert stats.value_max_age_seconds({}, {"preprocessing": [{"type": "19", "params": ""}]}) == 3600
    assert stats.value_max_age_seconds({}, {"preprocessing": [{"type": "20", "params": "{$HB}"}]}) == 3600
    assert stats.value_max_age_seconds({}, {"preprocessing": []}) == 59
    capped = {"max_value_age_minutes": 10}
    assert stats.value_max_age_seconds(capped, {"preprocessing": [{"type": "20", "params": "1h"}]}) == 600


def test_align_nearest_and_backward():
    g = grid()
    nearest = stats.align_to_minutes(g, [((T0 + 30) * 1000, 0.1), ((T0 + 90) * 1000, 0.3)], 59)
    assert nearest.to_list() == [0.1, 0.3, None, None, None]
    backward = stats.align_to_minutes(g, [((T0 + 20) * 1000, 0.5)], 300)
    assert backward.to_list() == [0.5] * 5


# --- collection with the fake API -------------------------------------------------------------------


def lab_zabbix():
    hosts = [
        {"hostid": "10", "host": "r1", "name": "Router1", "inventory": [], "interfaces": [{"ip": "10.0.0.1", "main": "1"}]},
        {"hostid": "11", "host": "r1-copy", "name": "Copy", "inventory": [], "interfaces": [{"ip": "10.0.0.1", "main": "1"}]},
        {"hostid": "12", "host": "srv", "name": "Server", "inventory": [], "interfaces": [{"ip": "10.0.0.2", "main": "1"}, {"ip": "10.0.0.3", "main": "0"}]},
    ]
    items = [
        item("100", "10", "system.cpu.util[cpmCPUTotal5minRev.1]", "#1: CPU utilization", preprocessing=[{"type": "20", "params": "5m"}]),
        item("101", "10", "system.cpu.util[cpmCPUTotal5minRev.7]", "#7: CPU utilization", preprocessing=[{"type": "20", "params": "5m"}]),
        item("102", "10", "icmppingsec", value_type="0"),
        item("200", "12", "system.cpu.util", value_type="3"),
    ]
    history = [
        {"itemid": "100", "clock": str(T0 - 100), "value": "20"},  # before the window, valid 5 min
        {"itemid": "101", "clock": str(T0 + 25), "value": "40"},
        {"itemid": "102", "clock": str(T0 + 31), "value": "0.002"},
        {"itemid": "200", "clock": str(T0 + 29), "value": "50"},
        {"itemid": "200", "clock": str(T0 + 89), "value": "70"},  # 61 s before minute 3
    ]
    return FakeZabbix(hosts, items, history)


def test_hosts_by_ip_main_first_and_duplicates():
    hosts_by_ip, main_ips = stats.get_hosts_by_ip(lab_zabbix())
    assert hosts_by_ip["10.0.0.1"]["hostid"] == "10"  # first host wins
    assert hosts_by_ip["10.0.0.3"]["hostid"] == "12"  # additional interface still mapped
    assert main_ips == ["10.0.0.1", "10.0.0.2"]


def test_collect_metrics_bulk_requests():
    zabbix = lab_zabbix()
    cfg = {"target_ips": ["10.0.0.1", "10.0.0.2", "192.0.2.99"]}
    frames = stats.collect_metrics(zabbix, cfg, T0, T0 + 300, grid())
    methods = [m for m, _ in zabbix.calls]
    assert methods.count("host.get") == 1 and methods.count("item.get") == 1
    # one history.get per (value type, validity): float 5m, float 59s, unsigned 59s
    assert sorted((p["history"], T0 - p["time_from"]) for m, p in zabbix.calls if m == "history.get") == [
        (0, 59),
        (0, 300),
        (3, 59),
    ]
    by_ip = {f["ip"][0]: f for f in frames}
    router = by_ip["10.0.0.1"]
    assert router["hostname"][0] == "Router1"
    assert router["cpu_load"].to_list()[:2] == [0.3, 0.3]  # avg of 0.2 and 0.4, filled by heartbeat
    assert router["response_time"].to_list()[0] == 2.0
    server = by_ip["10.0.0.2"]
    assert server["cpu_load"].to_list()[:3] == [0.5, 0.7, None]  # unsigned item read too
    assert "192.0.2.99" not in by_ip


def test_inject_keeps_rows_with_any_metric():
    import polars as pl

    class Api:
        rows = None

        def inject_data(self, index, columns, rows):
            Api.rows = rows

    df = pl.DataFrame(
        {
            "timestamp": [1, 2, 3],
            "ip": ["a", "b", "c"],
            "hostname": ["A", "B", "C"],
            "response_time": [1.0, None, None],
            "cpu_load": [None, 0.5, None],
        }
    )
    stats.inject_new_data(Api(), {"index_name": "x"}, df)
    assert [r[1] for r in Api.rows] == ["a", "b"]


# --- lookup sync -------------------------------------------------------------------------------------


def test_lookup_interface_type_and_rows():
    assert lookup_sync.host_ip_and_type([{"type": "1", "ip": "10.0.0.5", "main": "1"}]) == ("10.0.0.5", "Agent")
    assert lookup_sync.host_ip_and_type(
        [{"type": "1", "ip": "10.0.0.5", "main": "1"}, {"type": "2", "ip": "10.0.0.6", "main": "0"}]
    ) == ("10.0.0.6", "SNMP")
    assert lookup_sync.host_ip_and_type([{"type": "4", "ip": "10.0.0.7", "main": "1"}]) == ("10.0.0.7", "JMX")

    hosts = [
        {"hostid": "1", "host": "dc02", "name": "DC02", "status": "0", "items": "12", "inventory": [],
         "interfaces": [{"type": "1", "ip": "10.0.0.5", "main": "1"}], "hostgroups": [{"name": "Windows"}]},
        {"hostid": "2", "host": "ping", "name": "Ping only", "status": "1", "items": "2", "inventory": [],
         "interfaces": [{"type": "1", "ip": "10.0.0.6", "main": "1"}], "hostgroups": []},
        {"hostid": "3", "host": "dns", "name": "DNS only", "status": "0", "items": "0", "inventory": [],
         "interfaces": [{"type": "1", "ip": "", "main": "1"}], "hostgroups": []},
    ]
    rows = lookup_sync.build_lookup_values(
        {"zabbix_host": "https://z/"}, hosts, {"2": ["77", "78"]}, {"2": 2}
    )
    assert [r[:3] for r in rows] == [["10.0.0.5", "DC02", "Agent"], ["10.0.0.6", "Ping only", "Agent"]]
    assert rows[0][4] == "No ICMP Items" and rows[0][5].startswith("https://z/zabbix.php")
    assert rows[1][4].endswith("itemids%5B%5D=77,78") and rows[1][5] == "No Other Items"
    assert rows[1][9] == "Disabled"


# --- API client and lock -----------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, result):
        self.result = result

    def raise_for_status(self):
        pass

    def json(self):
        return {"jsonrpc": "2.0", "result": self.result, "id": 1}


def test_logout_sends_session_and_token_never_logs_in(monkeypatch):
    sent = []

    def post(self, url, json=None, verify=None, timeout=None):
        sent.append((json["method"], self.headers.get("Authorization"), timeout))
        return FakeResponse("sess123" if json["method"] == "user.login" else True)

    monkeypatch.setattr(zabbix_api.requests.Session, "post", post)
    cfg = {"zabbix_host": "https://z", "zabbix_login": "u", "zabbix_pass": "p", "zabbix_timeout": 30}
    zabbix_api.ZabbixApi(cfg).close()
    assert sent == [("user.login", None, (10.0, 30.0)), ("user.logout", "Bearer sess123", (10.0, 30.0))]

    sent.clear()
    with zabbix_api.ZabbixApi({"zabbix_host": "https://z", "zabbix_token": "tok"}) as z:
        z.call("host.get", {})
    assert sent == [("host.get", "Bearer tok", (10.0, 60.0))]


def test_api_error_raises(monkeypatch):
    class ErrorResponse(FakeResponse):
        def json(self):
            return {"jsonrpc": "2.0", "error": {"message": "Not authorized.", "data": "Session terminated."}}

    monkeypatch.setattr(zabbix_api.requests.Session, "post", lambda *a, **k: ErrorResponse(None))
    with pytest.raises(zabbix_api.ZabbixApiError, match="Not authorized"):
        zabbix_api.ZabbixApi({"zabbix_host": "https://z", "zabbix_token": "t"}).call("host.get", {})


def test_single_instance():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "x.lock")
        with zabbix_api.single_instance(path):
            with pytest.raises(zabbix_api.AlreadyRunning):
                with zabbix_api.single_instance(path):
                    pass
        with zabbix_api.single_instance(path):  # released after the first run
            pass


def test_lookup_skips_loopback_and_invalid_ips():
    hosts = [
        {"hostid": "1", "host": "zbx", "name": "Zabbix server", "status": "0", "items": "5", "inventory": [],
         "interfaces": [{"type": "1", "ip": "127.0.0.1", "main": "1"}], "hostgroups": []},
        {"hostid": "2", "host": "bad", "name": "Bad", "status": "0", "items": "5", "inventory": [],
         "interfaces": [{"type": "1", "ip": "not-an-ip", "main": "1"}], "hostgroups": []},
        {"hostid": "3", "host": "ok", "name": "OK", "status": "0", "items": "5", "inventory": [],
         "interfaces": [{"type": "2", "ip": "2001:db8::1", "main": "1"}], "hostgroups": []},
    ]
    rows = lookup_sync.build_lookup_values({"zabbix_host": "https://z"}, hosts, {}, {})
    assert [r[0] for r in rows] == ["2001:db8::1"]


def test_lookup_not_changed_when_zabbix_returns_no_hosts(monkeypatch):
    class Zabbix:
        def __init__(self, cfg):
            pass

        def call(self, method, params):
            return []  # e.g. a token user without access to any host

        def close(self):
            pass

    touched = []
    monkeypatch.setattr(lookup_sync, "ZabbixApi", Zabbix)
    monkeypatch.setattr(lookup_sync, "SycopeApi", lambda **kw: touched.append(kw))
    lookup_sync.run({"lookup_name": "integration-zabbix", "zabbix_host": "https://z"})
    assert touched == []  # Sycope not contacted, the saved lookup stays
