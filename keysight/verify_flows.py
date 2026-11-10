#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Check that Keysight IxFlow records reach Sycope with the expected fields.

Checks, per exporter:
  1. configuration - custom fields defined, traffic profile exists and is bound to the exporter
  2. templates     - an IPFIX template with IxFlow elements was received; lists expected elements
                     that are missing from it and elements Sycope cannot decode (shown as 'unknown')
  3. data          - records in the netflow stream within the last N minutes and the fill rate of
                     every ix* field; server->client volume (serverBytes) is non-zero

Usage:
    python3 verify_flows.py [--exporter 10.0.0.5 ...] [--minutes 15]

Exit code: 0 = all OK, 1 = at least one FAIL, 2 = warnings only.

Script version: 1.0
"""

import argparse
import datetime
import logging
import os
import sys

import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sycope.api import SycopeApi
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings

from sycope import netflow as nf  # noqa: E402
from install import CONFIG_FILE, load_ixflow_fields

logger = logging.getLogger(__name__)

# IxFlow elements that cannot be stored as IxFlow data: the element id is a Sycope built-in field
# (Sycope ignores the PEN) or is reserved (176-179, ICMP). See docs/field_reference.md.
COLLIDING = {110, 123, 125, 127, 160, 176, 177, 178, 179, 180, 182, 183, 184, 187, 203, 207, 208, 209, 225}
# IxFlow elements known to carry meaningless values in some AppStack versions.
NOISY = {"ixDhcpClientId", "ixServiceType", "ixFramedProtocol",
         "ixQuicConnectionSetupTime", "ixQuicConnectionRoundTripTime", "ixQuicAppResponseTime"}
FMT = "@%Y-%m-%dT%H:%M:%S+00:00"


class Report:
    def __init__(self):
        self.worst = 0

    def add(self, level, msg):
        rank = {"OK": 0, "INFO": 0, "WARN": 2, "FAIL": 1}[level]
        if rank == 1 or (rank == 2 and self.worst == 0):
            self.worst = rank
        print(f"  [{level:<4}] {msg}")


def check_config(api, rep, fields, profile, exporter):
    defs = nf.get_field_defs(api)
    missing = [f["name"] for f in fields if defs.get(f["elementId"], {}).get("name") != f["name"]]
    if missing:
        rep.add("FAIL", f"custom fields not defined: {', '.join(missing)} (run install.py)")
    else:
        rep.add("OK", f"all {len(fields)} ix* custom fields are defined")
    prof = nf.get_traffic_profiles(api).get(profile)
    if prof is None:
        rep.add("FAIL", f"traffic profile '{profile}' does not exist (run install.py)")
    else:
        absent = [f["name"] for f in fields if f["elementId"] not in prof.get("fields", [])]
        if absent:
            rep.add("WARN", f"profile '{profile}' lacks: {', '.join(absent)}")
        else:
            rep.add("OK", f"traffic profile '{profile}' contains all ix* fields")
    bound = [b.get("trafficProfile") for b in nf.get_netflow_source(api)["config"].get("trafficProfiles", [])
             if b.get("exporterIp") == exporter]
    if profile in bound:
        rep.add("OK", f"profile '{profile}' is assigned to exporter {exporter}")
    else:
        rep.add("FAIL", f"exporter {exporter} uses {bound or 'no profile'} instead of '{profile}'")


def check_templates(api, rep, fields, exporter):
    tpls = nf.get_templates(api).get(exporter, [])
    if not tpls:
        rep.add("FAIL", f"no IPFIX templates received from {exporter} - check the exporter target "
                        "(collector IP, UDP/2055), firewalls and the exporter IP seen by Sycope")
        return
    names = {f["elementId"]: f["name"] for f in fields}
    ix = [t for t in tpls if any(fd["typeId"] in names for fd in t.get("fieldDefs", []))]
    rep.add("OK" if ix else "FAIL",
            f"{len(tpls)} template(s) received, {len(ix)} with IxFlow elements"
            + ("" if ix else " - enable the AppStack/IxFlow metadata in the NetFlow export profile"))
    if not ix:
        return
    seen = {fd["typeId"]: fd["name"] for t in ix for fd in t["fieldDefs"]}
    missing = [n for eid, n in names.items() if eid not in seen]
    if missing:
        rep.add("WARN", f"elements not exported by the device: {', '.join(missing)}")
    undecoded = sorted(eid for eid, n in seen.items() if n == "unknown")
    if undecoded:
        rep.add("INFO", "elements without a Sycope field (ignored): " + ", ".join(map(str, undecoded)))
    clash = sorted(eid for eid in seen if eid in COLLIDING)
    if clash:
        rep.add("INFO", "elements whose id collides with a Sycope built-in/reserved field (not usable): "
                        + ", ".join(f"{e}->{seen[e]}" for e in clash))


def check_data(api, rep, fields, exporter, minutes):
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(minutes=minutes)).strftime(FMT)
    names = [f["name"] for f in fields]
    agg = ", ".join(f"{n}=count({n})" for n in names)
    nql = (f'src stream="netflow" | where ixApplication != null '
           f'| aggr total=count(timestamp), srvBytes=sum(serverBytes), {agg} by exporterIps')
    rows = api.query_all_results(nql, start, now.strftime(FMT))
    # Sycope merges the same session seen by several exporters into one record, so the group key
    # is a list of exporter IPs (returned in "_id"); sum every group that contains this exporter.
    row = {}
    for r in rows:
        key = r.get("exporterIps", r.get("_id"))
        while isinstance(key, list) and len(key) == 1 and isinstance(key[0], list):
            key = key[0]
        if exporter in (key if isinstance(key, list) else [key]):
            for k, v in r.items():
                if isinstance(v, (int, float)):
                    row[k] = row.get(k, 0) + v
    if not row.get("total"):
        rep.add("FAIL", f"no flows with ixApplication from {exporter} in the last {minutes} min")
        return
    total = row["total"]
    rep.add("OK", f"{total} IxFlow flows from {exporter} in the last {minutes} min")
    empty, partial = [], []
    for n in names:
        pct = 100.0 * (row.get(n) or 0) / total
        if pct == 0:
            empty.append(n)
        elif pct < 50:
            partial.append(f"{n} {pct:.0f}%")
    if empty:
        rep.add("WARN", f"fields never filled: {', '.join(empty)}")
    if partial:
        rep.add("INFO", f"fields filled in <50% of flows (normal for protocol-specific fields): {', '.join(partial)}")
    if not empty:
        rep.add("OK", "every ix* field is present in the data")
    noisy = [n for n in names if n in NOISY and row.get(n)]
    if noisy:
        rep.add("INFO", f"check values of {', '.join(noisy)} - some AppStack versions fill them with "
                        "unrelated bytes (see README, Known limitations)")
    if not row.get("srvBytes"):
        rep.add("WARN", "serverBytes (server->client volume) is 0 - IxFlow sends it as PEN 3054:176/177, "
                        "which Sycope cannot store (see README, Known limitations)")


def main():
    parser = argparse.ArgumentParser(description="Verify Keysight IxFlow records in Sycope")
    parser.add_argument("--exporter", action="append", help="exporter IP (default: exporter_ips from config.json)")
    parser.add_argument("--minutes", type=int, help="look-back window for data checks")
    args = parser.parse_args()

    cfg = load_config(CONFIG_FILE, required_fields=["sycope_host", "sycope_login", "sycope_pass"])
    suppress_ssl_warnings()
    setup_logging("verify_flows.log", log_level=cfg.get("log_level", "info"))
    logging.getLogger().setLevel(max(logging.getLogger().level, logging.WARNING))  # keep the report readable

    exporters = args.exporter or cfg.get("exporter_ips", [])
    if not exporters:
        print("No exporter given: use --exporter IP or set exporter_ips in config.json")
        sys.exit(1)
    minutes = args.minutes or int(cfg.get("verify_minutes", 15))
    profile = cfg.get("traffic_profile_name", "Keysight IxFlow")
    fields = load_ixflow_fields()

    rep = Report()
    api = None
    with requests.Session() as session:
        session.headers.update({"Content-Type": "application/json"})
        try:
            api = SycopeApi(session=session, host=cfg["sycope_host"], login=cfg["sycope_login"],
                            password=cfg["sycope_pass"], api_endpoint=cfg.get("api_base", "/npm/api/v1/"))
            for exp in exporters:
                print(f"\nExporter {exp}")
                print(" Configuration")
                check_config(api, rep, fields, profile, exp)
                print(" Templates")
                check_templates(api, rep, fields, exp)
                print(" Data")
                check_data(api, rep, fields, exp, minutes)
        except SycopeError as e:
            print(f"Sycope API error: {e}")
            sys.exit(1)
        finally:
            if api is not None:
                api.log_out()
    print("\nResult:", {0: "OK", 1: "FAIL", 2: "WARNINGS"}[rep.worst])
    sys.exit(rep.worst)


if __name__ == "__main__":
    main()
