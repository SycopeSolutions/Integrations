#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Check that nProbe flows reach Sycope with the profile's fields.

Per exporter:
  1. the traffic profile is bound to the exporter IP Sycope sees
  2. templates were received and which profile fields they contain
  3. flows in the last N minutes and how many carry each L7/DNS/HTTP/JA3 field

Usage:
    python3 verify_flows.py [--exporter 10.0.0.5 ...] [--minutes 15]

Exit code: 0 = OK, 1 = at least one FAIL, 2 = warnings only.
"""

import argparse
import sys

import requests

from install import CONFIG_FILE, connect, load
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import suppress_ssl_warnings
from sycope import netflow

# Fields nProbe fills only for some protocols: never filled is a warning, not an error.
PROTOCOL_SPECIFIC = ("dns", "http", "ja3")


def main():
    ap = argparse.ArgumentParser(description="Verify nProbe flows in Sycope")
    ap.add_argument("--exporter", action="append", help="exporter IP (default: exporter_ips from config.json)")
    ap.add_argument("--minutes", type=int)
    args = ap.parse_args()

    cfg = load_config(CONFIG_FILE, required_fields=["sycope_host", "sycope_login", "sycope_pass"])
    suppress_ssl_warnings()
    doc = load(cfg)
    name = cfg.get("traffic_profile_name") or doc["profile"]["name"]
    doc["profile"]["name"] = name
    exporters = args.exporter or cfg.get("exporter_ips", [])
    if not exporters:
        print("No exporter given: use --exporter IP or set exporter_ips in config.json")
        sys.exit(1)
    minutes = args.minutes or int(cfg.get("verify_minutes", 15))
    fields = [f["name"] for f in doc["fields"]]
    worst = 0

    def report(level, msg):
        nonlocal worst
        if level == "FAIL":
            worst = 1
        elif level == "WARN" and worst == 0:
            worst = 2
        print(f"  [{level:<4}] {msg}")

    api = None
    with requests.Session() as session:
        try:
            api = connect(cfg, session)
            for ip in exporters:
                print(f"\nExporter {ip}")
                r = netflow.check_exporter(api, doc, ip)
                if r["bound_profile"] == name:
                    report("OK", f"traffic profile '{name}' is bound to {ip}")
                else:
                    report("FAIL", f"{ip} uses {r['bound_profile'] or 'no profile'} instead of '{name}' - "
                                   "bind it (install.py) to the exporter IP that Sycope sees")
                if not r["templates"]:
                    report("FAIL", f"no templates received from {ip} - check nProbe -n, firewall, exporter IP/NAT")
                    continue
                report("OK", f"{r['templates']} template(s), {len(r['sent'])}/{len(fields)} profile fields sent")
                if r["not_sent"]:
                    report("INFO", f"profile fields not in nProbe's template (-T): {', '.join(r['not_sent'])}")
                fill = netflow.field_fill(api, ip, r["sent"], minutes)
                if not fill["total"]:
                    report("FAIL", f"no flows from {ip} in the last {minutes} min")
                    continue
                report("OK", f"{fill['total']} flows from {ip} in the last {minutes} min")
                empty = [n for n, c in fill["fields"].items() if c == 0]
                core = [n for n in empty if not n.lower().startswith(PROTOCOL_SPECIFIC)]
                if core:
                    report("WARN", f"sent but never filled: {', '.join(core)}")
                if len(empty) > len(core):
                    report("INFO", "protocol fields not seen in this window (no such traffic?): "
                                   + ", ".join(n for n in empty if n not in core))
        except (SycopeError, ValueError) as e:
            print(f"Sycope API error: {e}")
            sys.exit(1)
        finally:
            if api is not None:
                api.log_out()
    print("\nResult:", {0: "OK", 1: "FAIL", 2: "WARNINGS"}[worst])
    sys.exit(worst)


if __name__ == "__main__":
    main()
