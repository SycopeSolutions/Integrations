#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configure Sycope to decode nProbe flows (L7 application, DNS, HTTP, JA3, latency,
retransmissions).

1. Creates or updates the traffic profile (Settings -> NetFlow -> Template Based Settings)
   from profiles/nprobe_profile.json. All its fields are Sycope built-in fields, so no
   custom fields are needed; the profile uses the "probe" source type.
2. Binds the profile to the nProbe exporter IPs from config.json (exporters that already
   use another profile are reported and left unchanged).
3. Imports dashboards/fields/drilldowns if the integration has them.

Usage:
    python3 install.py [--dry-run] [--sycope-3.2]

Script version: 1.0
Tested on Sycope 3.2.1 and 3.3.1 with nProbe 11.0
"""

import argparse
import logging
import os
import sys

import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sycope.api import SycopeApi  # noqa: E402
from sycope.config import load_config  # noqa: E402
from sycope.dashboards import add_install_arguments, install_components  # noqa: E402
from sycope.exceptions import SycopeError  # noqa: E402
from sycope.logging import setup_logging, suppress_ssl_warnings  # noqa: E402
from sycope import netflow  # noqa: E402

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")


def load(cfg):
    path = cfg.get("profile_file", "profiles/nprobe_profile.json")
    return netflow.load_profile(path if os.path.isabs(path) else os.path.join(SCRIPT_DIR, path))


def connect(cfg, session):
    return SycopeApi(session=session, host=cfg["sycope_host"], login=cfg["sycope_login"],
                     password=cfg["sycope_pass"], api_endpoint=cfg.get("api_base", "/npm/api/v1/"))


def main():
    parser = argparse.ArgumentParser(description="Configure Sycope for nProbe flows")
    parser.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    add_install_arguments(parser, dashboards=True)
    args = parser.parse_args()

    cfg = load_config(CONFIG_FILE, required_fields=["sycope_host", "sycope_login", "sycope_pass"])
    suppress_ssl_warnings()
    setup_logging("install.log", log_level=cfg.get("log_level", "info"))
    doc = load(cfg)
    name = cfg.get("traffic_profile_name") or doc["profile"]["name"]
    exporters = cfg.get("exporter_ips", [])
    if args.dry_run:
        logging.info("DRY RUN - nothing will be changed in Sycope")
    if not exporters:
        logging.warning("No 'exporter_ips' in config.json - the profile will not be bound to any exporter")

    api = None
    with requests.Session() as session:
        try:
            api = connect(cfg, session)
            logging.info(f"Traffic profile '{name}' and exporter binding")
            result = netflow.import_profile(api, doc, exporters, name=name, dry_run=args.dry_run, log=logging.info)
            if result["skipped"]:
                logging.warning(f"Fields not available on this Sycope: {', '.join(result['skipped'])}")
            install_components(api, SCRIPT_DIR, legacy_32=args.sycope_32, dry_run=args.dry_run,
                               dashboards=not args.skip_dashboards, log=logging.info)
            logging.info("Done. Run verify_flows.py once nProbe has sent templates and data.")
        except (SycopeError, ValueError) as e:
            logging.error(f"Sycope API error: {e}")
            sys.exit(1)
        finally:
            if api is not None:
                api.log_out()


if __name__ == "__main__":
    main()
