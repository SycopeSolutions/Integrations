#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configure Sycope to receive Keysight IxFlow (AppStack) IPFIX records.

Steps (each one is idempotent - re-running the script only adds what is missing):

1. NetFlow custom fields   - one field per supported IxFlow element (PEN 3054), fields/netflow_fields.json
2. Traffic profile         - "Template Based Settings" profile with those fields (default "Keysight IxFlow")
3. Exporter binding        - assigns the profile to the exporter IPs listed in config.json
4. Saved fields            - millisecond versions of the latency fields, fields/saved_fields/*.json
5. Dashboards              - 5 dashboards from dashboards/ (imported through the API, Sycope 3.2 and 3.3)

A JSON backup of the NetFlow configuration is written to backups/ before any change.

Usage:
    python3 install.py [--dry-run] [--skip-assign] [--skip-saved-fields] [--skip-dashboards] [--sycope-3.2]

Script version: 1.0
Tested on Sycope 3.2.1 and 3.3.1
"""

import argparse
import datetime
import glob
import json
import logging
import os
import sys

import requests

# Add parent directory to path for importing sycope modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sycope.api import SycopeApi
from sycope.config import load_config
from sycope.dashboards import install_components
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings

from sycope import netflow as nf  # noqa: E402

logger = logging.getLogger(__name__)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")
FIELDS_FILE = os.path.join(SCRIPT_DIR, "fields", "netflow_fields.json")
SAVED_FIELDS_DIR = os.path.join(SCRIPT_DIR, "fields", "saved_fields")
DASHBOARDS_DIR = os.path.join(SCRIPT_DIR, "dashboards")
BACKUP_DIR = os.path.join(SCRIPT_DIR, "backups")


def load_ixflow_fields():
    with open(FIELDS_FILE, encoding="utf-8") as fp:
        return json.load(fp)["fields"]


def backup(api):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    path = os.path.join(BACKUP_DIR, "netflow_config_%s.json" % datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    state = {
        "field_defs": list(nf.get_field_defs(api).values()),
        "traffic_profiles": list(nf.get_traffic_profiles(api).values()),
        "netflow_source": nf.get_netflow_source(api),
    }
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(state, fp, indent=2)
    logging.info(f"Backup of NetFlow configuration written to {path}")


def install_fields(api, fields, dry_run):
    """Create missing field definitions. Returns the element ids usable in the profile."""
    existing = nf.get_field_defs(api)
    usable = []
    for f in fields:
        eid = f["elementId"]
        cur = existing.get(eid)
        if cur is None:
            if not dry_run:
                nf.create_field_def(api, f)
            logging.info(f"  field {eid:>3} {f['name']:<32} {'would be created' if dry_run else 'created'}")
            usable.append(eid)
        elif cur.get("name") == f["name"]:
            logging.info(f"  field {eid:>3} {f['name']:<32} already exists")
            usable.append(eid)
        else:
            # Sycope identifies NetFlow fields by element id only (PEN is ignored), so an id that is
            # already used by another field cannot be defined again.
            logging.warning(
                f"  field {eid:>3} {f['name']:<32} SKIPPED - element id already used by "
                f"'{cur.get('name')}' ({'built-in' if cur.get('builtIn') else 'custom'})"
            )
    return usable


def main():
    parser = argparse.ArgumentParser(description="Configure Sycope for Keysight IxFlow IPFIX")
    parser.add_argument("--dry-run", action="store_true", help="show what would change, write nothing")
    parser.add_argument("--skip-assign", action="store_true", help="do not bind the profile to exporters")
    parser.add_argument("--skip-saved-fields", action="store_true", help="do not import saved fields")
    parser.add_argument("--skip-dashboards", action="store_true", help="do not import dashboards")
    parser.add_argument("--sycope-3.2", dest="sycope_32", action="store_true",
                        help="Sycope 3.2 (legacy) compatibility: convert dashboards to the 3.2 format before importing")
    args = parser.parse_args()

    try:
        cfg = load_config(CONFIG_FILE, required_fields=["sycope_host", "sycope_login", "sycope_pass"])
    except Exception as e:
        setup_logging("install.log")
        logging.error(f"Failed to load config: {e}")
        sys.exit(1)

    suppress_ssl_warnings()
    setup_logging("install.log", log_level=cfg.get("log_level", "info"))

    profile = cfg.get("traffic_profile_name", "Keysight IxFlow")
    exporters = cfg.get("exporter_ips", [])
    if args.dry_run:
        logging.info("DRY RUN - nothing will be written to Sycope")

    api = None
    with requests.Session() as session:
        session.headers.update({"Content-Type": "application/json"})
        try:
            api = SycopeApi(
                session=session,
                host=cfg["sycope_host"],
                login=cfg["sycope_login"],
                password=cfg["sycope_pass"],
                api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
            )
            if not args.dry_run:
                backup(api)

            # 1. fields
            logging.info("Step 1/5: NetFlow custom fields")
            usable = install_fields(api, load_ixflow_fields(), args.dry_run)

            # 2. traffic profile
            logging.info(f"Step 2/5: traffic profile '{profile}'")
            profile_fields = list(dict.fromkeys(cfg.get("profile_extra_fields", []) + usable))
            if args.dry_run:
                state = "exists" if profile in nf.get_traffic_profiles(api) else "would be created"
                logging.info(f"  profile {state} ({len(profile_fields)} fields)")
            else:
                state = nf.upsert_traffic_profile(api, profile, profile_fields)
                logging.info(f"  profile {state} ({len(profile_fields)} fields)")

            # 3. exporters
            logging.info("Step 3/5: exporter binding")
            if args.skip_assign:
                logging.info("  skipped (--skip-assign)")
            elif not exporters:
                logging.warning("  no 'exporter_ips' in config.json - assign the profile manually in the GUI")
            elif args.dry_run and profile not in nf.get_traffic_profiles(api):
                logging.info(f"  would assign the new profile to {', '.join(exporters)}")
            else:
                for ip, action in nf.assign_profile(api, profile, exporters, dry_run=args.dry_run):
                    level = logging.WARNING if action.startswith("SKIPPED") else logging.INFO
                    logging.log(level, f"  {ip}: {action}")

            # 4 + 5. saved fields and dashboards
            logging.info("Step 4-5/5: saved fields and dashboards"
                         + (" (Sycope 3.2 compatibility)" if args.sycope_32 else ""))
            install_components(
                api, SCRIPT_DIR, legacy_32=args.sycope_32, dry_run=args.dry_run,
                fields=not args.skip_saved_fields, drilldowns=False,
                dashboards=not args.skip_dashboards, log=logging.info,
            )

            logging.info("Done. Run verify_flows.py once the exporter has sent templates and data.")
        except (SycopeError, ValueError) as e:
            logging.error(f"Sycope API error: {e}")
            sys.exit(1)
        finally:
            if api is not None:
                api.log_out()


if __name__ == "__main__":
    main()
