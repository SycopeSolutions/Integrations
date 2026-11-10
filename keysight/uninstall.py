#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Remove everything install.py created for the Keysight IxFlow integration:

1. Dashboards and their widgets (matched by name from the dashboard files)
2. Saved fields from fields/saved_fields/
3. Exporter bindings of the traffic profile, then the profile itself
4. NetFlow custom fields from fields/netflow_fields.json (only custom fields with the same name -
   built-in fields are never touched)

Data already stored in the netflow stream is not deleted.

Usage:
    python3 uninstall.py [--dry-run] [--yes] [--keep-fields] [--keep-dashboards]

Script version: 1.0
"""

import argparse
import json
import glob
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
from sycope.dashboards import dashboard_names, list_components, to_component  # noqa: E402
from install import CONFIG_FILE, DASHBOARDS_DIR, SAVED_FIELDS_DIR, backup, load_ixflow_fields

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Remove the Keysight IxFlow configuration from Sycope")
    parser.add_argument("--dry-run", action="store_true", help="list what would be removed")
    parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    parser.add_argument("--keep-fields", action="store_true", help="keep NetFlow custom fields and the profile")
    parser.add_argument("--keep-dashboards", action="store_true", help="keep dashboards and saved fields")
    args = parser.parse_args()

    cfg = load_config(CONFIG_FILE, required_fields=["sycope_host", "sycope_login", "sycope_pass"])
    suppress_ssl_warnings()
    setup_logging("uninstall.log", log_level=cfg.get("log_level", "info"))
    profile = cfg.get("traffic_profile_name", "Keysight IxFlow")

    if not args.dry_run and not args.yes:
        answer = input(f"Remove Keysight IxFlow dashboards, saved fields, profile '{profile}' and fields "
                       f"from {cfg['sycope_host']}? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return

    verb = "would remove" if args.dry_run else "removed"
    api = None
    with requests.Session() as session:
        session.headers.update({"Content-Type": "application/json"})
        try:
            api = SycopeApi(session=session, host=cfg["sycope_host"], login=cfg["sycope_login"],
                            password=cfg["sycope_pass"], api_endpoint=cfg.get("api_base", "/npm/api/v1/"))
            if not args.dry_run:
                backup(api)

            if not args.keep_dashboards:
                comps = {(c["type"], c["name"]): c["id"] for c in list_components(api)}
                names = set()
                for path in glob.glob(os.path.join(DASHBOARDS_DIR, "*.json")):
                    dname, wnames = dashboard_names(path)
                    names.add(("dashboard", dname))
                    names.update(("visualization", w) for w in wnames)
                for path in glob.glob(os.path.join(SAVED_FIELDS_DIR, "*.json")):
                    names.add(("savedFields", to_component(json.load(open(path, encoding="utf-8")))["name"]))
                # dashboards first, so widgets are no longer referenced when deleted
                for key in sorted(names, key=lambda k: k[0] != "dashboard"):
                    if key in comps:
                        if not args.dry_run:
                            api.request("DELETE", f"component/{comps[key]}")
                        logging.info(f"  {key[0]:<13} {key[1]}: {verb}")

            if not args.keep_fields:
                src = nf.get_netflow_source(api)
                bound = [b["exporterIp"] for b in src["config"].get("trafficProfiles", [])
                         if b.get("trafficProfile") == profile]
                if bound:
                    if not args.dry_run:
                        nf.assign_profile(api, profile, bound, remove=True)
                    logging.info(f"  profile binding {', '.join(bound)}: {verb}")
                if profile in nf.get_traffic_profiles(api):
                    if not args.dry_run:
                        nf.delete_traffic_profile(api, profile)
                    logging.info(f"  traffic profile '{profile}': {verb}")
                existing = nf.get_field_defs(api)
                for f in load_ixflow_fields():
                    cur = existing.get(f["elementId"])
                    if cur and cur.get("name") == f["name"] and not cur.get("builtIn"):
                        if not args.dry_run:
                            nf.delete_field_def(api, f["elementId"])
                        logging.info(f"  field {f['elementId']:>3} {f['name']}: {verb}")
            logging.info("Done.")
        except SycopeError as e:
            logging.error(f"Sycope API error: {e}")
            sys.exit(1)
        finally:
            if api is not None:
                api.log_out()


if __name__ == "__main__":
    main()
