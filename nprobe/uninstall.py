#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Remove the nProbe traffic profile and its exporter bindings from Sycope.

The profile's fields are Sycope built-in fields and are never removed; flow data
already stored is not deleted.

Usage:
    python3 uninstall.py [--dry-run] [--yes]
"""

import argparse
import logging
import sys

import requests

from install import CONFIG_FILE, connect, load
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings
from sycope import netflow


def main():
    parser = argparse.ArgumentParser(description="Remove the nProbe traffic profile from Sycope")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    args = parser.parse_args()

    cfg = load_config(CONFIG_FILE, required_fields=["sycope_host", "sycope_login", "sycope_pass"])
    suppress_ssl_warnings()
    setup_logging("uninstall.log", log_level=cfg.get("log_level", "info"))
    name = cfg.get("traffic_profile_name") or load(cfg)["profile"]["name"]
    if not args.dry_run and not args.yes:
        if input(f"Remove traffic profile '{name}' from {cfg['sycope_host']}? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return

    api = None
    verb = "would remove" if args.dry_run else "removed"
    with requests.Session() as session:
        try:
            api = connect(cfg, session)
            bound = netflow.profile_exporters(api, name)
            if bound:
                if not args.dry_run:
                    netflow.assign_profile(api, name, bound, remove=True)
                logging.info(f"  binding {', '.join(bound)}: {verb}")
            if name in netflow.get_traffic_profiles(api):
                if not args.dry_run:
                    netflow.delete_traffic_profile(api, name)
                logging.info(f"  traffic profile '{name}': {verb}")
            else:
                logging.info(f"  traffic profile '{name}' does not exist")
        except (SycopeError, ValueError) as e:
            logging.error(f"Sycope API error: {e}")
            sys.exit(1)
        finally:
            if api is not None:
                api.log_out()


if __name__ == "__main__":
    main()
