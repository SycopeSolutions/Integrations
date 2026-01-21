#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
phpIPAM to Sycope Synchronization Script

This script synchronizes IP address inventory data from phpIPAM to a Sycope custom index.
It retrieves addresses, subnets, and associated metadata from phpIPAM and injects them
into Sycope for correlation, search, and visualization.

Features:
- Configurable sync modes (addresses, subnets, devices)
- Section filtering (include/exclude)
- State filtering (active, reserved, DHCP, inactive)
- Duplicate detection via Sycope query
- Comprehensive logging and error handling
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone

import pandas as pd
import requests
import urllib3
from requests import Session

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Path handling for config and modules
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "sycope"))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

# Extend path to load SycopeApi from external module
sys.path.append(PARENT_DIR)

from api import SycopeApi  # Import Sycope API wrapper
from phpipam_api import PhpipamApi

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("phpipam_sync.log"), logging.StreamHandler(sys.stdout)],
)

# State mapping from phpIPAM numeric codes to names
STATE_MAP = {
    "0": "Offline",
    "1": "Active",
    "2": "Reserved",
    "3": "DHCP",
}


def load_config():
    """Load configuration from JSON file."""
    try:
        with open(CONFIG_FILE, "r") as f:
            cfg = json.load(f)
            return cfg
    except Exception as e:
        logging.error(f"ERROR loading config:  {e}")
        sys.exit(1)
    else:
        logging.info(f"Loaded configuration from {CONFIG_FILE}")


def build_phpipam_conn(host_cfg):
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})

    """Create PhpipamApi instance from a host config dict."""
    return PhpipamApi(
        session=session,
        host=host_cfg["host"].rstrip("/"),
        app_id=host_cfg.get("app_id"),
        username=host_cfg.get("username"),
        password=host_cfg.get("password"),
        api_base=host_cfg.get("api_base", "/api"),
    )


def setup_api_connections(cfg):
    """Initialize API connections to one or more phpIPAM instances and Sycope."""
    # Sessions
    # phpipam_session = requests.Session()
    # phpipam_session.headers.update({"Content-Type": "application/json"})

    # Build list of phpipam host configs
    phpipam_hosts = []

    # Preferred modern config: phpipam_hosts (list of dicts)
    if isinstance(cfg.get("phpipam_hosts"), list) and cfg.get("phpipam_hosts"):
        phpipam_hosts = cfg.get("phpipam_hosts")
    else:
        # Backwards compatibility: single phpipam_host keys
        if cfg.get("phpipam_host"):
            phpipam_hosts = [
                {
                    "host": cfg.get("phpipam_host"),
                    "app_id": cfg.get("phpipam_app_id"),
                    "username": cfg.get("phpipam_username"),
                    "password": cfg.get("phpipam_password"),
                    "api_base": cfg.get("phpipam_api_base", "/api"),
                }
            ]

    phpipam_instances = []

    for host_cfg in phpipam_hosts:
        try:
            api = build_phpipam_conn(host_cfg)
            phpipam_instances.append(api)
            logging.info(f"Connected to phpIPAM: {host_cfg.get('host')}")
        except Exception as e:
            logging.error(f"Failed to connect to phpIPAM {host_cfg.get('host')}: {e}")


    # Connect to Sycope (one instance)
    sycope_session = requests.Session()
    sycope_session.headers.update({"Content-Type": "application/json"})
    sycope = SycopeApi(
        session=sycope_session,
        host=cfg["sycope_host"].rstrip("/"),
        login=cfg["sycope_login"],
        password=cfg["sycope_pass"],
        api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
    )

    return phpipam_instances, sycope, sycope_session


def get_section_mapping(phpipam):
    """
    Create mapping of section IDs to section names.

    Args:
        phpipam: PhpipamApi instance

    Returns:
        Dictionary mapping section ID to section name
    """
    sections = phpipam.get_all_sections()
    return {str(sec["id"]): sec["name"] for sec in sections if "id" in sec and "name" in sec}


def get_subnets(phpipam):
    """
    Create mapping of section IDs to section names.

    Args:
        phpipam: PhpipamApi instance

    Returns:
        Dictionary mapping section ID to section name
    """
    sections = phpipam.get_all_subnets()
    return sections


def get_vlan_mapping(phpipam):
    """
    Create mapping of VLAN IDs to VLAN numbers.

    Args:
        phpipam: PhpipamApi instance

    Returns:
        Dictionary mapping VLAN ID to VLAN number
    """
    vlans = phpipam.get_all_vlans()
    return {str(vlan["vlanId"]): vlan.get("number") for vlan in vlans if "vlanId" in vlan}


def get_device_mapping(phpipam):
    """
    Create mapping of device IDs to device names.

    Args:
        phpipam: PhpipamApi instance

    Returns:
        Dictionary mapping device ID to device hostname
    """
    devices = phpipam.get_all_devices()
    return {str(dev["id"]): dev.get("hostname", "") for dev in devices if "id" in dev}


def get_tag_mapping(phpipam):
    """
    Create mapping of tag IDs to tag names.

    Args:
        phpipam: PhpipamApi instance

    Returns:
        Dictionary mapping tag ID to tag type
    """
    tags = phpipam.get_all_tags()
    return {str(tag["id"]): tag.get("type", "") for tag in tags if "id" in tag}


def should_include_address(addr, cfg, section_id):
    """
    Determine if an address should be included based on filters.

    Args:
        addr: Address dictionary from phpIPAM
        cfg: Configuration dictionary
        section_id: Section ID of the address

    Returns:
        Boolean indicating if address should be included
    """
    # Check section filters
    include_sections = cfg.get("include_sections", [])
    exclude_sections = cfg.get("exclude_sections", [])

    if include_sections and section_id not in include_sections:
        return False
    if exclude_sections and section_id in exclude_sections:
        return False

    # Check state filters
    state_code = addr.get("state", "1")

    if state_code == "0" and not cfg.get("include_inactive", False):
        return False
    if state_code == "2" and not cfg.get("include_reserved", True):
        return False
    if state_code == "3" and not cfg.get("include_dhcp", True):
        return False

    return True


def fetch_from_phpipam_instance(phpipam, cfg):
    """Fetch processed address and subnet records from a single phpipam instance."""
    logging.info(f"Fetching data from phpIPAM {phpipam.host} ...")

    section_map = get_section_mapping(phpipam)
    vlan_map = get_vlan_mapping(phpipam)
    device_map = get_device_mapping(phpipam)
    tag_map = get_tag_mapping(phpipam)

    records = []

    sync_mode = cfg.get("sync_mode", "addresses")

    if sync_mode == "addresses":
        all_addresses = phpipam.get_all_addresses_all_subnets()
        logging.info(f"Retrieved {len(all_addresses)} addresses from {phpipam.host}")

        for addr in all_addresses:
            subnet_info = addr.get("subnet_info", {})
            section_id = str(subnet_info.get("section", ""))

            if not should_include_address(addr, cfg, section_id):
                continue

            # Build record
            state_code = addr.get("state", "1")
            state_name = STATE_MAP.get(state_code, "Unknown")

            vlan_id = str(subnet_info.get("vlan", "")) if subnet_info.get("vlan") else ""
            vlan_num = vlan_map.get(vlan_id) if vlan_id else None

            device_id = str(addr.get("switch", "")) if addr.get("switch") else ""
            device_name = device_map.get(device_id, "") if device_id else ""

            tag_id = str(addr.get("tag", "")) if addr.get("tag") else ""
            tag_name = tag_map.get(tag_id, "") if tag_id else ""

            # Parse last_seen timestamp
            last_seen = addr.get("lastSeen")
            last_seen_ms = None
            if last_seen:
                try:
                    dt = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                    last_seen_ms = int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)
                except:
                    pass

            record = {
                "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000),
                "ip": addr.get("ip", ""),
                "hostname": addr.get("hostname", ""),
                "description": addr.get("description", ""),
                "mac": addr.get("mac", ""),
                "owner": addr.get("owner", ""),
                "subnet": f"{subnet_info.get('subnet', '')}/{subnet_info.get('mask', '')}",
                "subnet_description": subnet_info.get("description", ""),
                "section": section_map.get(section_id, ""),
                "vlan": vlan_num,
                "device": device_name,
                "state": state_name,
                "tag": tag_name,
                "note": addr.get("note", ""),
                "last_seen": last_seen_ms,
            }
            records.append(record)

        logging.info(f"Processed {len(records)} addresses from {phpipam.host}")
        return records

    else:
        logging.error(f"Unsupported sync_mode: {sync_mode}")
        return []


def merge_lookup_data_with_summary(saved_lookup, lookupvalues_ip, lookupvalues_subnet, cfg=None):
    columns = saved_lookup["file"]["columns"]
    col_count = len(columns)

    existing = {row[0]: row for row in saved_lookup["file"]["rows"]}
    changes_summary = []
    excluded_rows = []
    updated_this_run = set()

    exclude_prefixes = cfg.get("exclude_description", []) if cfg else []

    def should_exclude(desc):
        if not desc:
            return False
        return any(desc.startswith(prefix) for prefix in exclude_prefixes)

    def new_empty_row(cidr):
        return [cidr] + [""] * (col_count - 1)

    def track_change(cidr, row, new_values, overwrite_cols):
        modified = False
        for idx, val in zip(overwrite_cols, new_values):
            if row[idx] != val:
                row[idx] = val
                modified = True
        return modified

    # ---- Process IP rows ----
    for cidr, name, description in lookupvalues_ip:
        if should_exclude(description):
            excluded_rows.append({"cidr": cidr, "description": description})
            continue

        if cidr in updated_this_run:
            # Already claimed by higher-priority phpIPAM
            continue

        updated_this_run.add(cidr)  # 🔒 lock CIDR immediately

        if cidr in existing:
            row = existing[cidr]
            modified = track_change(
                cidr,
                row,
                [cidr, name, description],
                overwrite_cols=[0, 1, 2],
            )
            changes_summary.append({
                "cidr": cidr,
                "change": "modified" if modified else "unchanged",
            })
        else:
            row = new_empty_row(cidr)
            row[0] = cidr
            row[1] = name
            row[2] = description
            existing[cidr] = row
            changes_summary.append({"cidr": cidr, "change": "added"})

    # ---- Process Subnet rows ----
    for cidr, name in lookupvalues_subnet:
        if should_exclude(name):
            excluded_rows.append({"cidr": cidr, "description": name})
            continue

        if cidr in updated_this_run:
            # Already claimed by higher-priority phpIPAM
            continue

        updated_this_run.add(cidr)  # lock CIDR immediately

        if cidr in existing:
            row = existing[cidr]
            modified = track_change(
                cidr,
                row,
                [cidr, name],
                overwrite_cols=[0, 1],
            )
            changes_summary.append({
                "cidr": cidr,
                "change": "modified" if modified else "unchanged",
            })
        else:
            row = new_empty_row(cidr)
            row[0] = cidr
            row[1] = name
            existing[cidr] = row
            changes_summary.append({"cidr": cidr, "change": "added"})

    saved_lookup["file"]["rows"] = list(existing.values())

    summary_counts = {"added": 0, "modified": 0, "unchanged": 0}
    for entry in changes_summary:
        summary_counts[entry["change"]] += 1

    return saved_lookup, changes_summary, summary_counts, excluded_rows


def main():
    logging.info("Starting phpIPAM to Sycope synchronization (multi-host)...")

    cfg = load_config()

    phpipams, sycope, sycope_session = setup_api_connections(cfg)

    try:
        # We'll collect IP records and subnets with priority: first phpipam wins.
        ip_seen = {}  # ip -> (hostname, description)

        subnet_seen = set()  # set of cidr strings like '192.168.1.0/24'

        lookupvalues_ip = []
        lookupvalues_subnet = []

        for php in phpipams:
            try:
                records = fetch_from_phpipam_instance(php, cfg)

                # Add IPs (skip duplicates if already seen)
                for r in records:
                    ip = r.get("ip")
                    if not ip or ":" in ip:
                        continue

                    if r.get("description") == "DHCP range":
                        continue

                    # FIRST phpIPAM ALWAYS WINS
                    if ip not in ip_seen:
                        ip_seen[ip] = (
                            r.get("hostname") or "",
                            r.get("description") or ""
                        )
                        lookupvalues_ip.append([
                            f"{ip}/32",
                            ip_seen[ip][0],
                            ip_seen[ip][1],
                        ])


                # Add subnets from this phpipam instance
                subnets = get_subnets(php)
                for s in subnets:
                    s_network = s.get("subnet")
                    s_mask = s.get("mask")
                    if not s_network or not s_mask:
                        continue
                    if ":" in s_network:
                        continue
                    cidr = f"{s_network}/{s_mask}"
                    if cidr in subnet_seen:
                        continue
                    subnet_seen.add(cidr)
                    if s.get("description") == "DHCP range":
                        continue
                    lookupvalues_subnet.append([cidr, s.get("description") or ""])

            except Exception as e:
                logging.error(f"Error fetching data from {php.host}: {e}")

        # For debugging - show collected lists
        df_ip = pd.DataFrame(lookupvalues_ip)
        print(df_ip)
        df_subnet = pd.DataFrame(lookupvalues_subnet)
        print(df_subnet)

        # Update Sycope lookup

        with requests.Session() as s:
            api = SycopeApi(s, cfg["sycope_host"].rstrip("/"), cfg["sycope_login"], cfg["sycope_pass"])
            lookup_id, saved_lookup = api.get_lookup(cfg["lookup_name"], lookup_type="subnet")

            updated_lookup, changes_list, summary_counts, excluded_rows = merge_lookup_data_with_summary(
                saved_lookup, lookupvalues_ip, lookupvalues_subnet, cfg=cfg
            )

            total_changes = summary_counts["added"] + summary_counts["modified"]

            if total_changes == 0:
                logging.info("No changes detected in the lookup. Nothing to update.")
            else:
                logging.info(
                    f"Changes detected in the lookup: added={summary_counts['added']} modified={summary_counts['modified']}"
                )

                if excluded_rows:
                    logging.info(f"Excluded rows: {len(excluded_rows)}")

                api.edit_lookup(lookup_id, updated_lookup, lookup_type="subnet")
                logging.info("Lookup host & subnets has been updated via API.")

    finally:
        # Logout all phpipam instances and sycope
        for p in phpipams:
            try:
                p.logout()
            except Exception:
                pass
        try:
            api.log_out()
        except Exception:
            pass


# Reuse merge function from original script (copy/paste or import if in module)
# For brevity, we import it from the original namespace if present; otherwise
# you should keep the merge_lookup_data_with_summary() function in this file.
try:
    from __main__ import merge_lookup_data_with_summary  # if merged into a single file during execution
except Exception:
    # If not present, the original function should be defined here or imported.
    pass


if __name__ == "__main__":
    main()
