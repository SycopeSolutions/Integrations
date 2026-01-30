#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
phpIPAM to Sycope Synchronization Script.

This script synchronizes IP address inventory data from phpIPAM to a Sycope lookup.
It retrieves addresses, subnets, and associated metadata from phpIPAM and uploads
them to Sycope for correlation, search, and visualization.

Features:
- Multi-instance phpIPAM support (first phpIPAM wins for duplicates)
- Configurable sync modes (addresses, subnets, devices)
- Section filtering (include/exclude)
- State filtering (active, reserved, DHCP, inactive)
- Comprehensive logging and error handling

Script version: 2.0
Tested on Sycope 3.1
"""

import logging
import os
import sys
from datetime import datetime, timezone

import requests

# Add parent directory to path for importing sycope modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from phpipam_api import PhpipamApi

from sycope.api import SycopeApi
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings

logger = logging.getLogger(__name__)

# Configuration file path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

# State mapping from phpIPAM numeric codes to names
STATE_MAP = {
    "0": "Offline",
    "1": "Active",
    "2": "Reserved",
    "3": "DHCP",
}


def build_phpipam_conn(host_cfg: dict) -> PhpipamApi:
    """Create PhpipamApi instance from a host config dict."""
    logger.debug(f"Building phpIPAM connection for host: {host_cfg.get('host')}")
    logger.debug(f"  App ID: {host_cfg.get('app_id')}")
    logger.debug(f"  Username: {host_cfg.get('username')}")
    logger.debug(f"  API base: {host_cfg.get('api_base', '/api')}")

    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})

    api = PhpipamApi(
        session=session,
        host=host_cfg["host"].rstrip("/"),
        app_id=host_cfg.get("app_id"),
        username=host_cfg.get("username"),
        password=host_cfg.get("password"),
        api_base=host_cfg.get("api_base", "/api"),
    )

    logger.debug(f"phpIPAM connection created for {host_cfg.get('host')}")
    return api


def setup_api_connections(cfg: dict) -> tuple:
    """Initialize API connections to one or more phpIPAM instances and Sycope."""
    logger.debug("Setting up API connections...")

    phpipam_hosts = []

    # Preferred modern config: phpipam_hosts (list of dicts)
    if isinstance(cfg.get("phpipam_hosts"), list) and cfg.get("phpipam_hosts"):
        phpipam_hosts = cfg.get("phpipam_hosts")
        logger.debug(f"Using phpipam_hosts list with {len(phpipam_hosts)} entries")
    else:
        # Backwards compatibility: single phpipam_host keys
        if cfg.get("phpipam_host"):
            logger.debug("Using legacy single phpipam_host configuration")
            phpipam_hosts = [
                {
                    "host": cfg.get("phpipam_host"),
                    "app_id": cfg.get("phpipam_app_id"),
                    "username": cfg.get("phpipam_username"),
                    "password": cfg.get("phpipam_password"),
                    "api_base": cfg.get("phpipam_api_base", "/api"),
                }
            ]

    logger.debug(f"Total phpIPAM hosts to connect: {len(phpipam_hosts)}")

    phpipam_instances = []
    for i, host_cfg in enumerate(phpipam_hosts):
        logger.debug(f"Connecting to phpIPAM instance {i + 1}/{len(phpipam_hosts)}: {host_cfg.get('host')}")
        try:
            api = build_phpipam_conn(host_cfg)
            phpipam_instances.append(api)
            logging.info(f"Connected to phpIPAM: {host_cfg.get('host')}")
            logger.debug(f"phpIPAM connection successful: {host_cfg.get('host')}")
        except Exception as e:
            logging.error(f"Failed to connect to phpIPAM {host_cfg.get('host')}: {e}")
            logger.debug(f"phpIPAM connection error: {type(e).__name__}: {e}")

    logger.debug(f"Successfully connected to {len(phpipam_instances)} phpIPAM instances")

    # Connect to Sycope (one instance)
    logger.debug("Connecting to Sycope...")
    sycope_session = requests.Session()
    sycope_session.headers.update({"Content-Type": "application/json"})

    sycope = SycopeApi(
        session=sycope_session,
        host=cfg["sycope_host"],
        login=cfg["sycope_login"],
        password=cfg["sycope_pass"],
        api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
    )
    logger.debug("Sycope connection established")

    return phpipam_instances, sycope, sycope_session


def get_section_mapping(phpipam: PhpipamApi) -> dict:
    """Create mapping of section IDs to section names."""
    logger.debug(f"Getting section mapping from {phpipam.host}")

    sections = phpipam.get_all_sections()
    logger.debug(f"Retrieved {len(sections)} sections")

    mapping = {str(sec["id"]): sec["name"] for sec in sections if "id" in sec and "name" in sec}
    logger.debug(f"Section mapping: {len(mapping)} entries")

    for sec_id, sec_name in list(mapping.items())[:5]:
        logger.debug(f"  Section {sec_id}: {sec_name}")
    if len(mapping) > 5:
        logger.debug(f"  ... and {len(mapping) - 5} more sections")

    return mapping


def get_subnets(phpipam: PhpipamApi) -> list:
    """Get all subnets from phpIPAM."""
    logger.debug(f"Getting subnets from {phpipam.host}")

    subnets = phpipam.get_all_subnets()
    logger.debug(f"Retrieved {len(subnets)} subnets")

    for subnet in subnets[:5]:
        logger.debug(
            f"  Subnet: {subnet.get('subnet')}/{subnet.get('mask')} - {subnet.get('description', '')[:50]}"
        )
    if len(subnets) > 5:
        logger.debug(f"  ... and {len(subnets) - 5} more subnets")

    return subnets


def get_vlan_mapping(phpipam: PhpipamApi) -> dict:
    """Create mapping of VLAN IDs to VLAN numbers."""
    logger.debug(f"Getting VLAN mapping from {phpipam.host}")

    vlans = phpipam.get_all_vlans()
    logger.debug(f"Retrieved {len(vlans)} VLANs")

    mapping = {str(vlan["vlanId"]): vlan.get("number") for vlan in vlans if "vlanId" in vlan}
    logger.debug(f"VLAN mapping: {len(mapping)} entries")

    return mapping


def get_device_mapping(phpipam: PhpipamApi) -> dict:
    """Create mapping of device IDs to device names."""
    logger.debug(f"Getting device mapping from {phpipam.host}")

    devices = phpipam.get_all_devices()
    logger.debug(f"Retrieved {len(devices)} devices")

    mapping = {str(dev["id"]): dev.get("hostname", "") for dev in devices if "id" in dev}
    logger.debug(f"Device mapping: {len(mapping)} entries")

    return mapping


def get_tag_mapping(phpipam: PhpipamApi) -> dict:
    """Create mapping of tag IDs to tag names."""
    logger.debug(f"Getting tag mapping from {phpipam.host}")

    tags = phpipam.get_all_tags()
    logger.debug(f"Retrieved {len(tags)} tags")

    mapping = {str(tag["id"]): tag.get("type", "") for tag in tags if "id" in tag}
    logger.debug(f"Tag mapping: {len(mapping)} entries")

    return mapping


def should_include_address(addr: dict, cfg: dict, section_id: str) -> bool:
    """Determine if an address should be included based on filters."""
    ip = addr.get("ip", "unknown")
    logger.debug(f"Checking address {ip} for inclusion (section_id={section_id})")

    # Check section filters
    include_sections = cfg.get("include_sections", [])
    exclude_sections = cfg.get("exclude_sections", [])

    if include_sections and section_id not in include_sections:
        logger.debug(f"  Address {ip} excluded: section {section_id} not in include_sections")
        return False
    if exclude_sections and section_id in exclude_sections:
        logger.debug(f"  Address {ip} excluded: section {section_id} in exclude_sections")
        return False

    # Check state filters
    state_code = addr.get("state", "1")
    state_name = STATE_MAP.get(state_code, "Unknown")
    logger.debug(f"  Address {ip} state: {state_code} ({state_name})")

    if state_code == "0" and not cfg.get("include_inactive", False):
        logger.debug(f"  Address {ip} excluded: inactive state not included")
        return False
    if state_code == "2" and not cfg.get("include_reserved", True):
        logger.debug(f"  Address {ip} excluded: reserved state not included")
        return False
    if state_code == "3" and not cfg.get("include_dhcp", True):
        logger.debug(f"  Address {ip} excluded: DHCP state not included")
        return False

    logger.debug(f"  Address {ip} included")
    return True


def fetch_from_phpipam_instance(phpipam: PhpipamApi, cfg: dict) -> list:
    """Fetch processed address records from a single phpipam instance."""
    logging.info(f"Fetching data from phpIPAM {phpipam.host} ...")
    logger.debug(f"Starting data fetch from {phpipam.host}")

    section_map = get_section_mapping(phpipam)
    vlan_map = get_vlan_mapping(phpipam)
    device_map = get_device_mapping(phpipam)
    tag_map = get_tag_mapping(phpipam)

    records = []
    sync_mode = cfg.get("sync_mode", "addresses")
    logger.debug(f"Sync mode: {sync_mode}")

    if sync_mode != "addresses":
        logging.error(f"Unsupported sync_mode: {sync_mode}")
        logger.debug(f"Aborting: unsupported sync_mode {sync_mode}")
        return []

    logger.debug("Fetching all addresses from all subnets...")
    all_addresses = phpipam.get_all_addresses_all_subnets()
    logging.info(f"Retrieved {len(all_addresses)} addresses from {phpipam.host}")
    logger.debug(f"Total addresses retrieved: {len(all_addresses)}")

    included_count = 0
    excluded_count = 0

    for addr in all_addresses:
        subnet_info = addr.get("subnet_info", {})
        section_id = str(subnet_info.get("section", ""))

        if not should_include_address(addr, cfg, section_id):
            excluded_count += 1
            continue

        included_count += 1

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
                logger.debug(f"  Parsed lastSeen: {last_seen} -> {last_seen_ms}")
            except Exception as e:
                logger.debug(f"  Failed to parse lastSeen: {last_seen} - {e}")

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

    logger.debug(f"Address processing complete: {included_count} included, {excluded_count} excluded")
    logging.info(f"Processed {len(records)} addresses from {phpipam.host}")
    return records


def merge_lookup_data_with_summary(
    saved_lookup: dict,
    lookupvalues_ip: list,
    lookupvalues_subnet: list,
    cfg: dict = None,
) -> tuple:
    """Merge new data with existing lookup data."""
    logger.debug("Merging lookup data...")
    logger.debug(f"  Existing lookup rows: {len(saved_lookup['file']['rows'])}")
    logger.debug(f"  New IP values: {len(lookupvalues_ip)}")
    logger.debug(f"  New subnet values: {len(lookupvalues_subnet)}")

    columns = saved_lookup["file"]["columns"]
    col_count = len(columns)
    logger.debug(f"  Lookup columns: {columns}")

    existing = {row[0]: row for row in saved_lookup["file"]["rows"]}
    logger.debug(f"  Existing entries by CIDR: {len(existing)}")

    changes_summary = []
    excluded_rows = []
    updated_this_run = set()

    exclude_prefixes = cfg.get("exclude_description", []) if cfg else []
    logger.debug(f"  Exclude prefixes: {exclude_prefixes}")

    def should_exclude(desc):
        if not desc:
            return False
        excluded = any(desc.startswith(prefix) for prefix in exclude_prefixes)
        if excluded:
            logger.debug(f"    Excluding description: {desc}")
        return excluded

    def new_empty_row(cidr):
        return [cidr] + [""] * (col_count - 1)

    def track_change(cidr, row, new_values, overwrite_cols):
        modified = False
        for idx, val in zip(overwrite_cols, new_values):
            if row[idx] != val:
                logger.debug(f"    Column {idx} changed: '{row[idx]}' -> '{val}'")
                row[idx] = val
                modified = True
        return modified

    # Process IP rows
    logger.debug("Processing IP rows...")
    ip_added = 0
    ip_modified = 0
    ip_unchanged = 0

    for cidr, name, description in lookupvalues_ip:
        if should_exclude(description):
            excluded_rows.append({"cidr": cidr, "description": description})
            continue

        if cidr in updated_this_run:
            logger.debug(f"  Skipping duplicate CIDR: {cidr}")
            continue

        updated_this_run.add(cidr)

        if cidr in existing:
            row = existing[cidr]
            modified = track_change(cidr, row, [cidr, name, description], overwrite_cols=[0, 1, 2])
            if modified:
                ip_modified += 1
                changes_summary.append({"cidr": cidr, "change": "modified"})
            else:
                ip_unchanged += 1
                changes_summary.append({"cidr": cidr, "change": "unchanged"})
        else:
            row = new_empty_row(cidr)
            row[0] = cidr
            row[1] = name
            row[2] = description
            existing[cidr] = row
            ip_added += 1
            changes_summary.append({"cidr": cidr, "change": "added"})
            logger.debug(f"  Added new IP: {cidr}")

    logger.debug(f"IP processing: added={ip_added}, modified={ip_modified}, unchanged={ip_unchanged}")

    # Process Subnet rows
    logger.debug("Processing subnet rows...")
    subnet_added = 0
    subnet_modified = 0
    subnet_unchanged = 0

    for cidr, name in lookupvalues_subnet:
        if should_exclude(name):
            excluded_rows.append({"cidr": cidr, "description": name})
            continue

        if cidr in updated_this_run:
            logger.debug(f"  Skipping duplicate CIDR: {cidr}")
            continue

        updated_this_run.add(cidr)

        if cidr in existing:
            row = existing[cidr]
            modified = track_change(cidr, row, [cidr, name], overwrite_cols=[0, 1])
            if modified:
                subnet_modified += 1
                changes_summary.append({"cidr": cidr, "change": "modified"})
            else:
                subnet_unchanged += 1
                changes_summary.append({"cidr": cidr, "change": "unchanged"})
        else:
            row = new_empty_row(cidr)
            row[0] = cidr
            row[1] = name
            existing[cidr] = row
            subnet_added += 1
            changes_summary.append({"cidr": cidr, "change": "added"})
            logger.debug(f"  Added new subnet: {cidr}")

    logger.debug(
        f"Subnet processing: added={subnet_added}, modified={subnet_modified}, unchanged={subnet_unchanged}"
    )

    saved_lookup["file"]["rows"] = list(existing.values())

    summary_counts = {"added": 0, "modified": 0, "unchanged": 0}
    for entry in changes_summary:
        summary_counts[entry["change"]] += 1

    logger.debug(f"Merge summary: {summary_counts}")
    logger.debug(f"Excluded rows: {len(excluded_rows)}")
    logger.debug(f"Final lookup rows: {len(saved_lookup['file']['rows'])}")

    return saved_lookup, changes_summary, summary_counts, excluded_rows


def main() -> None:
    """Main synchronization function."""
    # Load configuration first to get log_level
    try:
        cfg = load_config(
            CONFIG_FILE,
            required_fields=["sycope_host", "sycope_login", "sycope_pass", "lookup_name"],
        )
    except Exception as e:
        # Setup basic logging to report the error
        setup_logging("phpipam_sync.log")
        logging.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Setup environment with log_level from config
    suppress_ssl_warnings()
    setup_logging("phpipam_sync.log", log_level=cfg.get("log_level", "info"))

    logger.debug("=" * 60)
    logger.debug("phpIPAM Sync script starting")
    logger.debug(f"Script directory: {SCRIPT_DIR}")
    logger.debug(f"Config file: {CONFIG_FILE}")
    logger.debug("=" * 60)

    logger.debug("Configuration loaded successfully")
    logger.debug(f"  Sycope host: {cfg['sycope_host']}")
    logger.debug(f"  Lookup name: {cfg['lookup_name']}")
    logger.debug(f"  Sync mode: {cfg.get('sync_mode', 'addresses')}")

    logging.info("Starting phpIPAM to Sycope synchronization (multi-host)...")

    phpipams, sycope, sycope_session = setup_api_connections(cfg)
    logger.debug(f"Connected to {len(phpipams)} phpIPAM instances")

    try:
        # Collect IP records and subnets with priority: first phpipam wins
        ip_seen = {}  # ip -> (hostname, description)
        subnet_seen = set()  # set of cidr strings like '192.168.1.0/24'

        lookupvalues_ip = []
        lookupvalues_subnet = []

        for i, php in enumerate(phpipams, 1):
            logger.debug(f"Processing phpIPAM instance {i}/{len(phpipams)}: {php.host}")
            try:
                records = fetch_from_phpipam_instance(php, cfg)
                logger.debug(f"  Received {len(records)} records")

                # Add IPs (skip duplicates if already seen)
                ip_added = 0
                ip_skipped = 0

                for r in records:
                    ip = r.get("ip")
                    if not ip or ":" in ip:
                        logger.debug(f"  Skipping invalid/IPv6 address: {ip}")
                        continue

                    if r.get("description") == "DHCP range":
                        logger.debug(f"  Skipping DHCP range: {ip}")
                        continue

                    # FIRST phpIPAM ALWAYS WINS
                    if ip not in ip_seen:
                        ip_seen[ip] = (r.get("hostname") or "", r.get("description") or "")
                        lookupvalues_ip.append([f"{ip}/32", ip_seen[ip][0], ip_seen[ip][1]])
                        ip_added += 1
                    else:
                        ip_skipped += 1

                logger.debug(f"  IPs from {php.host}: {ip_added} added, {ip_skipped} skipped (duplicates)")

                # Add subnets from this phpipam instance
                logger.debug(f"  Fetching subnets from {php.host}...")
                subnets = get_subnets(php)
                subnet_added = 0
                subnet_skipped = 0

                for s in subnets:
                    s_network = s.get("subnet")
                    s_mask = s.get("mask")
                    if not s_network or not s_mask:
                        continue
                    if ":" in s_network:
                        logger.debug(f"  Skipping IPv6 subnet: {s_network}")
                        continue
                    cidr = f"{s_network}/{s_mask}"
                    if cidr in subnet_seen:
                        subnet_skipped += 1
                        continue
                    subnet_seen.add(cidr)
                    if s.get("description") == "DHCP range":
                        logger.debug(f"  Skipping DHCP range subnet: {cidr}")
                        continue
                    lookupvalues_subnet.append([cidr, s.get("description") or ""])
                    subnet_added += 1

                logger.debug(
                    f"  Subnets from {php.host}: {subnet_added} added, {subnet_skipped} skipped (duplicates)"
                )

            except Exception as e:
                logging.error(f"Error fetching data from {php.host}: {e}")
                logger.debug(f"phpIPAM error: {type(e).__name__}: {e}")

        # Display collected data for debugging
        logger.debug(f"Total collected: {len(lookupvalues_ip)} IPs, {len(lookupvalues_subnet)} subnets")

        logging.info(f"Collected {len(lookupvalues_ip)} IPs")
        if lookupvalues_ip:
            logger.debug("IP sample (first 10):")
            for row in lookupvalues_ip[:10]:
                logger.debug(f"  {row}")

        logging.info(f"Collected {len(lookupvalues_subnet)} subnets")
        if lookupvalues_subnet:
            logger.debug("Subnet sample (first 10):")
            for row in lookupvalues_subnet[:10]:
                logger.debug(f"  {row}")

        # Update Sycope lookup
        logger.debug("Updating Sycope lookup...")
        with requests.Session() as session:
            api = SycopeApi(
                session,
                cfg["sycope_host"],
                cfg["sycope_login"],
                cfg["sycope_pass"],
                cfg.get("api_base", "/npm/api/v1/"),
            )

            try:
                logger.debug(f"Getting existing lookup: {cfg['lookup_name']}")
                lookup_id, saved_lookup = api.get_lookup(cfg["lookup_name"], lookup_type="subnet")
                logger.debug(f"Lookup ID: {lookup_id}")
                logger.debug(f"Existing rows: {len(saved_lookup.get('file', {}).get('rows', []))}")

                updated_lookup, changes_list, summary_counts, excluded_rows = merge_lookup_data_with_summary(
                    saved_lookup, lookupvalues_ip, lookupvalues_subnet, cfg=cfg
                )

                total_changes = summary_counts["added"] + summary_counts["modified"]
                logger.debug(f"Total changes: {total_changes}")

                if total_changes == 0:
                    logging.info("No changes detected in the lookup. Nothing to update.")
                    logger.debug("Skipping update - no changes")
                else:
                    logging.info(
                        f"Changes detected: added={summary_counts['added']} modified={summary_counts['modified']}"
                    )

                    if excluded_rows:
                        logging.info(f"Excluded rows: {len(excluded_rows)}")
                        logger.debug(f"Excluded rows details: {excluded_rows[:10]}...")

                    logger.debug("Updating lookup via API...")
                    api.edit_lookup(lookup_id, updated_lookup, lookup_type="subnet")
                    logging.info("Lookup 'hosts & subnets' has been updated via API")
                    logger.debug("Lookup update complete")

            except SycopeError as e:
                logging.error(f"Sycope API error: {e}")
                logger.debug(f"Sycope exception: {type(e).__name__}: {e}")
                if hasattr(e, "status_code"):
                    logger.debug(f"  Status code: {e.status_code}")
                if hasattr(e, "response"):
                    logger.debug(f"  Response: {e.response}")
                sys.exit(1)
            finally:
                logger.debug("Logging out from Sycope...")
                api.log_out()

    finally:
        # Logout all phpipam instances
        logger.debug("Logging out from phpIPAM instances...")
        for p in phpipams:
            try:
                p.logout()
                logger.debug(f"Logged out from {p.host}")
            except Exception as e:
                logger.debug(f"Logout error for {p.host}: {e}")

        logger.debug("Script complete")


if __name__ == "__main__":
    main()
