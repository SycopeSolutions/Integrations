#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Lookup synchronization between Zabbix inventory data and Sycope.

This script retrieves host information from Zabbix (hosts with an SNMP, agent,
JMX or IPMI interface) and synchronizes it to a Sycope Lookup table.

Script version: 2.1
Tested on Sycope 3.1
"""

import json
import logging
import os
import sys
from collections import defaultdict

import requests

# Add parent directory to path for importing sycope modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# and this directory for zabbix_api (also when the script is imported from elsewhere)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sycope.api import SycopeApi
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings

from zabbix_api import AlreadyRunning, ZabbixApi, ZabbixApiError, single_instance

logger = logging.getLogger(__name__)

# Configuration file path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")


def create_lookup_structure(lookup_name: str) -> dict:
    """Create the lookup data structure."""
    logger.debug(f"Creating lookup structure for: {lookup_name}")

    structure = {
        "config": {
            "name": lookup_name,
            "type": "csvFile",
            "active": True,
            "dataFile": "test-csv-file.csv",
            "delimiter": ",",
            "types": [
                "ip",
                "string",
                "string",
                "string",
                "string",
                "string",
                "string",
                "string",
                "string",
                "string",
            ],
        },
        "file": {
            "columns": [
                "ip",
                "hostname",
                "host_type",
                "group",
                "icmp_url",
                "graph_url",
                "os",
                "serial_no",
                "notes",
                "status",
            ],
            "rows": [],
        },
    }

    logger.debug(f"Lookup structure created with columns: {structure['file']['columns']}")
    return structure


# Interface types in the order they are used for the lookup IP and the host type
INTERFACE_TYPES = [("2", "SNMP"), ("1", "Agent"), ("4", "JMX"), ("3", "IPMI")]


def get_hosts(zabbix: ZabbixApi) -> list:
    """Get all hosts with at least one interface (one host.get, with the number of items)."""
    hosts = zabbix.call(
        "host.get",
        {
            "output": ["hostid", "host", "name", "status", "available"],
            "selectInterfaces": ["type", "ip", "main"],
            "selectInventory": ["hostname", "os", "serialno_a", "notes", "name"],
            "selectHostGroups": ["name"],
            "selectItems": "count",
        },
    )
    logger.debug(f"Total hosts received: {len(hosts)}")
    hosts = [host for host in hosts if host.get("interfaces")]
    logger.debug(f"Hosts with interfaces: {len(hosts)}")
    return hosts


def get_icmp_items(zabbix: ZabbixApi, hostids: list) -> tuple:
    """ICMP items of all hosts in one item.get.

    Returns (response time item IDs by host, number of items with "ICMP" in the name by host).
    """
    if not hostids:
        return {}, {}
    items = zabbix.call(
        "item.get",
        {"output": ["itemid", "hostid", "name"], "hostids": hostids, "search": {"name": "ICMP"}},
    )
    response_time_ids = defaultdict(list)
    icmp_count = defaultdict(int)
    for item in items:
        if "ICMP" in item["name"]:
            icmp_count[item["hostid"]] += 1
        if "icmp response time" in item["name"].lower():
            response_time_ids[item["hostid"]].append(item["itemid"])
    return response_time_ids, icmp_count


def host_ip_and_type(interfaces: list) -> tuple:
    """IP and type of the host: SNMP, then Zabbix agent, JMX, IPMI interface; main interface first."""
    for type_id, type_name in INTERFACE_TYPES:
        candidates = [iface for iface in interfaces if str(iface.get("type")) == type_id and iface.get("ip")]
        candidates.sort(key=lambda iface: iface.get("main") != "1")
        if candidates:
            return candidates[0]["ip"], type_name
    return "", "Unknown"


def build_lookup_values(cfg: dict, hosts: list, response_time_ids: dict, icmp_count: dict) -> list:
    """Build lookup rows from the hosts."""
    logger.debug(f"Building lookup values for {len(hosts)} hosts")

    status_map = {"0": "Enabled", "1": "Disabled"}
    zabbix_url = cfg["zabbix_host"].rstrip("/")
    lookupvalues = []

    for host in hosts:
        host_id = host.get("hostid")
        inventory = host.get("inventory")
        if not isinstance(inventory, dict):  # inventory disabled: Zabbix returns []
            inventory = {}

        ip, host_type = host_ip_and_type(host.get("interfaces", []))
        if not ip:
            logger.debug(f"Host {host_id}: no interface with an IP address, skipped")
            continue

        # Inventory "Name", inventory "Hostname", visible name, technical host name - the same order
        # as resolve_hostname() in zabbix_statistics.py (empty inventory fields fall through)
        host_name = inventory.get("name") or inventory.get("hostname") or host.get("name") or host.get("host")
        group_names = [group.get("name", "Unknown") for group in host.get("hostgroups", [])]

        icmp_ids = response_time_ids.get(host_id, [])
        if icmp_ids:
            icmp_url = f"{zabbix_url}/history.php?action=showgraph&itemids%5B%5D={','.join(icmp_ids)}"
        else:
            icmp_url = "No ICMP Items"

        if int(host.get("items") or 0) > icmp_count.get(host_id, 0):
            graph_url = (
                f"{zabbix_url}/zabbix.php?action=charts.view&filter_hostids%5B0%5D={host_id}"
                "&filter_show=1&filter_set=1"
            )
        else:
            graph_url = "No Other Items"

        row = [
            str(x)
            for x in [
                ip,
                host_name,
                host_type,
                ", ".join(group_names) if group_names else "N/A",
                icmp_url,
                graph_url,
                inventory.get("os", ""),
                inventory.get("serialno_a", ""),
                inventory.get("notes", ""),
                status_map.get(str(host.get("status")), "Unknown"),
            ]
        ]
        logger.debug(f"  Host {host_id}: IP={row[0]}, hostname={row[1]}, type={row[2]}, status={row[-1]}")
        lookupvalues.append(row)

    logger.debug(f"Built {len(lookupvalues)} lookup rows")
    return lookupvalues


def sync_lookup(api: SycopeApi, cfg: dict, lookup: dict) -> None:
    """Create the lookup or update it when its rows or configuration differ, then set its privacy."""
    logger.debug(f"Checking for existing lookup: {cfg['lookup_name']}")
    lookup_id, saved_lookup = api.get_lookup(cfg["lookup_name"])
    logger.debug(f"Lookup ID: {lookup_id}")

    if lookup_id == "0":
        logging.info(f'Creating new lookup "{cfg["lookup_name"]}"')
        lookup_id = api.create_lookup(cfg["lookup_name"], lookup)
        logger.debug(f"Create lookup result: id={lookup_id}")
        if lookup_id == "0":
            logging.error("Failed to create lookup, dumping to file")
            with open("lookup_rows_problem.json", "w") as f:
                json.dump(lookup, f)
            sys.exit(1)
    else:
        compare_config = sorted(lookup["config"].items()) == sorted(saved_lookup["config"].items())
        compare_rows = sorted(lookup["file"]["rows"], key=str) == sorted(saved_lookup["file"]["rows"], key=str)
        logger.debug(
            f"Config identical: {compare_config}, rows identical: {compare_rows}"
            f" (new {len(lookup['file']['rows'])}, saved {len(saved_lookup['file']['rows'])})"
        )
        if compare_config and compare_rows:
            logging.info(f'Saved data in lookup "{cfg["lookup_name"]}" is identical. No changes required.')
        else:
            logging.info(f'Updating lookup "{cfg["lookup_name"]}" ({len(lookup["file"]["rows"])} rows)')
            lookup.update(
                {
                    "attributes": {"defaultColumns": []},
                    "tags": None,
                    "id": lookup_id,
                    "category": "lookup.lookup",
                }
            )
            api.edit_lookup(lookup_id, lookup)

    logger.debug(f"Setting lookup privacy to: {cfg['lookup_privacy']}")
    api.privacy_edit_lookup(lookup_id, cfg["lookup_privacy"])


def run(cfg: dict) -> None:
    """One synchronization: Zabbix hosts -> Sycope lookup."""
    lookup = create_lookup_structure(cfg["lookup_name"])

    zabbix = ZabbixApi(cfg)
    try:
        hosts = get_hosts(zabbix)
        response_time_ids, icmp_count = get_icmp_items(zabbix, [host["hostid"] for host in hosts])
    finally:
        zabbix.close()

    logging.info(f"Found {len(hosts)} hosts with interfaces in Zabbix")
    lookup["file"]["rows"].extend(build_lookup_values(cfg, hosts, response_time_ids, icmp_count))

    with requests.Session() as session:
        api = None
        try:
            api = SycopeApi(
                session=session,
                host=cfg["sycope_host"],
                login=cfg["sycope_login"],
                password=cfg["sycope_pass"],
                api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
            )
            sync_lookup(api, cfg, lookup)
        finally:
            if api is not None:
                logging.info("Logging out from Sycope")
                api.log_out()


def main() -> None:
    """Main synchronization function."""
    # Load configuration first to get log_level
    try:
        cfg = load_config(
            CONFIG_FILE,
            required_fields=[
                "zabbix_host",
                "sycope_host",
                "sycope_login",
                "sycope_pass",
                "lookup_name",
                "lookup_privacy",
            ],
        )
        if not cfg.get("zabbix_token") and not (cfg.get("zabbix_login") and cfg.get("zabbix_pass")):
            raise ValueError("set zabbix_token, or zabbix_login and zabbix_pass")
    except Exception as e:
        # Setup basic logging to report the error
        setup_logging("zabbix_lookup_sync.log")
        logging.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Setup environment with log_level from config
    suppress_ssl_warnings()
    setup_logging("zabbix_lookup_sync.log", log_level=cfg.get("log_level", "info"))

    logger.debug("=" * 60)
    logger.debug("Zabbix Lookup Sync script starting")
    logger.debug(f"Config file: {CONFIG_FILE}")
    logger.debug(f"  Zabbix host: {cfg['zabbix_host']} ({'API token' if cfg.get('zabbix_token') else 'login'})")
    logger.debug(f"  Sycope host: {cfg['sycope_host']}")
    logger.debug(f"  Lookup: {cfg['lookup_name']} ({cfg['lookup_privacy']})")

    try:
        with single_instance(os.path.join(SCRIPT_DIR, "zabbix_lookup_sync.lock")):
            run(cfg)
    except AlreadyRunning as e:
        logging.warning(f"The previous run is still running, skipping this one ({e})")
    except ZabbixApiError as e:
        logging.error(f"Zabbix API error: {e}")
        sys.exit(1)
    except SycopeError as e:
        logging.error(f"Sycope API error: {e}")
        sys.exit(1)
    logger.debug("Script complete")


if __name__ == "__main__":
    main()
