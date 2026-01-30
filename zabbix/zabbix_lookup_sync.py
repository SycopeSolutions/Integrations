#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Lookup synchronization between Zabbix inventory data and Sycope.

This script retrieves host information from Zabbix (SNMP/ICMP hosts)
and synchronizes it to a Sycope Lookup table.

Script version: 2.0
Tested on Sycope 3.1
"""

import json
import logging
import os
import sys

import requests

# Add parent directory to path for importing sycope modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sycope.api import SycopeApi
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings

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


def zabbix_login(cfg: dict) -> tuple:
    """Authenticate to Zabbix API."""
    url = cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"]
    logger.debug(f"Zabbix login URL: {url}")
    logger.debug(f"Zabbix user: {cfg['zabbix_login']}")

    login_payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {"username": cfg["zabbix_login"], "password": cfg["zabbix_pass"]},
        "id": 1,
    }

    logger.debug("Sending Zabbix login request")
    response = requests.post(url, json=login_payload, verify=False)
    logging.info(f"Zabbix Login Response: {response.status_code}")
    logger.debug(f"Response headers: {dict(response.headers)}")

    try:
        result = response.json()
        logger.debug(f"Response keys: {list(result.keys())}")

        if "result" in result:
            auth_token = result["result"]
            logger.debug(
                f"Auth token received (first 10 chars): {auth_token[:10] if len(auth_token) > 10 else '***'}..."
            )
            headers = {
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json-rpc",
            }
            return auth_token, headers
        else:
            error = result.get("error", "Unknown error")
            logger.debug(f"Login failed with error: {error}")
            raise Exception(f"Login failed: {error}")
    except requests.exceptions.JSONDecodeError as e:
        logger.debug(f"JSON decode error: {e}")
        logger.debug(f"Response text: {response.text[:500] if response.text else 'empty'}")
        raise Exception("Invalid JSON response from Zabbix server")


def zabbix_logout(cfg: dict) -> None:
    """Log out from Zabbix API."""
    url = cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"]
    logger.debug(f"Zabbix logout URL: {url}")

    logout_payload = {
        "jsonrpc": "2.0",
        "method": "user.logout",
        "params": [],
        "id": 2,
    }
    logging.info("Logging out from Zabbix")
    response = requests.post(url, json=logout_payload, verify=False)
    logger.debug(f"Logout response status: {response.status_code}")


def get_snmp_icmp_hosts(cfg: dict, headers: dict) -> list:
    """Get hosts with SNMP/ICMP interfaces from Zabbix."""
    url = cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"]
    logger.debug(f"Getting SNMP/ICMP hosts from: {url}")

    hosts_payload = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": ["hostid", "host", "name", "status", "available"],
            "selectInterfaces": ["type", "ip"],
            "selectInventory": ["hostname", "os", "serialno_a", "notes", "name"],
            "selectHostGroups": ["name"],
        },
        "id": 2,
    }

    logger.debug("Sending host.get request")
    response = requests.post(url, headers=headers, json=hosts_payload, verify=False)
    logger.debug(f"Response status: {response.status_code}")

    hosts_data = response.json().get("result", [])
    logger.debug(f"Total hosts received: {len(hosts_data)}")

    # Filter to include only hosts with SNMP (type=2) or ICMP (type=1) interfaces
    filtered_hosts = [
        host
        for host in hosts_data
        if any(int(iface.get("type", -1)) in [1, 2] for iface in host.get("interfaces", []))
    ]

    logger.debug(f"Hosts with SNMP/ICMP interfaces: {len(filtered_hosts)}")

    # Log first few hosts for debugging
    for host in filtered_hosts[:5]:
        interfaces = host.get("interfaces", [])
        iface_types = [iface.get("type") for iface in interfaces]
        logger.debug(f"  Host: id={host.get('hostid')}, name={host.get('name')}, interfaces={iface_types}")
    if len(filtered_hosts) > 5:
        logger.debug(f"  ... and {len(filtered_hosts) - 5} more hosts")

    return filtered_hosts


def get_icmp_items(cfg: dict, headers: dict, host_id: str) -> list:
    """Get ICMP item IDs for a host."""
    url = cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"]
    logger.debug(f"Getting ICMP items for host {host_id}")

    payload = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": ["itemid", "name"],
            "hostids": host_id,
            "search": {"name": "ICMP response time"},
        },
        "id": 3,
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    logger.debug(f"Response status: {response.status_code}")

    items = response.json().get("result", [])
    item_ids = [item["itemid"] for item in items]
    logger.debug(f"Found {len(item_ids)} ICMP items for host {host_id}: {item_ids}")

    return item_ids


def get_non_icmp_items(cfg: dict, headers: dict, host_id: str) -> bool:
    """Check if host has any non-ICMP items."""
    url = cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"]
    logger.debug(f"Checking for non-ICMP items on host {host_id}")

    payload = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": ["itemid", "name"],
            "hostids": host_id,
        },
        "id": 4,
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    logger.debug(f"Response status: {response.status_code}")

    all_items = response.json().get("result", [])
    filtered_items = [item for item in all_items if "ICMP" not in item["name"]]

    logger.debug(f"Host {host_id}: {len(all_items)} total items, {len(filtered_items)} non-ICMP items")
    return bool(filtered_items)


def build_lookup_values(cfg: dict, headers: dict, snmp_hosts: list) -> list:
    """Build lookup values from SNMP/ICMP hosts."""
    logger.debug(f"Building lookup values for {len(snmp_hosts)} hosts")

    status_map = {"0": "Enabled", "1": "Disabled"}
    lookupvalues = []

    for i, host in enumerate(snmp_hosts, 1):
        host_id = host.get("hostid")
        logger.debug(f"Processing host {i}/{len(snmp_hosts)}: id={host_id}")

        inventory = host.get("inventory", {})
        interfaces = host.get("interfaces", [])
        groups = host.get("hostgroups", [])

        logger.debug(
            f"  Inventory keys: {list(inventory.keys()) if isinstance(inventory, dict) else 'not a dict'}"
        )
        logger.debug(f"  Interfaces count: {len(interfaces)}")
        logger.debug(f"  Groups count: {len(groups)}")

        snmp_ip = next(
            (iface.get("ip") for iface in interfaces if int(iface.get("type", -1)) == 2),
            "N/A",
        )
        icmp_ip = next(
            (iface.get("ip") for iface in interfaces if int(iface.get("type", -1)) == 1),
            "N/A",
        )

        logger.debug(f"  SNMP IP: {snmp_ip}, ICMP IP: {icmp_ip}")

        group_names = [group.get("name", "Unknown") for group in groups]
        logger.debug(f"  Groups: {group_names}")

        # Get hostname from inventory or host name
        if isinstance(inventory, dict):
            inventory_name = inventory.get("name", "")
            host_name = inventory_name if inventory_name else inventory.get("hostname", host.get("name"))
        else:
            host_name = host.get("name")
        logger.debug(f"  Resolved hostname: {host_name}")

        # Determine host type
        host_type = "Unknown"
        if any(int(iface.get("type", -1)) == 2 for iface in interfaces):
            host_type = "SNMP"
        elif any(int(iface.get("type", -1)) == 1 for iface in interfaces):
            host_type = "ICMP"
        logger.debug(f"  Host type: {host_type}")

        # Get items for URL building
        icmp_item_ids = get_icmp_items(cfg, headers, host_id)
        has_items = get_non_icmp_items(cfg, headers, host_id)

        # Build URLs
        if icmp_item_ids:
            icmp_url = f"{cfg['zabbix_host'].rstrip('/')}/history.php?action=showgraph&itemids%5B%5D={','.join(map(str, icmp_item_ids))}"
        else:
            icmp_url = "No ICMP Items"

        if has_items:
            graph_url = f"{cfg['zabbix_host'].rstrip('/')}/zabbix.php?action=charts.view&filter_hostids%5B0%5D={host_id}&filter_show=1&filter_set=1"
        else:
            graph_url = "No Other Items"

        logger.debug(f"  ICMP URL: {icmp_url[:80]}..." if len(icmp_url) > 80 else f"  ICMP URL: {icmp_url}")
        logger.debug(
            f"  Graph URL: {graph_url[:80]}..." if len(graph_url) > 80 else f"  Graph URL: {graph_url}"
        )

        row = [
            str(x)
            for x in [
                snmp_ip if host_type == "SNMP" else icmp_ip,
                host_name,
                host_type,
                ", ".join(group_names) if group_names else "N/A",
                icmp_url,
                graph_url,
                inventory.get("os", "") if isinstance(inventory, dict) else "",
                inventory.get("serialno_a", "") if isinstance(inventory, dict) else "",
                inventory.get("notes", "") if isinstance(inventory, dict) else "",
                status_map.get(str(host.get("status")), "Unknown"),
            ]
        ]

        logger.debug(f"  Row values: IP={row[0]}, hostname={row[1]}, type={row[2]}, status={row[-1]}")
        lookupvalues.append(row)

    logger.debug(f"Built {len(lookupvalues)} lookup rows")
    return lookupvalues


def main() -> None:
    """Main synchronization function."""
    # Load configuration first to get log_level
    try:
        cfg = load_config(
            CONFIG_FILE,
            required_fields=[
                "zabbix_host",
                "zabbix_api_base",
                "zabbix_login",
                "zabbix_pass",
                "sycope_host",
                "sycope_login",
                "sycope_pass",
                "lookup_name",
                "lookup_privacy",
            ],
        )
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
    logger.debug(f"Script directory: {SCRIPT_DIR}")
    logger.debug(f"Config file: {CONFIG_FILE}")
    logger.debug("=" * 60)

    logger.debug("Configuration loaded successfully")
    logger.debug(f"  Zabbix host: {cfg['zabbix_host']}")
    logger.debug(f"  Sycope host: {cfg['sycope_host']}")
    logger.debug(f"  Lookup name: {cfg['lookup_name']}")
    logger.debug(f"  Lookup privacy: {cfg['lookup_privacy']}")

    logging.info(f"Loaded configuration from {CONFIG_FILE}")

    # Create lookup structure
    lookup = create_lookup_structure(cfg["lookup_name"])

    # Authenticate to Zabbix
    try:
        logger.debug("Authenticating to Zabbix API...")
        auth_token, headers = zabbix_login(cfg)
        logger.debug("Zabbix authentication successful")
    except Exception as e:
        logging.error(f"Zabbix login failed: {e}")
        logger.debug(f"Zabbix login exception: {type(e).__name__}: {e}")
        sys.exit(1)

    try:
        # Get SNMP/ICMP hosts
        logger.debug("Fetching SNMP/ICMP hosts from Zabbix...")
        snmp_hosts = get_snmp_icmp_hosts(cfg, headers)

        if not snmp_hosts:
            logging.info("No SNMP or ICMP hosts found in Zabbix")
            logger.debug("No hosts to process")
        else:
            logging.info(f"Found {len(snmp_hosts)} SNMP/ICMP hosts in Zabbix")
            logger.debug("Building lookup values from host data...")
            lookupvalues = build_lookup_values(cfg, headers, snmp_hosts)
            lookup["file"]["rows"].extend(lookupvalues)
            logger.debug(f"Total rows in lookup: {len(lookup['file']['rows'])}")

        # Sync to Sycope
        logger.debug("Creating Sycope session...")
        with requests.Session() as session:
            logger.debug("Authenticating to Sycope API...")
            api = SycopeApi(
                session=session,
                host=cfg["sycope_host"],
                login=cfg["sycope_login"],
                password=cfg["sycope_pass"],
                api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
            )
            logger.debug("Sycope authentication successful")

            try:
                logger.debug(f"Checking for existing lookup: {cfg['lookup_name']}")
                lookup_id, saved_lookup = api.get_lookup(cfg["lookup_name"])
                logger.debug(f"Lookup ID: {lookup_id}")
                logger.debug(f"Saved lookup keys: {list(saved_lookup.keys()) if saved_lookup else 'empty'}")

                logging.info("Checking data...")

                if lookup_id == "0":
                    logging.info(f'Creating new lookup "{cfg["lookup_name"]}"')
                    logger.debug("Lookup does not exist, creating new one...")
                    lookup_id = api.create_lookup(cfg["lookup_name"], lookup)
                    logger.debug(f"Create lookup result: id={lookup_id}")

                    if lookup_id == "0":
                        logging.error("Failed to create lookup, dumping to file")
                        logger.debug("Dumping lookup data to lookup_rows_problem.json")
                        with open("lookup_rows_problem.json", "w") as f:
                            json.dump(lookup, f)
                        sys.exit(1)
                else:
                    logger.debug("Lookup exists, comparing data...")

                    # Compare configurations
                    compare_config = sorted(lookup["config"].items()) == sorted(
                        saved_lookup["config"].items()
                    )
                    logger.debug(f"Config comparison result: {compare_config}")
                    if not compare_config:
                        logger.debug(f"  New config: {sorted(lookup['config'].items())}")
                        logger.debug(f"  Saved config: {sorted(saved_lookup['config'].items())}")

                    # Compare rows
                    new_rows_sorted = sorted(lookup["file"]["rows"], key=lambda x: str(x))
                    saved_rows_sorted = sorted(saved_lookup["file"]["rows"], key=lambda x: str(x))
                    compare_rows = new_rows_sorted == saved_rows_sorted
                    logger.debug(f"Rows comparison result: {compare_rows}")
                    logger.debug(f"  New rows count: {len(lookup['file']['rows'])}")
                    logger.debug(f"  Saved rows count: {len(saved_lookup['file']['rows'])}")

                    if compare_config and compare_rows:
                        logging.info(
                            f'Saved data in lookup "{cfg["lookup_name"]}" is identical. No changes required.'
                        )
                        logger.debug("No update needed")
                    else:
                        logger.debug("Data differs, updating lookup...")
                        lookup.update(
                            {
                                "attributes": {"defaultColumns": []},
                                "tags": None,
                                "id": lookup_id,
                                "category": "lookup.lookup",
                            }
                        )
                        logger.debug(f"Updated lookup structure keys: {list(lookup.keys())}")
                        api.edit_lookup(lookup_id, lookup)
                        logger.debug("Lookup updated successfully")

                # Set privacy
                logger.debug(f"Setting lookup privacy to: {cfg['lookup_privacy']}")
                api.privacy_edit_lookup(lookup_id, cfg["lookup_privacy"])
                logger.debug("Privacy setting complete")

            except SycopeError as e:
                logging.error(f"Sycope API error: {e}")
                logger.debug(f"Sycope exception: {type(e).__name__}: {e}")
                sys.exit(1)
            finally:
                logging.info("Logging out from Sycope")
                api.log_out()
                logger.debug("Logged out from Sycope")

    finally:
        zabbix_logout(cfg)
        logger.debug("Script complete")


if __name__ == "__main__":
    main()
