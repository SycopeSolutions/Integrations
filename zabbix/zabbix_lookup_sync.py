#!/usr/bin/env python
# coding: utf-8

# Lookup synchronization between Zabbix inventory data and Sycope
# Script version: 1.0
# Tested on Sycope 3.1
import json
import sys
import os
import requests
import logging

# Hiding SSL certificate warning messages
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Path handling for config and modules
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, '..', 'sycope'))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

# Extend path to load SycopeApi from external module
sys.path.append(PARENT_DIR)

from api import SycopeApi  # Import Sycope API wrapper

try:
    with open(CONFIG_FILE, 'r') as f:
        cfg = json.load(f)
except Exception as e:
    logging.error(f"ERROR loading config: {e}")
    sys.exit(1)
else:
    logging.info(f"Loaded configuration from {CONFIG_FILE}")

lookup = {
    "config": {
        "name": cfg["lookup_name"],
        "type": "csvFile",
        "active": True,
        "dataFile": "test-csv-file.csv",
        "delimiter": ",",
        "types": [
            "ip4",
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

# Step 1: Authenticate
login_payload = {
    "jsonrpc": "2.0",
    "method": "user.login",
    "params": {"username": cfg["zabbix_login"], "password": cfg["zabbix_pass"]},
    "id": 1,
}

login_response = requests.post(cfg["zabbix_host"].rstrip("/")+cfg["zabbix_api_base"], json=login_payload, verify=False)
print("Zabbix Login Response:", login_response.text)

try:
    login_result = login_response.json()
    if "result" in login_result:
        auth_token = login_result["result"]

        headers = {
            'Authorization': f'Bearer {auth_token}',
            'Content-Type': 'application/json-rpc'
        }

    else:
        print("Login failed:", login_result.get("error", "Unknown error"))
        exit()

except requests.exceptions.JSONDecodeError:
    print("Invalid JSON response from Zabbix server.")
    exit()

# Step 2: Get hosts with SNMP/ICMP interfaces
hosts_payload = {
    "jsonrpc": "2.0",
    "method": "host.get",
    "params": {
        "output": ["hostid", "host", "name", "status", "available"],
        "selectInterfaces": ["type", "ip"],
        "selectInventory": ["hostname", "os", "serialno_a", "notes", "name"],
        "selectHostGroups": ["name"],
        # "filter": {"status": 0},
    },
    "id": 2
}

hosts_response = requests.post(cfg["zabbix_host"].rstrip("/")+cfg["zabbix_api_base"], headers=headers, json=hosts_payload, verify=False)
hosts_data = hosts_response.json().get("result", [])

# Filter to include only hosts with SNMP or ICMP interfaces
snmp_hosts = [
    host
    for host in hosts_data
    if any(int(iface.get("type", -1)) in [1, 2] for iface in host.get("interfaces", []))
]

lookupvalues = []

# Step 3: Display host info
if not snmp_hosts:
    print("No SNMP or ICMP hosts found in Zabbix.")
else:
    print("Getting SNMP/ICMP Host Information from Zabbix.")

    for host in snmp_hosts:
        inventory = host.get("inventory", {})
        interfaces = host.get("interfaces", [])
        groups = host.get("hostgroups", [])
        host_id = host.get("hostid")
        status = host.get("status")
        available = host.get("available")

        snmp_ip = next((iface.get("ip") for iface in interfaces if int(iface.get("type", -1)) == 2), "N/A")
        icmp_ip = next((iface.get("ip") for iface in interfaces if int(iface.get("type", -1)) == 1), "N/A")

        group_names = [group.get("name", "Unknown") for group in groups]

        if isinstance(inventory, dict):
            inventory_name = inventory.get("name", "")
            host_name = inventory_name if inventory_name else inventory.get("hostname", host.get("name"))
        else:
            host_name = host.get("name")

        host_type = "Unknown"
        if any(int(iface.get("type", -1)) == 2 for iface in interfaces):
            host_type = "SNMP"
        elif any(int(iface.get("type", -1)) == 1 for iface in interfaces):
            host_type = "ICMP"

        # Step 4: Get all ICMP items
        icmp_item_payload = {
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "output": ["itemid", "name"],
                "hostids": host_id,
                "search": {"name": "ICMP response time"},
            },
            "id": 3
        }
        icmp_item_response = requests.post(cfg["zabbix_host"].rstrip("/")+cfg["zabbix_api_base"], headers=headers, json=icmp_item_payload, verify=False)
        icmp_item_data = icmp_item_response.json().get("result", [])
        icmp_item_ids = [item["itemid"] for item in icmp_item_data]

        # Step 5: Check if host has any items excluding ICMP items
        items_check_payload = {
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "output": ["itemid", "name"],
                "hostids": host_id,
            },
            "id": 4
        }
        items_check_response = requests.post(cfg["zabbix_host"].rstrip("/")+cfg["zabbix_api_base"], headers=headers, json=items_check_payload, verify=False)
        all_items = items_check_response.json().get("result", [])
        # Filter out ICMP items from the list
        # Filter out ICMP items from the list
        filtered_items = [item for item in all_items if "ICMP" not in item["name"]]
        has_items = bool(filtered_items)

        # Build URLs conditionally
        icmp_url = (
            f"{cfg['zabbix_host'].rstrip('/')}/history.php?action=showgraph&itemids%5B%5D={','.join(map(str, icmp_item_ids))}"
            if icmp_item_ids
            else "No ICMP Items"
        )
        graph_url = (
            f"{cfg['zabbix_host'].rstrip('/')}/zabbix.php?action=charts.view&filter_hostids%5B0%5D={host_id}&filter_show=1&filter_set=1"
            if has_items
            else "No Other Items"
        )

        # Host config status
        status_map = {"0": "Enabled", "1": "Disabled"}

        # Host availability status (based on agent/ICMP/etc.)
        availability_map = {"0": "Unknown", "1": "Available", "2": "Unavailable"}
        # Display host info
        # print(f"Hostname      : {host_name}")
        # print(f"  Host Type   : {host_type}")
        # print(f"  IP Address  : {snmp_ip if host_type == 'SNMP' else icmp_ip}")
        # print(f"  Groups      : {', '.join(group_names) if group_names else 'N/A'}")
        # print(f"  ICMP URL    : {icmp_url}")
        # print(f"  Graph URL   : {graph_url}")

        # if isinstance(inventory, dict):
        #    print(f"  OS          : {inventory.get('os', '')}")
        #    print(f"  Serial No.  : {inventory.get('serialno_a', '')}")
        #    print(f"  Notes       : {inventory.get('notes', '')}")
        # else:
        #    print(f"  OS          : ")
        #    print(f"  Serial No.  : ")
        #    print(f"  Notes       : ")

        # print("=" * 40)

        lookupvalues.append(
            [
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
        )

# For debugging
# Output lookupvalues
#print("Lookup values:")
#for entry in lookupvalues:
#    print(f"    {entry},")
#print("]")


lookup["file"]["rows"].extend(lookupvalues)

# Creating new session
with requests.Session() as s:
    api = SycopeApi(s, cfg["sycope_host"].rstrip("/"), cfg["sycope_login"], cfg["sycope_pass"])
    lookup_id, saved_lookup = api.get_lookup(cfg["lookup_name"])

    # For debugging
    # print(json.dumps(saved_lookup, indent=2))
    #
    print("Checking data...")

    if lookup_id == '0':
        print(f'There are no Lookups with "{cfg["lookup_name"]}" name. Creating new...')
        lookup_id = api.create_lookup(cfg["lookup_name"],lookup)
    else:
        compare_config = sorted(lookup["config"].items()) == sorted(saved_lookup["config"].items())
        compare_rows = sorted(lookup["file"]["rows"], key=lambda x: str(x)) == sorted(
            saved_lookup["file"]["rows"], key=lambda x: str(x)
        )

        # For debugging
        # print(f'compare_config: {compare_config}')
        # print(f'compare_rows: {compare_rows}')

        if compare_config and compare_rows:
            print(f'Saved data in the Lookup "{cfg["lookup_name"]}" is identical to the input. No changes required.')
        else:
            lookup.update(
                {
                    "attributes": {"defaultColumns": []},
                    "tags": None,
                    "id": lookup_id,
                    "category": "lookup.lookup",
                }
            )
            api.edit_lookup(lookup_id, lookup)

    # Let's check the privacy configuration
    api.privacy_edit_lookup(lookup_id, cfg["lookup_privacy"])

    # Build the logout payload for Zabbix
    logout_payload = {
        "jsonrpc": "2.0",
        "method": "user.logout",
        "params": [],
        "id": 2
    }

    # Send the logout request to Zabbix
    print("Logging out from Zabbix.")
    logout_response = requests.post(
        cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"],
        json=logout_payload,
        verify=False
    )

    # Closing the REST API session
    # Session should be automatically closed in session context manager
    print("Logging out from Sycope.")
    api.log_out()
    s.close()
