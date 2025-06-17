#!/usr/bin/env python
# coding: utf-8

# Lookup synchronization between Zabbix inventory data and Sycope
# Script version: 1.0
# Tested on Sycope 3.1


import requests
import json
# Hiding SSL certificate warning messages
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Sycope credentials
sycopeHost = 'https://192.168.1.14'
sycopeLogin = 'admin'
sycopePassword = ''

# Zabbix API Credentials
ZABBIX_URL_SHORT = "http://192.168.1.46:8080"
ZABBIX_URL = ZABBIX_URL_SHORT+"/api_jsonrpc.php"
USERNAME = "Admin"
PASSWORD = ""


null = None # workaround for defining null in JSON

api_command = '/npm/api/v1/config-element-lookup/csvFile'
lookupname = 'integration-zabbix'
lookupid = '' # clearing the ID
lookupprivacy = 'Public' # Script supports Private and Public privacy
lookup = {
    "config": {
        "name": lookupname,
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
            "string"
        ]
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
            "status"
        ],
        "rows": []
       
    }
    
}



# Step 1: Authenticate
login_payload = {
    "jsonrpc": "2.0",
    "method": "user.login",
    "params": {
        "username": USERNAME,
        "password": PASSWORD
    },
    "id": 1
}

login_response = requests.post(ZABBIX_URL, json=login_payload)
print("Login Response:", login_response.text)

try:
    login_result = login_response.json()
    if "result" in login_result:
        auth_token = login_result["result"]
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
        "selectGroups": ["name"],
        #"filter": {"status": 0},
    },
    "auth": auth_token,
    "id": 2
}

hosts_response = requests.post(ZABBIX_URL, json=hosts_payload)
hosts_data = hosts_response.json().get("result", [])

# Filter to include only hosts with SNMP or ICMP interfaces
snmp_hosts = [
    host for host in hosts_data
    if any(int(iface.get("type", -1)) in [1, 2] for iface in host.get("interfaces", []))
]

lookupvalues = []


# Step 3: Display host info
if not snmp_hosts:
    print("No SNMP or ICMP hosts found.")
else:
    print("SNMP/ICMP Host Information:")

    for host in snmp_hosts:
        inventory = host.get("inventory", {})
        interfaces = host.get("interfaces", [])
        groups = host.get("groups", [])
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
                "search": {"name": "ICMP response time"}
            },
            "auth": auth_token,
            "id": 3
        }
        icmp_item_response = requests.post(ZABBIX_URL, json=icmp_item_payload)
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
            "auth": auth_token,
            "id": 4
        }
        items_check_response = requests.post(ZABBIX_URL, json=items_check_payload)
        all_items = items_check_response.json().get("result", [])
        # Filter out ICMP items from the list
        # Filter out ICMP items from the list
        filtered_items = [item for item in all_items if "ICMP" not in item["name"]]
        has_items = bool(filtered_items)

        # Build URLs conditionally
        icmp_url = f"{ZABBIX_URL_SHORT}/history.php?action=showgraph&itemids%5B%5D={','.join(map(str, icmp_item_ids))}" if icmp_item_ids else "No ICMP Items"
        graph_url = f"{ZABBIX_URL_SHORT}/zabbix.php?action=charts.view&filter_hostids%5B0%5D={host_id}&filter_show=1&filter_set=1" if has_items else "No Other Items"


        # Host config status
        status_map = {
            "0": "Enabled",
            "1": "Disabled"
        }
        
        # Host availability status (based on agent/ICMP/etc.)
        availability_map = {
            "0": "Unknown",
            "1": "Available",
            "2": "Unavailable"
        }
        # Display host info
        #print(f"Hostname      : {host_name}")
        #print(f"  Host Type   : {host_type}")
        #print(f"  IP Address  : {snmp_ip if host_type == 'SNMP' else icmp_ip}")
        #print(f"  Groups      : {', '.join(group_names) if group_names else 'N/A'}")
        #print(f"  ICMP URL    : {icmp_url}")
        #print(f"  Graph URL   : {graph_url}")

        #if isinstance(inventory, dict):
        #    print(f"  OS          : {inventory.get('os', '')}")
        #    print(f"  Serial No.  : {inventory.get('serialno_a', '')}")
        #    print(f"  Notes       : {inventory.get('notes', '')}")
        #else:
        #    print(f"  OS          : ")
        #    print(f"  Serial No.  : ")
        #    print(f"  Notes       : ")

        #print("=" * 40)

        lookupvalues.append([
            snmp_ip if host_type == "SNMP" else icmp_ip,
            host_name,
            host_type,
            ", ".join(group_names) if group_names else "N/A",
            icmp_url,
            graph_url,
            inventory.get("os", "") if isinstance(inventory, dict) else "",
            inventory.get("serialno_a", "") if isinstance(inventory, dict) else "",
            inventory.get("notes", "") if isinstance(inventory, dict) else "",
            status_map.get(str(host.get('status')), 'Unknown'),
        ])

#For debugging
#Output lookupvalues
print("Lookup values:")
for entry in lookupvalues:
    print(f"    {entry},")
print("]")


lookup["file"]["rows"].extend(lookupvalues)

# Creating new session
with requests.Session() as s:

    payload = {"username": sycopeLogin, "password": sycopePassword}
    s.post(sycopeHost + '/npm/api/v1/login', json=payload, verify=False)

    print('Searching in saved Lookups...')
    r = s.get(sycopeHost+'/npm/api/v1/config-elements?offset=0&limit=2147483647&filter=category = "lookup.lookup"',json=payload, verify=False)
    all_data = r.json()["data"]

    
    for result in all_data:
        if result['config']['name'] == lookupname:
            lookupid = result['id']
            savedtags = result['tags']
            print(f'Found Lookup "{lookupname}" with ID "{lookupid}".')

            r = s.get(f'{sycopeHost}/npm/api/v1/config-element-lookup/csvFile/{lookupid}',json=payload, verify=False)
            savedlookup = r.json()

            #For debugging
            #print(json.dumps(savedlookup, indent=2))

            print('Checking data...')
            compare_config = sorted(lookup['config'].items()) == sorted(savedlookup['config'].items())
            compare_rows = sorted(lookup['file']['rows'], key=lambda x: str(x)) == \
                           sorted(savedlookup['file']['rows'], key=lambda x: str(x))
            
            #For debugging
            #print(f'compare_config: {compare_config}')
            #print(f'compare_rows: {compare_rows}')

            if compare_config == True and compare_rows == True:
                print(f'Saved data in the Lookup "{lookupname}" is identical to the input. No changes required.')
            else:
                lookup.update({
                    "attributes": {"defaultColumns": []},
                    "tags": None,
                    "id": lookupid,
                    "category": "lookup.lookup"
                })
    
                api_command = api_command + "/" + lookupid
    
                r = s.put(sycopeHost+api_command,json=lookup, verify=False)
                data = r.json()
                
                if data['status'] == 200:
                    print(f'Data in the Lookup "{lookupname}" with ID "{lookupid}" have been successfully modified.')
                else:
                    #For debugging
                    print(r.json()) 
                
            break

    if lookupid == '':

        print(f'There are no Lookups with "{lookupname}" name. Creating new...')
        r = s.post(f'{sycopeHost}/npm/api/v1/config-element-lookup/csvFile',json=lookup, verify=False)
        data = r.json()

        lookupid = data['id']

        if data['status'] == 200:
            print(f'New Lookup "{lookupname}" with ID "{lookupid}" has been created.')
        else:
            #For debugging
            print(r.json())

    # Let's check the privacy configuration
    print('Checking privacy...')

    r = s.get(f'{sycopeHost}/npm/api/v1/permissions/CONFIGURATION.lookup.lookup/{lookupid}',json=lookup, verify=False)
    data = r.json()
    savedsidPerms = data['sidPerms']


    # Definition for Public Privacy
    sidPermsPublic = [
      {
        "sid": "ROLE_USER",
        "perms": [
          "VIEW"
        ]
      }
    ]
    # Definition for Private Privacy
    sidPermsPrivate = []

    # Checking defined Privacy in Sycope
    savedsidPermsValue = ''
    if savedsidPerms == sidPermsPublic: savedsidPermsValue = 'Public'
    if savedsidPerms == sidPermsPrivate: savedsidPermsValue = 'Private'

    #For debugging
    #print(json.dumps(data, indent=2))

    if lookupprivacy == 'Public' and savedsidPermsValue != 'Public':
        r = s.put(f'{sycopeHost}/npm/api/v1/permissions/CONFIGURATION.lookup.lookup/{lookupid}',json=sidPermsPublic, verify=False)
        data = r.json()
        # Verifying if data was saved successfully
        if data['sidPerms'] == sidPermsPublic:
            print(f'Privacy for Lookup "{lookupname}" with ID "{lookupid}" has been modified to Public.')
        else:
            #For debugging
            print(r.json()) 

    elif lookupprivacy == 'Private' and savedsidPermsValue != 'Private':
        r = s.put(f'{sycopeHost}/npm/api/v1/permissions/CONFIGURATION.lookup.lookup/{lookupid}',json=sidPermsPrivate, verify=False)
        data = r.json()
        # Verifying if data was saved successfully
        if data['sidPerms'] == sidPermsPrivate:
            print(f'Privacy for Lookup "{lookupname}" with ID "{lookupid}" has been modified to Private.')
        else:
            #For debugging
            print(r.json()) 
    elif savedsidPermsValue == '':
        print(f'Script could not identify the Privacy configuration in the Lookup "{lookupname}". Are you using custom Shared Privacy?')
    else:
        print(f'Privacy in the Lookup "{lookupname}" is identical to the input. No changes required.')
                
  
    # Closing the REST API session
    # Session should be automatically closed in session context manager
    print("Logging out from Sycope.")
    r = s.get(sycopeHost+'/npm/api/v1/logout', verify=False)
    s.close()
