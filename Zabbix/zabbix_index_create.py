#!/usr/bin/env python
# coding: utf-8

# Create new custom stream for Zabbix statistics (Hostname, Response Time, CPU Load, Memory Usage, Packet Loss)
# Script version: 1.0
# Tested on Sycope 3.1

import requests
import time
# Hiding SSL certificate warning messages
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#### Script Parameters

# Sycope website & credentials
host = 'https://192.168.1.14'
login = 'admin'
password = ''

stream_name = 'ZabbixStats'
rotation = 'daily'

### Creating new session
with requests.Session() as s: 
    

    payload={"username":login,"password":password}
    r = s.post(host+'/npm/api/v1/login',json=payload, verify=False)
    
    data = r.json()
    if data['status'] == 200:
        print(f'Login successful. Proceeding...')
    else:
        #For debugging
        print(r.json())
        
    payload = {
        "name": stream_name,
        "active": True,
        "rotation": rotation,
        "storeRaw": True,
        "fields": [
          {
            "name": "timestamp",
            "type": "long",
            "sortable": True,
            "description": "Timestamp",
            "displayName": "Time"
          },
          {
            "name": "ip",
            "type": "ip4",
            "description": "IP Address",
            "displayName": "IP Address"
          },
            {
            "name": "hostname",
            "type": "string",
            "description": "Hostname",
            "displayName": "Hostname"
          },
            {
            "name": "response_time",
            "type": "float",
            "description": "Reponse Time (ms)",
            "displayName": "Reponse Time"
          },
            {
            "name": "cpu_load",
            "type": "float",
            "description": "CPU Percentage Load",
            "displayName": "CPU Load"
          },
            {
            "name": "memory_usage",
            "type": "float",
            "description": "Memory Percentage Usage",
            "displayName": "Memory Usage"
          },
            {
            "name": "packet_loss",
            "type": "float",
            "description": "Percentage Packet Loss",
            "displayName": "Packet Loss"
          }
        ]
    }
    r = s.post(host+'/npm/api/v1/config-element-index/user-index',json=payload, verify=False)
    
    data = r.json()
    if data['status'] == 200:
        print(f'New custom stream "{stream_name}" has been created.')
    else:
        #For debugging
        print("API response:")
        print(r.json())


    # Closing the REST API session
    # Session should be automatically closed in session context manager
    r = s.get(host+'/npm/api/v1/logout', verify=False)
    s.close()
