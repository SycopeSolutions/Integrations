#!/usr/bin/env python
# coding: utf-8

# Removing Zabbix custom index
# Script version: 1.0
# Tested on Sycope 3.1

import requests
import json
import time
# Hiding SSL certificate warning messages
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#### Script Parameters

# Sycope website & credentials
host = 'https://192.168.1.14'
login = 'admin'
password = ''

indexToBeRemoved = 'ZabbixStats'

### Creating new session
with requests.Session() as s: 
    
    payload={"username":login,"password":password}
    r = s.post(host+'/npm/api/v1/login',json=payload, verify=False)
    
    data = r.json()
    
    if data['status'] == 200:
        print(f'Sycope API login successful. Proceeding...')
    else:
        #For debugging
        print(f'Sycope API login failed:')
        print(r.json())

    print('Searching in existing custom indexes...')
    r = s.get(host+'/npm/api/v1/config-elements?filter=category="userIndex.index"', verify=False)
    all_data = r.json()["data"]

    #For debugging
    #print(json.dumps(all_data, indent=2))
    
    for result in all_data:
        if result['config']['name'] == indexToBeRemoved:
            indexid = result['id']
            print(f'Found custom index "{indexToBeRemoved}" with ID "{indexid}".')

            r = s.delete(host+'/npm/api/v1/config-element-index/user-index/'+indexid, verify=False)
            
            data = ''
            data = r.json()
            
            if data['status'] == 200:
                print(f'Custom index "{indexToBeRemoved}" has been successfully removed.')
            else:
                #For debugging
                print(f'Removing custom index "{indexToBeRemoved}" failed. Error message:')
                print(r.json())

    # Closing the REST API session
    # Session should be automatically closed in session context manager
    r = s.get(host+'/npm/api/v1/logout', verify=False)
    s.close()

