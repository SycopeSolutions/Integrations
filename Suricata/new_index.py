#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import urllib3
import requests
from requests import Session

# --- Disable SSL warnings (self-signed certs) ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("create_index.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# --- Load configuration from config.json ---
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE  = os.path.join(SCRIPT_DIR, "config.json")
cfg          = json.load(open(CONFIG_FILE))
SYCOPE_HOST  = cfg["sycope_host"].rstrip("/")      # Sycope address with protocol and port
LOGIN        = cfg["sycope_login"]                 # Sycope username
PASSWORD     = cfg["sycope_pass"]                  # Sycope password
INDEX_NAME   = cfg["index_name"]                   # Name of the index to create
API_BASE     = "/npm/api/v1"                       # Base path to the API

# --- Suricata fields definition ---
FIELDS = [
    {"name":"timestamp",           "type":"long",     "description":"Event timestamp",         "displayName":"Timestamp"},
    {"name":"flow_id",             "type":"long",     "description":"Suricata flow ID",        "displayName":"Flow ID"},
    {"name":"in_iface",            "type":"string",   "description":"Interface name",          "displayName":"Interface"},
    {"name":"event_type",          "type":"string",   "description":"Type of event",           "displayName":"Event Type"},
    {"name":"src_ip",              "type":"ip4",      "description":"Source IP address",       "displayName":"Src IP"},
    {"name":"src_port",            "type":"int",      "description":"Source port",             "displayName":"Src Port"},
    {"name":"dest_ip",             "type":"ip4",      "description":"Destination IP address",  "displayName":"Dest IP"},
    {"name":"dest_port",           "type":"int",      "description":"Destination port",        "displayName":"Dest Port"},
    {"name":"proto",               "type":"string",   "description":"Layer 4 protocol",        "displayName":"Protocol"},
    # alert fields
    {"name":"alert_action",        "type":"string",   "description":"Alert action",            "displayName":"Alert Action"},
    {"name":"alert_gid",           "type":"int",      "description":"Generator ID",            "displayName":"Alert GID"},
    {"name":"alert_signature_id",  "type":"int",      "description":"Signature ID",            "displayName":"Sig ID"},
    {"name":"alert_rev",           "type":"int",      "description":"Signature revision",      "displayName":"Sig Rev"},
    {"name":"event_signature",     "type":"string",   "description":"Signature text",          "displayName":"Signature"},
    {"name":"event_category",      "type":"string",   "description":"Signature category",      "displayName":"Category"},
    {"name":"alert_severity",      "type":"int",      "description":"Severity level",          "displayName":"Severity"},
    # anomaly fields
#    {"name":"anomaly_type",        "type":"string",   "description":"Anomaly type",            "displayName":"Anomaly Type"},
#    {"name":"anomaly_event",       "type":"string",   "description":"Anomaly event",           "displayName":"Anomaly Event"},
#    {"name":"anomaly_layer",       "type":"string",   "description":"Anomaly layer",           "displayName":"Layer"},
    # additional
    {"name":"app_proto",           "type":"string",   "description":"Application protocol",    "displayName":"App Proto"}
]

def main():
    # 1. Create session
    session = Session()
    session.verify = False
    session.headers.update({"Content-Type": "application/json"})

    # 2. Login
    login_payload = {"username": LOGIN, "password": PASSWORD}
    login_url     = f"{SYCOPE_HOST}{API_BASE}/login"
    r = session.post(login_url, json=login_payload)
    if r.status_code != 200:
        logging.error(f"Login failed: {r.status_code} {r.text}")
        sys.exit(1)
    logging.info("Logged in to Sycope API")

    # 3. Retrieve CSRF token from cookie (if present)
    csrf = session.cookies.get("XSRF-TOKEN")
    if csrf:
        session.headers.update({"X-XSRF-TOKEN": csrf})

    # 4. Prepare payload for index creation
    payload = {
        "category": "userIndex.index",
        "config": {
            "name":       INDEX_NAME,
            "active":     True,
            "rotation":   "daily",
            "storeRaw":   True,
            "fields":     FIELDS
        }
    }

    # 5. Send index creation request
    create_url = f"{SYCOPE_HOST}{API_BASE}/config-element-index/user-index"
    r = session.post(create_url, json=payload)
    if r.status_code in (200, 201):
        logging.info(f"Index '{INDEX_NAME}' created successfully.")
        print(json.dumps(r.json(), indent=2))
    else:
        logging.error(f"Error creating index: {r.status_code}")
        try:
            print(r.json())
        except ValueError:
            print(r.text)

    # 6. (Optional) Logout
    session.get(f"{SYCOPE_HOST}{API_BASE}/logout")
    logging.info("Session ended")

if __name__ == "__main__":
    main()
