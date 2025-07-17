#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
import requests
import urllib3

sys.path.insert(0, os.path.abspath(".."))
from sycope.api import SycopeApi
from sycope.functions import load_config

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Logging config
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler("install.log"), logging.StreamHandler(sys.stdout)],
)

# Example config file
# {
#     "sycope_host": "https://sycope.local",              // Sycope API hostname (with https)
#     "sycope_login": "admin",                            // API login
#     "sycope_pass": "admin",                             // API password
#     "index_name": "suricata",                           // Name of the custom index to use
#     "api_base": "/npm/api/v1",                          // API base path prefix
#     "suricata_eve_json_path": "/var/log/suricata/eve.json",  // Path to Suricata's eve.json file
#     "last_timestamp_file": "last_timestamp.txt",        // File storing last processed timestamp
#     "event_types": ["anomaly", "alert"],                // Event types to process (e.g., "alert", "anomaly")
#     "anomaly_whitelist": []],                         // If true, only allow anomaly events listed in anomaly_whitelist
#     "alert_whitelist": []],                           // If true, only allow alert SIDs listed in alert_whitelist
#     "anomaly_blacklist": [],                            // List of anomaly event names to skip
#     "alert_blacklist": []                               // List of Suricata alert signature IDs to skip
# }

# Path to config
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")

# Suricata field definitions
FIELDS = [
    {"name": "timestamp", "type": "long", "description": "Event timestamp", "displayName": "Timestamp"},
    {"name": "flow_id", "type": "long", "description": "Suricata flow ID", "displayName": "Flow ID"},
    {"name": "in_iface", "type": "string", "description": "Interface name", "displayName": "Interface"},
    {"name": "event_type", "type": "string", "description": "Type of event", "displayName": "Event Type"},
    {"name": "src_ip", "type": "ip4", "description": "Source IP address", "displayName": "Source IP"},
    {"name": "src_port", "type": "int", "description": "Source port", "displayName": "Source Port"},
    {"name": "dest_ip", "type": "ip4", "description": "Destination IP address", "displayName": "Destination IP"},
    {"name": "dest_port", "type": "int", "description": "Destination port", "displayName": "Destination Port"},
    {"name": "clientIp", "type": "ip4", "description": "Source IP address", "displayName": "Client IP"},
    {"name": "clientPort", "type": "int", "description": "Source port", "displayName": "Client Port"},
    {"name": "serverIp", "type": "ip4", "description": "Destination IP address", "displayName": "Server IP"},
    {"name": "serverPort", "type": "int", "description": "Destination port", "displayName": "Server Port"},
    {"name": "proto", "type": "string", "description": "Layer 4 protocol", "displayName": "Protocol"},
    # alert fields
    {"name": "alert_action", "type": "string", "description": "Alert action", "displayName": "Suricata Alert Action"},
    {"name": "alert_gid", "type": "int", "description": "Generator ID", "displayName": "Suricata Alert GID"},
    {"name": "alert_signature_id", "type": "int", "description": "Signature ID", "displayName": "Sig ID"},
    {"name": "alert_rev", "type": "int", "description": "Signature revision", "displayName": "Sig Rev"},
    {"name": "event_signature","type": "string","description": "Signature text","displayName": "Signature"},
    {"name": "event_category","type": "string", "description": "Signature category","displayName": "Category"},
    {"name": "alert_severity", "type": "int", "description": "Severity level", "displayName": "Severity"},
    # anomaly fields
    #    {"name":"anomaly_type",        "type":"string",   "description":"Anomaly type",            "displayName":"Anomaly Type"},
    #    {"name":"anomaly_event",       "type":"string",   "description":"Anomaly event",           "displayName":"Anomaly Event"},
    #    {"name":"anomaly_layer",       "type":"string",   "description":"Anomaly layer",           "displayName":"Layer"},
    # additional
    {"name": "app_proto", "type": "string", "description": "Application protocol", "displayName": "App Proto"}
]
def main():
    try:
        cfg = load_config(CONFIG_PATH)
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        sys.exit(1)

    with requests.Session() as s:
        s.headers.update({"Content-Type": "application/json"})
        api = SycopeApi(
            session=s,
            host=cfg["sycope_host"].rstrip("/"),
            login=cfg["sycope_login"],
            password=cfg["sycope_pass"],
            api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
        )
        api.create_index(cfg["index_name"], FIELDS, rotation="daily")
        api.log_out()

if __name__ == "__main__":
    main()
