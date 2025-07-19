#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Suricata Integration Installer

This script creates a custom index in Sycope for storing Suricata security events.
It connects to the Sycope API and sets up the necessary database schema with
predefined fields for Suricata EVE JSON log data.

The installer creates an index with fields for:
- Common network event data (IPs, ports, protocols, timestamps)
- Alert-specific fields (signature ID, severity, action, etc.)
- Anomaly-specific fields (event type, category)
- Client/server role determination fields

Usage:
    python install.py

Configuration:
    Requires a config.json file with Sycope API credentials and settings.

Author: Sycope Integration Team
"""

import logging
import os
import sys
import requests
import urllib3

# Add parent directory to path for importing sycope modules
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

# Configuration file paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")

# Suricata field definitions for the custom index
# These fields map to the data structure of Suricata EVE JSON logs
FIELDS = [
    # Common network event fields
    {"name": "timestamp", "type": "long", "description": "Event timestamp", "displayName": "Timestamp"},
    {"name": "flow_id", "type": "long", "description": "Suricata flow ID", "displayName": "Flow ID"},
    {"name": "in_iface", "type": "string", "description": "Interface name", "displayName": "Interface"},
    {"name": "event_type", "type": "string", "description": "Type of event", "displayName": "Event Type"},
    {"name": "src_ip", "type": "ip4", "description": "Source IP address", "displayName": "Source IP"},
    {"name": "src_port", "type": "int", "description": "Source port", "displayName": "Source Port"},
    {"name": "dest_ip", "type": "ip4", "description": "Destination IP address", "displayName": "Destination IP"},
    {"name": "dest_port", "type": "int", "description": "Destination port", "displayName": "Destination Port"},
    {"name": "clientIp", "type": "ip4", "description": "Client IP address (determined by port)", "displayName": "Client IP"},
    {"name": "clientPort", "type": "int", "description": "Client port (higher port number)", "displayName": "Client Port"},
    {"name": "serverIp", "type": "ip4", "description": "Server IP address (determined by port)", "displayName": "Server IP"},
    {"name": "serverPort", "type": "int", "description": "Server port (lower port number)", "displayName": "Server Port"},
    {"name": "proto", "type": "string", "description": "Layer 4 protocol", "displayName": "Protocol"},

    # Alert-specific fields (from Suricata alert events)
    {"name": "alert_action", "type": "string", "description": "Alert action", "displayName": "Suricata Alert Action"},
    {"name": "alert_gid", "type": "int", "description": "Generator ID", "displayName": "Suricata Alert GID"},
    {"name": "alert_signature_id", "type": "int", "description": "Signature ID", "displayName": "Sig ID"},
    {"name": "alert_rev", "type": "int", "description": "Signature revision", "displayName": "Sig Rev"},
    {"name": "event_signature","type": "string","description": "Signature text","displayName": "Signature"},
    {"name": "event_category","type": "string", "description": "Signature category","displayName": "Category"},
    {"name": "alert_severity", "type": "int", "description": "Severity level", "displayName": "Severity"},

    # Anomaly fields (from Suricata anomaly events)
    # Note: These are handled dynamically in the processor using event_signature and event_category
    #    {"name":"anomaly_type",        "type":"string",   "description":"Anomaly type",            "displayName":"Anomaly Type"},
    #    {"name":"anomaly_event",       "type":"string",   "description":"Anomaly event",           "displayName":"Anomaly Event"},
    #    {"name":"anomaly_layer",       "type":"string",   "description":"Anomaly layer",           "displayName":"Layer"},

    # Additional protocol information
    {"name": "app_proto", "type": "string", "description": "Application protocol", "displayName": "App Proto"}
]
def main():
    """
    Main installation function.

    Loads configuration, connects to Sycope API, and creates the custom index
    with the predefined field schema for Suricata events.
    """
    # Load configuration file
    try:
        cfg = load_config(CONFIG_PATH)
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        sys.exit(1)

    # Create HTTP session and connect to Sycope API
    with requests.Session() as s:
        s.headers.update({"Content-Type": "application/json"})
        api = SycopeApi(
            session=s,
            host=cfg["sycope_host"].rstrip("/"),
            login=cfg["sycope_login"],
            password=cfg["sycope_pass"],
            api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
        )

        # Create the custom index with daily rotation
        logging.info(f"Creating Suricata index: {cfg['index_name']}")
        api.create_index(cfg["index_name"], FIELDS, rotation="daily")
        logging.info("Index created successfully")

        # Clean up API session
        api.log_out()

if __name__ == "__main__":
    main()
