#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Suricata Integration Uninstaller

This script removes the Suricata custom index from Sycope, effectively
uninstalling the Suricata integration. It connects to the Sycope API
and deletes the index specified in the configuration file.

Usage:
    python uninstall.py

Configuration:
    Requires a config.json file with Sycope API credentials and the
    index name to remove.

Warning:
    This will permanently delete all data stored in the Suricata index.
    Make sure to backup any important data before running this script.

Author: Sycope Integration Team
"""

import logging
import os
import sys
import urllib3
import requests

# Add parent directory to path for importing sycope modules
sys.path.insert(0, os.path.abspath(".."))
from sycope.api import SycopeApi
from sycope.functions import load_config

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Configuration file paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")

def main():
    """
    Main uninstallation function.

    Loads configuration, connects to Sycope API, and removes the
    Suricata custom index from the system.
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
        api = SycopeApi(s, cfg["sycope_host"], cfg["sycope_login"], cfg["sycope_pass"], cfg["api_base"])

        # Remove the Suricata index
        logging.info(f"Removing Suricata index: {cfg['index_name']}")
        api.remove_index(cfg["index_name"])
        logging.info("Index removed successfully")

        # Clean up API session
        api.log_out()

if __name__ == "__main__":
    main()
