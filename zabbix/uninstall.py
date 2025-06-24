#!/usr/bin/env python
# coding: utf-8

# Remove custom stream for Zabbix statistics
# Script version: 1.0
# Tested on Sycope 3.1

import time
import json
import logging
import os
import sys

import requests
import urllib3
from requests import Session

# setting path
sys.path.append('../sycope')
from api import SycopeApi

# --- Disable SSL warnings (self-signed certs) ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler("create_index.log"), logging.StreamHandler(sys.stdout)],
)

SCRIPT_DIR = os.getcwd()  # use current directory
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

def main():
    try:
        with open(CONFIG_FILE, 'r') as f:
            cfg = json.load(f)
    except Exception as e:
        logging.error(f"ERROR loading config: {e}")
        sys.exit(1)
    else:
        logging.info(f"Loaded configuration from {CONFIG_FILE}")
    ### Creating new session
    with requests.Session() as s:
        api = SycopeApi(s, cfg["sycope_host"].rstrip("/"), cfg["sycope_login"], cfg["sycope_pass"])

        # Removing custom Zabbix index
        r = api.remove_index(cfg["index_name"])
    
        # Closing the REST API session
        # Session should be automatically closed in session context manager
        api.log_out()
        s.close()

if __name__ == "__main__":
    main()
