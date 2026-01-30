#!/usr/bin/env python
# coding: utf-8

# Create new custom stream for Zabbix statistics (Hostname, Response Time, CPU Load, Memory Usage, Packet Loss)
# Script version: 1.0
# Tested on Sycope 3.1

import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

import requests
import urllib3

# setting path
sys.path.append("../sycope")
from api import SycopeApi

# --- Disable SSL warnings (self-signed certs) ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        RotatingFileHandler("create_index.log", maxBytes=10 * 1024 * 1024, backupCount=5),
        logging.StreamHandler(sys.stdout),
    ],
)

SCRIPT_DIR = os.getcwd()  # use current directory
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

FIELDS = [
    {
        "name": "timestamp",
        "type": "long",
        "sortable": True,
        "description": "Timestamp",
        "displayName": "Time",
    },
    {"name": "ip", "type": "ip4", "description": "IP Address", "displayName": "IP Address"},
    {"name": "hostname", "type": "string", "description": "Hostname", "displayName": "Hostname"},
    {
        "name": "response_time",
        "type": "float",
        "description": "Reponse Time (ms)",
        "displayName": "Reponse Time",
    },
    {
        "name": "cpu_load",
        "type": "float",
        "description": "CPU Percentage Load",
        "displayName": "CPU Load",
    },
    {
        "name": "memory_usage",
        "type": "float",
        "description": "Memory Percentage Usage",
        "displayName": "Memory Usage",
    },
    {
        "name": "packet_loss",
        "type": "float",
        "description": "Percentage Packet Loss",
        "displayName": "Packet Loss",
    },
]


def main():
    try:
        with open(CONFIG_FILE, "r") as f:
            cfg = json.load(f)
    except Exception as e:
        logging.error(f"ERROR loading config: {e}")
        sys.exit(1)
    else:
        logging.info(f"Loaded configuration from {CONFIG_FILE}")
    ### Creating new session
    with requests.Session() as s:
        api = SycopeApi(s, cfg["sycope_host"].rstrip("/"), cfg["sycope_login"], cfg["sycope_pass"])
        r = api.create_index(cfg["index_name"] + "_" + str(cfg["user_number"]), FIELDS, cfg["index_rotation"])

        # Closing the REST API session
        # Session should be automatically closed in session context manager
        api.log_out()
        s.close()


if __name__ == "__main__":
    main()
