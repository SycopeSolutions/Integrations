#!/usr/bin/env python3

import logging
import os
import sys
import urllib3
import requests
sys.path.insert(0, os.path.abspath(".."))
from sycope.api import SycopeApi
from sycope.functions import load_config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")

def main():
    try:
        cfg = load_config(CONFIG_PATH)
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        sys.exit(1)

    with requests.Session() as s:
        s.headers.update({"Content-Type": "application/json"})
        api = SycopeApi(s, cfg["sycope_host"], cfg["sycope_login"], cfg["sycope_pass"], cfg["api_base"])
        api.remove_index(cfg["index_name"])
        api.log_out()

if __name__ == "__main__":
    main()
