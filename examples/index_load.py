#!/usr/bin/env python
# coding: utf-8

import json
import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler

import requests
import urllib3

# Repository root on the import path, so the shared "sycope" package can be imported
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(SCRIPT_DIR, "..")))
from sycope.api import SycopeApi  # noqa: E402

# --- Disable SSL warnings (self-signed certs) ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        RotatingFileHandler(os.path.join(SCRIPT_DIR, "index_load.log"), maxBytes=10 * 1024 * 1024, backupCount=5),
        logging.StreamHandler(sys.stdout),
    ],
)

CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")


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

        # Load the saved JSON data
        with open(os.path.join(SCRIPT_DIR, "new_data.json"), "r") as f:
            new_data = json.load(f)

        # Step 1: Extract all timestamps
        timestamps = [entry[0] for entry in new_data]

        # Step 2: Find the latest timestamp in the data
        max_timestamp = max(timestamps)

        # Step 3: Get current time in milliseconds
        current_time_ms = int(time.time() * 1000)

        # Step 4: Calculate the time shift (delta)
        delta = current_time_ms - max_timestamp

        # Step 5: Apply the delta to all timestamps
        for entry in new_data:
            entry[0] += delta

        # Optional: Save the updated data back to file
        # with open("new_data_shifted.json", "w") as f:
        #    json.dump(new_data, f, indent=2)

        payload = {
            "columns": [
                "timestamp",
                "ip",
                "hostname",
                "response_time",
                "cpu_load",
                "memory_usage",
                "packet_loss",
            ],
            "indexName": cfg["index_name"] + "_" + str(cfg["user_number"]),
            "sortTimestamp": True,
            "rows": new_data,
        }

        r = s.post(cfg["sycope_host"].rstrip("/") + "/npm/api/v1/index/inject", json=payload, verify=False)
        data = r.json()
        if data["status"] == 200:
            print("Sycope API successfully saved new data.")
        else:
            # For debugging
            print("Sycope API encountered an issue. Error message:")
            print(r.json())

        # Closing the REST API session
        # Session should be automatically closed in session context manager
        api.log_out()
        s.close()


if __name__ == "__main__":
    main()
