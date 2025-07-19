#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Suricata EVE JSON Log Processor

This module processes Suricata EVE JSON logs and injects filtered events into a Sycope custom index.
It continuously reads from Suricata's eve.json file, filters events based on configuration,
and sends them to the Sycope API for indexing and analysis.

Features:
- Incremental processing using timestamp tracking
- Configurable event type filtering (alerts, anomalies, etc.)
- Whitelist/blacklist support for alerts and anomalies
- Automatic client/server IP determination based on port numbers
- Column mapping and data type conversion
- Comprehensive logging and error handling

Author: Sycope Integration Team
"""

import json
import logging
import os
import socket
import sys
from datetime import datetime, timezone
import requests
import urllib3

# Add parent directory to path for importing sycope modules
sys.path.insert(0, os.path.abspath(".."))
from sycope.api import SycopeApi
from sycope.functions import load_config

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging to both file and console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("eve_processor.log"), logging.StreamHandler(sys.stdout)],
)

# Configuration file paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")

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
#     "anomaly_whitelist": false,                         // If true, only allow anomaly events listed in anomaly_whitelist
#     "alert_whitelist": false,                           // If true, only allow alert SIDs listed in alert_whitelist
#     "anomaly_blacklist": [],                            // List of anomaly event names to skip
#     "alert_blacklist": []                               // List of Suricata alert signature IDs to skip
# }


def load_last_ts(path):
    """
    Load the last processed timestamp from a file.

    Args:
        path (str): Path to the timestamp file

    Returns:
        datetime: The last processed timestamp in UTC, or epoch if file doesn't exist
    """
    if not os.path.exists(path):
        return datetime.fromtimestamp(0, tz=timezone.utc)
    txt = open(path).read().strip()
    return datetime.fromisoformat(txt) if txt else datetime.fromtimestamp(0, tz=timezone.utc)


def save_last_ts(path, dt):
    """
    Save the last processed timestamp to a file.

    Args:
        path (str): Path to the timestamp file
        dt (datetime): Timestamp to save
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    open(path, "w").write(dt.isoformat())


def parse_eve_ts(s):
    """
    Parse a Suricata EVE timestamp string into a UTC datetime object.

    Handles timezone offset formats and ensures the result is in UTC.

    Args:
        s (str): Timestamp string from EVE JSON

    Returns:
        datetime: Parsed timestamp in UTC
    """
    # Handle timezone offset format (e.g., "+02:00" -> "+0200")
    if len(s) > 6 and s[-3] == ":":
        s = s[:-3] + s[-2:]
    dt = datetime.fromisoformat(s)
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def should_process(ev, cfg, last_dt):
    """
    Determine if an event should be processed based on configuration filters.

    Filters events based on:
    - Event type inclusion
    - Timestamp (only process newer events)
    - Alert whitelist/blacklist (for alert events)
    - Anomaly whitelist/blacklist (for anomaly events)

    Args:
        ev (dict): Event dictionary from EVE JSON
        cfg (dict): Configuration dictionary
        last_dt (datetime): Last processed timestamp

    Returns:
        tuple: (should_process: bool, event_timestamp: datetime or None)
    """
    et, ts = ev.get("event_type"), ev.get("timestamp", False)
    if not et or not ts:
        return False, None
    dt = parse_eve_ts(ts)
    if dt <= last_dt or et not in cfg["event_types"]:
        return False, dt

    # Check alert filtering rules
    if et == "alert":
        sid = ev.get("alert", {}).get("signature_id")
        if (
            sid is None
            or (cfg["alert_whitelist"] and sid not in cfg["alert_whitelist_set"])
            or (not cfg["alert_whitelist"] and sid in cfg["alert_blacklist_set"])
        ):
            return False, dt

    # Check anomaly filtering rules
    if et == "anomaly":
        name = ev.get("anomaly", {}).get("event")
        if (
            name is None
            or (cfg["anomaly_whitelist"] and name not in cfg["anomaly_whitelist_set"])
            or (not cfg["anomaly_whitelist"] and name in cfg["anomaly_blacklist_set"])
        ):
            return False, dt
    return True, dt


def action_valid_ipv4(addr):
    """
    Validate and return an IPv4 address.

    Args:
        addr (str): IP address string to validate

    Returns:
        str or None: Valid IP address or None if invalid
    """
    try:
        socket.inet_aton(addr)
        return addr
    except Exception:
        return None


def action_convert_time(val):
    """
    Convert timestamp string to Unix timestamp in milliseconds.

    Args:
        val (str): Timestamp string

    Returns:
        int or None: Unix timestamp in milliseconds, or None if conversion fails
    """
    try:
        dt = parse_eve_ts(val)
        return int(dt.timestamp() * 1000)
    except:
        return None


def build_row(ev, column_names, column_mapping, cols_idxs, column_actions=None):
    """
    Build a row for database insertion from an EVE event.

    Maps event fields to database columns according to the column mapping,
    applies column actions for data transformation, and determines client/server
    roles based on port numbers (higher port = client).

    Args:
        ev (dict): Event dictionary from EVE JSON
        column_names (list): List of database column names
        column_mapping (dict): Mapping of columns to event field paths
        cols_idxs (list): Indices of IP/port columns for client/server determination
        column_actions (dict, optional): Functions to apply to specific columns

    Returns:
        list: Row data ready for database insertion
    """
    if column_actions is None:
        column_actions = {}

    et = ev.get("event_type")
    # Build column mapping for this event type
    row_map = column_mapping["common"].copy()
    row_map.update(column_mapping.get(et, {}))

    # Extract values for each column
    row = []
    for col in column_names:
        if col in row_map:
            if row_map[col]:
                # Navigate nested dictionary structure
                val = ev
                for key in row_map[col]:
                    val = val.get(key, None)
            else:
                val = None
        else:
            val = ev.get(col) or None

        # Apply column-specific transformations
        if col in column_actions:
            try:
                val = column_actions[col](val)
            except Exception as e:
                logging.debug(f"Column action failed for {col}: {val} - {e}")
                raise

        row.append(val)

    # Determine client/server roles based on port numbers (higher port = client)
    if 'clientIp' in column_names or 'serverIp' in column_names:
        src_ip_idx, dst_ip_idx, src_port_idx, dst_port_idx, serverIp_idx, clientIp_idx, serverPort_idx, clientPort_idx = cols_idxs

        src_ip = row[src_ip_idx] if src_ip_idx is not None else None
        dst_ip = row[dst_ip_idx] if dst_ip_idx is not None else None
        src_port = row[src_port_idx] if src_port_idx is not None else None
        dst_port = row[dst_port_idx] if dst_port_idx is not None else None

        # Use port comparison to determine client/server roles
        src_port_cmp = src_port if src_port is not None else 0
        dst_port_cmp = dst_port if dst_port is not None else 0

        if src_port_cmp >= dst_port_cmp:
            client_ip, server_ip = src_ip, dst_ip
            client_port, server_port = src_port, dst_port
        else:
            client_ip, server_ip = dst_ip, src_ip
            client_port, server_port = dst_port, src_port

        # Update row with client/server information
        row[clientIp_idx] = client_ip
        row[serverIp_idx] = server_ip
        row[clientPort_idx] = client_port
        row[serverPort_idx] = server_port
    return row


def main():
    """
    Main function to process Suricata EVE JSON logs.

    Loads configuration, connects to Sycope API, processes EVE log entries,
    and injects filtered events into the configured custom index.
    """
    # Load and validate configuration
    try:
        cfg = load_config(CONFIG_PATH)
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Convert filter lists to sets for faster lookups
    cfg["alert_whitelist_set"] = set(cfg.get("alert_whitelist", []))
    cfg["alert_blacklist_set"] = set(cfg.get("alert_blacklist", []))
    cfg["anomaly_whitelist_set"] = set(cfg.get("anomaly_whitelist", []))
    cfg["anomaly_blacklist_set"] = set(cfg.get("anomaly_blacklist", []))

    # Initialize timestamp tracking and processing state
    last_ts_file = os.path.join(SCRIPT_DIR, cfg["last_timestamp_file"])
    last_dt = load_last_ts(last_ts_file)
    max_dt = last_dt
    rows = []
    counts = {"processed": 0, "skipped": 0, "invalid": 0}

    # Initialize HTTP session and Sycope API connection
    with requests.Session() as s:
        s.headers.update({"Content-Type": "application/json"})
        api = SycopeApi(
            session=s,
            host=cfg["sycope_host"].rstrip("/"),
            login=cfg["sycope_login"],
            password=cfg["sycope_pass"],
            api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
        )

        # Get target index configuration
        indexes = api.get_user_indicies()
        match = [x for x in indexes if x["config"]["name"] == cfg["index_name"]]
        if not match:
            logging.error(f"Index '{cfg['index_name']}' not found.")
            sys.exit(1)

        # Extract column names and types from index schema
        idx = match[0]
        fields = idx["config"]["fields"]
        COLUMNS = [f["name"] for f in fields]
        TYPES = [f["type"] for f in fields]

        # Define mapping from database columns to EVE JSON field paths
        COLUMN_MAP = {
            "common": {
                "timestamp": ["timestamp"],
                "flow_id": ["flow_id"],
                "in_iface": ["in_iface"],
                "event_type": ["event_type"],
                "src_ip": ["src_ip"],
                "src_port": ["src_port"],
                "dest_ip": ["dest_ip"],
                "dest_port": ["dest_port"],
                "proto": ["proto"],
                "app_proto": ["app_proto"],
                "clientIp": [],  # Computed field
                "clientPort": [],  # Computed field
                "serverIp": [],  # Computed field
                "serverPort": [],  # Computed field
            },
            "anomaly": {
                "event_category": ["anomaly", "type"],
                "event_signature": ["anomaly", "event"],
            },
            "alert": {
                "alert_action": ["alert", "action"],
                "alert_gid": ["alert", "gid"],
                "alert_signature_id": ["alert", "signature_id"],
                "alert_rev": ["alert", "rev"],
                "event_signature": ["alert", "signature"],
                "event_category": ["alert", "category"],
                "alert_severity": ["alert", "severity"],
            },
        }

        # Get column indices for client/server determination
        src_ip_idx = COLUMNS.index('src_ip') if 'src_ip' in COLUMNS else None
        dst_ip_idx = COLUMNS.index('dest_ip') if 'dest_ip' in COLUMNS else None
        src_port_idx = COLUMNS.index('src_port') if 'src_port' in COLUMNS else None
        dst_port_idx = COLUMNS.index('dest_port') if 'dest_port' in COLUMNS else None
        serverIp_idx = COLUMNS.index('serverIp') if 'serverIp' in COLUMNS else None
        clientIp_idx = COLUMNS.index('clientIp') if 'clientIp' in COLUMNS else None
        serverPort_idx = COLUMNS.index('serverPort') if 'serverPort' in COLUMNS else None
        clientPort_idx = COLUMNS.index('clientPort') if 'clientPort' in COLUMNS else None
        cols_idxs = [src_ip_idx, dst_ip_idx, src_port_idx, dst_port_idx, serverIp_idx, clientIp_idx, serverPort_idx, clientPort_idx]

        logging.info(f"Using index '{cfg['index_name']}' with columns: {COLUMNS}")

        # Set up column transformation functions based on data types
        column_actions = {}
        for col, typ in zip(COLUMNS, TYPES):
            if typ == "ip4":
                column_actions[col] = action_valid_ipv4
            if col == "timestamp":
                column_actions[col] = action_convert_time

        # Process EVE JSON log file line by line
        with open(cfg["suricata_eve_json_path"]) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Parse JSON event
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    counts["skipped"] += 1
                    continue

                # Apply filters and timestamp checks
                ok, dt = should_process(ev, cfg, last_dt)
                if dt and dt > max_dt:
                    max_dt = dt
                if not ok:
                    counts["skipped"] += 1
                    continue

                # Build database row from event
                try:
                    row = build_row(ev, COLUMNS, COLUMN_MAP, cols_idxs, column_actions)
                except Exception:
                    counts["invalid"] += 1
                else:
                    rows.append(row)
                    counts["processed"] += 1

        # Log processing statistics
        logging.info(f"Processed={counts['processed']} Skipped={counts['skipped']} Invalid={counts['invalid']}")

        # Inject processed events into Sycope index
        if rows:
            payload = {
                "columns": COLUMNS,
                "indexName": cfg["index_name"],
                "sortTimestamp": True,
                "rows": rows,
            }
            inj = s.post(f"{cfg['sycope_host']}{cfg['api_base']}index/inject", json=payload, verify=False)
            logging.info(f"Inject status: {inj.status_code} {inj.text}")
        else:
            logging.info("No valid rows to inject.")

        # Update timestamp tracking file
        if max_dt > last_dt:
            save_last_ts(last_ts_file, max_dt)
            logging.info(f"Saved new timestamp: {max_dt.isoformat()}")

        # Clean up API session
        api.log_out()


if __name__ == "__main__":
    main()
