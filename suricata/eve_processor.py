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

Script version: 2.1
Author: Sycope Integration Team
"""

import json
import logging
import os
import socket
import sys
from datetime import datetime, timezone

import requests

# Add parent directory to path for importing sycope modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sycope.api import SycopeApi
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings

logger = logging.getLogger(__name__)

# Configuration file paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")


def load_last_ts(path):
    """
    Load the last processed timestamp from a file.

    Args:
        path (str): Path to the timestamp file

    Returns:
        datetime: The last processed timestamp in UTC, or epoch if file doesn't exist
    """
    logger.debug(f"Loading last timestamp from: {path}")

    if not os.path.exists(path):
        logger.debug("Timestamp file does not exist, using epoch")
        return datetime.fromtimestamp(0, tz=timezone.utc)

    txt = open(path).read().strip()
    logger.debug(f"Read timestamp text: {txt}")

    result = datetime.fromisoformat(txt) if txt else datetime.fromtimestamp(0, tz=timezone.utc)
    logger.debug(f"Parsed timestamp: {result}")
    return result


def save_last_ts(path, dt):
    """
    Save the last processed timestamp to a file.

    Args:
        path (str): Path to the timestamp file
        dt (datetime): Timestamp to save
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    logger.debug(f"Saving timestamp to {path}: {dt.isoformat()}")
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
    logger.debug(f"Parsing EVE timestamp: {s}")

    # Handle timezone offset format (e.g., "+02:00" -> "+0200")
    if len(s) > 6 and s[-3] == ":":
        original = s
        s = s[:-3] + s[-2:]
        logger.debug(f"Adjusted timezone format: {original} -> {s}")

    dt = datetime.fromisoformat(s)
    result = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    logger.debug(f"Parsed result: {result}")
    return result


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
        logger.debug(f"Missing event_type or timestamp: event_type={et}, timestamp={ts}")
        return False, None

    dt = parse_eve_ts(ts)

    if dt <= last_dt:
        logger.debug(f"Event too old: {dt} <= {last_dt}")
        return False, dt

    if et not in cfg["event_types"]:
        logger.debug(f"Event type not in allowed types: {et} not in {cfg['event_types']}")
        return False, dt

    # Check alert filtering rules
    if et == "alert":
        sid = ev.get("alert", {}).get("signature_id")
        logger.debug(f"Alert event: signature_id={sid}")

        if sid is None:
            logger.debug("Alert rejected: signature_id is None")
            return False, dt

        if cfg["alert_whitelist"] and sid not in cfg["alert_whitelist_set"]:
            logger.debug(f"Alert rejected: sid {sid} not in whitelist")
            return False, dt

        if not cfg["alert_whitelist"] and sid in cfg["alert_blacklist_set"]:
            logger.debug(f"Alert rejected: sid {sid} in blacklist")
            return False, dt

        logger.debug(f"Alert accepted: sid={sid}")

    # Check anomaly filtering rules
    if et == "anomaly":
        name = ev.get("anomaly", {}).get("event")
        logger.debug(f"Anomaly event: name={name}")

        if name is None:
            logger.debug("Anomaly rejected: event name is None")
            return False, dt

        if cfg["anomaly_whitelist"] and name not in cfg["anomaly_whitelist_set"]:
            logger.debug(f"Anomaly rejected: name {name} not in whitelist")
            return False, dt

        if not cfg["anomaly_whitelist"] and name in cfg["anomaly_blacklist_set"]:
            logger.debug(f"Anomaly rejected: name {name} in blacklist")
            return False, dt

        logger.debug(f"Anomaly accepted: name={name}")

    logger.debug(f"Event accepted: type={et}, timestamp={dt}")
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
        logger.debug(f"Valid IPv4: {addr}")
        return addr
    except Exception as e:
        logger.debug(f"Invalid IPv4 address: {addr} - {e}")
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
        result = int(dt.timestamp() * 1000)
        logger.debug(f"Converted timestamp: {val} -> {result}")
        return result
    except Exception as e:
        logger.debug(f"Timestamp conversion failed: {val} - {e}")
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
    logger.debug(f"Building row for event_type: {et}")

    # Build column mapping for this event type
    row_map = column_mapping["common"].copy()
    row_map.update(column_mapping.get(et, {}))
    logger.debug(f"Row mapping keys: {list(row_map.keys())}")

    # Extract values for each column
    row = []
    for col in column_names:
        if col in row_map:
            if row_map[col]:
                # Navigate nested dictionary structure
                val = ev
                path = row_map[col]
                for key in path:
                    val = val.get(key, None)
                    if val is None:
                        break
                logger.debug(f"  Column {col}: path={path} -> {val}")
            else:
                val = None
                logger.debug(f"  Column {col}: computed field (empty path)")
        else:
            val = ev.get(col) or None
            logger.debug(f"  Column {col}: direct lookup -> {val}")

        # Apply column-specific transformations
        if col in column_actions:
            try:
                old_val = val
                val = column_actions[col](val)
                logger.debug(f"  Column {col}: action applied: {old_val} -> {val}")
            except Exception as e:
                logging.debug(f"Column action failed for {col}: {val} - {e}")
                raise

        row.append(val)

    # Determine client/server roles based on port numbers (higher port = client)
    if "clientIp" in column_names or "serverIp" in column_names:
        (
            src_ip_idx,
            dst_ip_idx,
            src_port_idx,
            dst_port_idx,
            serverIp_idx,
            clientIp_idx,
            serverPort_idx,
            clientPort_idx,
        ) = cols_idxs

        src_ip = row[src_ip_idx] if src_ip_idx is not None else None
        dst_ip = row[dst_ip_idx] if dst_ip_idx is not None else None
        src_port = row[src_port_idx] if src_port_idx is not None else None
        dst_port = row[dst_port_idx] if dst_port_idx is not None else None

        logger.debug(
            f"Client/server determination: src_ip={src_ip}, src_port={src_port}, dst_ip={dst_ip}, dst_port={dst_port}"
        )

        # Use port comparison to determine client/server roles
        src_port_cmp = src_port if src_port is not None else 0
        dst_port_cmp = dst_port if dst_port is not None else 0

        if src_port_cmp >= dst_port_cmp:
            client_ip, server_ip = src_ip, dst_ip
            client_port, server_port = src_port, dst_port
            logger.debug("  src_port >= dst_port: client=src, server=dst")
        else:
            client_ip, server_ip = dst_ip, src_ip
            client_port, server_port = dst_port, src_port
            logger.debug("  src_port < dst_port: client=dst, server=src")

        # Update row with client/server information
        row[clientIp_idx] = client_ip
        row[serverIp_idx] = server_ip
        row[clientPort_idx] = client_port
        row[serverPort_idx] = server_port

        logger.debug(
            f"  Final: clientIp={client_ip}, clientPort={client_port}, serverIp={server_ip}, serverPort={server_port}"
        )

    return row


def initialize_config():
    """Load and initialize configuration with filter sets."""
    logger.debug(f"Loading configuration from: {CONFIG_PATH}")

    try:
        cfg = load_config(
            CONFIG_PATH,
            required_fields=[
                "sycope_host",
                "sycope_login",
                "sycope_pass",
                "index_name",
                "suricata_eve_json_path",
                "event_types",
            ],
            list_to_set_fields=[
                "alert_whitelist",
                "alert_blacklist",
                "anomaly_whitelist",
                "anomaly_blacklist",
            ],
        )

        logger.debug("Configuration loaded successfully:")
        logger.debug(f"  Sycope host: {cfg['sycope_host']}")
        logger.debug(f"  Index name: {cfg['index_name']}")
        logger.debug(f"  EVE JSON path: {cfg['suricata_eve_json_path']}")
        logger.debug(f"  Event types: {cfg['event_types']}")
        logger.debug(f"  Alert whitelist count: {len(cfg.get('alert_whitelist', []))}")
        logger.debug(f"  Alert blacklist count: {len(cfg.get('alert_blacklist', []))}")
        logger.debug(f"  Anomaly whitelist count: {len(cfg.get('anomaly_whitelist', []))}")
        logger.debug(f"  Anomaly blacklist count: {len(cfg.get('anomaly_blacklist', []))}")

    except Exception as e:
        logging.error(f"Failed to load config: {e}")
        logger.debug(f"Config load exception: {type(e).__name__}: {e}")
        sys.exit(1)

    return cfg


def setup_api_connection(cfg):
    """Initialize HTTP session and Sycope API connection."""
    logger.debug("Setting up Sycope API connection...")

    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    logger.debug("HTTP session created")

    api = SycopeApi(
        session=session,
        host=cfg["sycope_host"],
        login=cfg["sycope_login"],
        password=cfg["sycope_pass"],
        api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
    )
    logger.debug("Sycope API connection established")

    return session, api


def get_index_configuration(api, index_name):
    """Get and validate index configuration."""
    logger.debug(f"Getting index configuration for: {index_name}")

    indexes = api.get_user_indicies()
    logger.debug(f"Found {len(indexes)} user indexes")

    match = [x for x in indexes if x["config"]["name"] == index_name]
    logger.debug(f"Matching indexes: {len(match)}")

    if not match:
        logging.error(f"Index '{index_name}' not found.")
        logger.debug(f"Available indexes: {[x['config']['name'] for x in indexes]}")
        sys.exit(1)

    idx = match[0]
    logger.debug(f"Index configuration: id={idx.get('id')}, fields={len(idx['config'].get('fields', []))}")

    return idx


def setup_column_mapping(fields):
    """Setup column mappings and transformations."""
    columns = [f["name"] for f in fields]
    types = [f["type"] for f in fields]

    logger.debug(f"Setting up column mapping for {len(fields)} fields")
    for i, (col, typ) in enumerate(zip(columns, types)):
        logger.debug(f"  Field {i}: name={col}, type={typ}")

    # Define mapping from database columns to EVE JSON field paths
    column_map = {
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

    logger.debug(
        f"Column mapping defined: common={len(column_map['common'])}, anomaly={len(column_map['anomaly'])}, alert={len(column_map['alert'])}"
    )

    # Get column indices for client/server determination
    cols_idxs = [
        columns.index("src_ip") if "src_ip" in columns else None,
        columns.index("dest_ip") if "dest_ip" in columns else None,
        columns.index("src_port") if "src_port" in columns else None,
        columns.index("dest_port") if "dest_port" in columns else None,
        columns.index("serverIp") if "serverIp" in columns else None,
        columns.index("clientIp") if "clientIp" in columns else None,
        columns.index("serverPort") if "serverPort" in columns else None,
        columns.index("clientPort") if "clientPort" in columns else None,
    ]
    logger.debug(f"Column indices for client/server: {cols_idxs}")

    # Set up column transformation functions based on data types
    column_actions = {}
    for col, typ in zip(columns, types):
        if typ == "ip4":
            column_actions[col] = action_valid_ipv4
            logger.debug(f"  Action for {col}: IPv4 validation")
        if col == "timestamp":
            column_actions[col] = action_convert_time
            logger.debug(f"  Action for {col}: timestamp conversion")

    logger.debug(f"Column actions configured: {len(column_actions)}")

    return columns, column_map, cols_idxs, column_actions


def process_log_file(cfg, columns, column_map, cols_idxs, column_actions, last_dt):
    """Process EVE JSON log file and return rows and statistics."""
    eve_path = cfg["suricata_eve_json_path"]
    logger.debug(f"Processing EVE log file: {eve_path}")
    logger.debug(f"Last processed timestamp: {last_dt}")

    max_dt = last_dt
    rows = []
    counts = {"processed": 0, "skipped": 0, "invalid": 0}
    line_count = 0

    with open(eve_path) as f:
        for line in f:
            line_count += 1
            line = line.strip()
            if not line:
                continue

            # Parse JSON event
            try:
                ev = json.loads(line)
            except json.JSONDecodeError as e:
                counts["skipped"] += 1
                logger.debug(f"Line {line_count}: JSON decode error: {e}")
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
                row = build_row(ev, columns, column_map, cols_idxs, column_actions)
            except Exception as e:
                counts["invalid"] += 1
                logger.debug(f"Line {line_count}: Row build failed: {e}")
            else:
                rows.append(row)
                counts["processed"] += 1

            # Log progress every 1000 lines
            if line_count % 1000 == 0:
                logger.debug(
                    f"Progress: {line_count} lines read, {counts['processed']} processed, {counts['skipped']} skipped"
                )

    logger.debug("File processing complete:")
    logger.debug(f"  Total lines read: {line_count}")
    logger.debug(f"  Processed: {counts['processed']}")
    logger.debug(f"  Skipped: {counts['skipped']}")
    logger.debug(f"  Invalid: {counts['invalid']}")
    logger.debug(f"  Max timestamp: {max_dt}")

    return rows, counts, max_dt


def update_timestamp(last_ts_file, max_dt, last_dt):
    """Update timestamp tracking file if needed."""
    logger.debug(f"Checking timestamp update: max_dt={max_dt}, last_dt={last_dt}")

    if max_dt > last_dt:
        save_last_ts(last_ts_file, max_dt)
        logging.info(f"Saved new timestamp: {max_dt.isoformat()}")
    else:
        logger.debug("No timestamp update needed (max_dt <= last_dt)")


def main():
    """
    Main function to process Suricata EVE JSON logs.

    Loads configuration, connects to Sycope API, processes EVE log entries,
    and injects filtered events into the configured custom index.
    """
    # Initialize configuration first to get log_level
    cfg = initialize_config()

    # Setup environment with log_level from config
    suppress_ssl_warnings()
    setup_logging("eve_processor.log", log_level=cfg.get("log_level", "info"))

    logger.debug("=" * 60)
    logger.debug("Suricata EVE Processor starting")
    logger.debug(f"Script directory: {SCRIPT_DIR}")
    logger.debug(f"Config path: {CONFIG_PATH}")
    logger.debug("=" * 60)

    # Initialize timestamp tracking
    last_ts_file = os.path.join(SCRIPT_DIR, cfg.get("last_timestamp_file", "last_timestamp.txt"))
    logger.debug(f"Timestamp file: {last_ts_file}")
    last_dt = load_last_ts(last_ts_file)
    logger.debug(f"Last processed timestamp: {last_dt}")

    # Setup API connection
    session, api = setup_api_connection(cfg)

    try:
        # Get index configuration
        idx = get_index_configuration(api, cfg["index_name"])
        fields = idx["config"]["fields"]
        logger.debug(f"Index has {len(fields)} fields")

        # Setup column mapping and transformations
        columns, column_map, cols_idxs, column_actions = setup_column_mapping(fields)
        logging.info(f"Using index '{cfg['index_name']}' with columns: {columns}")

        # Process log file
        logger.debug("Starting log file processing...")
        rows, counts, max_dt = process_log_file(cfg, columns, column_map, cols_idxs, column_actions, last_dt)

        # Log processing statistics
        logging.info(
            f"Processed={counts['processed']} Skipped={counts['skipped']} Invalid={counts['invalid']}"
        )

        # Inject data using API method
        if rows:
            logger.debug(f"Injecting {len(rows)} rows into Sycope...")
            api.inject_data(cfg["index_name"], columns, rows)
            logger.debug("Data injection complete")
        else:
            logging.info("No valid rows to inject")
            logger.debug("Skipping injection - no rows")

        # Update timestamp
        update_timestamp(last_ts_file, max_dt, last_dt)

    except SycopeError as e:
        logging.error(f"Sycope API error: {e}")
        logger.debug(f"Sycope exception: {type(e).__name__}: {e}")
        if hasattr(e, "status_code"):
            logger.debug(f"  Status code: {e.status_code}")
        if hasattr(e, "response"):
            logger.debug(f"  Response: {e.response}")
        sys.exit(1)
    finally:
        # Clean up API session
        logger.debug("Logging out from Sycope...")
        api.log_out()
        logger.debug("Script complete")


if __name__ == "__main__":
    main()
