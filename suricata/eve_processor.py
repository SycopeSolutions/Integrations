#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Suricata EVE JSON Log Processor

This module processes Suricata EVE JSON logs and injects filtered events into a Sycope custom index.
It continuously reads from Suricata's eve.json file, filters events based on configuration,
and sends them to the Sycope API for indexing and analysis.

Features:
- Incremental processing using byte-offset tracking (survives log rotation)
- Configurable event type filtering (alert, anomaly, and any protocol with a filter_keys entry)
- Per-event-type whitelist/blacklist support
- Automatic client/server IP determination based on port numbers
- Column mapping and data type conversion, including list-indexed paths and value flattening
- Comprehensive logging and error handling

Script version: 3.0
Author: Sycope Integration Team
"""

import json
import logging
import os
import socket
import sys
from datetime import datetime, timezone

import requests

try:
    import orjson
except ImportError:
    orjson = None

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

# Default per-event-type field path used for whitelist/blacklist filtering.
DEFAULT_FILTER_KEYS = {
    "alert": ["alert", "signature_id"],
    "anomaly": ["anomaly", "event"],
    "smb": ["smb", "command"],
}


def json_loads(line):
    """Parse a JSON line using orjson if available, otherwise stdlib json."""
    if orjson is not None:
        return orjson.loads(line)
    return json.loads(line)


def load_state(path):
    """
    Load the file-tracking state (dev, inode, offset, size, last_timestamp).

    Args:
        path (str): Path to the state JSON file

    Returns:
        dict or None: Parsed state, or None if the file doesn't exist / is invalid
    """
    logger.debug(f"Loading processing state from: {path}")

    if not os.path.exists(path):
        logger.debug("State file does not exist")
        return None

    try:
        with open(path, "r", encoding="utf-8") as fp:
            state = json.load(fp)
        logger.debug(f"Loaded state: {state}")
        return state
    except (json.JSONDecodeError, OSError) as e:
        logger.debug(f"Failed to load state file: {e}")
        return None


def save_state(path, state):
    """
    Save the file-tracking state to disk atomically.

    Writes to a temp file in the same directory and renames it over the
    target path, so a crash mid-write can never leave a truncated/corrupt
    state.json - os.rename is atomic on the same filesystem, and the reader
    either sees the old file or the new one, never a partial one.

    Args:
        path (str): Path to the state JSON file
        state (dict): State to persist
    """
    logger.debug(f"Saving processing state to {path}: {state}")
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as fp:
        json.dump(state, fp)
        fp.flush()
        os.fsync(fp.fileno())
    os.replace(tmp_path, path)


def migrate_legacy_timestamp_state(eve_path, legacy_ts_path):
    """
    Build an initial state when upgrading from timestamp-based tracking.

    There is no way to map an old timestamp back to a byte offset safely,
    so processing resumes from the current end of the file. Events written
    between the last processed timestamp and now may be skipped once.

    Args:
        eve_path (str): Path to the live eve.json file
        legacy_ts_path (str): Path to the old last_timestamp.txt file

    Returns:
        dict: Initial state positioned at the end of the current file
    """
    st = os.stat(eve_path)
    logging.warning(
        "Migrating from timestamp-based tracking to offset-based tracking. "
        f"Starting from the current end of {eve_path} (offset={st.st_size}). "
        "Events logged between the last processed timestamp and now may be skipped."
    )
    try:
        os.remove(legacy_ts_path)
    except OSError as e:
        logger.debug(f"Could not remove legacy timestamp file: {e}")

    return {
        "dev": st.st_dev,
        "inode": st.st_ino,
        "offset": st.st_size,
        "size": st.st_size,
        "last_timestamp": None,
    }


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


def build_prefilter_needles(event_types):
    """Build the raw-string markers used to cheaply reject uninteresting lines."""
    return [f'"event_type":"{et}"' for et in event_types]


def line_passes_prefilter(line, needles):
    """
    Cheap pre-json.loads check: does the raw line contain any of the
    configured event_type markers? Skips a full parse for lines we would
    discard anyway (e.g. the bulk of blacklisted SMB traffic).
    """
    return any(needle in line for needle in needles)


def should_process(ev, cfg, last_dt):
    """
    Determine if an event should be processed based on configuration filters.

    Filters events based on:
    - Event type inclusion
    - Generic per-event-type whitelist/blacklist (see cfg["filter_keys"])

    Args:
        ev (dict): Event dictionary from EVE JSON
        cfg (dict): Configuration dictionary
        last_dt (datetime): Last processed timestamp (telemetry only)

    Returns:
        tuple: (should_process: bool, event_timestamp: datetime or None)
    """
    if not isinstance(ev, dict):
        logger.debug(f"Event is not a dict, rejecting: {type(ev).__name__}")
        return False, None

    et, ts = ev.get("event_type"), ev.get("timestamp", False)

    if not et or not ts:
        logger.debug(f"Missing event_type or timestamp: event_type={et}, timestamp={ts}")
        return False, None

    try:
        dt = parse_eve_ts(ts)
    except (ValueError, TypeError) as e:
        # A malformed timestamp must not crash the whole run - that would
        # stop the offset from ever advancing past this line, wedging
        # ingestion at this exact byte offset on every subsequent cycle.
        # Treat it like any other invalid/unusable event instead.
        logger.debug(f"Unparseable timestamp, rejecting event: {ts!r} - {e}")
        return False, None

    if et not in cfg["event_types"]:
        logger.debug(f"Event type not in allowed types: {et} not in {cfg['event_types']}")
        return False, dt

    filter_path = cfg.get("filter_keys", {}).get(et)
    if filter_path:
        val = ev
        for key in filter_path:
            if not isinstance(val, dict):
                val = None
                break
            val = val.get(key)
        logger.debug(f"{et} filter value at {filter_path}: {val}")

        if val is None:
            logger.debug(f"{et} rejected: filter value is None")
            return False, dt

        whitelist_set = cfg.get(f"{et}_whitelist_set")
        blacklist_set = cfg.get(f"{et}_blacklist_set")

        if whitelist_set and val not in whitelist_set:
            logger.debug(f"{et} rejected: {val} not in whitelist")
            return False, dt

        if not whitelist_set and blacklist_set and val in blacklist_set:
            logger.debug(f"{et} rejected: {val} in blacklist")
            return False, dt

        logger.debug(f"{et} accepted: filter value={val}")

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


def flatten_value(val):
    """
    Flatten a value into something the Sycope custom index can store.

    Lists become comma-joined strings, booleans become "true"/"false",
    and dicts (nested structures aren't supported by index columns) become
    None. Everything else passes through unchanged.

    Args:
        val: Raw value extracted from the event

    Returns:
        A scalar value safe to insert as a column value.
    """
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, list):
        return ",".join(str(v) for v in val)
    if isinstance(val, dict):
        return None
    return val


def resolve_path(ev, path):
    """
    Navigate a nested dict/list structure following a path of keys/indices.

    A string segment is a dict key lookup; an int segment is a list index.
    Any missing key, out-of-range index, or type mismatch along the way
    returns None instead of raising.

    Args:
        ev: Root object to navigate (typically the event dict)
        path (list): Sequence of str (dict key) or int (list index) segments

    Returns:
        The resolved value, or None if the path can't be fully followed.
    """
    val = ev
    for key in path:
        if isinstance(key, int):
            if not isinstance(val, list):
                return None
            try:
                val = val[key]
            except IndexError:
                return None
        else:
            if not isinstance(val, dict):
                return None
            val = val.get(key)
        if val is None:
            return None
    return val


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
                val = resolve_path(ev, row_map[col])
                logger.debug(f"  Column {col}: path={row_map[col]} -> {val}")
            else:
                val = None
                logger.debug(f"  Column {col}: computed field (empty path)")
        else:
            val = ev.get(col) or None
            logger.debug(f"  Column {col}: direct lookup -> {val}")

        val = flatten_value(val)

        # Apply column-specific transformations
        if col in column_actions:
            try:
                old_val = val
                val = column_actions[col](val)
                logger.debug(f"  Column {col}: action applied: {old_val} -> {val}")
            except Exception as e:
                # Visible at the default log level - a column action
                # failing systemically (e.g. a Suricata field changing
                # shape) would otherwise only show up as a rising
                # "Invalid" count in the summary line, with no clue which
                # column or value caused it short of enabling debug logs.
                logging.warning(
                    f"Column action failed for '{col}' (event_type={et}): value={val!r} - {e}"
                )
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
        )

        cfg.setdefault("filter_keys", DEFAULT_FILTER_KEYS)

        # Build a whitelist/blacklist set for every event type that has a
        # filter_keys entry and a corresponding list in config.json.
        for et in cfg["filter_keys"]:
            for kind in ("whitelist", "blacklist"):
                list_key = f"{et}_{kind}"
                set_key = f"{list_key}_set"
                cfg[set_key] = set(cfg.get(list_key, []))

        logger.debug("Configuration loaded successfully:")
        logger.debug(f"  Sycope host: {cfg['sycope_host']}")
        logger.debug(f"  Index name: {cfg['index_name']}")
        logger.debug(f"  EVE JSON path: {cfg['suricata_eve_json_path']}")
        logger.debug(f"  Event types: {cfg['event_types']}")
        logger.debug(f"  Filter keys: {cfg['filter_keys']}")

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
        "tls": {
            "tls_ja4": ["tls", "ja4"],
            "tls_client_alpns": ["tls", "client_alpns"],
            "tls_subjectaltname": ["tls", "subjectaltname"],
        },
        "smb": {
            "smb_command": ["smb", "command"],
            "smb_status": ["smb", "status"],
            "smb_dialect": ["smb", "dialect"],
            "smb_session_id": ["smb", "session_id"],
            "smb_tree_id": ["smb", "tree_id"],
            "smb_access": ["smb", "access"],
            "smb_filename": ["smb", "filename"],
        },
        "krb5": {
            "krb5_msg_type": ["krb5", "msg_type"],
            "krb5_cname": ["krb5", "cname"],
            "krb5_realm": ["krb5", "realm"],
            "krb5_sname": ["krb5", "sname"],
            "krb5_encryption": ["krb5", "encryption"],
            "krb5_weak_encryption": ["krb5", "weak_encryption"],
        },
        "dhcp": {
            "dhcp_type": ["dhcp", "dhcp_type"],
            "dhcp_client_mac": ["dhcp", "client_mac"],
            "dhcp_assigned_ip": ["dhcp", "assigned_ip"],
            "dhcp_hostname": ["dhcp", "hostname"],
        },
        "snmp": {
            "snmp_version": ["snmp", "version"],
            "snmp_pdu_type": ["snmp", "pdu_type"],
            "snmp_community": ["snmp", "community"],
        },
        "dcerpc": {
            "dcerpc_request": ["dcerpc", "request"],
            "dcerpc_call_id": ["dcerpc", "call_id"],
            "dcerpc_interfaces": ["dcerpc", "interfaces"],
        },
        "ssh": {
            "ssh_client_software": ["ssh", "client", "software_version"],
            "ssh_server_software": ["ssh", "server", "software_version"],
        },
        "smtp": {
            "smtp_helo": ["smtp", "helo"],
            "smtp_mail_from": ["smtp", "mail_from"],
            "smtp_rcpt_to": ["smtp", "rcpt_to"],
        },
        "rdp": {
            "rdp_protocol": ["rdp", "protocol"],
            "rdp_cookie": ["rdp", "cookie"],
        },
        "sip": {
            "sip_method": ["sip", "method"],
            "sip_uri": ["sip", "uri"],
        },
        "nfs": {
            "nfs_procedure": ["nfs", "procedure"],
            "nfs_filename": ["nfs", "filename"],
        },
        "ftp": {
            "ftp_command": ["ftp", "command"],
            "ftp_reply": ["ftp", "reply"],
        },
        "tftp": {
            "tftp_packet": ["tftp", "packet"],
            "tftp_file": ["tftp", "file"],
        },
        "telnet": {
            "telnet_data": ["telnet", "data"],
        },
        "ldap": {
            "ldap_operation": ["ldap", "request", "operation"],
            "ldap_bind_name": ["ldap", "request", "bind_request", "name"],
            "ldap_bind_sasl_mechanism": ["ldap", "request", "bind_request", "sasl", "mechanism"],
            "ldap_bind_result_code": ["ldap", "responses", 0, "bind_response", "result_code"],
        },
        "pop3": {
            "pop3_command": ["pop3", "command"],
        },
    }

    logger.debug(f"Column mapping defined for types: {list(column_map.keys())}")

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


def stat_or_none(path):
    """os.stat() that returns None instead of raising when the path is missing."""
    try:
        return os.stat(path)
    except OSError:
        return None


MAX_ROTATION_DEPTH = 5


def find_matching_rotated_file(eve_path, dev, inode, max_depth=MAX_ROTATION_DEPTH):
    """
    Find which numbered rotated file (eve.json.1 .. eve.json.N) has the
    given (dev, inode), i.e. is the file we were previously tracking
    before one or more logrotate cycles moved it along the .1, .2, ...
    chain.

    Args:
        eve_path (str): Path to the live eve.json file
        dev, inode: Identity of the file to find
        max_depth (int): How many numbered files to check before giving up

    Returns:
        tuple: (path, stat) of the matching file, or (None, None) if not found
    """
    for n in range(1, max_depth + 1):
        candidate = f"{eve_path}.{n}"
        candidate_stat = stat_or_none(candidate)
        if candidate_stat and candidate_stat.st_ino == inode and candidate_stat.st_dev == dev:
            return candidate, candidate_stat
    return None, None


def is_rotation(prev_state, st):
    """
    Decide whether the current file stat indicates a rotation relative to
    the previously saved state.

    Different inode -> rotated via 'create'. Same inode but smaller size
    -> truncated in place ('copytruncate').
    """
    if prev_state is None:
        return False
    if st.st_ino != prev_state["inode"] or st.st_dev != prev_state["dev"]:
        return True
    if st.st_size < prev_state["offset"]:
        return True
    return False


DEFAULT_MAX_BYTES_PER_CYCLE = 256 * 1024 * 1024  # 256 MB


def read_new_lines(path, start_offset, max_bytes=DEFAULT_MAX_BYTES_PER_CYCLE):
    """
    Read whole lines from `path` starting at `start_offset`, capped at
    `max_bytes` per call.

    Reading the entire unprocessed tail in one shot has no upper bound - if
    the processor falls behind (crashed, API down, disk full) for long
    enough, the backlog can grow to multiple GB, and reading all of it at
    once risks exhausting memory and building a single inject_data payload
    too large for the API. Capping the read means a large backlog is
    drained gradually over several cycles instead of in one attempt.

    Any trailing partial line (no terminating newline, e.g. a write still
    in progress) is not returned and not counted towards the new offset.

    Args:
        path (str): File to read
        start_offset (int): Byte offset to seek to before reading
        max_bytes (int): Upper bound on bytes read in this call

    Returns:
        tuple: (list of decoded lines without newline, new_offset)
    """
    with open(path, "rb") as f:
        f.seek(start_offset)
        data = f.read(max_bytes)

    lines = []
    consumed = 0
    start = 0
    while True:
        nl = data.find(b"\n", start)
        if nl == -1:
            break
        raw_line = data[start:nl]
        lines.append(raw_line.decode("utf-8", errors="replace"))
        consumed = nl + 1
        start = nl + 1

    offset = start_offset + consumed
    return lines, offset


def process_file_from(path, start_offset, cfg, columns, column_map, cols_idxs, column_actions, prefilter_needles):
    """
    Read and process all complete lines in `path` starting at `start_offset`.

    Returns:
        tuple: (rows, counts dict, new_offset, max_timestamp or None)
    """
    lines, new_offset = read_new_lines(path, start_offset)

    rows = []
    counts = {"processed": 0, "skipped": 0, "invalid": 0, "prefiltered": 0}
    max_dt = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if not line_passes_prefilter(line, prefilter_needles):
            counts["prefiltered"] += 1
            continue

        try:
            ev = json_loads(line)
        except ValueError as e:
            counts["skipped"] += 1
            logger.debug(f"JSON decode error: {e}")
            continue

        try:
            ok, dt = should_process(ev, cfg, max_dt or datetime.fromtimestamp(0, tz=timezone.utc))
        except Exception as e:
            # Any unexpected shape (e.g. a valid JSON line that isn't a
            # dict) must not crash the run - see the poison-pill note on
            # parse_eve_ts above for why: a crash here would wedge the
            # offset at this line forever.
            counts["skipped"] += 1
            logger.debug(f"should_process failed unexpectedly: {e}")
            continue
        if dt and (max_dt is None or dt > max_dt):
            max_dt = dt
        if not ok:
            counts["skipped"] += 1
            continue

        try:
            row = build_row(ev, columns, column_map, cols_idxs, column_actions)
        except Exception as e:
            counts["invalid"] += 1
            logger.debug(f"Row build failed: {e}")
        else:
            rows.append(row)
            counts["processed"] += 1

    return rows, counts, new_offset, max_dt


def process_log_file(cfg, columns, column_map, cols_idxs, column_actions, state):
    """
    Process the EVE JSON log file (and, on rotation, the tail of the
    previous file) starting from the saved offset.

    Args:
        cfg (dict): Configuration dictionary
        columns, column_map, cols_idxs, column_actions: from setup_column_mapping()
        state (dict): Previously saved {dev, inode, offset, size, last_timestamp}

    Returns:
        tuple: (rows, counts, new_state)
    """
    eve_path = cfg["suricata_eve_json_path"]
    prefilter_needles = build_prefilter_needles(cfg["event_types"])

    all_rows = []
    total_counts = {"processed": 0, "skipped": 0, "invalid": 0, "prefiltered": 0}
    max_dt = None

    def merge_counts(c):
        for k in total_counts:
            total_counts[k] += c.get(k, 0)

    def track_max_dt(dt):
        nonlocal max_dt
        if dt and (max_dt is None or dt > max_dt):
            max_dt = dt

    def process_one_file(path, start_offset, is_backlog_entry):
        """
        Read one file (bounded by the per-cycle byte cap) and merge its
        results into the running totals.

        Returns True if the file was fully drained (reached EOF within
        the cap), False if there's more left to read next cycle.
        """
        rows, counts, new_offset, dt = process_file_from(
            path, start_offset, cfg, columns, column_map, cols_idxs, column_actions, prefilter_needles
        )
        all_rows.extend(rows)
        merge_counts(counts)
        track_max_dt(dt)
        current_size = os.stat(path).st_size if is_backlog_entry else None
        return new_offset, current_size

    # backlog: files queued from a previous cycle that didn't finish within
    # the read cap, in the order they must be read (oldest rotated file
    # first, ending with the live eve.json). Persisted in state so a large
    # multi-rotation backlog drains gradually across cycles instead of
    # trying to read everything in one shot.
    backlog = list((state or {}).get("pending_backlog", []))

    # Drain queued backlog files in order. Each file is still read through
    # the per-call byte cap (process_one_file -> read_new_lines), so a
    # single huge file can't blow the cycle's memory budget; but once a
    # file is *fully* consumed we move straight on to the next queued file
    # in the same cycle instead of waiting a full extra cycle to notice
    # there was nothing left in it (e.g. a rotated file already drained by
    # a previous run's tail-read).
    while backlog:
        entry = backlog[0]
        entry_stat = stat_or_none(entry["path"])
        if entry_stat and entry_stat.st_ino == entry["inode"] and entry_stat.st_dev == entry["dev"]:
            new_offset, size = process_one_file(entry["path"], entry["offset"], is_backlog_entry=True)
            if new_offset < size:
                backlog[0]["offset"] = new_offset
                break
            backlog.pop(0)
        else:
            logging.warning(
                f"Queued backlog file {entry['path']} no longer matches what was being drained "
                "(rotated again before we finished it). Dropping it from the backlog; some events "
                "may be lost."
            )
            backlog.pop(0)

    if backlog:
        # Still work queued - persist progress and stop; don't touch
        # the live file's own state until the backlog is empty.
        new_state = dict(state)
        new_state["pending_backlog"] = backlog
        new_state["last_timestamp"] = max_dt.isoformat() if max_dt else state.get("last_timestamp")
        return all_rows, total_counts, new_state
    elif (state or {}).get("pending_backlog"):
        # Backlog fully drained - fall through to check/process the live file.
        state = dict(state)
        state.pop("pending_backlog", None)

    st = os.stat(eve_path)
    rotated = is_rotation(state, st)

    if rotated and state is not None:
        match_path, match_stat = find_matching_rotated_file(eve_path, state["dev"], state["inode"])
        if match_path:
            # Figure out which numbered rotated files sit between the one
            # we were tracking and the live file, and queue them in order
            # (oldest first) so nothing in between is skipped.
            depth = int(match_path.rsplit(".", 1)[-1])
            new_backlog = [{"path": match_path, "dev": match_stat.st_dev, "inode": match_stat.st_ino, "offset": state["offset"]}]
            for n in range(depth - 1, 0, -1):
                p = f"{eve_path}.{n}"
                p_stat = stat_or_none(p)
                if p_stat:
                    new_backlog.append({"path": p, "dev": p_stat.st_dev, "inode": p_stat.st_ino, "offset": 0})

            while new_backlog:
                entry = new_backlog[0]
                new_offset, size = process_one_file(entry["path"], entry["offset"], is_backlog_entry=True)
                if new_offset < size:
                    new_backlog[0]["offset"] = new_offset
                    break
                new_backlog.pop(0)

            if new_backlog:
                new_state = {
                    "dev": state["dev"],
                    "inode": state["inode"],
                    "offset": state["offset"],
                    "size": state["size"],
                    "pending_backlog": new_backlog,
                    "last_timestamp": max_dt.isoformat() if max_dt else state.get("last_timestamp"),
                }
                return all_rows, total_counts, new_state
            # Whole backlog drained in this one cycle - fall through to the live file.
        else:
            logging.warning(
                f"Rotation detected but no eve.json.1..{MAX_ROTATION_DEPTH} matches the previously "
                "tracked file (processor may have missed more rotations than that). Skipping to the "
                "current file; some events may be lost."
            )
        start_offset = 0
    else:
        start_offset = state["offset"] if state else 0

    rows, counts, new_offset, dt = process_file_from(
        eve_path, start_offset, cfg, columns, column_map, cols_idxs, column_actions, prefilter_needles
    )
    all_rows.extend(rows)
    merge_counts(counts)
    track_max_dt(dt)

    new_state = {
        "dev": st.st_dev,
        "inode": st.st_ino,
        "offset": new_offset,
        "size": st.st_size,
        "last_timestamp": max_dt.isoformat() if max_dt else (state or {}).get("last_timestamp"),
    }

    return all_rows, total_counts, new_state


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

    # Initialize offset-based state, migrating from the legacy timestamp file if needed
    state_file = os.path.join(SCRIPT_DIR, cfg.get("state_file", "state.json"))
    legacy_ts_file = os.path.join(SCRIPT_DIR, cfg.get("last_timestamp_file", "last_timestamp.txt"))

    state = load_state(state_file)
    if state is None and os.path.exists(legacy_ts_file):
        state = migrate_legacy_timestamp_state(cfg["suricata_eve_json_path"], legacy_ts_file)
        save_state(state_file, state)

    logger.debug(f"Processing state: {state}")

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
        rows, counts, new_state = process_log_file(cfg, columns, column_map, cols_idxs, column_actions, state)

        # Log processing statistics
        logging.info(
            f"Processed={counts['processed']} Skipped={counts['skipped']} "
            f"Invalid={counts['invalid']} Prefiltered={counts['prefiltered']}"
        )

        # Inject data using API method
        if rows:
            logger.debug(f"Injecting {len(rows)} rows into Sycope...")
            api.inject_data(cfg["index_name"], columns, rows)
            logger.debug("Data injection complete")
        else:
            logging.info("No valid rows to inject")
            logger.debug("Skipping injection - no rows")

        # Persist new state only after a successful injection
        save_state(state_file, new_state)
        logger.debug(f"Saved new state: {new_state}")

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
