#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import sys
import logging
import socket
from datetime import datetime, timezone
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

#  Disable SSL warnings (self-signed certs)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#  Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("eve_processor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

CONFIG_FILE = 'config.json'
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))


def load_config(path):
    try:
        cfg = json.load(open(path))
        logging.info(f"Loaded configuration from {path}")
        for key in ("anomaly_whitelist", "alert_whitelist",
                    "anomaly_blacklist", "alert_blacklist"):
            lst = cfg.get(key)
            cfg[f"{key}_set"] = set(lst) if isinstance(lst, list) else set()
        return cfg
    except Exception as e:
        logging.error(f"ERROR loading config: {e}")
        sys.exit(1)


def load_last_ts(path):
    if not os.path.exists(path):
        return datetime.fromtimestamp(0, tz=timezone.utc)
    txt = open(path).read().strip()
    return datetime.fromisoformat(txt) if txt else datetime.fromtimestamp(0, tz=timezone.utc)


def save_last_ts(path, dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    open(path, 'w').write(dt.isoformat())


def parse_eve_ts(s):
    if len(s) > 6 and s[-3] == ':':
        s = s[:-3] + s[-2:]
    dt = datetime.fromisoformat(s)
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def should_process(ev, cfg, last_dt):
    et, ts = ev.get("event_type"), ev.get("timestamp", False)
    if not et or not ts:
        return False, None
    dt = parse_eve_ts(ts)
    if dt <= last_dt or et not in cfg["event_types"]:
        return False, dt
    if et == "alert":
        sid = ev.get("alert", {}).get("signature_id")
        if sid is None or (cfg["alert_whitelist"] and sid not in cfg["alert_whitelist_set"]) \
           or (not cfg["alert_whitelist"] and sid in cfg["alert_blacklist_set"]):
            return False, dt
    if et == "anomaly":
        name = ev.get("anomaly", {}).get("event")
        if name is None or (cfg["anomaly_whitelist"] and name not in cfg["anomaly_whitelist_set"]) \
           or (not cfg["anomaly_whitelist"] and name in cfg["anomaly_blacklist_set"]):
            return False, dt
    return True, dt


#  Col actions
def action_valid_ipv4(addr):
    try:
        socket.inet_aton(addr)
        return addr
    except Exception:
        raise


def action_convert_time(val):
    try:
        dt = parse_eve_ts(val)
        return int(dt.timestamp() * 1000)
    except:
        return None


def init_sycope(cfg):
    host = cfg["sycope_host"].rstrip("/")
    sess = requests.Session()
    sess.verify = False
    sess.headers.update({"Content-Type": "application/json"})
    r = sess.post(
        f"{host}/npm/api/v1/login",
        json={"username": cfg["sycope_login"], "password": cfg["sycope_pass"]}
    )
    if r.status_code != 200:
        logging.error(f"Login failed: {r.status_code} {r.text}")
        sys.exit(1)
    token = sess.cookies.get("XSRF-TOKEN")
    if token:
        sess.headers.update({"X-XSRF-TOKEN": token})
    return sess, host


def build_row(ev, columns, column_actions=None):
    if column_actions is None:
        column_actions = {}

    # Fields map (by event_type)
    COLUMN_MAP = {
        "common": {
            "timestamp": ["timestamp"],
            "flow_id":   ["flow_id"],
            "in_iface":  ["in_iface"],
            "event_type": ["event_type"],
            "src_ip": ["src_ip"],
            "src_port": ["src_port"],
            "dest_ip": ["dest_ip"],
            "dest_port": ["dest_port"],
            "proto": ["proto"],
            "app_proto": ["app_proto"]
        },
        "anomaly": {
            "event_category":  ["anomaly", "type"],
            "event_signature": ["anomaly", "event"]
#            ,"anomaly_layer":    ["anomaly", "layer"]
        },
        "alert": {
            "alert_action": ["alert", "action"],
            "alert_gid": ["alert", "gid"],
            "alert_signature_id": ["alert", "signature_id"],
            "alert_rev": ["alert", "rev"],
            "event_signature": ["alert", "signature"],
            "event_category": ["alert", "category"],
            "alert_severity": ["alert", "severity"]
        }
    }

    et = ev.get("event_type")
    row_map = COLUMN_MAP["common"].copy()
    row_map.update(COLUMN_MAP.get(et, {}))

    row = []
    for col in columns:

        if col in row_map:
            val = ev
            for key in row_map[col]:
                val = val.get(key, None)
        else:
            val = ev.get(col) or None

        if col in column_actions:
            val = column_actions[col](val)

        row.append(val)
    return row


def main():
    cfg      = load_config(os.path.join(SCRIPT_DIR, CONFIG_FILE))
    eve_path = cfg["suricata_eve_json_path"]
    ts_path  = os.path.join(SCRIPT_DIR, cfg["last_timestamp_file"])
    last_dt  = load_last_ts(ts_path)
    max_dt   = last_dt
    rows     = []
    counts   = {"processed": 0, "skipped": 0, "invalid": 0}

    sess, host = init_sycope(cfg)

    r = sess.get(
        f"{host}/npm/api/v1/config-elements",
        params={'filter': 'category="userIndex.index"'}
    )
    data = r.json().get("data", [])
    if not data:
        logging.error("No custom indexes defined in Sycope.")
        sys.exit(1)
    idx         = data[0]
    INDEX_NAME  = idx["config"]["name"]
    fields      = idx["config"]["fields"]
    COLUMNS     = [f["name"] for f in fields]
    TYPES       = [f["type"] for f in fields]
    logging.info(f"Using index '{INDEX_NAME}', columns: {COLUMNS}")


    column_actions = {}
    for col, typ in zip(COLUMNS, TYPES):
        if typ == "ip4":
            column_actions[col] = action_valid_ipv4
        if col == "timestamp":
            column_actions[col] = action_convert_time

    with open(eve_path) as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                counts["skipped"] += 1
                continue

            ok, dt = should_process(ev, cfg, last_dt)
            if dt and dt > max_dt:
                max_dt = dt
            if not ok:
                counts["skipped"] += 1
                continue

            try:
                row = build_row(ev, COLUMNS, column_actions)
            except Exception:
                counts["invalid"] += 1
            else:
                rows.append(row)
                counts["processed"] += 1

    logging.info(f"Processed={counts['processed']} Skipped={counts['skipped']} InvalidIP={counts['invalid']}")

    if rows:
        payload = {
            "columns":       COLUMNS,
            "indexName":     INDEX_NAME,
            "sortTimestamp": True,
            "rows":          rows
        }
        inj = sess.post(f"{host}/npm/api/v1/index/inject", json=payload)
        logging.info(f"Inject status: {inj.status_code} {inj.text}")
    else:
        logging.info("No valid rows to inject.")

    if max_dt > last_dt:
        save_last_ts(ts_path, max_dt)
        logging.info(f"Saved new timestamp: {max_dt.isoformat()}")

    sess.get(f"{host}/npm/api/v1/logout")
    logging.info("Session ended")


if __name__ == "__main__":
    main()
