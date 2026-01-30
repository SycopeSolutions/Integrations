#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Zabbix statistics integration with Sycope.

This script retrieves metrics from Zabbix (Response Time, CPU Load,
Memory Usage, Packet Loss) and injects them into a Sycope custom index.

Script version: 2.1
Tested on Sycope 3.1
"""

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

import polars as pl
import requests
from requests import Session

# Add parent directory to path for importing sycope modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sycope.api import SycopeApi
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings

logger = logging.getLogger(__name__)

# Configuration file path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")


# Metric validation and transformation functions
def val_numeric_range(val, lower=0, upper=100):
    """Validate if a value is a float within a specified range."""
    try:
        result = lower <= float(val) <= upper
        logger.debug(f"val_numeric_range({val}, {lower}, {upper}) = {result}")
        return result
    except Exception as e:
        logger.debug(f"val_numeric_range({val}) failed: {e}")
        return False


def val_div(x, div=100):
    """Divide a value (default by 100)."""
    result = x / div
    logger.debug(f"val_div({x}, {div}) = {result}")
    return result


def val_multi(x, multi=1000):
    """Multiply a value (default by 1000)."""
    result = x * multi
    logger.debug(f"val_multi({x}, {multi}) = {result}")
    return result


# Keys for metrics (multiple keys for CPU Load to support different platforms)
ITEM_KEYS = {
    "cpu_load": {
        "values": ["system.cpu.load", "system.cpu.util"],
        "output_type": float,
        "validation_function": val_numeric_range,
        "validation_args": {"lower": 0, "upper": 100},
        "transform_function": val_div,
        "round": 3,
    },
    "response_time": {
        "values": ["icmppingsec"],
        "output_type": float,
        "validation_function": val_numeric_range,
        "validation_args": {"lower": -1, "upper": 100000000},
        "transform_function": val_multi,
        "round": None,
    },
    "memory_usage": {
        "values": ["vm.memory.util"],
        "output_type": float,
        "validation_function": val_numeric_range,
        "validation_args": {"lower": 0, "upper": 100},
        "transform_function": val_div,
        "round": 3,
    },
    "packet_loss": {
        "values": ["icmppingloss"],
        "output_type": float,
        "validation_function": val_numeric_range,
        "validation_args": {"lower": 0, "upper": 100},
        "transform_function": val_div,
        "round": 3,
    },
}


def zabbix_login(cfg: dict) -> tuple:
    """Log in to Zabbix API and retrieve auth token."""
    url = cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"].rstrip("/")
    logger.debug(f"Zabbix login URL: {url}")
    logger.debug(f"Zabbix user: {cfg['zabbix_login']}")

    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {"username": cfg["zabbix_login"], "password": cfg["zabbix_pass"]},
        "id": 1,
    }
    logger.debug(f"Zabbix login request: method=user.login, user={cfg['zabbix_login']}")

    response = requests.post(url, json=payload, verify=False)
    logger.debug(f"Zabbix login response status: {response.status_code}")

    data = response.json()
    logger.debug(f"Zabbix login response keys: {list(data.keys())}")

    if "result" in data:
        logging.info("Zabbix API login successful")
        auth_token = data["result"]
        logger.debug(
            f"Auth token received (first 10 chars): {auth_token[:10] if len(auth_token) > 10 else '***'}..."
        )
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json-rpc",
        }
        return auth_token, headers

    logger.debug(f"Zabbix login error: {data.get('error')}")
    raise Exception(f"Zabbix API login failed: {data.get('error')}")


def zabbix_logout(cfg: dict) -> None:
    """Log out from Zabbix API."""
    url = cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"]
    logger.debug(f"Zabbix logout URL: {url}")

    logout_payload = {
        "jsonrpc": "2.0",
        "method": "user.logout",
        "params": [],
        "id": 2,
    }
    logging.info("Logging out from Zabbix")
    response = requests.post(url, json=logout_payload, verify=False)
    logger.debug(f"Zabbix logout response status: {response.status_code}")


def get_all_host_ips(cfg: dict, headers: dict) -> list:
    """Get all primary host interface IPs from Zabbix."""
    url = cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"]
    logger.debug(f"Getting all host IPs from: {url}")

    payload = {
        "jsonrpc": "2.0",
        "method": "hostinterface.get",
        "params": {
            "output": ["ip"],
            "filter": {"main": "1"},
        },
        "id": 1001,
    }
    logger.debug("Zabbix request: method=hostinterface.get, filter=main:1")

    response = requests.post(url, headers=headers, json=payload, verify=False)
    logger.debug(f"Response status: {response.status_code}")

    result = response.json()["result"]
    logger.debug(f"Received {len(result)} host interfaces")

    ips = sorted(set([x["ip"] for x in result if "ip" in x]))
    logger.debug(f"Unique IPs found: {len(ips)}")
    logger.debug(f"First 10 IPs: {ips[:10]}")

    return ips


def get_host_id_by_ip(cfg: dict, headers: dict, ip: str) -> Optional[str]:
    """Get Zabbix host ID by IP address."""
    url = cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"].rstrip("/")
    logger.debug(f"Getting host ID for IP: {ip}")

    payload = {
        "jsonrpc": "2.0",
        "method": "hostinterface.get",
        "params": {"filter": {"ip": ip}},
        "id": 2,
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    logger.debug(f"Response status: {response.status_code}")

    data = response.json()["result"]
    logger.debug(f"Found {len(data)} interfaces for IP {ip}")

    if data:
        host_id = data[0]["hostid"]
        logger.debug(f"Host ID for {ip}: {host_id}")
        return host_id

    logger.debug(f"No host found for IP {ip}")
    return None


def get_hostname_by_id(cfg: dict, headers: dict, host_id: str) -> str:
    """Get hostname (inventory name) from Zabbix using host ID."""
    url = cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"].rstrip("/")
    logger.debug(f"Getting hostname for host ID: {host_id}")

    payload = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": ["hostid"],
            "selectInventory": ["name"],
            "hostids": host_id,
        },
        "id": 5,
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    logger.debug(f"Response status: {response.status_code}")

    result = response.json()["result"]
    logger.debug(f"Host.get result: {result}")

    if result and "inventory" in result[0] and result[0]["inventory"]:
        hostname = result[0]["inventory"].get("name", "")
        logger.debug(f"Hostname for host {host_id}: {hostname}")
        return hostname

    logger.debug(f"No inventory name found for host {host_id}")
    return ""


def get_items_id(cfg: dict, headers: dict, host_id: str) -> list:
    """Get all item definitions from Zabbix host."""
    url = cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"].rstrip("/")
    logger.debug(f"Getting items for host ID: {host_id}")

    payload = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": ["itemid", "name", "key_"],
            "hostids": host_id,
            "sortfield": "name",
        },
        "id": 3,
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    logger.debug(f"Response status: {response.status_code}")

    items = response.json()["result"]
    logger.debug(f"Found {len(items) if items else 0} items for host {host_id}")

    if items:
        # Log first 10 items for debugging
        for item in items[:10]:
            logger.debug(f"  Item: id={item.get('itemid')}, key={item.get('key_')}, name={item.get('name')}")
        if len(items) > 10:
            logger.debug(f"  ... and {len(items) - 10} more items")

    return items if items else []


def get_history(
    cfg: dict, headers: dict, item_id: str, start_time: int, end_time: int, history_type: int = 0
) -> list:
    """Get historical metric data from Zabbix."""
    url = cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"].rstrip("/")
    logger.debug(f"Getting history for item {item_id}, time range: {start_time} - {end_time}")

    payload = {
        "jsonrpc": "2.0",
        "method": "history.get",
        "params": {
            "output": "extend",
            "history": history_type,
            "itemids": item_id,
            "sortfield": "clock",
            "sortorder": "ASC",
            "time_from": start_time,
            "time_till": end_time,
        },
        "id": 4,
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    logger.debug(f"Response status: {response.status_code}")

    result = response.json()["result"]
    logger.debug(f"Retrieved {len(result)} history entries for item {item_id}")

    if result:
        logger.debug(f"  First entry: clock={result[0].get('clock')}, value={result[0].get('value')}")
        if len(result) > 1:
            logger.debug(f"  Last entry: clock={result[-1].get('clock')}, value={result[-1].get('value')}")

    return result


def create_minute_df_pl(start_datetime: datetime, stop_datetime: datetime) -> pl.DataFrame:
    """Create time-aligned Polars DataFrame (1-minute interval)."""
    logger.debug(f"Creating minute DataFrame: {start_datetime} to {stop_datetime}")

    df = pl.DataFrame(
        pl.datetime_range(
            start=start_datetime,
            end=stop_datetime,
            interval="1m",
            time_unit="ms",
            eager=True,
            time_zone="UTC",
        ).alias("datetime")
    )

    logger.debug(f"Created DataFrame with {len(df)} time slots")
    return df


def collect_metrics_for_ip(
    cfg: dict, headers: dict, ip: str, start_time_int: int, end_time_int: int, df_time_range: pl.DataFrame
) -> Optional[pl.DataFrame]:
    """Collect all metrics for a single IP and return aligned DataFrame."""
    logger.debug(f"Collecting metrics for IP: {ip}")
    logger.debug(f"Time range: {start_time_int} to {end_time_int}")

    history_data = {metric_name: [] for metric_name in ITEM_KEYS}

    host_id = get_host_id_by_ip(cfg, headers, ip)
    if not host_id:
        logger.debug(f"No host ID found for IP {ip}, skipping")
        return None

    hostname = get_hostname_by_id(cfg, headers, host_id)
    logger.debug(f"Hostname for {ip}: {hostname}")

    items_id = get_items_id(cfg, headers, host_id)
    items_ids_dict = {x["key_"].split("[")[0]: x["itemid"] for x in items_id}
    logger.debug(f"Item keys found: {list(items_ids_dict.keys())}")

    for metric_name, val_config in ITEM_KEYS.items():
        logger.debug(f"Processing metric: {metric_name}")
        logger.debug(f"  Looking for keys: {val_config['values']}")

        if not any(x in items_ids_dict for x in val_config["values"]):
            logger.debug(f"  No matching item key found for {metric_name}")
            continue

        for key_ in val_config["values"]:
            if key_ not in items_ids_dict:
                logger.debug(f"  Key {key_} not found in items")
                continue

            logger.debug(f"  Found item key: {key_} -> itemid={items_ids_dict[key_]}")

            history = get_history(
                cfg, headers, items_ids_dict[key_], start_time_int, end_time_int, history_type=0
            )

            valid_count = 0
            invalid_count = 0

            for entry in history:
                timestamp = int(entry["clock"]) * 1000
                value = entry["value"]

                if val_config["validation_function"] and not val_config["validation_function"](
                    value, **val_config["validation_args"]
                ):
                    history_data[metric_name].append((timestamp, None))
                    invalid_count += 1
                    continue

                value = val_config["output_type"](value)

                if val_config["transform_function"]:
                    value = val_config["transform_function"](value)
                if val_config["output_type"] is float and val_config["round"]:
                    value = round(value, val_config["round"])

                history_data[metric_name].append((timestamp, value))
                valid_count += 1

            logger.debug(f"  {metric_name}: {valid_count} valid, {invalid_count} invalid entries")

    total_entries = sum(len(v) for v in history_data.values())
    logger.debug(f"Total history entries collected for {ip}: {total_entries}")

    if not history_data:
        logger.debug(f"No history data for IP {ip}")
        return None

    dfs = []
    for col, vals in history_data.items():
        if not vals:
            logger.debug(f"  Column {col}: no values, skipping")
            continue

        logger.debug(f"  Column {col}: {len(vals)} values")

        z = pl.DataFrame(vals, schema=["timestamp", col], orient="row").with_columns(
            datetime=pl.from_epoch("timestamp", time_unit="ms").dt.convert_time_zone(time_zone="UTC")
        )
        df = df_time_range.sort("datetime").join_asof(
            z.sort("datetime").drop("timestamp"),
            on="datetime",
            tolerance="59s",
            strategy="nearest",
        )
        dfs.append(df)

    if not dfs:
        logger.debug(f"No DataFrames created for IP {ip}")
        return None

    result = pl.concat(dfs, how="align_full").with_columns(ip=pl.lit(ip), hostname=pl.lit(hostname))
    logger.debug(f"Created combined DataFrame for {ip}: {len(result)} rows, columns: {result.columns}")

    return result


def query_existing_data(api: SycopeApi, cfg: dict, start_time: datetime, end_time: datetime) -> list:
    """Query Sycope for already indexed data to avoid duplicates."""
    end_time_str = "@" + end_time.astimezone().isoformat("T", "seconds")
    start_time_str = "@" + start_time.astimezone().isoformat("T", "seconds")
    query = f'src stream="{cfg["index_name"]}"'

    logger.debug("Querying existing data from Sycope")
    logger.debug(f"  Query: {query}")
    logger.debug(f"  Time range: {start_time_str} to {end_time_str}")

    results = api.query_all_results(query, start_time_str, end_time_str)
    logger.debug(f"Found {len(results)} existing records in Sycope")

    return results


def inject_new_data(api: SycopeApi, cfg: dict, new_entries: pl.DataFrame) -> None:
    """Inject new data into Sycope index."""
    columns_order = [
        "timestamp",
        "ip",
        "hostname",
        "response_time",
        "cpu_load",
        "memory_usage",
        "packet_loss",
    ]
    metric_columns = ["response_time", "cpu_load", "memory_usage", "packet_loss"]

    logger.debug("Preparing data for injection")
    logger.debug(f"  DataFrame shape: {new_entries.shape}")
    logger.debug(f"  DataFrame columns: {new_entries.columns}")

    available_columns = [x for x in columns_order if x in new_entries.columns]
    available_metrics = [x for x in metric_columns if x in new_entries.columns]

    logger.debug(f"  Available columns for injection: {available_columns}")
    logger.debug(f"  Available metrics: {available_metrics}")

    rows = new_entries[available_columns].drop_nulls(subset=available_metrics).rows()

    logger.debug(f"  Rows to inject after dropping nulls: {len(rows)}")
    if rows:
        logger.debug(f"  First row sample: {rows[0]}")
        api.inject_data(cfg["index_name"], available_columns, rows)
    else:
        logger.debug("  No rows to inject after filtering")


def main() -> None:
    """Main script logic."""
    # Load configuration first to get log_level
    try:
        cfg = load_config(
            CONFIG_FILE,
            required_fields=[
                "zabbix_host",
                "zabbix_api_base",
                "zabbix_login",
                "zabbix_pass",
                "sycope_host",
                "sycope_login",
                "sycope_pass",
                "index_name",
                "period_minutes",
            ],
        )
    except Exception as e:
        # Setup basic logging to report the error
        setup_logging("zabbix_statistics.log")
        logging.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Setup environment with log_level from config
    suppress_ssl_warnings()
    setup_logging("zabbix_statistics.log", log_level=cfg.get("log_level", "info"))

    logger.debug("=" * 60)
    logger.debug("Zabbix Statistics script starting")
    logger.debug(f"Script directory: {SCRIPT_DIR}")
    logger.debug(f"Config file: {CONFIG_FILE}")
    logger.debug("=" * 60)

    logger.debug("Configuration loaded successfully")
    logger.debug(f"  Zabbix host: {cfg['zabbix_host']}")
    logger.debug(f"  Sycope host: {cfg['sycope_host']}")
    logger.debug(f"  Index name: {cfg['index_name']}")
    logger.debug(f"  Period minutes: {cfg['period_minutes']}")

    # Authenticate to Zabbix
    try:
        logger.debug("Authenticating to Zabbix API...")
        auth_token, headers = zabbix_login(cfg)
        logger.debug("Zabbix authentication successful")
    except Exception as e:
        logging.error(f"Zabbix login failed: {e}")
        logger.debug(f"Zabbix login exception: {type(e).__name__}: {e}")
        sys.exit(1)

    # Initialize Sycope session
    session = Session()
    logger.debug("Created HTTP session for Sycope")

    try:
        logger.debug("Authenticating to Sycope API...")
        api = SycopeApi(
            session,
            cfg["sycope_host"],
            cfg["sycope_login"],
            cfg["sycope_pass"],
            cfg.get("api_base", "/npm/api/v1/"),
        )
        logger.debug("Sycope authentication successful")

        # Define time range
        start_time = datetime.now(timezone.utc) - timedelta(minutes=cfg["period_minutes"])
        end_time = datetime.now(timezone.utc) - timedelta(seconds=75)
        end_time_int = int(end_time.timestamp())
        start_time_int = int(start_time.timestamp())

        logger.debug("Time range calculation:")
        logger.debug(f"  Period minutes: {cfg['period_minutes']}")
        logger.debug(f"  Start time: {start_time} ({start_time_int})")
        logger.debug(f"  End time: {end_time} ({end_time_int})")

        df_time_range = create_minute_df_pl(start_time.replace(second=30), end_time.replace(second=30))

        # Get target IPs
        if cfg.get("use_dynamic_ips", False):
            logger.debug("Using dynamic IP discovery from Zabbix")
            ips = get_all_host_ips(cfg, headers)
            logging.info(f"Discovered {len(ips)} IPs dynamically from Zabbix")
        else:
            logger.debug("Using static IPs from config")
            ips = cfg.get("target_ips", [])
            logging.info(f"Using {len(ips)} static IPs from config")

        logger.debug(f"Target IPs ({len(ips)}): {ips[:20]}{'...' if len(ips) > 20 else ''}")

        # Collect metrics for all IPs
        logger.debug("Starting metrics collection for all IPs...")
        dfs_ips = []
        for i, ip in enumerate(ips, 1):
            logger.debug(f"Processing IP {i}/{len(ips)}: {ip}")
            df_ip = collect_metrics_for_ip(cfg, headers, ip, start_time_int, end_time_int, df_time_range)
            if df_ip is not None:
                dfs_ips.append(df_ip)
                logger.debug(f"  Collected data for {ip}")
            else:
                logger.debug(f"  No data for {ip}")

        logger.debug(f"Metrics collection complete: {len(dfs_ips)} IPs with data")

        if not dfs_ips:
            logging.info("No new data collected")
            logger.debug("No DataFrames to process, exiting")
            return

        # Combine all IP data
        logger.debug("Combining data from all IPs...")
        df = pl.concat(dfs_ips, how="diagonal_relaxed")
        logger.debug(f"Combined DataFrame shape: {df.shape}")
        logger.debug(f"Combined DataFrame columns: {df.columns}")

        df = df.with_columns(
            timestamp=pl.col("datetime").dt.epoch(time_unit="ms"),
            datetime=pl.col("datetime").dt.strftime("%Y/%m/%d %H:%M"),
        )
        logger.debug(f"DataFrame after timestamp conversion: {len(df)} rows")

        # Query existing data to avoid duplicates
        logger.debug("Checking for existing data in Sycope to avoid duplicates...")
        saved_data = query_existing_data(api, cfg, start_time, end_time)

        # Filter new records
        logging.info("Found new data, preparing payload...")
        if saved_data:
            logger.debug(f"Found {len(saved_data)} existing records, filtering duplicates...")
            saved_df = pl.DataFrame(saved_data).with_columns(
                datetime=pl.from_epoch(pl.col("timestamp"), time_unit="ms").dt.strftime("%Y/%m/%d %H:%M")
            )
            new_entries = df.join(saved_df, on=["datetime", "ip"], how="anti")
            logger.debug(
                f"After filtering: {len(new_entries)} new records (removed {len(df) - len(new_entries)} duplicates)"
            )
        else:
            logger.debug("No existing data found, all records are new")
            new_entries = df

        if not new_entries.is_empty():
            logger.debug(f"Injecting {len(new_entries)} new records into Sycope...")
            inject_new_data(api, cfg, new_entries)
            logger.debug("Data injection complete")
        else:
            logger.debug("No new entries to inject")

    except SycopeError as e:
        logging.error(f"Sycope API error: {e}")
        logger.debug(f"Sycope exception: {type(e).__name__}: {e}")
        sys.exit(1)
    finally:
        logger.debug("Cleanup: logging out from APIs...")
        zabbix_logout(cfg)
        logging.info("Logging out from Sycope")
        api.log_out()
        logger.debug("Script complete")


if __name__ == "__main__":
    main()
