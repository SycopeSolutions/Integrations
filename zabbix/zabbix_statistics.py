#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Zabbix statistics integration with Sycope.

This script retrieves metrics from Zabbix (Response Time, CPU Load,
Memory Usage, Packet Loss) and injects them into a Sycope custom index.

Script version: 2.2
Tested on Sycope 3.1
"""

import logging
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

import polars as pl
from requests import Session

# Add parent directory to path for importing sycope modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# and this directory for zabbix_api (also when the script is imported from elsewhere)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sycope.api import SycopeApi
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings

from zabbix_api import AlreadyRunning, ZabbixApi, ZabbixApiError, single_instance

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


# Zabbix item preprocessing step types
PREPROC_DISCARD_UNCHANGED = "19"
PREPROC_DISCARD_UNCHANGED_HEARTBEAT = "20"

# Value types a metric item can have: 0 = numeric (float), 3 = numeric (unsigned)
NUMERIC_VALUE_TYPES = ("0", "3")
HISTORY_CHUNK = 500  # item IDs per history.get request


# Item selection rules per metric. The rules are tried in order and the first one that matches an
# item of the host wins; "*" matches any text, everything else is literal. When a rule matches
# several items (one per CPU, one per memory pool), "prefer_name" keeps the items whose name before
# ":" is that text (Cisco "Processor: Memory utilization"), then "aggregate" (avg or max) combines
# the remaining items minute by minute. config.json "item_keys" can replace the rules of a metric.
#
# system.cpu.load (load average) is not CPU utilization in percent and is not used.
ITEM_KEYS = {
    "cpu_load": {
        "rules": [
            {"key": "system.cpu.util"},  # Windows/Linux by Zabbix agent
            {"key": "system.cpu.util[snmp,*]", "aggregate": "avg"},  # Linux by SNMP
            {"key": "system.cpu.util[cpmCPUTotal5minRev.*]", "aggregate": "avg"},  # Cisco IOS by SNMP
            {"key": "system.cpu.util[hrProcessorLoad.*]", "aggregate": "avg"},  # HOST-RESOURCES-MIB
        ],
        "output_type": float,
        "validation_function": val_numeric_range,
        "validation_args": {"lower": 0, "upper": 100},
        "transform_function": val_div,
        "round": 3,
    },
    "response_time": {
        "rules": [{"key": "icmppingsec"}, {"key": "icmppingsec[*]"}],
        "output_type": float,
        "validation_function": val_numeric_range,
        "validation_args": {"lower": -1, "upper": 100000000},
        "transform_function": val_multi,
        "round": 3,
    },
    "memory_usage": {
        "rules": [
            {"key": "vm.memory.util"},  # Windows by Zabbix agent
            {"key": "vm.memory.utilization"},  # Linux by Zabbix agent
            {"key": "vm.memory.util[snmp]"},  # Linux by SNMP
            # Cisco and other SNMP templates: one item per memory pool, the "Processor" pool
            # (as in "show memory"), otherwise the fullest pool
            {"key": "vm.memory.util[*]", "aggregate": "max", "prefer_name": "Processor"},
        ],
        "output_type": float,
        "validation_function": val_numeric_range,
        "validation_args": {"lower": 0, "upper": 100},
        "transform_function": val_div,
        "round": 3,
    },
    "packet_loss": {
        "rules": [{"key": "icmppingloss"}, {"key": "icmppingloss[*]"}],
        "output_type": float,
        "validation_function": val_numeric_range,
        "validation_args": {"lower": 0, "upper": 100},
        "transform_function": val_div,
        "round": 3,
    },
}


def resolve_hostname(host: dict) -> str:
    """Pick the host's name the same way as zabbix_lookup_sync.py.

    Order: inventory "Name", inventory "Hostname", the host's visible name, its technical host name.
    Hosts with inventory disabled return an empty list instead of an inventory object, so the visible
    name is what most hosts end up with.
    """
    inventory = host.get("inventory")
    if not isinstance(inventory, dict):
        inventory = {}
    return inventory.get("name") or inventory.get("hostname") or host.get("name") or host.get("host") or ""


def parse_zabbix_seconds(value: str) -> Optional[int]:
    """Convert a Zabbix time value ("300", "5m", "1h", "1d", "1w") to seconds; None for macros etc."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    value = (value or "").strip()
    try:
        if value and value[-1] in units:
            return int(value[:-1]) * units[value[-1]]
        return int(value)
    except ValueError:
        return None


def value_max_age_seconds(cfg: dict, item: dict) -> int:
    """How long a stored value of the item still describes the current state.

    Items with "Discard unchanged" preprocessing store a value only when it changes (or once per
    heartbeat), so an idle host has no history for most minutes. Such a value stays valid until the
    heartbeat; without a heartbeat it is used for at most max_value_age_minutes (default 60).
    Other items keep the original one-minute match.
    """
    cap = int(cfg.get("max_value_age_minutes", 60)) * 60
    for step in item.get("preprocessing") or []:
        if str(step.get("type")) == PREPROC_DISCARD_UNCHANGED_HEARTBEAT:
            heartbeat = parse_zabbix_seconds(step.get("params", ""))
            return min(max(heartbeat, 59), cap) if heartbeat else cap
        if str(step.get("type")) == PREPROC_DISCARD_UNCHANGED:
            return cap
    return 59


def metric_rules(cfg: dict, metric_name: str) -> list:
    """Item selection rules of a metric: config.json "item_keys" or the built-in ITEM_KEYS rules.

    In config.json a rule is either a key pattern ("vm.memory.util[*]") or an object with "key" and
    optionally "aggregate" and "prefer_name".
    """
    override = (cfg.get("item_keys") or {}).get(metric_name)
    if not override:
        return ITEM_KEYS[metric_name]["rules"]
    return [rule if isinstance(rule, dict) else {"key": rule} for rule in override]


def key_matches(pattern: str, key: str) -> bool:
    """Match an item key against a rule pattern; "*" matches any text, everything else is literal."""
    regex = ".*".join(re.escape(part) for part in pattern.split("*"))
    return re.fullmatch(regex, key) is not None


def select_items(items: list, rules: list) -> tuple:
    """Return (items, aggregate, rule key) for the first rule that matches items of the host."""
    for rule in rules:
        matched = [item for item in items if key_matches(rule["key"], item["key_"])]
        if not matched:
            continue
        prefer = rule.get("prefer_name")
        if prefer:
            preferred = [
                item
                for item in matched
                if item.get("name", "").split(":")[0].strip().lower() == prefer.strip().lower()
            ]
            if preferred:
                matched = preferred
        return matched, rule.get("aggregate", "avg"), rule["key"]
    return [], None, None


def convert_history(history: list, val_config: dict) -> list:
    """Validate and transform Zabbix history into (timestamp ms, value) pairs."""
    values = []
    for entry in history:
        timestamp = int(entry["clock"]) * 1000
        value = entry["value"]

        if val_config["validation_function"] and not val_config["validation_function"](
            value, **val_config["validation_args"]
        ):
            values.append((timestamp, None))
            continue

        value = val_config["output_type"](value)
        if val_config["transform_function"]:
            value = val_config["transform_function"](value)
        if val_config["output_type"] is float and val_config["round"]:
            value = round(value, val_config["round"])
        values.append((timestamp, value))
    return values


def align_to_minutes(df_time_range: pl.DataFrame, values: list, max_age: int) -> pl.Series:
    """Put an item's values on the minute grid.

    Regular items: the value nearest to the minute. "Discard unchanged" items: the last stored
    value, as long as it is younger than the heartbeat (see value_max_age_seconds).
    """
    z = pl.DataFrame(values, schema=["timestamp", "value"], orient="row").with_columns(
        # cast_time_unit: polars >= 2.0 returns datetime[us] from from_epoch(..., "ms"),
        # which no longer matches the datetime[ms] minute grid in join_asof below.
        datetime=pl.from_epoch("timestamp", time_unit="ms")
        .dt.convert_time_zone(time_zone="UTC")
        .dt.cast_time_unit("ms")
    )
    joined = df_time_range.join_asof(
        z.sort("datetime").drop("timestamp"),
        on="datetime",
        tolerance=f"{max_age}s",
        strategy="nearest" if max_age <= 59 else "backward",
    )
    return joined["value"].cast(pl.Float64)


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


def get_hosts_by_ip(zabbix: ZabbixApi) -> tuple:
    """Map the interface IPs of enabled hosts to the hosts (one host.get for all hosts).

    Returns (hosts_by_ip, main_ips). Main interfaces win over additional ones. When several enabled
    hosts share an IP, the first one is used and the others are logged.
    """
    hosts = zabbix.call(
        "host.get",
        {
            "output": ["hostid", "host", "name"],
            "selectInterfaces": ["ip", "main", "type"],
            "selectInventory": ["name", "hostname"],
            "filter": {"status": "0"},  # enabled hosts only
        },
    )
    hosts_by_ip = {}
    main_ips = set()
    for main in ("1", "0"):
        for host in hosts:
            for iface in host.get("interfaces", []):
                ip = (iface.get("ip") or "").strip()
                if not ip or iface.get("main") != main:
                    continue
                if main == "1":
                    main_ips.add(ip)
                other = hosts_by_ip.setdefault(ip, host)
                if other["hostid"] != host["hostid"]:
                    logger.debug(f"IP {ip} is used by hosts {other['hostid']} and {host['hostid']}, using {other['hostid']}")
    logger.debug(f"{len(hosts)} enabled hosts, {len(hosts_by_ip)} IPs, {len(main_ips)} main interface IPs")
    return hosts_by_ip, sorted(main_ips)


def rule_key_prefixes(cfg: dict) -> list:
    """Key prefixes of all metric rules (text before "[" or "*"), for the item.get search."""
    prefixes = set()
    for metric_name in ITEM_KEYS:
        for rule in metric_rules(cfg, metric_name):
            prefixes.add(re.split(r"[\[*]", rule["key"], maxsplit=1)[0])
    return sorted(prefixes)


def get_metric_items(zabbix: ZabbixApi, cfg: dict, hostids: list) -> dict:
    """Enabled numeric items that a metric rule can match, grouped by host ID (one item.get)."""
    if not hostids:
        return {}
    params = {
        "output": ["itemid", "hostid", "name", "key_", "value_type"],
        "selectPreprocessing": ["type", "params"],
        "hostids": hostids,
        "filter": {"status": "0", "value_type": list(NUMERIC_VALUE_TYPES)},
    }
    prefixes = rule_key_prefixes(cfg)
    if "" not in prefixes:  # a rule starting with "*" needs every item
        params.update({"search": {"key_": prefixes}, "searchByAny": True, "startSearch": True})
    items_by_host = defaultdict(list)
    for item in zabbix.call("item.get", params):
        items_by_host[item["hostid"]].append(item)
    return items_by_host


def select_metric_items(cfg: dict, items: list) -> dict:
    """Pick the items of each metric for one host: {metric: (items, aggregate)}."""
    selection = {}
    for metric_name in ITEM_KEYS:
        selected, aggregate, rule_key = select_items(items, metric_rules(cfg, metric_name))
        if not selected:
            continue
        for item in selected:
            item["max_age"] = value_max_age_seconds(cfg, item)
        selection[metric_name] = (selected, aggregate)
        logger.debug(
            f"  {metric_name}: rule {rule_key} -> {[(i['key_'], i.get('name'), i['max_age']) for i in selected]},"
            f" aggregate={aggregate}"
        )
    return selection


def get_history_bulk(zabbix: ZabbixApi, items: list, start_time: int, end_time: int) -> dict:
    """History of the items grouped by item ID.

    One history.get per value type, value validity and chunk of item IDs. Each item is read from
    start_time minus its validity (item["max_age"]), so the first minutes get the last stored value.
    """
    groups = defaultdict(list)
    for item in items:
        groups[(item["value_type"], item["max_age"])].append(item["itemid"])

    history = defaultdict(list)
    for (value_type, max_age), itemids in groups.items():
        for i in range(0, len(itemids), HISTORY_CHUNK):
            rows = zabbix.call(
                "history.get",
                {
                    "output": ["itemid", "clock", "value"],
                    "history": int(value_type),
                    "itemids": itemids[i : i + HISTORY_CHUNK],
                    "time_from": start_time - max_age,
                    "time_till": end_time,
                    "sortfield": "clock",
                    "sortorder": "ASC",
                },
            )
            for row in rows:
                history[row["itemid"]].append(row)
    logger.debug(f"History: {sum(len(v) for v in history.values())} values for {len(history)} of {len(items)} items")
    return history


def build_ip_frame(
    ip: str, hostname: str, selection: dict, history: dict, grid: pl.DataFrame
) -> Optional[pl.DataFrame]:
    """Put the selected items of one IP on the minute grid, one column per metric."""
    columns = {}
    for metric_name, (items, aggregate) in selection.items():
        val_config = ITEM_KEYS[metric_name]
        series = []
        for item in items:
            values = convert_history(history.get(item["itemid"], []), val_config)
            if values:
                series.append(align_to_minutes(grid, values, item["max_age"]).alias(item["itemid"]))
        if not series:
            continue
        if len(series) == 1:
            columns[metric_name] = series[0]
        else:
            combine = pl.max_horizontal if aggregate == "max" else pl.mean_horizontal
            columns[metric_name] = pl.DataFrame(series).select(combine(pl.all())).to_series()
            if val_config["round"]:
                columns[metric_name] = columns[metric_name].round(val_config["round"])

    if not columns:
        return None
    return grid.with_columns(
        *[col.alias(name) for name, col in columns.items()], ip=pl.lit(ip), hostname=pl.lit(hostname)
    )


def collect_metrics(
    zabbix: ZabbixApi, cfg: dict, start_time_int: int, end_time_int: int, grid: pl.DataFrame
) -> list:
    """Collect the metrics of all target IPs with a few bulk requests; one DataFrame per IP."""
    hosts_by_ip, main_ips = get_hosts_by_ip(zabbix)
    if cfg.get("use_dynamic_ips", False):
        ips = main_ips
        logging.info(f"Discovered {len(ips)} IPs dynamically from Zabbix")
    else:
        ips = cfg.get("target_ips", [])
        logging.info(f"Using {len(ips)} static IPs from config")

    targets = []
    for ip in ips:
        host = hosts_by_ip.get(ip)
        if host is None:
            logger.debug(f"No enabled Zabbix host with IP {ip}")
            continue
        targets.append((ip, host))

    items_by_host = get_metric_items(zabbix, cfg, sorted({host["hostid"] for _, host in targets}))
    selections = {}
    for ip, host in targets:
        logger.debug(f"{ip}: host {host['hostid']} ({resolve_hostname(host)})")
        selections[ip] = select_metric_items(cfg, items_by_host.get(host["hostid"], []))

    selected = {item["itemid"]: item for sel in selections.values() for items, _ in sel.values() for item in items}
    history = get_history_bulk(zabbix, list(selected.values()), start_time_int, end_time_int)

    frames = []
    for ip, host in targets:
        frame = build_ip_frame(ip, resolve_hostname(host), selections[ip], history, grid)
        if frame is None:
            logger.debug(f"No metric data for {ip}")
        else:
            frames.append(frame)
    return frames


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

    # Keep a row when at least one metric has a value. Hosts differ in what they collect (no ICMP
    # template, no memory item, ...) and requiring every metric dropped all rows of such hosts.
    # Sycope stores the missing metrics as absent fields.
    rows = (
        new_entries[available_columns]
        .filter(~pl.all_horizontal([pl.col(c).is_null() for c in available_metrics]))
        .rows()
    )

    logger.debug(f"  Rows to inject (with at least one metric): {len(rows)}")
    if rows:
        logger.debug(f"  First row sample: {rows[0]}")
        api.inject_data(cfg["index_name"], available_columns, rows)
    else:
        logger.debug("  No rows to inject after filtering")


def run(cfg: dict) -> None:
    """One synchronization: Zabbix history of the last period_minutes -> new samples in Sycope."""
    zabbix = ZabbixApi(cfg)
    session = Session()
    api = None
    try:
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
        logger.debug(f"Time range: {start_time} ({start_time_int}) - {end_time} ({end_time_int})")

        df_time_range = create_minute_df_pl(start_time.replace(second=30), end_time.replace(second=30))

        dfs_ips = collect_metrics(zabbix, cfg, start_time_int, end_time_int, df_time_range)
        logger.debug(f"Metrics collection complete: {len(dfs_ips)} IPs with data")
        if not dfs_ips:
            logging.info("No data collected from Zabbix")
            return

        df = pl.concat(dfs_ips, how="diagonal_relaxed").with_columns(
            timestamp=pl.col("datetime").dt.epoch(time_unit="ms"),
            datetime=pl.col("datetime").dt.strftime("%Y/%m/%d %H:%M"),
        )
        logger.debug(f"Combined DataFrame: {df.shape}, columns: {df.columns}")

        # Skip the minutes already saved in Sycope (one sample per IP and minute)
        saved_data = query_existing_data(api, cfg, start_time, end_time)
        if saved_data:
            saved_df = pl.DataFrame(saved_data).with_columns(
                datetime=pl.from_epoch(pl.col("timestamp"), time_unit="ms").dt.strftime("%Y/%m/%d %H:%M")
            )
            new_entries = df.join(saved_df, on=["datetime", "ip"], how="anti")
        else:
            new_entries = df
        logger.debug(f"{len(df) - len(new_entries)} of {len(df)} samples are already in Sycope")

        if new_entries.is_empty():
            logging.info("No new samples")
            return
        logging.info(f"{len(new_entries)} new samples for {new_entries['ip'].n_unique()} IPs, sending to Sycope")
        inject_new_data(api, cfg, new_entries)
    finally:
        zabbix.close()
        if api is not None:
            logging.info("Logging out from Sycope")
            api.log_out()
        session.close()


def main() -> None:
    """Main script logic."""
    # Load configuration first to get log_level
    try:
        cfg = load_config(
            CONFIG_FILE,
            required_fields=[
                "zabbix_host",
                "sycope_host",
                "sycope_login",
                "sycope_pass",
                "index_name",
                "period_minutes",
            ],
        )
        if not cfg.get("zabbix_token") and not (cfg.get("zabbix_login") and cfg.get("zabbix_pass")):
            raise ValueError("set zabbix_token, or zabbix_login and zabbix_pass")
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
    logger.debug(f"Config file: {CONFIG_FILE}")
    logger.debug(f"  Zabbix host: {cfg['zabbix_host']} ({'API token' if cfg.get('zabbix_token') else 'login'})")
    logger.debug(f"  Sycope host: {cfg['sycope_host']}")
    logger.debug(f"  Index name: {cfg['index_name']}, period minutes: {cfg['period_minutes']}")

    try:
        with single_instance(os.path.join(SCRIPT_DIR, "zabbix_statistics.lock")):
            run(cfg)
    except AlreadyRunning as e:
        logging.warning(f"The previous run is still running, skipping this one ({e})")
    except ZabbixApiError as e:
        logging.error(f"Zabbix API error: {e}")
        sys.exit(1)
    except SycopeError as e:
        logging.error(f"Sycope API error: {e}")
        sys.exit(1)
    logger.debug("Script complete")


if __name__ == "__main__":
    main()
