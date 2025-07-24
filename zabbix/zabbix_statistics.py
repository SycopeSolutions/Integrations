## !/usr/bin/env python
# coding: utf-8

# Zabbix statistics integration with Sycope (Hostname, Response Time, CPU Load, Memory Usage, Packet Loss)
# Script version: 1.0
# Tested on Sycope 3.1

import json
import os
import sys
import logging
from datetime import datetime, timedelta, timezone

import polars as pl
import requests
from requests import Session

# Hiding SSL certificate warning messages
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

sys.path.append('../sycope')
from api import SycopeApi

SCRIPT_DIR = os.getcwd()  # use current directory
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

try:
    with open(CONFIG_FILE, 'r') as f:
        cfg = json.load(f)
except Exception as e:
    logging.error(f"ERROR loading config: {e}")
    sys.exit(1)

def val_numeric_range(val, lower=0, upper=100):
    try:
        return float(val) >= lower and float(val) <= upper
    except Exception:
        return False


def val_div(x, div=100):
    return x / div


def val_multi(x, multi=1000):
    return x * multi


# Keys for metrics (multiple keys for CPU Load to support different platforms)
# Other items can be included, but they would require additional columns in custom index
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


# Defining session for Sycope
s = Session()

def zabbix_login():
    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {"username": cfg["zabbix_login"], "password": cfg["zabbix_pass"]},
        "id": 1,
    }
    response = requests.post(cfg["zabbix_host"].rstrip("/")+cfg["zabbix_api_base"].rstrip("/"), json=payload, verify=False)
    data = response.json()
    if "result" in data:
        print("Zabbix API login successful. Proceeding...")
        return data["result"]
    raise Exception(f"Zabbix API login failed: {data.get('error')}")


def get_host_id_by_ip(headers, ip):
    payload = {
        "jsonrpc": "2.0",
        "method": "hostinterface.get",
        "params": {"filter": {"ip": ip}},
        "id": 2
    }
    response = requests.post(cfg["zabbix_host"].rstrip("/")+cfg["zabbix_api_base"].rstrip("/"), headers=headers, json=payload, verify=False)
    data = response.json()["result"]
    if data:
        return data[0]["hostid"]
    return None


def get_hostname_by_id(headers, host_id):
    payload = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {"output": ["hostid"], "selectInventory": ["name"], "hostids": host_id},
        "id": 5
    }
    response = requests.post(cfg["zabbix_host"].rstrip("/")+cfg["zabbix_api_base"].rstrip("/"), headers=headers, json=payload, verify=False)
    result = response.json()["result"]
    # print(result)
    if result and "inventory" in result[0] and result[0]["inventory"]:
        return result[0]["inventory"].get("name", "")
    return ""


# def get_items_id(headers, host_id, key_):
def get_items_id(headers, host_id):
    payload = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": ["itemid", "name", "key_"],
            "hostids": host_id,
            # "search": {"key_": key_},
            "sortfield": "name",
        },
        "id": 3
    }
    response = requests.post(cfg["zabbix_host"].rstrip("/")+cfg["zabbix_api_base"].rstrip("/"), headers=headers, json=payload, verify=False)

    items = response.json()["result"]
    if items:
        return items
    return []


def get_history(headers, item_id, start_time, end_time, history_type=0):
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
        "id": 4
    }

    response = requests.post(cfg["zabbix_host"].rstrip("/")+cfg["zabbix_api_base"].rstrip("/"), headers=headers, json=payload, verify=False)
    return response.json()["result"]


def create_minute_df_pl(start_datetime, stop_datetime):
    return pl.DataFrame(
        pl.datetime_range(
            start=start_datetime,
            end=stop_datetime,
            interval="1m",
            time_unit="ms",
            eager=True,  # Return a Series directly
            time_zone="UTC"
        ).alias("datetime")
    )


def main():

    auth_token = zabbix_login()

    headers = {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json-rpc'
    }

    api = SycopeApi(s, cfg["sycope_host"].rstrip("/"), cfg["sycope_login"], cfg["sycope_pass"])
    columns = []

    startTime = datetime.now(timezone.utc) - timedelta(minutes=cfg["period_minutes"])
    endTime = datetime.now(timezone.utc) - timedelta(seconds=75)
    end_time_int = int(endTime.timestamp())
    start_time_int = int(startTime.timestamp())
    df_time_range = create_minute_df_pl(startTime.replace(second=30), endTime.replace(second=30))

    dfs_ips = []
    for ip in cfg['target_ips']:
        history_data = {}
        for metric_name in ITEM_KEYS:
            history_data[metric_name] = []
        host_id = get_host_id_by_ip(headers, ip)
        if not host_id:
            continue

        hostname = get_hostname_by_id(headers, host_id)
        # items_id = get_items_id(headers, host_id, key_)
        items_id = get_items_id(headers, host_id)
        # items_ids_dict = {x["_key"].split("[")[0]:x["itemid"]}
        items_ids_dict = {x["key_"].split("[")[0]: x["itemid"] for x in items_id}
        # print(items_ids_dict)

        for metric_name, val_config in ITEM_KEYS.items():
            if not any([x in items_ids_dict for x in val_config["values"]]):
                continue

            for key_ in val_config["values"]:
                if key_ not in items_ids_dict:
                    continue
                history = get_history(
                    headers, items_ids_dict[key_], start_time_int, end_time_int, history_type=0
                )

                # For debugging
                # print(history)
                for entry in history:
                    # For debugging
                    # print(entry)
                    timestamp = int(entry["clock"]) * 1000
                    value = entry["value"]

                    # For debugging
                    # print(val_config)

                    if val_config["validation_function"] and not val_config["validation_function"](
                        value, **val_config["validation_args"]
                    ):

                        #history_data[metric_name].append((timestamp, ip, hostname, None))
                        history_data[metric_name].append((timestamp, None))
                        continue

                    value = val_config["output_type"](value)

                    if val_config["transform_function"]:
                        value = val_config["transform_function"](value)
                    if val_config["output_type"] is float and val_config["round"]:
                        value = round(value, val_config["round"])

                    history_data[metric_name].append((timestamp, value))

        if history_data:
            dfs = []
            for col, vals in history_data.items():
                z = pl.DataFrame(vals, schema=["timestamp", col], orient="row").with_columns(
                    datetime=pl.from_epoch(
                        "timestamp", time_unit="ms"
                    )
                )
                df = df_time_range.sort("datetime").join_asof(
                    z.sort("datetime").drop("timestamp"), on="datetime", tolerance="59s", strategy="nearest"
                )

                dfs.append(df)
            dfs_ips.append(
                pl.concat(dfs, how="align_full").with_columns(ip=pl.lit(ip), hostname=pl.lit(hostname))
            )


    df = pl.DataFrame()
    if dfs_ips:

        df = pl.concat(dfs_ips, how="diagonal_relaxed")
        df = df.with_columns(
            timestamp=pl.col("datetime").dt.epoch(time_unit="ms"),
            datetime=pl.col("datetime").dt.strftime("%Y/%m/%d %H:%M"),
        )


    ###### Checking current statistics in custom stream, in order not to duplicate samples

    endTime = "@" + endTime.astimezone().isoformat("T", "seconds")

    # For debugging
    # print(startTime)
    # print("endTime =", endTime)

    startTime = startTime.astimezone().isoformat("T", "seconds")
    startTime = "@" + startTime

    query = f'src stream="{cfg["index_name"]}"'

    ### Sending NQL query (HTTPS POST) to find ID of the requested IP address
    ### Output will include jobId
    off_size = 50000
    payload = {
        "startTime": startTime,
        "endTime": endTime,
        "nql": query,
        "fsActive": False,
        "waitTime": 30000,
        "limit": off_size,
    }


    r = s.post(cfg["sycope_host"].rstrip("/") + "/npm/api/v1/pipeline/run", json=payload, verify=False)
    job_run = r.json()

    # For debugging
    # print(r.json())

    ### Gathering query output using jobId
    saved_data = []
    for offset in range(job_run["data"]["total"] // off_size + 1):
        # print(offset) # for debugging
        payload = {"limit": off_size, "offset": offset * off_size}
        r = s.post(f"{cfg['sycope_host'].rstrip('/')}/npm/api/v1/pipeline/{job_run['jobId']}/data", json=payload, verify=False)
        chunk = r.json()
        saved_data.extend(chunk["data"])

    # For debugging

    # API response
    # print("Data from Sycope:")
    # print(json.dumps(saved_data))
    # print("----------")

    # print("Data from Zabbix:")
    # print(json.dumps(new_data))


    if not df.is_empty():
        print("We have found new data. Preparing the payload...")
        if saved_data:
            saved_df = pl.DataFrame(saved_data).with_columns(
                datetime=pl.from_epoch(pl.col("timestamp"), time_unit="ms").dt.strftime("%Y/%m/%d %H:%M")
            )

            new_entries = df.join(saved_df, on=["datetime", "ip"], how="anti")

        else:
            new_entries = df
        new_data = {
            "columns": [
                x
                for x in [
                    "timestamp",
                    "ip",
                    "hostname",
                    "response_time",
                    "cpu_load",
                    "memory_usage",
                    "packet_loss",
                ]
                if x in new_entries.columns
            ],
            "indexName": cfg["index_name"],
            "sortTimestamp": True,
            "rows": new_entries[
                [
                    x
                    for x in [
                        "timestamp",
                        "ip",
                        "hostname",
                        "response_time",
                        "cpu_load",
                        "memory_usage",
                        "packet_loss",
                    ]
                    if x in new_entries.columns
                ]
            ]
            .drop_nulls(
                subset=[
                    x
                    for x in ["response_time", "cpu_load", "memory_usage", "packet_loss"]
                    if x in new_entries.columns
                ]
            )
            .rows(),

        }
        print("Sending new data to Sycope...")
        r = s.post(cfg["sycope_host"].rstrip("/") + "/npm/api/v1/index/inject", json=new_data, verify=False)
        data = r.json()
        if data['status'] == 200:
            print(f'Sycope API successfully saved new data.')
        else:
            #For debugging
            print(f'Sycope API encountered an issue. Error message:')
            print(r.json())


    # Build the logout payload for Zabbix
    logout_payload = {
        "jsonrpc": "2.0",
        "method": "user.logout",
        "params": [],
        "id": 2
    }

    # Send the logout request to Zabbix
    print("Logging out from Zabbix.")
    logout_response = requests.post(
        cfg["zabbix_host"].rstrip("/") + cfg["zabbix_api_base"],
        json=logout_payload,
        verify=False
    )

    # Closing the REST API session
    # Session should be automatically closed in session context manager
    print("Logging out from Sycope.")
    api.log_out()


if __name__ == "__main__":
    main()
