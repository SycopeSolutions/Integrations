#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Create custom index for Zabbix statistics in Sycope.

This script creates a custom index with fields for storing Zabbix
metrics: Hostname, Response Time, CPU Load, Memory Usage, Packet Loss.

Script version: 2.0
Tested on Sycope 3.1
"""

import logging
import os
import sys

import requests

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

# Field definitions for the Zabbix statistics index
FIELDS = [
    {
        "name": "timestamp",
        "type": "long",
        "sortable": True,
        "description": "Timestamp",
        "displayName": "Time",
    },
    {
        "name": "ip",
        "type": "ip4",
        "description": "IP Address",
        "displayName": "IP Address",
    },
    {
        "name": "hostname",
        "type": "string",
        "description": "Hostname",
        "displayName": "Hostname",
    },
    {
        "name": "response_time",
        "type": "float",
        "description": "Response Time (ms)",
        "displayName": "Response Time",
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


def main() -> None:
    """Create the Zabbix statistics custom index."""
    # Load configuration first to get log_level
    try:
        cfg = load_config(
            CONFIG_FILE,
            required_fields=["sycope_host", "sycope_login", "sycope_pass", "index_name", "index_rotation"],
        )
    except Exception as e:
        # Setup basic logging to report the error
        setup_logging("install.log")
        logging.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Setup environment with log_level from config
    suppress_ssl_warnings()
    setup_logging("install.log", log_level=cfg.get("log_level", "info"))

    logger.debug("=" * 60)
    logger.debug("Zabbix Install script starting")
    logger.debug(f"Script directory: {SCRIPT_DIR}")
    logger.debug(f"Config file: {CONFIG_FILE}")
    logger.debug("=" * 60)

    # Log field definitions
    logger.debug(f"Index field definitions ({len(FIELDS)} fields):")
    for field in FIELDS:
        logger.debug(f"  {field['name']}: type={field['type']}, displayName={field.get('displayName')}")

    logger.debug("Configuration loaded successfully")
    logger.debug(f"  Sycope host: {cfg['sycope_host']}")
    logger.debug(f"  Index name: {cfg['index_name']}")
    logger.debug(f"  Index rotation: {cfg['index_rotation']}")
    logger.debug(f"  API base: {cfg.get('api_base', '/npm/api/v1/')}")

    logging.info(f"Loaded configuration from {CONFIG_FILE}")

    # Connect to Sycope and create index
    logger.debug("Creating HTTP session...")
    with requests.Session() as session:
        try:
            logger.debug("Authenticating to Sycope API...")
            api = SycopeApi(
                session=session,
                host=cfg["sycope_host"],
                login=cfg["sycope_login"],
                password=cfg["sycope_pass"],
                api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
            )
            logger.debug("Sycope authentication successful")

            logging.info(f"Creating index: {cfg['index_name']}")
            logger.debug("Index parameters:")
            logger.debug(f"  Name: {cfg['index_name']}")
            logger.debug(f"  Rotation: {cfg['index_rotation']}")
            logger.debug(f"  Fields count: {len(FIELDS)}")

            api.create_index(cfg["index_name"], FIELDS, cfg["index_rotation"])
            logging.info("Index created successfully")
            logger.debug("Index creation complete")

        except SycopeError as e:
            logging.error(f"Sycope API error: {e}")
            logger.debug(f"Sycope exception: {type(e).__name__}: {e}")
            if hasattr(e, "status_code"):
                logger.debug(f"  Status code: {e.status_code}")
            if hasattr(e, "response"):
                logger.debug(f"  Response: {e.response}")
            sys.exit(1)
        finally:
            logger.debug("Logging out from Sycope...")
            api.log_out()
            logger.debug("Script complete")


if __name__ == "__main__":
    main()
