#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generic lookup uninstallation script.

This module provides a reusable function for removing lookups
from Sycope. It can be imported and called from integration-specific
uninstall scripts, or run directly from the command line.

Usage as module:
    from sycope.scripts.uninstall_lookup import uninstall_lookup
    uninstall_lookup("config.json")

Usage from command line:
    python -m sycope.scripts.uninstall_lookup config.json [lookup_name]
"""

import logging
import sys
from typing import Optional

import requests

from ..api import SycopeApi
from ..config import load_config, validate_sycope_config
from ..exceptions import SycopeConfigError, SycopeError
from ..logging import setup_logging, suppress_ssl_warnings


def uninstall_lookup(
    config_path: str,
    lookup_name: Optional[str] = None,
    lookup_type: str = "csvFile",
    log_file: Optional[str] = "uninstall.log",
) -> None:
    """
    Remove a lookup from Sycope.

    This function loads configuration from a JSON file, connects to
    the Sycope API, and removes the specified lookup.

    Args:
        config_path: Path to config.json file
        lookup_name: Name of lookup to remove. If None, uses config["lookup_name"]
        lookup_type: Type of lookup ('csvFile' or 'subnet')
        log_file: Path to log file. If None, logs only to console.

    Raises:
        SycopeConfigError: If configuration is invalid or missing required fields
        SycopeError: If the API operation fails
        FileNotFoundError: If config file doesn't exist
    """
    # Load and validate configuration first to get log_level
    cfg = load_config(
        config_path,
        required_fields=["sycope_host", "sycope_login", "sycope_pass"],
    )
    validate_sycope_config(cfg)

    # Setup environment with log_level from config
    suppress_ssl_warnings()
    setup_logging(log_file, log_level=cfg.get("log_level", "info"))

    # Determine target lookup name
    target_lookup = lookup_name or cfg.get("lookup_name")
    if not target_lookup:
        raise SycopeConfigError("No lookup_name specified in config or as argument")

    logging.info(f"Removing lookup: {target_lookup}")

    # Connect to Sycope and remove lookup
    with requests.Session() as session:
        api = SycopeApi(
            session=session,
            host=cfg["sycope_host"],
            login=cfg["sycope_login"],
            password=cfg["sycope_pass"],
            api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
        )

        try:
            api.delete_lookup(target_lookup, lookup_type=lookup_type)
            logging.info(f"Lookup '{target_lookup}' removed successfully")
        finally:
            api.log_out()


def main() -> None:
    """Command-line entry point."""
    if len(sys.argv) < 2:
        print("Usage: python -m sycope.scripts.uninstall_lookup <config_path> [lookup_name] [lookup_type]")
        print("")
        print("Arguments:")
        print("  config_path  Path to config.json file")
        print("  lookup_name  Optional: Override lookup name from config")
        print("  lookup_type  Optional: Lookup type ('csvFile' or 'subnet', default: csvFile)")
        sys.exit(1)

    config_path = sys.argv[1]
    lookup_name = sys.argv[2] if len(sys.argv) > 2 else None
    lookup_type = sys.argv[3] if len(sys.argv) > 3 else "csvFile"

    try:
        uninstall_lookup(config_path, lookup_name, lookup_type)
    except SycopeConfigError as e:
        logging.error(f"Configuration error: {e}")
        sys.exit(1)
    except SycopeError as e:
        logging.error(f"Sycope API error: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
