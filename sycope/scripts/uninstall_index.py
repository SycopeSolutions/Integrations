#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generic index uninstallation script.

This module provides a reusable function for removing custom indexes
from Sycope. It can be imported and called from integration-specific
uninstall scripts, or run directly from the command line.

Usage as module:
    from sycope.scripts.uninstall_index import uninstall_index
    uninstall_index("config.json")

Usage from command line:
    python -m sycope.scripts.uninstall_index config.json [index_name]
"""

import logging
import sys
from typing import Optional

import requests

from ..api import SycopeApi
from ..config import load_config, validate_sycope_config
from ..exceptions import SycopeConfigError, SycopeError
from ..logging import setup_logging, suppress_ssl_warnings


def uninstall_index(
    config_path: str,
    index_name: Optional[str] = None,
    log_file: Optional[str] = "uninstall.log",
) -> None:
    """
    Remove a custom index from Sycope.

    This function loads configuration from a JSON file, connects to
    the Sycope API, and removes the specified custom index.

    Args:
        config_path: Path to config.json file
        index_name: Name of index to remove. If None, uses config["index_name"]
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

    # Determine target index name
    target_index = index_name or cfg.get("index_name")
    if not target_index:
        raise SycopeConfigError("No index_name specified in config or as argument")

    logging.info(f"Removing index: {target_index}")

    # Connect to Sycope and remove index
    with requests.Session() as session:
        api = SycopeApi(
            session=session,
            host=cfg["sycope_host"],
            login=cfg["sycope_login"],
            password=cfg["sycope_pass"],
            api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
        )

        try:
            api.remove_index(target_index)
            logging.info(f"Index '{target_index}' removed successfully")
        finally:
            api.log_out()


def main() -> None:
    """Command-line entry point."""
    if len(sys.argv) < 2:
        print("Usage: python -m sycope.scripts.uninstall_index <config_path> [index_name]")
        print("")
        print("Arguments:")
        print("  config_path  Path to config.json file")
        print("  index_name   Optional: Override index name from config")
        sys.exit(1)

    config_path = sys.argv[1]
    index_name = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        uninstall_index(config_path, index_name)
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
