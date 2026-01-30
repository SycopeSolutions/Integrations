#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Remove Suricata custom index from Sycope.

This script removes the custom index used for Suricata security events
from the Sycope platform.

Script version: 2.0
Tested on Sycope 3.1

Warning:
    This will permanently delete all data stored in the Suricata index.
    Make sure to backup any important data before running this script.
"""

import os
import sys

# Add parent directory to path for importing sycope modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sycope.scripts.uninstall_index import uninstall_index

if __name__ == "__main__":
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    uninstall_index(config_path, log_file="uninstall.log")
