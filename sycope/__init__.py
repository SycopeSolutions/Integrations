"""
Sycope Integration Library.

This package provides utilities for building integrations with the Sycope
network observability and security platform.

Modules:
    api: SycopeApi class for REST API interactions
    config: Configuration loading and validation
    logging: Logging setup utilities
    exceptions: Custom exception classes

Example:
    >>> from sycope.api import SycopeApi
    >>> from sycope.config import load_config
    >>> from sycope.logging import setup_logging, suppress_ssl_warnings
    >>>
    >>> suppress_ssl_warnings()
    >>> setup_logging("integration.log")
    >>> cfg = load_config("config.json")
    >>>
    >>> with requests.Session() as session:
    ...     api = SycopeApi(session, cfg["sycope_host"], cfg["sycope_login"], cfg["sycope_pass"])
    ...     # ... do work ...
    ...     api.log_out()
"""

__version__ = "2.0.0"

# Re-export main classes and functions for convenience
from .api import SycopeApi
from .config import load_config, validate_sycope_config, get_config_value
from .exceptions import SycopeError, SycopeAuthError, SycopeApiError, SycopeConfigError
from .logging import setup_logging, suppress_ssl_warnings, get_logger

__all__ = [
    # Version
    "__version__",
    # API
    "SycopeApi",
    # Config
    "load_config",
    "validate_sycope_config",
    "get_config_value",
    # Exceptions
    "SycopeError",
    "SycopeAuthError",
    "SycopeApiError",
    "SycopeConfigError",
    # Logging
    "setup_logging",
    "suppress_ssl_warnings",
    "get_logger",
]
