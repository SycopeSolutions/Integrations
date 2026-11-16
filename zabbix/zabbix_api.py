#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Zabbix API client shared by zabbix_statistics.py and zabbix_lookup_sync.py.

- Authentication with an API token (config "zabbix_token", Zabbix 5.4+) or with
  "zabbix_login"/"zabbix_pass". A token needs no login and no logout, so it opens no sessions.
- Every request has a (connect, read) timeout ("zabbix_timeout", default 60 s).
- After a password login the session is closed with user.logout.
- single_instance() keeps cron runs of one script from overlapping.
"""

import contextlib
import fcntl
import logging
import os
from typing import Any, Iterator, Optional

import requests

logger = logging.getLogger(__name__)


class ZabbixApiError(Exception):
    """The Zabbix API returned an error or an invalid response."""


class AlreadyRunning(Exception):
    """Another run of the same script still holds the lock."""


class ZabbixApi:
    """Minimal Zabbix JSON-RPC client (Zabbix 6.4+: authentication in the Authorization header)."""

    def __init__(self, cfg: dict) -> None:
        api_base = cfg.get("zabbix_api_base", "/api_jsonrpc.php")
        self.url = cfg["zabbix_host"].rstrip("/") + "/" + api_base.strip("/")
        read_timeout = float(cfg.get("zabbix_timeout", 60))
        self.timeout = (min(10.0, read_timeout), read_timeout)
        self.verify = cfg.get("zabbix_verify_ssl", False)
        self.session = requests.Session()
        self.session.headers["Content-Type"] = "application/json-rpc"
        self._request_id = 0
        self._logged_in = False

        token = cfg.get("zabbix_token")
        if token:
            logger.debug(f"Zabbix API {self.url}: using API token")
            self.session.headers["Authorization"] = f"Bearer {token}"
        else:
            logger.debug(f"Zabbix API {self.url}: logging in as {cfg['zabbix_login']}")
            session_id = self.call("user.login", {"username": cfg["zabbix_login"], "password": cfg["zabbix_pass"]})
            self.session.headers["Authorization"] = f"Bearer {session_id}"
            self._logged_in = True
            logging.info("Zabbix API login successful")

    def call(self, method: str, params: Any) -> Any:
        """Call an API method and return its result; raise ZabbixApiError on an API error."""
        self._request_id += 1
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": self._request_id}
        try:
            response = self.session.post(self.url, json=payload, verify=self.verify, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError) as e:
            raise ZabbixApiError(f"{method}: {e}") from e

        if "error" in data:
            error = data["error"]
            raise ZabbixApiError(f"{method}: {error.get('message')} {error.get('data', '')}".strip())
        result = data.get("result")
        logger.debug(f"Zabbix {method}: {len(result) if isinstance(result, list) else 'ok'} result(s)")
        return result

    def close(self) -> None:
        """Log out after a password login (a token stays valid) and close the HTTP session."""
        try:
            if self._logged_in:
                logging.info("Logging out from Zabbix")
                self.call("user.logout", [])
                self._logged_in = False
        except ZabbixApiError as e:
            logging.warning(f"Zabbix logout failed: {e}")
        finally:
            self.session.close()

    def __enter__(self) -> "ZabbixApi":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


@contextlib.contextmanager
def single_instance(lock_path: str) -> Iterator[None]:
    """Hold an exclusive lock on lock_path; raise AlreadyRunning when another process holds it."""
    handle: Optional[Any] = open(lock_path, "a")
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            raise AlreadyRunning(f"another run holds {lock_path}") from e
        handle.truncate(0)
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        yield
    finally:
        handle.close()
