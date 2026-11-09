"""
Helpers for the Sycope NetFlow configuration API used by the Keysight IxFlow integration.

The shared ``sycope.api.SycopeApi`` client handles login, session and NQL queries.
This module adds the endpoints it does not cover yet:

* NetFlow custom field definitions   (``/netflow/field-def``)
* Traffic profiles                   (GUI: Settings -> NetFlow -> Template Based Settings)
* Traffic profile <-> exporter binding (``/config-element/netflow/sources``)
* Received IPFIX templates            (``/netflow/templates``)

All functions take an authenticated ``SycopeApi`` instance as the first argument.
"""

import copy
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from sycope.api import SycopeApi
from sycope.exceptions import SycopeApiError

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------- low level
def request(api: SycopeApi, method: str, path: str, payload: Any = None, ok=(200, 201, 204)) -> Any:
    """Call ``<host><api_base><path>`` and return decoded JSON (or None for an empty body)."""
    return api.request(method, path, payload, ok=ok)


def _data(obj: Any) -> List[Dict[str, Any]]:
    return obj.get("data", []) if isinstance(obj, dict) else (obj or [])


# ----------------------------------------------------------------------------- field definitions
def get_field_defs(api: SycopeApi) -> Dict[int, Dict[str, Any]]:
    """All NetFlow field definitions (built-in and custom) keyed by element id."""
    return {f["typeId"]: f for f in _data(request(api, "GET", "netflow/field-defs?offset=0&limit=10000"))}


def create_field_def(api: SycopeApi, field: Dict[str, Any]) -> None:
    body = {
        "typeId": field["elementId"],
        "name": field["name"],
        "displayName": field["displayName"],
        "description": field["description"],
        "typeCode": field["typeCode"],
        "dedupExporterStrategy": "FIRST",
        "dedupConversationStrategy": "FIRST",
        "common": False,
        "indexed": bool(field.get("indexed")),
        "active": True,
        "defaultValue": None,
    }
    request(api, "POST", "netflow/field-def", body)


def delete_field_def(api: SycopeApi, type_id: int) -> None:
    request(api, "DELETE", f"netflow/field-def/{type_id}")


# ----------------------------------------------------------------------------- traffic profiles
def get_traffic_profiles(api: SycopeApi) -> Dict[str, Dict[str, Any]]:
    return {p["name"]: p for p in _data(request(api, "GET", "netflow/traffic-profiles"))}


def upsert_traffic_profile(api: SycopeApi, name: str, fields: List[int]) -> str:
    """Create the profile or replace its field list. Returns 'created' / 'updated' / 'unchanged'."""
    existing = get_traffic_profiles(api).get(name)
    if existing is None:
        request(api, "POST", "netflow/traffic-profile", {
            "name": name, "fields": fields, "type": "default", "disablePen": False,
            "icmpEncoding": "STANDARD", "samplingInterval": None,
        })
        return "created"
    if sorted(existing.get("fields", [])) == sorted(fields):
        return "unchanged"
    body = {k: v for k, v in existing.items() if k not in ("created", "modified", "modifiedBy")}
    body["fields"] = fields
    body.setdefault("type", body.pop("sourceType", "default"))
    request(api, "PUT", f"netflow/traffic-profile/{existing['id']}", body)
    return "updated"


def delete_traffic_profile(api: SycopeApi, name: str) -> bool:
    existing = get_traffic_profiles(api).get(name)
    if existing is None:
        return False
    request(api, "DELETE", f"netflow/traffic-profile/{existing['id']}")
    return True


# ----------------------------------------------------------------------------- exporters
def get_netflow_source(api: SycopeApi) -> Dict[str, Any]:
    sources = request(api, "GET", "config-element/netflow/sources") or []
    for s in sources:
        if (s.get("config") or {}).get("type") == "netflow":
            return s
    raise SycopeApiError("NetFlow collector source not found (GET config-element/netflow/sources)")


def assign_profile(api: SycopeApi, profile: str, exporter_ips: List[str],
                   remove: bool = False, dry_run: bool = False) -> List[Tuple[str, str]]:
    """Bind (or unbind) a traffic profile to exporter IPs. Returns a list of (ip, action)."""
    src = get_netflow_source(api)
    new = copy.deepcopy(src)
    bindings = new["config"].setdefault("trafficProfiles", [])
    actions = []
    for ip in exporter_ips:
        current = [b for b in bindings if b.get("exporterIp") == ip]
        if remove:
            if any(b.get("trafficProfile") == profile for b in current):
                bindings[:] = [b for b in bindings
                               if not (b.get("exporterIp") == ip and b.get("trafficProfile") == profile)]
                actions.append((ip, "unassigned"))
            continue
        if any(b.get("trafficProfile") == profile for b in current):
            actions.append((ip, "already assigned"))
        elif current:
            # One profile per exporter: report, do not overwrite somebody else's binding.
            actions.append((ip, f"SKIPPED - exporter already uses profile '{current[0].get('trafficProfile')}'"))
        else:
            bindings.append({"exporterIp": ip, "trafficProfile": profile})
            actions.append((ip, "assigned"))
    if new != src and not dry_run:
        request(api, "PUT", f"config-element/netflow/source/{src['id']}", new)
    return actions


def get_templates(api: SycopeApi) -> Dict[str, List[Dict[str, Any]]]:
    """IPFIX templates received by the collector, keyed by exporter IP."""
    return request(api, "GET", "netflow/templates") or {}


# ----------------------------------------------------------------------------- components
# Dashboards, widgets and saved fields: see sycope.dashboards (shared library).
from sycope.dashboards import (  # noqa: E402,F401
    dashboard_names,
    import_dashboard,
    list_components,
    to_component,
    upsert_component,
)


def delete_component(api: SycopeApi, cid: str) -> None:
    request(api, "DELETE", f"component/{cid}")


def load_saved_field(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fp:
        return to_component(json.load(fp))
