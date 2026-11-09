"""
Helpers for the Sycope NetFlow configuration API used by the Keysight IxFlow integration.

The shared ``sycope.api.SycopeApi`` client handles login, session and NQL queries.
This module adds the endpoints it does not cover yet:

* NetFlow custom field definitions   (``/netflow/field-def``)
* Traffic profiles                   (GUI: Settings -> NetFlow -> Template Based Settings)
* Traffic profile <-> exporter binding (``/config-element/netflow/sources``)
* Received IPFIX templates            (``/netflow/templates``)
* Components: dashboards, widgets, saved fields (``/component``)

All functions take an authenticated ``SycopeApi`` instance as the first argument.
"""

import copy
import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sycope.api import SycopeApi
from sycope.exceptions import SycopeApiError

logger = logging.getLogger(__name__)

# Keys that belong to the component envelope, not to ``properties``.
_COMPONENT_META = {
    "id", "name", "type", "tags", "createdBy", "modifiedBy", "created", "modified",
    "entitySet", "entityType", "annotations", "acl", "aclEdit", "permissions",
    "isSystem", "_qbId", "$ref", "entityId", "displayName", "streams",
}


# ----------------------------------------------------------------------------- low level
def request(api: SycopeApi, method: str, path: str, payload: Any = None, ok=(200, 201, 204)) -> Any:
    """Call ``<host><api_base><path>`` and return decoded JSON (or None for an empty body)."""
    url = f"{api.host}{api.api_endpoint}{path.lstrip('/')}"
    if method in ("POST", "PUT") and not isinstance(payload, dict):
        # SycopeApi._make_request only accepts dict payloads; send lists directly.
        logger.debug(f"{method} {url} (list payload)")
        resp = getattr(api.session, method.lower())(url, json=payload, verify=False,
                                                  timeout=getattr(api, "timeout", (5, 60)))
    else:
        resp = api._make_request(method, url, json_payload=payload, operation_name=f"{method} {path}")
    if resp.status_code not in ok:
        raise SycopeApiError(
            f"{method} {path} failed with HTTP {resp.status_code}: {resp.text[:500]}",
            status_code=resp.status_code,
        )
    text = resp.text
    if not text:
        return None
    try:
        return resp.json()
    except ValueError:
        return text


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
def list_components(api: SycopeApi, ctype: Optional[str] = None) -> List[Dict[str, Any]]:
    comps = _data(request(api, "GET", "components?offset=0&limit=2147483647"))
    return [c for c in comps if ctype is None or c.get("type") == ctype]


def _to_component(flat: Dict[str, Any]) -> Dict[str, Any]:
    """GUI export (flat) -> API component {name, type, tags, properties}."""
    return {
        "name": flat["name"],
        "type": flat["type"],
        "tags": [],
        "properties": {k: copy.deepcopy(v) for k, v in flat.items() if k not in _COMPONENT_META},
    }


def upsert_component(api: SycopeApi, comp: Dict[str, Any],
                     existing: Dict[Tuple[str, str], str]) -> Tuple[str, str]:
    """PUT when a component of the same type+name exists, POST otherwise. Returns (id, action)."""
    key = (comp["type"], comp["name"])
    if key in existing:
        cid = existing[key]
        request(api, "PUT", f"component/{cid}", comp)
        action = "updated"
    else:
        r = request(api, "POST", "component", comp)
        cid = r.get("id") if isinstance(r, dict) else None
        if not cid:
            raise SycopeApiError(f"POST component '{comp['name']}' returned no id: {r!r}")
        existing[key] = cid
        action = "created"
    # make it visible to all users (same as the GUI "Share" default)
    request(api, "PUT", f"permissions/COMPONENT.{comp['type']}/{cid}",
            [{"sid": "ROLE_USER", "perms": ["VIEW"]}])
    return cid, action


def delete_component(api: SycopeApi, cid: str) -> None:
    request(api, "DELETE", f"component/{cid}")


# ----------------------------------------------------------------------------- dashboard files
def load_dashboard_file(path: str) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
    """Read a dashboard export in either format.

    * Sycope 3.2: one dashboard object, widgets embedded in ``items[].config``.
    * Sycope 3.3: ``{"type": "dashboard", "configs": [dashboard, widget, ...]}``.

    Returns (dashboard, {widget_id: widget}) - all objects in flat GUI-export form.
    """
    with open(path, encoding="utf-8") as fp:
        doc = json.load(fp)
    if "configs" in doc:
        dash = next(c for c in doc["configs"] if c.get("type") == "dashboard")
        widgets = {c["id"]: c for c in doc["configs"] if c.get("type") != "dashboard"}
    else:
        dash = doc
        widgets = {it["config"].get("$ref") or it["config"]["id"]: it["config"] for it in doc["items"]}
    return dash, widgets


def import_dashboard(api: SycopeApi, path: str, existing: Dict[Tuple[str, str], str]) -> Tuple[str, str, int]:
    """Create/update all widgets of an exported dashboard, then the dashboard itself.

    Components are matched by type + name, so re-running the import updates them in place.
    Returns (dashboard id, action, widget count).
    """
    dash, widgets = load_dashboard_file(path)
    new_ids = {}
    for wid, w in widgets.items():
        new_ids[wid], _ = upsert_component(api, _to_component(w), existing)
    comp = _to_component(dash)
    items = []
    for it in comp["properties"].get("items", []):
        ref = it["config"].get("$ref") or it["config"].get("id")
        items.append({
            "layout": it["layout"],
            "config": {"$ref": new_ids[ref], "_qbId": str(uuid.uuid4())},
            **({"style": it["style"]} if "style" in it else {}),
        })
    comp["properties"]["items"] = items
    did, action = upsert_component(api, comp, existing)
    return did, action, len(widgets)


def dashboard_widget_names(path: str) -> Tuple[str, List[str]]:
    dash, widgets = load_dashboard_file(path)
    return dash["name"], [w["name"] for w in widgets.values()]


def load_saved_field(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fp:
        return _to_component(json.load(fp))
