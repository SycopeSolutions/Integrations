"""
Sycope NetFlow configuration through the REST API.

* NetFlow field definitions            (``/netflow/field-def``)
* Traffic profiles                     (GUI: Settings -> NetFlow -> Template Based Settings)
* Traffic profile <-> exporter binding (``/config-element/netflow/sources``)
* Received IPFIX/NetFlow templates     (``/netflow/templates``)
* Export / import of a traffic profile as a portable JSON file (``export_profile``,
  ``import_profile``; command line: ``python3 -m sycope.scripts.traffic_profile``)

Sycope identifies NetFlow fields by element id only (the enterprise number is ignored),
so an element id can be defined once per system. Imports therefore resolve fields by
name first and never redefine an id that another field already uses.

All functions take an authenticated ``SycopeApi`` instance as the first argument.
"""

import copy
import json
import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .exceptions import SycopeApiError

logger = logging.getLogger(__name__)

PROFILE_FORMAT = "sycope-traffic-profile"
PROFILE_FORMAT_VERSION = 1
PROFILE_SETTINGS = ("disablePen", "icmpEncoding", "samplingInterval")
FIELD_DEF_KEYS = ("typeCode", "description", "indexed", "common", "dedupExporterStrategy",
                  "dedupConversationStrategy", "defaultValue")

Log = Callable[[str], None]


def _data(obj: Any) -> List[Dict[str, Any]]:
    return obj.get("data", []) if isinstance(obj, dict) else (obj or [])


# ----------------------------------------------------------------------------- field definitions
def get_field_defs(api) -> Dict[int, Dict[str, Any]]:
    """All NetFlow field definitions (built-in and custom) keyed by element id."""
    return {f["typeId"]: f for f in _data(api.request("GET", "netflow/field-defs?offset=0&limit=10000"))}


def create_field_def(api, field: Dict[str, Any]) -> None:
    """Create a custom NetFlow field. ``field`` uses Sycope keys (typeId, name, ...);
    ``elementId`` is accepted as an alias of ``typeId``."""
    body = {
        "typeId": field.get("typeId", field.get("elementId")),
        "name": field["name"],
        "displayName": field.get("displayName") or field["name"],
        "description": field.get("description") or "",
        "typeCode": field["typeCode"],
        "dedupExporterStrategy": field.get("dedupExporterStrategy", "FIRST"),
        "dedupConversationStrategy": field.get("dedupConversationStrategy", "FIRST"),
        "common": bool(field.get("common", False)),
        "indexed": bool(field.get("indexed")),
        "active": True,
        "defaultValue": field.get("defaultValue"),
    }
    api.request("POST", "netflow/field-def", body)


def delete_field_def(api, type_id: int) -> None:
    api.request("DELETE", f"netflow/field-def/{type_id}")


# ----------------------------------------------------------------------------- traffic profiles
def get_traffic_profiles(api) -> Dict[str, Dict[str, Any]]:
    return {p["name"]: p for p in _data(api.request("GET", "netflow/traffic-profiles"))}


def upsert_traffic_profile(api, name: str, fields: List[int], source_type: str = "default",
                           settings: Optional[Dict[str, Any]] = None) -> str:
    """Create the profile or update its fields/type/settings.

    Returns 'created', 'updated' or 'unchanged'. ``source_type`` is the GUI "Source type"
    (for example ``default`` or ``probe``); the API calls it ``type`` on write and
    ``sourceType`` on read.
    """
    settings = {k: v for k, v in (settings or {}).items() if k in PROFILE_SETTINGS}
    wanted = {"disablePen": False, "icmpEncoding": "STANDARD", "samplingInterval": None}
    wanted.update(settings)
    existing = get_traffic_profiles(api).get(name)
    if existing is None:
        api.request("POST", "netflow/traffic-profile", dict(name=name, fields=fields, type=source_type, **wanted))
        return "created"
    same = (sorted(existing.get("fields", [])) == sorted(fields)
            and existing.get("sourceType", "default") == source_type
            and all(existing.get(k) == v for k, v in wanted.items()))
    if same:
        return "unchanged"
    body = {k: v for k, v in existing.items() if k not in ("created", "modified", "modifiedBy", "sourceType")}
    body.update(fields=fields, type=source_type, **wanted)
    api.request("PUT", f"netflow/traffic-profile/{existing['id']}", body)
    return "updated"


def delete_traffic_profile(api, name: str) -> bool:
    existing = get_traffic_profiles(api).get(name)
    if existing is None:
        return False
    api.request("DELETE", f"netflow/traffic-profile/{existing['id']}")
    return True


# ----------------------------------------------------------------------------- exporters
def get_netflow_source(api) -> Dict[str, Any]:
    for s in api.request("GET", "config-element/netflow/sources") or []:
        if (s.get("config") or {}).get("type") == "netflow":
            return s
    raise SycopeApiError("NetFlow collector source not found (GET config-element/netflow/sources)")


def profile_exporters(api, profile: str) -> List[str]:
    """Exporter IPs bound to a traffic profile."""
    return [b["exporterIp"] for b in get_netflow_source(api)["config"].get("trafficProfiles", [])
            if b.get("trafficProfile") == profile]


def assign_profile(api, profile: str, exporter_ips: Iterable[str],
                   remove: bool = False, dry_run: bool = False) -> List[Tuple[str, str]]:
    """Bind (or unbind) a traffic profile to exporter IPs. Returns a list of (ip, action).

    An exporter can use one profile; an exporter bound to another profile is reported
    and left unchanged.
    """
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
            actions.append((ip, f"SKIPPED - exporter already uses profile '{current[0].get('trafficProfile')}'"))
        else:
            bindings.append({"exporterIp": ip, "trafficProfile": profile})
            actions.append((ip, "assigned" if not dry_run else "would be assigned"))
    if new != src and not dry_run:
        api.request("PUT", f"config-element/netflow/source/{src['id']}", new)
    return actions


def get_templates(api) -> Dict[str, List[Dict[str, Any]]]:
    """Templates received by the collector, keyed by exporter IP."""
    return api.request("GET", "netflow/templates") or {}


# ----------------------------------------------------------------------------- export / import
def export_profile(api, name: str) -> Dict[str, Any]:
    """Portable description of a traffic profile: settings plus every field, with the full
    definition of custom fields (built-in fields exist on every Sycope)."""
    profile = get_traffic_profiles(api).get(name)
    if profile is None:
        raise ValueError(f"traffic profile '{name}' not found")
    defs = get_field_defs(api)
    fields = []
    for type_id in profile.get("fields", []):
        f = defs.get(type_id)
        if f is None:
            raise ValueError(f"profile '{name}' references unknown field id {type_id}")
        entry = {"typeId": type_id, "name": f["name"], "displayName": f.get("displayName"),
                 "builtIn": bool(f.get("builtIn"))}
        if not entry["builtIn"]:
            entry["definition"] = {k: f.get(k) for k in FIELD_DEF_KEYS}
        fields.append(entry)
    return {
        "format": PROFILE_FORMAT,
        "formatVersion": PROFILE_FORMAT_VERSION,
        "profile": {"name": profile["name"], "sourceType": profile.get("sourceType", "default"),
                    **{k: profile.get(k) for k in PROFILE_SETTINGS}},
        "fields": fields,
    }


def load_profile(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fp:
        doc = json.load(fp)
    if doc.get("format") != PROFILE_FORMAT:
        raise ValueError(f"{path} is not a Sycope traffic profile export (format '{PROFILE_FORMAT}')")
    return doc


def import_profile(api, doc: Dict[str, Any], exporter_ips: Iterable[str] = (), name: Optional[str] = None,
                   dry_run: bool = False, log: Log = logger.info) -> Dict[str, Any]:
    """Create or update a traffic profile from ``export_profile()`` output.

    * Fields are matched by name on the target system (element ids may differ between
      Sycope versions). A missing custom field is created with its exported definition,
      unless its element id is already used by another field (reported, skipped).
      A missing built-in field is reported and skipped.
    * The profile gets the exported source type and settings.
    * Exporters are bound unless they already use another profile.

    Returns {"profile": state, "fields": [ids], "skipped": [names], "exporters": [(ip, action)]}.
    """
    profile = doc["profile"]
    name = name or profile["name"]
    defs = get_field_defs(api)
    by_name = {f["name"]: tid for tid, f in defs.items()}
    ids, skipped = [], []
    for f in doc.get("fields", []):
        if f["name"] in by_name:
            ids.append(by_name[f["name"]])
            continue
        if f.get("builtIn"):
            log(f"  field {f['name']}: built-in field not available on this Sycope version - skipped")
            skipped.append(f["name"])
            continue
        clash = defs.get(f["typeId"])
        if clash is not None:
            log(f"  field {f['name']}: element id {f['typeId']} already used by '{clash['name']}' - skipped")
            skipped.append(f["name"])
            continue
        if not dry_run:
            create_field_def(api, dict(f["definition"], typeId=f["typeId"], name=f["name"],
                                       displayName=f.get("displayName")))
        log(f"  field {f['name']} ({f['typeId']}): {'would be created' if dry_run else 'created'}")
        ids.append(f["typeId"])

    settings = {k: profile.get(k) for k in PROFILE_SETTINGS if k in profile}
    if dry_run:
        state = "exists" if name in get_traffic_profiles(api) else "would be created"
    else:
        state = upsert_traffic_profile(api, name, ids, profile.get("sourceType", "default"), settings)
    log(f"  traffic profile '{name}' ({profile.get('sourceType', 'default')}, {len(ids)} fields): {state}")

    exporters = list(exporter_ips)
    actions: List[Tuple[str, str]] = []
    if exporters:
        if dry_run and state == "would be created":
            actions = [(ip, "would be assigned") for ip in exporters]
        else:
            actions = assign_profile(api, name, exporters, dry_run=dry_run)
        for ip, action in actions:
            log(f"  exporter {ip}: {action}")
    return {"profile": state, "fields": ids, "skipped": skipped, "exporters": actions}


def check_exporter(api, doc: Dict[str, Any], exporter: str) -> Dict[str, Any]:
    """Compare what an exporter actually sends with a profile export.

    Returns {"templates": n, "bound_profile": name or None, "sent": [names], "not_sent": [names]}.
    """
    profile = doc["profile"]["name"]
    bound = [b.get("trafficProfile") for b in get_netflow_source(api)["config"].get("trafficProfiles", [])
             if b.get("exporterIp") == exporter]
    templates = get_templates(api).get(exporter, [])
    seen = {fd.get("name") for t in templates for fd in t.get("fieldDefs", [])}
    template_ids = {t.get("templateId") for t in templates}
    names = [f["name"] for f in doc.get("fields", [])]
    return {
        "profile": profile,
        "bound_profile": bound[0] if bound else None,
        "templates": len(template_ids),
        "sent": [n for n in names if n in seen],
        "not_sent": [n for n in names if n not in seen],
    }


def field_fill(api, exporter: str, field_names: List[str], minutes: int = 15) -> Dict[str, Any]:
    """Number of flows from ``exporter`` in the last ``minutes`` and how many have each field.

    Sycope merges the same session seen by several exporters into one record, so the
    aggregation key is the list of exporter IPs; every group containing ``exporter`` counts.
    Returns {"total": n, "fields": {name: count}}.
    """
    import datetime

    fmt = "@%Y-%m-%dT%H:%M:%S+00:00"
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(minutes=minutes)).strftime(fmt)
    agg = ", ".join(f"f{i}=count({n})" for i, n in enumerate(field_names))
    nql = f'src stream="netflow" | aggr total=count(timestamp){", " + agg if agg else ""} by exporterIps'
    totals: Dict[str, int] = {}
    for row in api.query_all_results(nql, start, now.strftime(fmt)):
        key = row.get("exporterIps", row.get("_id"))
        while isinstance(key, list) and len(key) == 1 and isinstance(key[0], list):
            key = key[0]
        if exporter in (key if isinstance(key, list) else [key]):
            for k, v in row.items():
                if isinstance(v, (int, float)):
                    totals[k] = totals.get(k, 0) + v
    return {"total": int(totals.get("total", 0)),
            "fields": {n: int(totals.get(f"f{i}", 0)) for i, n in enumerate(field_names)}}
