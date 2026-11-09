"""
Sycope dashboard export formats: load, convert and import.

Sycope 3.3 is the default format of the dashboards in this repository. Sycope 3.2
(legacy) uses a different export format; ``to_32()`` converts a 3.3 export so it can
be imported in the 3.2 GUI, and ``import_dashboard()`` imports either format through
the REST API into both versions.

Formats
-------
* **3.2** - one dashboard object; every widget is embedded in ``items[].config``.
* **3.3** - envelope ``{"type": "dashboard", "id", "configs": [dashboard, widget, ...]}``;
  dashboard items only reference widgets: ``{"$ref": <widget id>, "_qbId": <uuid>}``.

Command line: ``python3 -m sycope.scripts.convert_dashboard --help``.
"""

import copy
import json
import logging
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Highest schema versions used by Sycope 3.2.1 (dashboard 9, widget 35).
DASH_VERSION_32 = 9
WIDGET_VERSION_32 = 35

AVAIL_PERMS = ["VIEW", "EDIT", "ADD", "DELETE", "EXECUTE", "MODIFY_OWNERSHIP", "GRANT_PERMISSIONS"]
DEFAULT_STYLE_33 = {"padding": {"top": 4, "bottom": 4, "left": 4, "right": 4}}

DASH_ORDER = ["id", "name", "type", "tags", "createdBy", "modifiedBy", "created", "modified",
              "dashboardConfig", "items", "version", "descriptionDefaultShow", "entitySet",
              "entityType", "annotations", "isSystem", "aclEdit", "entityId", "permissions", "acl"]
WIDGET_ORDER = ["id", "name", "type", "tags", "createdBy", "modifiedBy", "created", "modified",
                "visualizationConfig", "data", "version", "options", "acl", "entitySet",
                "entityType", "annotations", "isSystem", "_qbId", "permissions", "aclEdit"]

# Keys of the component envelope (everything else belongs to the API "properties").
_COMPONENT_META = {
    "id", "name", "type", "tags", "createdBy", "modifiedBy", "created", "modified",
    "entitySet", "entityType", "annotations", "acl", "aclEdit", "permissions",
    "isSystem", "_qbId", "$ref", "entityId", "displayName", "streams",
}

Warn = Callable[[str], None]


def _ordered(obj: Dict[str, Any], order: List[str]) -> Dict[str, Any]:
    out = {k: obj[k] for k in order if k in obj}
    out.update({k: v for k, v in obj.items() if k not in out})
    return out


def _permissions(entity_id: str, entity_type: str) -> Dict[str, Any]:
    return {"entityId": entity_id, "entityType": entity_type, "canAdd": True, "canView": True,
            "canEdit": True, "canDelete": True, "canExecute": True, "canModifyOwner": True,
            "canGrantPermissions": True}


def _acl(src: Optional[Dict[str, Any]], entity_id: str, entity_type: str, owner: str) -> Dict[str, Any]:
    acl = copy.deepcopy(src) if src else {
        "permissions": [{"role": "ROLE_USER", "permissions": []}],
        "privacy": "shared", "owner": owner, "availPerms": AVAIL_PERMS,
        "isOwner": True, "aclEdit": True,
    }
    acl["entityId"] = entity_id
    acl["entityType"] = entity_type
    return acl


# ----------------------------------------------------------------------------- detect / load
def detect_format(doc: Dict[str, Any]) -> str:
    """Return "3.3" or "3.2" for a dashboard export, raise ValueError otherwise."""
    if isinstance(doc, dict) and isinstance(doc.get("configs"), list):
        return "3.3"
    if isinstance(doc, dict) and doc.get("type") == "dashboard" and isinstance(doc.get("items"), list):
        return "3.2"
    raise ValueError("not a Sycope dashboard export (neither 3.2 nor 3.3 format)")


def split(doc: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
    """Return (dashboard, {widget id: widget}) for an export in either format.

    Widgets referenced but not embedded (3.2) are not returned; they must already
    exist on the target system.
    """
    if detect_format(doc) == "3.3":
        dash = next((c for c in doc["configs"] if c.get("type") == "dashboard"), None)
        if dash is None:
            raise ValueError("3.3 export has no dashboard in 'configs'")
        widgets = {c["id"]: c for c in doc["configs"] if c is not dash and c.get("id")}
        return dash, widgets
    widgets = {}
    for item in doc["items"]:
        cfg = item.get("config") or {}
        wid = cfg.get("id") or cfg.get("$ref")
        if wid and _is_embedded(cfg):
            widgets[wid] = cfg
    return doc, widgets


def _is_embedded(cfg: Dict[str, Any]) -> bool:
    """True when an item config carries a full widget definition (not just a reference)."""
    return any(k in cfg for k in ("visualizationConfig", "data", "properties"))


def _is_widget_item(item: Dict[str, Any]) -> bool:
    """Frames and other non-widget items have no widget reference in their config."""
    cfg = item.get("config") or {}
    return bool(cfg.get("$ref") or cfg.get("id"))


def load_dashboard(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fp:
        doc = json.load(fp)
    detect_format(doc)
    return doc


# ----------------------------------------------------------------------------- 3.2 -> 3.3
def to_33(doc: Dict[str, Any], warn: Warn = logger.warning) -> Dict[str, Any]:
    """Convert a 3.2 export to the 3.3 envelope. A 3.3 export is returned unchanged.

    Widget/dashboard schema versions are kept: Sycope 3.3 migrates older schemas
    when it loads them.
    """
    if detect_format(doc) == "3.3":
        return copy.deepcopy(doc)
    dash = copy.deepcopy(doc)
    dash_id = dash.get("id") or (dash.get("acl") or {}).get("entityId") \
        or (dash.get("permissions") or {}).get("entityId") or _new_id()
    dash_acl = dash.get("acl")
    owner = (dash_acl or {}).get("owner") or dash.get("createdBy", "admin")

    widgets, seen, items = [], {}, []
    for idx, item in enumerate(dash["items"]):
        item = copy.deepcopy(item)
        if not _is_widget_item(item):  # frame or other non-widget item
            item.setdefault("style", copy.deepcopy(DEFAULT_STYLE_33))
            items.append(item)
            continue
        cfg = item.get("config") or {}
        wid = cfg.get("id") or cfg.get("$ref")
        if _is_embedded(cfg):
            w = {k: v for k, v in cfg.items() if k != "$ref"}
            w["id"] = wid
            etype = w.get("entityType") or f"COMPONENT.{w.get('type', 'visualization')}"
            if not etype.startswith("COMPONENT."):
                etype = f"COMPONENT.{etype}"
            w["_qbId"] = wid
            w.setdefault("isSystem", False)
            w.setdefault("aclEdit", True)
            base_acl = w.get("acl") or (dash_acl and {k: v for k, v in dash_acl.items()
                                                       if k not in ("entityId", "entityType")})
            w["acl"] = _acl(base_acl, wid, etype, owner)
            if wid not in seen:
                seen[wid] = w
                widgets.append(_ordered(w, WIDGET_ORDER))
            elif seen[wid] != w:
                warn(f"widget {wid} embedded twice with different content; keeping the first")
        else:
            warn(f"item {idx} only references widget {wid}; it must already exist on the target")
        item["config"] = {"$ref": wid, "_qbId": str(uuid.uuid4())}
        item.setdefault("type", "widget")
        item.setdefault("style", copy.deepcopy(DEFAULT_STYLE_33))
        items.append(_ordered(item, ["layout", "config", "type", "style"]))

    dash["items"] = items
    dash["id"] = dash_id
    dash["entityId"] = dash_id
    dash.setdefault("isSystem", False)
    dash.setdefault("aclEdit", True)
    dash["acl"] = _acl(dash_acl, dash_id, "COMPONENT.dashboard", owner)
    if isinstance(dash.get("permissions"), dict):
        dash["permissions"]["entityId"] = dash_id
    dash.setdefault("dashboardConfig", {}).setdefault("dashboardStyles", {})
    return {"type": "dashboard", "id": dash_id, "configs": [_ordered(dash, DASH_ORDER)] + widgets}


# ----------------------------------------------------------------------------- 3.3 -> 3.2 (legacy)
def _widget_to_32(w: Dict[str, Any], wid: str, warn: Warn) -> Dict[str, Any]:
    w = copy.deepcopy(w)
    name = w.get("name", wid)
    for key in ("acl", "aclEdit", "isSystem", "id", "$ref", "_qbId"):
        w.pop(key, None)
    if isinstance(w.get("version"), int) and w["version"] > WIDGET_VERSION_32:
        # Options added in 3.3 stay in the definition; 3.2 ignores keys it does not know.
        warn(f"widget '{name}': schema version {w['version']} lowered to {WIDGET_VERSION_32}; "
             "options introduced in Sycope 3.3 are ignored by 3.2")
        w["version"] = WIDGET_VERSION_32
    etype = w.get("type", "visualization")
    out = {"$ref": wid, "id": wid}
    out.update(w)
    out.setdefault("entitySet", "COMPONENT")
    out.setdefault("entityType", etype)
    out["_qbId"] = wid
    out["permissions"] = _permissions(wid, f"COMPONENT.{etype}")
    return out


def to_32(doc: Dict[str, Any], warn: Warn = logger.warning) -> Dict[str, Any]:
    """Convert a 3.3 export to the 3.2 format (legacy support). A 3.2 export is returned unchanged.

    Widgets are embedded back into ``items[].config``, keys that exist only in 3.3 are
    removed and schema versions are lowered to the 3.2 maximum. Features that 3.2 does
    not have (alternative data source, query sub-pipelines) are dropped with a warning.
    """
    if detect_format(doc) == "3.2":
        return copy.deepcopy(doc)
    dash, widgets = split(doc)
    dash = copy.deepcopy(dash)
    dash_id = dash.get("id") or doc.get("id") or _new_id()

    items = []
    for idx, item in enumerate(dash.get("items", [])):
        item = copy.deepcopy(item)
        if item.get("type") == "widget":
            item.pop("type")
        if isinstance(item.get("config"), dict):
            item["config"].pop("frameStyles", None)  # 3.3 widget frame styling
        if not _is_widget_item(item):  # frame or other non-widget item
            items.append(item)
            continue
        cfg = item.get("config") or {}
        wid = cfg.get("$ref") or cfg.get("id")
        if wid in widgets:
            item["config"] = _widget_to_32(widgets[wid], wid, warn)
        else:
            warn(f"item {idx} references widget {wid} that is not in the export; "
                 "it must already exist on the target")
            item["config"] = {"$ref": wid, "_qbId": cfg.get("_qbId") or str(uuid.uuid4())}
        item.setdefault("style", {"padding": {"top": 0, "bottom": 0, "left": 0, "right": 0}})
        items.append(item)

    for key in ("id", "entityId", "isSystem"):
        dash.pop(key, None)
    cfg = dash.get("dashboardConfig")
    if isinstance(cfg, dict):
        # dashboard/frame/widget styling exists only in 3.3
        for key in ("dashboardStyles", "frameBackground", "frameBorder", "widgetBackground", "widgetBorder"):
            if cfg.pop(key, None) not in (None, {}):
                warn(f"dashboard '{dash.get('name')}': '{key}' styling is not supported by Sycope 3.2 - dropped")
    dash["items"] = items
    if isinstance(dash.get("version"), int) and dash["version"] > DASH_VERSION_32:
        warn(f"dashboard '{dash.get('name')}': schema version {dash['version']} lowered to {DASH_VERSION_32}")
        dash["version"] = DASH_VERSION_32
    dash.setdefault("entitySet", "COMPONENT")
    dash.setdefault("entityType", "dashboard")
    owner = (dash.get("acl") or {}).get("owner") or dash.get("createdBy", "admin")
    dash["acl"] = _acl(dash.get("acl"), dash_id, "COMPONENT.dashboard", owner)
    dash["permissions"] = _permissions(dash_id, "COMPONENT.dashboard")
    dash["aclEdit"] = True
    order = [k for k in DASH_ORDER if k not in ("id", "isSystem", "entityId")]
    return _ordered(dash, order)


def convert(doc: Dict[str, Any], target: str, warn: Warn = logger.warning) -> Dict[str, Any]:
    if target == "3.3":
        return to_33(doc, warn)
    if target == "3.2":
        return to_32(doc, warn)
    raise ValueError(f"unsupported target version {target!r} (use 3.2 or 3.3)")


def _new_id() -> str:
    h = uuid.uuid4().hex
    return f"{h[:8]}-{h[8:16]}-{h[16:24]}"


# ----------------------------------------------------------------------------- API import
def to_component(flat: Dict[str, Any]) -> Dict[str, Any]:
    """Exported object (flat GUI form) -> API component {name, type, tags, properties}."""
    return {
        "name": flat["name"],
        "type": flat["type"],
        "tags": [],
        "properties": {k: copy.deepcopy(v) for k, v in flat.items() if k not in _COMPONENT_META},
    }


def list_components(api, ctype: Optional[str] = None) -> List[Dict[str, Any]]:
    data = api.request("GET", "components?offset=0&limit=2147483647")
    comps = data.get("data", []) if isinstance(data, dict) else (data or [])
    return [c for c in comps if ctype is None or c.get("type") == ctype]


def upsert_component(api, comp: Dict[str, Any], existing: Dict[Tuple[str, str], str],
                     share: bool = True) -> Tuple[str, str]:
    """PUT when a component with the same type and name exists, POST otherwise.

    ``existing`` maps (type, name) -> id and is updated in place. Returns (id, "created"/"updated").
    """
    key = (comp["type"], comp["name"])
    if key in existing:
        cid = existing[key]
        api.request("PUT", f"component/{cid}", comp)
        action = "updated"
    else:
        r = api.request("POST", "component", comp)
        cid = r.get("id") if isinstance(r, dict) else None
        if not cid:
            raise ValueError(f"POST component '{comp['name']}' returned no id: {r!r}")
        existing[key] = cid
        action = "created"
    if share:
        api.request("PUT", f"permissions/COMPONENT.{comp['type']}/{cid}",
                    [{"sid": "ROLE_USER", "perms": ["VIEW"]}])
    return cid, action


def import_dashboard(api, source: Any, existing: Optional[Dict[Tuple[str, str], str]] = None
                     ) -> Tuple[str, str, int]:
    """Import a dashboard export (path or parsed dict, 3.2 or 3.3 format) through the REST API.

    Works with Sycope 3.2 and 3.3. Widgets and the dashboard are matched by type and
    name, so importing again updates them in place. Returns (dashboard id, action, widgets).
    """
    doc = load_dashboard(source) if isinstance(source, str) else source
    if existing is None:
        existing = {(c["type"], c["name"]): c["id"] for c in list_components(api)}
    dash, widgets = split(doc)
    new_ids = {wid: upsert_component(api, to_component(w), existing)[0] for wid, w in widgets.items()}
    comp = to_component(dash)
    items = []
    for item in comp["properties"].get("items", []):
        if not _is_widget_item(item):  # frame or other non-widget item
            items.append(copy.deepcopy(item))
            continue
        ref = (item.get("config") or {}).get("$ref") or (item.get("config") or {}).get("id")
        if ref not in new_ids:
            raise ValueError(f"dashboard '{dash['name']}' references widget {ref} that is not in the export")
        new = {"layout": item["layout"], "config": {"$ref": new_ids[ref], "_qbId": str(uuid.uuid4())}}
        if "style" in item:
            new["style"] = item["style"]
        items.append(new)
    comp["properties"]["items"] = items
    did, action = upsert_component(api, comp, existing)
    return did, action, len(widgets)


def dashboard_names(source: Any) -> Tuple[str, List[str]]:
    """(dashboard name, [widget names]) of an export."""
    doc = load_dashboard(source) if isinstance(source, str) else source
    dash, widgets = split(doc)
    return dash["name"], [w["name"] for w in widgets.values()]
