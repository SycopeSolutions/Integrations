#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for sycope.dashboards: format detection and 3.2 <-> 3.3 conversion."""

import copy
import glob
import json
import os
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)

from sycope import dashboards as d  # noqa: E402
from sycope.scripts import convert_dashboard  # noqa: E402

REPO_DASHBOARDS = sorted(glob.glob(os.path.join(REPO, "*", "dashboards", "*.json")))

W1, W2, DASH = "aaaaaaaa-bbbbbbbb-00000001", "aaaaaaaa-bbbbbbbb-00000002", "aaaaaaaa-bbbbbbbb-000000ff"


def _widget(wid, name, version=38):
    return {
        "id": wid, "name": name, "type": "visualization", "tags": [],
        "visualizationConfig": {"type": "chart", "concreteVisualizationConfig": {"type": "bar"}},
        "data": {"source": {"name": "netflow", "type": "stream"}, "queries": [{"nql": "x", "subpipes": []}]},
        "version": version, "options": {"icon": None, "tags": []},
        "acl": {"owner": "admin", "entityId": wid}, "isSystem": False, "_qbId": wid, "aclEdit": True,
    }


def native_33():
    """A dashboard as Sycope 3.3 stores it: schema 10/38, a frame item and 3.3-only styling."""
    dash = {
        "id": DASH, "name": "Test", "type": "dashboard", "tags": [],
        "dashboardConfig": {"cols": 24, "aspectRatio": 1.7, "dashboardStyles": {"x": 1},
                            "widgetBorder": {"active": True}},
        "items": [
            {"layout": {"id": "l1", "x": 0, "y": 0, "w": 12, "h": 6},
             "config": {"$ref": W1, "_qbId": "q1", "frameStyles": {"active": True}}, "type": "widget"},
            {"layout": {"id": "l2", "x": 12, "y": 0, "w": 12, "h": 6},
             "config": {"$ref": W2, "_qbId": "q2"}, "type": "widget"},
            {"layout": {"id": "l3", "x": 0, "y": 6, "w": 24, "h": 1}, "config": {}, "type": "frame"},
        ],
        "version": 10, "isSystem": False, "entityId": DASH,
        "acl": {"owner": "admin", "privacy": "public", "permissions": [], "entityId": DASH},
    }
    return {"type": "dashboard", "id": DASH, "configs": [dash, _widget(W1, "A"), _widget(W2, "B", 30)]}


def test_detect_format():
    assert d.detect_format(native_33()) == "3.3"
    assert d.detect_format(d.to_32(native_33(), warn=lambda m: None)) == "3.2"
    with pytest.raises(ValueError):
        d.detect_format({"type": "visualization"})


def test_to_32_embeds_widgets_and_strips_33_only_keys():
    warnings = []
    out = d.to_32(native_33(), warn=warnings.append)
    assert "configs" not in out and "id" not in out and "isSystem" not in out and "entityId" not in out
    cfg = out["dashboardConfig"]
    assert "dashboardStyles" not in cfg and "widgetBorder" not in cfg and cfg["aspectRatio"] == 1.7
    assert out["version"] == d.DASH_VERSION_32
    w1, w2, frame = out["items"]
    assert w1["config"]["$ref"] == W1 and w1["config"]["id"] == W1 and w1["config"]["name"] == "A"
    assert "type" not in w1 and "frameStyles" not in w1["config"]
    assert "acl" not in w1["config"] and "isSystem" not in w1["config"]
    assert w1["config"]["version"] == d.WIDGET_VERSION_32      # 38 -> 35
    assert w2["config"]["version"] == 30                         # already 3.2-compatible
    assert w1["config"]["data"]["queries"][0]["subpipes"] == []  # exists in 3.2 too: kept
    assert frame == native_33()["configs"][0]["items"][2]  # frames pass through unchanged
    assert any("lowered" in w for w in warnings)
    assert any("widgetBorder" in w for w in warnings)


def test_to_33_of_33_is_unchanged_and_to_32_of_32_is_unchanged():
    doc = native_33()
    assert d.to_33(doc) == doc
    legacy = d.to_32(doc, warn=lambda m: None)
    assert d.to_32(legacy) == legacy


def test_split_returns_same_widgets_for_both_formats():
    doc = native_33()
    dash33, w33 = d.split(doc)
    dash32, w32 = d.split(d.to_32(doc, warn=lambda m: None))
    assert set(w33) == set(w32) == {W1, W2}
    assert dash33["name"] == dash32["name"] == "Test"


@pytest.mark.parametrize("path", REPO_DASHBOARDS, ids=[os.path.relpath(p, REPO) for p in REPO_DASHBOARDS])
def test_repo_dashboards_are_33_and_survive_round_trip(path):
    with open(path, encoding="utf-8") as fp:
        doc = json.load(fp)
    assert d.detect_format(doc) == "3.3", "dashboards in the repository must use the Sycope 3.3 format"
    legacy = d.to_32(doc, warn=lambda m: None)
    back = d.to_33(legacy, warn=lambda m: None)
    dash_a, wid_a = d.split(doc)
    dash_b, wid_b = d.split(back)
    assert set(wid_a) == set(wid_b)
    for wid in wid_a:
        assert wid_a[wid]["data"] == wid_b[wid]["data"]
        assert wid_a[wid]["visualizationConfig"] == wid_b[wid]["visualizationConfig"]
    assert [i["layout"] for i in dash_a["items"]] == [i["layout"] for i in dash_b["items"]]
    assert dash_a["dashboardConfig"] == dash_b["dashboardConfig"]


def test_cli_writes_converted_copies(tmp_path):
    src = tmp_path / "in"
    src.mkdir()
    (src / "dash.json").write_text(json.dumps(native_33()), encoding="utf-8")
    out = tmp_path / "out"
    assert convert_dashboard.main(["--to", "3.2", str(src / "dash.json"), "-o", str(out)]) == 0
    legacy = json.loads((out / "dash.json").read_text(encoding="utf-8"))
    assert d.detect_format(legacy) == "3.2"
    # refuses to overwrite the input directory
    assert convert_dashboard.main(["--to", "3.2", str(src / "dash.json"), "-o", str(src)]) == 1


def test_import_dashboard_posts_widgets_then_dashboard():
    class FakeApi:
        def __init__(self):
            self.calls = []

        def request(self, method, path, payload=None, ok=None):
            self.calls.append((method, path, copy.deepcopy(payload)))
            if method == "POST" and path == "component":
                return {"id": f"new-{len(self.calls)}"}
            return None

    api = FakeApi()
    did, action, n = d.import_dashboard(api, d.to_32(native_33(), warn=lambda m: None), existing={})
    posts = [c for c in api.calls if c[0] == "POST"]
    assert action == "created" and n == 2 and len(posts) == 3
    dash = posts[-1][2]
    assert dash["type"] == "dashboard" and "id" not in dash["properties"]
    refs = [i["config"].get("$ref") for i in dash["properties"]["items"]]
    assert refs[:2] == ["new-1", "new-3"]  # ids returned by the widget POSTs (each followed by a permissions PUT)
    assert dash["properties"]["items"][2] == native_33()["configs"][0]["items"][2]  # frame kept
