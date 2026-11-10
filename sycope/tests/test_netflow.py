#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for sycope.netflow: traffic profile export/import with a fake API."""

import copy
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)

from sycope import netflow  # noqa: E402


class FakeSycope:
    """Minimal in-memory model of the NetFlow configuration endpoints."""

    def __init__(self, defs, profiles=(), bindings=()):
        self.defs = {d["typeId"]: dict(d) for d in defs}
        self.profiles = {p["name"]: dict(p, id=f"p{i}") for i, p in enumerate(profiles)}
        self.source = {"id": "src", "config": {"type": "netflow", "trafficProfiles": [dict(b) for b in bindings]}}
        self.writes = []

    def request(self, method, path, payload=None, ok=None):
        if method != "GET":
            self.writes.append((method, path, copy.deepcopy(payload)))
        if path.startswith("netflow/field-defs"):
            return {"data": list(self.defs.values())}
        if method == "POST" and path == "netflow/field-def":
            self.defs[payload["typeId"]] = dict(payload, builtIn=False)
            return None
        if path == "netflow/traffic-profiles":
            return {"data": list(self.profiles.values())}
        if method == "POST" and path == "netflow/traffic-profile":
            p = dict(payload, id=f"p{len(self.profiles)}", sourceType=payload.pop("type"))
            p.pop("type", None)
            self.profiles[p["name"]] = p
            return None
        if method == "PUT" and path.startswith("netflow/traffic-profile/"):
            p = dict(payload, sourceType=payload.get("type"))
            p.pop("type", None)
            self.profiles[p["name"]] = p
            return None
        if path == "config-element/netflow/sources":
            return [self.source]
        if method == "PUT" and path.startswith("config-element/netflow/source/"):
            self.source = payload
            return None
        if path == "netflow/templates":
            return {}
        raise AssertionError(f"unexpected {method} {path}")


BUILTIN = [{"typeId": 205, "name": "dnsQuery", "displayName": "Dns Query", "builtIn": True, "typeCode": 2},
           {"typeId": 118, "name": "dpiAppId", "displayName": "L7 Protocol ID", "builtIn": True, "typeCode": 5}]
CUSTOM = {"typeId": 111, "name": "ixApplication", "displayName": "Ix Application", "builtIn": False,
          "typeCode": 2, "description": "app", "indexed": True, "common": False,
          "dedupExporterStrategy": "FIRST", "dedupConversationStrategy": "FIRST", "defaultValue": None}


def source_system():
    return FakeSycope(BUILTIN + [CUSTOM], profiles=[
        {"name": "Mixed", "fields": [205, 118, 111], "sourceType": "probe",
         "disablePen": False, "icmpEncoding": "STANDARD", "samplingInterval": None}])


def test_export_contains_settings_and_custom_definitions():
    doc = netflow.export_profile(source_system(), "Mixed")
    assert doc["format"] == netflow.PROFILE_FORMAT and doc["profile"]["sourceType"] == "probe"
    by_name = {f["name"]: f for f in doc["fields"]}
    assert by_name["dnsQuery"]["builtIn"] and "definition" not in by_name["dnsQuery"]
    assert by_name["ixApplication"]["definition"]["typeCode"] == 2


def test_import_creates_custom_field_profile_and_binding_then_is_idempotent():
    doc = netflow.export_profile(source_system(), "Mixed")
    target = FakeSycope(BUILTIN)
    res = netflow.import_profile(target, doc, ["10.0.0.5"], log=lambda m: None)
    assert res["profile"] == "created" and not res["skipped"]
    assert target.defs[111]["name"] == "ixApplication"
    assert target.profiles["Mixed"]["sourceType"] == "probe"
    assert sorted(target.profiles["Mixed"]["fields"]) == [111, 118, 205]
    assert {"exporterIp": "10.0.0.5", "trafficProfile": "Mixed"} in target.source["config"]["trafficProfiles"]
    n = len(target.writes)
    res2 = netflow.import_profile(target, doc, ["10.0.0.5"], log=lambda m: None)
    assert res2["profile"] == "unchanged" and len(target.writes) == n


def test_import_matches_by_name_and_never_redefines_a_taken_id():
    doc = netflow.export_profile(source_system(), "Mixed")
    # on the target, dnsQuery has another id and 111 is used by a different field
    target = FakeSycope([dict(BUILTIN[0], typeId=999), BUILTIN[1],
                         {"typeId": 111, "name": "somethingElse", "builtIn": False, "typeCode": 5}])
    res = netflow.import_profile(target, doc, [], log=lambda m: None)
    assert res["skipped"] == ["ixApplication"]
    assert sorted(target.profiles["Mixed"]["fields"]) == [118, 999]
    assert target.defs[111]["name"] == "somethingElse"


def test_dry_run_and_foreign_binding_are_not_changed():
    doc = netflow.export_profile(source_system(), "Mixed")
    target = FakeSycope(BUILTIN + [CUSTOM], bindings=[{"exporterIp": "10.0.0.5", "trafficProfile": "Other"}])
    netflow.import_profile(target, doc, ["10.0.0.5"], dry_run=True, log=lambda m: None)
    assert target.writes == []
    res = netflow.import_profile(target, doc, ["10.0.0.5"], log=lambda m: None)
    assert res["exporters"][0][1].startswith("SKIPPED")
    assert target.source["config"]["trafficProfiles"] == [{"exporterIp": "10.0.0.5", "trafficProfile": "Other"}]
