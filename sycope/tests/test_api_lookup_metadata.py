"""edit_lookup must not wipe a lookup's description / tags set in the Sycope GUI:
writers only build name/types/rows, and a PUT replaces the whole object."""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

import json

import pytest

from sycope.api import SycopeApi, SycopeApiError  # noqa: E402


class FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body
        self.headers = {}
        self.text = json.dumps(body) if body is not None else ""

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    def __init__(self, responses):
        self._queue = list(responses)
        self.cookies = {}
        self.requests = []

    def post(self, url, json=None, verify=True, **kw):
        return FakeResponse(200, {"status": 200})

    def get(self, url, verify=True, **kw):
        self.requests.append(("GET", url, None))
        return self._queue.pop(0)

    def put(self, url, json=None, verify=True, **kw):
        self.requests.append(("PUT", url, json))
        return self._queue.pop(0)


def _api(session):
    return SycopeApi(session=session, host="https://sycope", login="admin", password="pw")


def _payload(**extra):
    p = {"id": "L1", "tags": None,
         "config": {"name": "device-status", "type": "csvFile", "types": ["ip"]},
         "file": {"columns": ["ip"], "rows": [["10.0.0.1"]]}}
    p.update(extra)
    return p


CURRENT = {"config": {"name": "device-status", "description": "Device status"}, "tags": ["T1", "T2"]}
OK = {"status": 200}


def test_description_and_tags_are_carried_over():
    s = FakeSession([FakeResponse(200, CURRENT), FakeResponse(200, OK)])
    payload = _payload()
    _api(s).edit_lookup("L1", payload)
    (m1, u1, _), (m2, _, sent) = s.requests
    assert m1 == "GET" and u1.endswith("/L1?maxRows=1")
    assert m2 == "PUT"
    assert sent["config"]["description"] == "Device status"
    assert sent["tags"] == ["T1", "T2"]
    assert sent["file"]["rows"] == [["10.0.0.1"]]
    assert "description" not in payload["config"] and payload["tags"] is None  # caller's dict untouched


def test_explicit_metadata_is_not_overridden_and_needs_no_get():
    s = FakeSession([FakeResponse(200, OK)])
    p = _payload(tags=["X"])
    p["config"]["description"] = "mine"
    _api(s).edit_lookup("L1", p)
    assert [r[0] for r in s.requests] == ["PUT"]
    assert s.requests[0][2]["tags"] == ["X"] and s.requests[0][2]["config"]["description"] == "mine"


def test_lookup_without_metadata_is_put_unchanged():
    s = FakeSession([FakeResponse(200, {"config": {"name": "x"}, "tags": None}), FakeResponse(200, OK)])
    p = _payload()
    _api(s).edit_lookup("L1", p)
    assert s.requests[1][2] == p


def test_unreadable_lookup_aborts_the_write():
    s = FakeSession([FakeResponse(500, None)])
    with pytest.raises(SycopeApiError):
        _api(s).edit_lookup("L1", _payload())
    assert [r[0] for r in s.requests] == ["GET"]
