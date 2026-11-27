"""Optional SycopeApi hooks: ``auth`` (one shared login for many clients) and
``lookup_cache`` (lookup ids remembered between clients). Without them the
client behaves as before: its own login and no cache."""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from sycope.api import SycopeApi  # noqa: E402
from test_api_reauth import FakeResponse, FakeSession  # noqa: E402


class Cookies(dict):
    def get_dict(self):
        return dict(self)


class CookieSession(FakeSession):
    def __init__(self, responses):
        super().__init__(responses)
        self.cookies = Cookies()


class SharedAuth:
    def __init__(self):
        self.applied = 0
        self.refreshed = []

    def apply(self, session):
        self.applied += 1
        session.cookies["SESSION"] = "shared-1"

    def refresh(self, session, failed=None):
        self.refreshed.append(failed)
        session.cookies["SESSION"] = "shared-2"


class DictCache:
    def __init__(self, ids=None):
        self.ids = dict(ids or {})
        self.privacy = set()

    def get_id(self, name):
        return self.ids.get(name)

    def put_id(self, name, lookup_id):
        self.ids[name] = lookup_id

    def drop_id(self, name):
        self.ids.pop(name, None)

    def privacy_ok(self, lookup_id, privacy):
        return (lookup_id, privacy) in self.privacy

    def set_privacy(self, lookup_id, privacy):
        self.privacy.add((lookup_id, privacy))


def _lookup(lookup_id, name):
    return {"id": lookup_id, "config": {"name": name}}


def test_shared_auth_skips_login_and_refreshes_on_401():
    session = CookieSession([FakeResponse(401, {"status": 401}), FakeResponse(200, {"data": []})])
    auth = SharedAuth()
    api = SycopeApi(session=session, host="https://sycope", login="admin", password="pw", auth=auth)

    assert session.login_count == 0 and auth.applied == 1
    assert api.get_lookups() == []
    # refresh got the cookies that Sycope rejected, then the request was retried once
    assert auth.refreshed == [{"SESSION": "shared-1"}]
    assert session.login_count == 0
    assert len(session.requests) == 2


def test_shared_auth_log_out_does_not_end_the_session():
    session = CookieSession([])
    api = SycopeApi(session=session, host="https://sycope", login="admin", password="pw", auth=SharedAuth())
    assert api.log_out() is None
    assert session.requests == []


def test_cached_lookup_id_skips_listing():
    session = FakeSession([FakeResponse(200, _lookup("42", "hosts"))])
    cache = DictCache({"hosts": "42"})
    api = SycopeApi(session=session, host="https://sycope", login="admin", password="pw", lookup_cache=cache)

    lookup_id, data = api.get_lookup("hosts")
    assert lookup_id == "42" and data["config"]["name"] == "hosts"
    assert session.requests == [("GET", "https://sycope/npm/api/v1/config-element-lookup/csvFile/42")]


def test_stale_cached_id_is_dropped_and_lookups_are_listed():
    session = FakeSession([
        FakeResponse(200, _lookup("42", "other")),                 # cached id now belongs to another lookup
        FakeResponse(200, {"data": [_lookup("77", "hosts")]}),    # full listing
        FakeResponse(200, _lookup("77", "hosts")),                 # GET by the new id
    ])
    cache = DictCache({"hosts": "42"})
    api = SycopeApi(session=session, host="https://sycope", login="admin", password="pw", lookup_cache=cache)

    assert api.get_lookup("hosts")[0] == "77"
    assert cache.ids == {"hosts": "77"}


def test_without_hooks_lookup_is_always_listed():
    session = FakeSession([
        FakeResponse(200, {"data": [_lookup("77", "hosts")]}),
        FakeResponse(200, _lookup("77", "hosts")),
        FakeResponse(200, {"data": [_lookup("77", "hosts")]}),
        FakeResponse(200, _lookup("77", "hosts")),
    ])
    api = SycopeApi(session=session, host="https://sycope", login="admin", password="pw")
    api.get_lookup("hosts")
    api.get_lookup("hosts")
    assert session.login_count == 1
    assert len(session.requests) == 4
