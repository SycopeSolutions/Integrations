"""A Sycope client with its own login must re-authenticate on a 401 (or a redirect to
the login endpoint, Sycope 3.3.1) and retry once, so an expired/dead session
(e.g. a Sycope restart) self-heals instead of silently returning empty reads."""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

import json

from sycope.api import SycopeApi  # noqa: E402


class FakeResponse:
    def __init__(self, status_code, body=None, text=""):
        self.status_code = status_code
        self._body = body
        self.headers = {}
        self.text = text or (json.dumps(body) if body is not None else "")

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    """Serves /login POSTs as successful logins (counted) and every other
    request from a queue."""

    def __init__(self, responses, login_body=None):
        self._queue = list(responses)
        self._login_body = login_body or {"status": 200}
        self.login_count = 0
        self.cookies = {}
        self.requests = []

    def post(self, url, json=None, verify=True, **kw):
        if url.endswith("/login"):
            self.login_count += 1
            return FakeResponse(200, self._login_body)
        self.requests.append(("POST", url))
        return self._queue.pop(0)

    def get(self, url, verify=True, **kw):
        self.requests.append(("GET", url))
        return self._queue.pop(0)

    def put(self, url, json=None, verify=True, **kw):
        self.requests.append(("PUT", url))
        return self._queue.pop(0)

    def delete(self, url, verify=True, **kw):
        self.requests.append(("DELETE", url))
        return self._queue.pop(0)


def _api(session):
    return SycopeApi(session=session, host="https://sycope", login="admin", password="pw")


def test_reauth_on_401_then_retry_succeeds():
    # First GET returns 401 (dead session); after re-login the retry returns data.
    session = FakeSession([
        FakeResponse(401, {"status": 401, "message": "unauthorized"}),
        FakeResponse(200, {"data": [{"id": "1", "config": {"name": "snmp-control"}}]}),
    ])
    api = _api(session)
    assert session.login_count == 1  # initial login in __init__

    result = api.get_lookups()

    assert session.login_count == 2  # re-authenticated exactly once on the 401
    assert result == [{"id": "1", "config": {"name": "snmp-control"}}]


def test_reauth_at_most_once_no_infinite_loop():
    # Session stays dead: 401 then 401 again after re-login -> give up gracefully.
    session = FakeSession([
        FakeResponse(401, {"status": 401}),
        FakeResponse(401, {"status": 401}),
    ])
    api = _api(session)

    result = api.get_lookups()

    assert session.login_count == 2  # one re-auth attempt, then stop
    assert result == []              # graceful empty, no exception, no loop


def test_success_path_does_not_reauth():
    session = FakeSession([FakeResponse(200, {"data": []})])
    api = _api(session)

    api.get_lookups()

    assert session.login_count == 1  # no spurious re-login on a healthy 200


def test_private_client_reauths_on_login_redirect():
    # Sycope 3.3.1 answers a dead session with 302 -> /npm/api/v1/login, which
    # requests follows to a 400 "Invalid username or password".
    redirect = FakeResponse(302)
    redirect.headers = {"Location": "http://sycope/npm/api/v1/login"}
    dead = FakeResponse(400, {"status": 400, "message": "Invalid username or password."})
    dead.history = [redirect, FakeResponse(301)]
    session = FakeSession([dead, FakeResponse(200, {"data": [{"id": "1"}]})])
    api = _api(session)

    assert api.get_lookups() == [{"id": "1"}]
    assert session.login_count == 2


def test_redirect_elsewhere_is_not_an_auth_failure():
    moved = FakeResponse(301)
    moved.headers = {"Location": "https://sycope/npm/api/v1/config-elements"}
    ok = FakeResponse(200, {"data": []})
    ok.history = [moved]
    session = FakeSession([ok])
    api = _api(session)

    api.get_lookups()
    assert session.login_count == 1
