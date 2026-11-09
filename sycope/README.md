# Sycope API Library

The api.py script serves as a centralized library for custom functions used in integrations with third-party software. It provides a collection of predefined methods to facilitate integrations that do not have dedicated templates available.

## Usage

```python
import requests
from sycope import SycopeApi, load_config, setup_logging, suppress_ssl_warnings

suppress_ssl_warnings()
setup_logging("integration.log")
cfg = load_config("config.json", required_fields=["sycope_host", "sycope_login", "sycope_pass"])

with requests.Session() as session:
    api = SycopeApi(session, cfg["sycope_host"], cfg["sycope_login"], cfg["sycope_pass"])
    rows = api.query_all_results('src stream="netflow" | limit 10',
                                 "@2026-01-01T00:00:00+00:00", "@2026-01-01T01:00:00+00:00")
    api.log_out()
```

## Dashboards (`sycope.dashboards`)

Dashboards in this repository use the Sycope 3.3 export format. The module reads both formats and converts between them:

- `to_32(doc)` - legacy support: converts a 3.3 export so it can be imported in the Sycope 3.2 GUI. It embeds the widgets back into the dashboard, removes keys that exist only in 3.3 and lowers schema versions to the 3.2 maximum (dashboard 9, widget 35).
- `to_33(doc)` - converts an old 3.2 export to the 3.3 format.
- `import_dashboard(api, path)` - imports a file in either format through the REST API into Sycope 3.2 or 3.3, updating widgets and the dashboard in place when they already exist (matched by name).

Command line, from the repository root:

```bash
python3 -m sycope.scripts.convert_dashboard --to 3.2 keysight/dashboards/*.json -o dashboards-3.2/
```

Tests: `python3 -m pytest sycope/tests`.

## Changes in 2.0.0

- Every request has a timeout: `SycopeApi(..., timeout=(5, 60))` sets (connect, read) seconds. NQL queries wait at least `wait_time` + 30 s.
- An expired session (for example after a Sycope restart) is detected: HTTP 401, or HTTP 400 "Invalid username or password.". The client logs in again and repeats the request once.
- The debug log no longer contains session tokens: cookie values and token/password fields in headers and responses are replaced with `<redacted>`.
- `get_user_indicies()` returns all custom indexes, not only the first page. The correctly spelled alias `get_user_indices()` is available.
- The package exports its main classes and functions: `from sycope import SycopeApi, load_config, ...`.
- `SycopeApi.request(method, path, payload)` calls any REST endpoint and returns decoded JSON.
- New module `sycope.dashboards` and command `sycope.scripts.convert_dashboard` (3.3 <-> 3.2 dashboard conversion, API import).
