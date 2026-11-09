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

## Changes in 2.0.0

- Every request has a timeout: `SycopeApi(..., timeout=(5, 60))` sets (connect, read) seconds. NQL queries wait at least `wait_time` + 30 s.
- An expired session (for example after a Sycope restart) is detected: HTTP 401, or HTTP 400 "Invalid username or password.". The client logs in again and repeats the request once.
- The debug log no longer contains session tokens: cookie values and token/password fields in headers and responses are replaced with `<redacted>`.
- `get_user_indicies()` returns all custom indexes, not only the first page.
- The package exports its main classes and functions: `from sycope import SycopeApi, load_config, ...`.
