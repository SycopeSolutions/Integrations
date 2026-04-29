# Zabbix Template for Sycope Monitoring

Zabbix external check integration for the **Sycope NTA/Security Analytics** platform.

Sycope collects and analyzes network flow data, providing visibility into traffic patterns, asset discovery, and security alerts. This integration brings that data into Zabbix by querying the Sycope REST API using NQL (Network Query Language) — the same query language used natively in the Sycope UI.

For each monitored host, the script authenticates against the Sycope API, runs targeted NQL queries filtered by the host's IP address, and returns structured JSON results. Zabbix collects these via external checks every 5 minutes and evaluates them against configurable thresholds to generate alerts.

> **Sycope is available as a [free version](https://free.sycope.com/)** supporting up to 5,000 flows/second with no limitations on data sources, subnetworks, or number of monitored hosts. The free version includes threat detection, anomaly detection, and personalized dashboards — making it viable for production use without a license cost. The main differences vs. the paid version are data retention (14 days vs. unlimited), access management (single admin role vs. full RBAC), and performance monitoring availability.

---

## Files

| File | Description |
|---|---|
| `sycope_check.py` | External check script — place in Zabbix ExternalScripts directory |
| `zbx_sycope_monitoring.yaml` | Zabbix 7.x template — import via Configuration → Templates |

---

## Requirements

- Zabbix 7.0+
- Python 3.8+ on the Zabbix server/proxy
- Sycope 3.x with REST API accessible from the Zabbix server
- Zabbix server must be able to reach Sycope on HTTPS (port 443)

---

## Installation

### 1. Deploy the script

```bash
cp sycope_check.py /usr/lib/zabbix/externalscripts/sycope_check.py
chmod 755 /usr/lib/zabbix/externalscripts/sycope_check.py
chown zabbix:zabbix /usr/lib/zabbix/externalscripts/sycope_check.py
```

### 2. Configure credentials

The script reads credentials from `/etc/zabbix/sycope.conf` (preferred) or environment variables.

**Option A — Config file (recommended)**

```bash
cat > /etc/zabbix/sycope.conf << 'EOF'
SYCOPE_USER=admin
SYCOPE_PASSWORD=yourpassword
EOF

chmod 640 /etc/zabbix/sycope.conf
chown root:zabbix /etc/zabbix/sycope.conf
```

The config file uses plain `KEY=VALUE` format. Lines starting with `#` are ignored. Values can optionally be quoted.

**Option B — Environment variables**

Set before running or in the Zabbix server's systemd environment:

```bash
export SYCOPE_USER=admin
export SYCOPE_PASSWORD=yourpassword
```

**Option C — Inline for testing only**

```bash
SYCOPE_USER=admin SYCOPE_PASSWORD=yourpassword python3 sycope_check.py ...
```

> **Note:** The config file is read at script startup via `load_config_file()`. Environment variables set before the script runs take precedence over the config file (`os.environ.setdefault` is used, so existing env vars are never overwritten).

### 3. Import the Zabbix template

In Zabbix: **Data Collection → Templates → Import**

- Browse to `zbx_sycope_monitoring.yaml`
- Check **Update existing** if re-importing after changes
- Click **Import**

### 4. Assign the template to hosts

1. Go to **Data Collection → Hosts → [host] → Templates**
2. Add **Sycope Monitoring**
3. Go to the **Macros** tab and set `{$SYCOPE_IP}` to your Sycope appliance IP
4. Click **Update**

> The script uses `{HOST.IP}` automatically as the monitored IP for all NQL queries — no manual configuration needed per host beyond the `{$SYCOPE_IP}` macro.

---

## Zabbix Macros

All macros can be overridden per-host via **Data Collection → Hosts → [host] → Macros → Inherited and host macros**.

| Macro | Default | Description |
|---|---|---|
| `{$SYCOPE_IP}` | `192.168.1.14` | IP or hostname of the Sycope appliance |
| `{$SYCOPE_ALERT_MINUTES}` | `15` | Lookback window (minutes) for all alert queries |
| `{$SYCOPE_ASSET_DAYS}` | `7` | Lookback window (days) for active services discovery |
| `{$SYCOPE_MATCHED_MINUTES}` | `60` | Lookback window (minutes) for matched/unmatched IP queries |
| `{$SYCOPE_CONN_MINUTES}` | `30` | Lookback window (minutes) for connection count queries |
| `{$SYCOPE_ALERT_WARN}` | `1` | Alert count threshold for WARNING trigger |
| `{$SYCOPE_ALERT_HIGH}` | `5` | Alert count threshold for HIGH trigger |

> **Tip:** Performance latency alerts (`High Server/Client Network Latency`) tend to be infrequent. If those items always show 0, increase `{$SYCOPE_ALERT_MINUTES}` to `1440` (24 hours) on the host level.

---

## Check Types

The script supports the following check types, passed as the second argument:

| Check type | Extra args | Description |
|---|---|---|
| `alert_count` | `<alert_name> <include_client> <minutes>` | Count of a specific named alert |
| `alert_count_msg` | `<alert_name> <include_client> <minutes>` | Same as above, for message text extraction |
| `any_alerts` | `<minutes> [severity]` | All alerts for the host, with severity breakdown |
| `any_alerts_msg` | `<minutes>` | Same as above, for detail text extraction |
| `active_services` | `<days> <disable_nat_ports>` | Active server ports seen on the host |
| `active_services_msg` | `<days> <disable_nat_ports>` | Same, for port list text extraction |
| `matched_ips` | `<minutes> <field>` | Matched/unmatched client/server IP counts |
| `connections` | `<minutes> <field>` | Inbound/outbound connection counts |

All check types return a JSON object. Zabbix items use JSONPath preprocessing to extract individual values.

---

## Template Items

### Visibility
| Item | Key field | Trigger |
|---|---|---|
| Only SYN Client TCP Flag | `$.value` | WARNING > 1, HIGH > 5 |
| Initial Connections from Public IPs | `$.value` | HIGH > 5 |

### Security
| Item | Key field | Trigger |
|---|---|---|
| Horizontal Scan | `$.value` | WARNING > 1, HIGH > 5 |
| Vertical Scan | `$.value` | WARNING > 1, HIGH > 5 |

### Performance
| Item | Key field | Trigger |
|---|---|---|
| High Server Network Latency | `$.value` | WARNING > 1 |
| High Client Network Latency | `$.value` | WARNING > 1 |

### Sycope - Active Alerts
| Item | Key field | Trigger |
|---|---|---|
| Active Alerts (total) | `$.value` | WARNING > 1, HIGH > 5 |
| Active Alerts (critical) | `$.severity_critical` | DISASTER ≥ 1 |
| Active Alerts (high) | `$.severity_high` | HIGH ≥ 1 |
| Active Alerts (medium) | `$.severity_medium` | — |
| Active Alerts (low) | `$.severity_low` | — |
| Active Alerts (info) | `$.severity_info` | — |
| Active Alerts (detail) | `$.message` | — |

### Asset Discovery
| Item | Description |
|---|---|
| Active Services (count) | Number of unique server ports active in last `{$SYCOPE_ASSET_DAYS}` days |
| Active Services (port list) | Port numbers with application names, e.g. `22 (SSH), 443 (HTTPS)` |
| Matched/Unmatched Client/Server Public/Private IPs | 8 distinct counters |
| Private/Public Connections From/To Node | 4 distinct counters |

All items are tagged with `source: sycope` and a `component` tag for easy filtering in Zabbix Latest Data.

---

## Testing

Test the script manually on the Zabbix server. Always use the actual host IP as the third argument.

**Basic connectivity — all alerts with severity breakdown:**
```bash
SYCOPE_USER=admin SYCOPE_PASSWORD=yourpassword \
  python3 /usr/lib/zabbix/externalscripts/sycope_check.py \
  192.168.1.14 any_alerts 10.0.0.5 15
```

Expected output:
```json
{
  "value": 8,
  "severity_critical": 0,
  "severity_high": 0,
  "severity_medium": 8,
  "severity_low": 0,
  "severity_info": 0,
  "message": "Total: 8 | Medium: 8 | Only SYN Client TCP Flag [Medium]: 7 | Unauthorized LLMNR/NetBIOS Activity [Medium]: 1"
}
```

**Specific named alert:**
```bash
SYCOPE_USER=admin SYCOPE_PASSWORD=yourpassword \
  python3 /usr/lib/zabbix/externalscripts/sycope_check.py \
  192.168.1.14 alert_count 10.0.0.5 "Horizontal Scan" true 15
```

**Wider time window for infrequent alerts (24 hours):**
```bash
SYCOPE_USER=admin SYCOPE_PASSWORD=yourpassword \
  python3 /usr/lib/zabbix/externalscripts/sycope_check.py \
  192.168.1.14 alert_count 10.0.0.5 "High Server Network Latency" true 1440
```

**Active services discovery:**
```bash
SYCOPE_USER=admin SYCOPE_PASSWORD=yourpassword \
  python3 /usr/lib/zabbix/externalscripts/sycope_check.py \
  192.168.1.14 active_services 10.0.0.5 7 true
```

**Connection counts:**
```bash
SYCOPE_USER=admin SYCOPE_PASSWORD=yourpassword \
  python3 /usr/lib/zabbix/externalscripts/sycope_check.py \
  192.168.1.14 connections 10.0.0.5 30
```

**Common error responses:**

| Output | Cause |
|---|---|
| `{"error": "SYCOPE_USER or SYCOPE_PASSWORD env vars not set"}` | Config file missing or not readable by zabbix user |
| `{"error": "...SSL..."}` | Certificate issue — SSL verification is disabled by default, check network connectivity |
| `{"value": 0, "message": "Total: 0..."}` | No alerts in time window — try wider window |
| `{"error": "Unknown check_type: ..."}` | Typo in check type argument |

---

## Adding or Modifying NQL Queries

All NQL queries are contained in the `check_*` functions in `sycope_check.py`. Each function follows the same pattern:

1. Build timestamps with `make_timestamps()`
2. Construct the NQL string
3. Call `run_nql()` which handles job polling and pagination automatically
4. Process results and return a dict with at minimum a `value` key

**Example: Adding a check for a new alert type**

The simplest approach requires no code changes — use the existing `alert_count` check type with the alert name as an argument. First discover what alert names exist on a host:

```bash
SYCOPE_USER=admin SYCOPE_PASSWORD=yourpassword \
  python3 sycope_check.py 192.168.1.14 any_alerts 10.0.0.5 1440
```

This returns all alert names seen in the last 24 hours. Once you have the exact name, add it as a dedicated template item in `zbx_sycope_monitoring.yaml`:

```yaml
- uuid: <generate: python3 -c "import uuid; print(uuid.uuid4().hex)">
  name: 'Security - DNS Tunneling'
  type: EXTERNAL
  key: 'sycope_check.py["{$SYCOPE_IP}","alert_count","{HOST.IP}","DNS Tunneling","true","{$SYCOPE_ALERT_MINUTES}"]'
  delay: 5m
  history: 7d
  trends: '0'
  value_type: FLOAT
  preprocessing:
    - type: JSONPATH
      parameters:
        - '$.value'
      error_handler: CUSTOM_VALUE
      error_handler_params: '-1'
  tags:
    - tag: component
      value: security
    - tag: source
      value: sycope
  triggers:
    - uuid: <generate new uuid>
      expression: 'last(/Sycope Monitoring/sycope_check.py["{$SYCOPE_IP}","alert_count","{HOST.IP}","DNS Tunneling","true","{$SYCOPE_ALERT_MINUTES}"])>=1'
      name: 'Sycope: DNS Tunneling detected on {HOST.NAME}'
      priority: HIGH
```

**Example: Custom NQL query in the script**

To add a completely new check type — for example counting unique external IPs communicating with a host — add a new function to `sycope_check.py`:

```python
def check_unique_external_ips(base_url, cookie, ip, last_minutes):
    start_time, end_time = make_timestamps(minutes_back=last_minutes)
    nql = (
        f'src stream="assetNetflowAggr" | serverIp = "{ip}" | '
        f'set privacy=lookup("hosts & subnets", "privacy", {{"cidr": clientIp}}) | '
        f'privacy != "Private" | '
        f'aggr unique_ips=dc(clientIp) unwind=true | limit 1'
    )
    rows = run_nql(base_url, cookie, nql, start_time, end_time)
    count = int(rows[0].get("unique_ips", 0)) if rows else 0
    return {"value": count, "message": f"Unique external IPs: {count}"}
```

Then register it in `main()` before the `else` clause:

```python
elif check_type == "unique_external_ips":
    last_minutes = int(extra[0]) if len(extra) > 0 else 60
    result = check_unique_external_ips(base_url, cookie, monitored_ip, last_minutes)
    print(json.dumps(result))
```

Key rules when writing NQL queries:
- Use f-strings when embedding the `ip` variable: `f'... serverIp = "{ip}" ...'`
- Always call `make_timestamps()` for consistent time window handling
- Use `run_nql()` — it handles job ID polling and result pagination automatically
- Always return a dict with at least a `value` key (numeric) so Zabbix can graph it

---


---

## Disabling Checks for Unlicensed Modules

Sycope is modular — not all installations include every module. If a module is not licensed or enabled, the corresponding NQL queries will return empty results and items will show `0` or `error`. To avoid noise, disable the relevant items on the host.

### Which items belong to which module

| Sycope Module | Template Items |
|---|---|
| **Visibility** | Visibility, Sycope - Active Alerts |
| **Asset Discovery** | Asset Discovery - Active Services, Matched/Unmatched IPs, Connections From/To Node |
| **Performance** | Performance - High Server/Client Network Latency |
| **Security** | Security - Horizontal Scan/Vertical Scan |

### How to disable items in Zabbix

**Per host (recommended)** — disables items only on a specific host without affecting others:

1. Go to **Data Collection → Hosts → [host] → Items**
2. Filter by `sycope` in the search box
3. Select all items you want to disable
4. Click **Mass update → Status → Disabled**

**Per template** — disables items for all hosts using the template:

1. Go to **Data Collection → Templates → Sycope Monitoring → Items**
2. Select the items to disable
3. Click **Mass update → Status → Disabled**

> **Note:** Disabled items are not collected and do not trigger alerts, but they remain in the template and can be re-enabled at any time.

### Disabling entire item groups by tag

Since all items have a `component` tag, you can filter and bulk-disable by component:

1. Go to **Data Collection → Hosts → [host] → Items**
2. Use the **Tags** filter: `component = asset_discovery`
3. Select all → **Mass update → Status → Disabled**

Component tag values used in this template:

| Tag value | Items |
|---|---|
| `visibility` | Only SYN TCP Flag, Initial connections from Public IPs |
| `security` | Horizontal Scan, Vertical Scan |
| `performance` | High Server/Client Network Latency |
| `alerts` | Sycope - Active Alerts (all severity items) |
| `asset_discovery` | Active Services, Matched/Unmatched IPs, Connections |

## Architecture

```
Zabbix Server
  └── External Check (every 5 minutes)
        └── sycope_check.py <sycope_ip> <check_type> <host_ip> [args]
              ├── POST /npm/api/v1/login           → session cookie
              ├── POST /npm/api/v1/pipeline/run    → jobId
              ├── POST /npm/api/v1/pipeline/{id}/data → results (paginated)
              └── GET  /npm/api/v1/logout
```

- Each Zabbix item invocation creates one full login → query → logout cycle
- SSL certificate verification is disabled (`CERT_NONE`) — Sycope typically uses a self-signed certificate
- Pagination is handled automatically by `run_nql()` using the `total` field from the first response
- The script has no persistent state and is safe to run concurrently across multiple hosts

---

## Production Considerations

**API load:** With 4 hosts × 33 items × 5-minute interval, the Zabbix server makes approximately 26 API calls per host per cycle. Each call performs a full login/logout. If Sycope API load becomes a concern, increase intervals for asset discovery items (matched IPs, connections, active services) via their respective macros.

**Credentials security:** Keep `/etc/zabbix/sycope.conf` at `chmod 640` owned by `root:zabbix`. Never pass credentials as Zabbix macro arguments — macros are visible in the Zabbix UI and stored in plaintext in the database.

**Alert name accuracy:** Alert names in NQL queries must exactly match the names defined in Sycope alert templates. Use `any_alerts` with a wide time window to discover the exact names active on a host before creating dedicated items.

**Time window tuning:** The default 15-minute window works well for frequent security alerts. Performance and latency alerts are less frequent — override `{$SYCOPE_ALERT_MINUTES}` to `60` or `1440` at the host level if those items consistently show 0.

**Host IP matching:** The script uses `{HOST.IP}` as the NQL filter IP. If the monitored host uses NAT, has multiple interfaces, or its primary Zabbix IP differs from the IP visible in Sycope traffic, items will return 0. In that case override the IP by adding a custom item key or adjusting the host's Zabbix IP to match what Sycope sees.

**Token expiry:** The Sycope session cookie is created and destroyed on each script invocation — there is no token reuse or caching. This is intentional to keep the script stateless.
