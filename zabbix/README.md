# Zabbix Integration with Sycope

This directory contains two complementary integrations between Zabbix and Sycope, covering both directions of data flow.

- **Zabbix → Sycope:** scripts that send Zabbix monitoring statistics and inventory data to a custom index and a dedicated Lookup in Sycope.
- **Sycope → Zabbix:** a Zabbix template that shows Sycope statistics and alerts in Zabbix.

> **Sycope is available as a [free version](https://free.sycope.com/)** supporting up to 5,000 flows/second with no limitations on data sources, subnetworks, or number of monitored hosts. The free version includes threat detection, anomaly detection, and personalized dashboards — making it viable for production use without a license cost. The main differences vs. the paid version are data retention (14 days vs. unlimited), access management (single admin role vs. full RBAC), and probes monitoring availability.

## Zabbix Statistics & Inventory Sync

**Direction: Zabbix → Sycope**

This integration enables sending monitoring statistics and inventory data from Zabbix to a custom index and dedicated Lookup in **Sycope** for further correlation, search, and visualization.

An example of the Zabbix Statistics Dashboard

<img width="1870" alt="image" src="https://github.com/user-attachments/assets/4c16e0d5-91c2-41a4-8a9a-877e06085b30" />


An example of the Zabbix Inventory Dashboard

<img width="1865" alt="image" src="https://github.com/user-attachments/assets/44f602c4-821e-478b-88c3-15aa4e256f73" />

---

## Sycope Monitoring Template for Zabbix

**Direction: Sycope → Zabbix**

Bring Sycope's network visibility, security alerts, and asset discovery data directly into Zabbix — without any additional middleware, lookup services, or data pipeline. The template uses only the **Sycope REST API and NQL** to query traffic and alert data for each monitored host.

This means you get Sycope's deep network intelligence — scan detection, anomaly alerts, passive port discovery, connection profiling — surfaced as native Zabbix items, triggers, graphs, and dashboards, fully integrated with your existing Zabbix monitoring workflow.

### What's included

- **33 monitoring items** per host covering security alerts, performance, visibility, asset discovery, and active alert severity breakdown
- **Built-in graphs** with trigger threshold lines for Security Alerts, Performance Alerts, Connections, Matched IPs, and Active Services
- **Triggers** with configurable WARNING and HIGH thresholds, plus DISASTER trigger for critical severity alerts
- **Multi-host dashboard** importable via Zabbix API script
- **No agent, no SNMP, no port scanning** — all data is collected passively via NQL queries

### Screenshots

**All Sycope monitoring items collected per host, tagged and filterable by `source: sycope`:**

<img width="1921" height="1170" alt="Zabbix - All Sycope monitoring items copy" src="https://github.com/user-attachments/assets/0f19fc9f-0140-4f6d-a544-79f5976ab3c5" />

**Custom dashboard with live security KPIs, alert graphs, connection trends, and performance monitoring:**

<img width="1920" height="860" alt="Zabbix - Create custom dashboard using statistics and alerts from Sycope" src="https://github.com/user-attachments/assets/8bcf7bfb-7656-4168-aab1-c7bdc3aad9ef" />

See [template folder](https://github.com/SycopeSolutions/Integrations/tree/main/zabbix/template) for full documentation.

---

## Components

The integrations consists of :

1. **Sycope** - Receives data through the REST API
2. **Zabbix** - Provides statistics and inventory data using active monitoring and REST API
3. **Integration Scripts** - Python-based scripts for synchronizing all the data from Zabbix to Sycope
4. **Dashboards** - Ready to use dashboards for presenting data from Zabbix in Sycope
5. **Fields** - Custom fields for different Zabbix inventory data used in Sycope
6. **Drilldowns** - Ad hoc drilldown actions for Sycope such as hyperlinks and inventory data

> **Scripts can be executed on the same host as Zabbix. Due to permissions and other limitations, please do not run them on Sycope Appliance.**

---

## How the Integrations works

The `zabbix_statistics_sync.py` script:

- Logs in to the Zabbix API and collects metrics for defined IP addresses
- Aligns timestamps for different metrics - `CPU Load, ICMP Reponse Time, Memory Usage and Packet Loss`
- Compares gathered metric with already available metrics in Sycope's custom index to avoid duplicate samples
- Saves the difference in Sycope

The `zabbix_lookup_sync.py` script:

- Logs in to the Zabbix API and collects inventory data such as Hostname, OS version, Serial number, Notes and URLs
- Compares gathered inventory data with already available custom Lookup to avoid duplicate records
- Saves the difference in Sycope

---

## Repository Content

```
.
├── template/               # Sycope Monitoring Template for Zabbix (Sycope → Zabbix)
│   ├── sycope_check.py              # External check script for Zabbix
│   └── zbx_sycope_monitoring.yaml   # Zabbix 7.x template
├── dashboards                       # Optional dashboards to import into Sycope
├── drilldowns                       # Optional drilldown action to import into Sycope
├── fields                           # Optional custom fields to import into Sycope
├── config.json                      # Configuration file
├── install.py                       # Creates the custom index, imports fields, drilldowns and dashboards
├── uninstall.py                     # Optional cleanup for custom indexes and custom Lookups
├── zabbix_statistics_sync.py        # Main processing script for synchronizing metrics data
├── zabbix_lookup_sync.py            # Main processing script for synchronizing inventory data
```

---

## Requirements

- Python 3.8+
- Zabbix 7.0+
- Sycope >= 3.1 with API access
- Tested with Zabbix 7.0.5 and Sycope 3.3.1, Python 3.10 and 3.15, polars 1.32 and 2.1
- `requests` module:
  ```bash
  pip3 install requests
  ```
- `polars` module:
  ```bash
  pip3 install polars
  ```
  
---

##  User & Role Setup in Sycope

After creating new index, add a dedicated user and role in Sycope for log ingestion:

1. **Create a Role**  
   Go to **Configuration → Roles**, create a role (e.g., `ZabbixInject`) with:
   - Permission to inject data only into custom indexes

2. **Create a User**  
   Go to **Configuration → Users**, create a user (e.g., `zabbix_ingestor`) and assign the above role.

---

##  Installation

```bash
git clone https://github.com/SycopeSolutions/Integrations.git
cd Integrations/zabbix
pip3 install -r requirements.txt
# edit config.json (see below)
python3 install.py --dry-run     # shows what would be created or updated, changes nothing
python3 install.py               # Sycope 3.3
python3 install.py --sycope-3.2  # Sycope 3.2 (legacy): dashboards converted to the 3.2 format first
```

`install.py` creates the `ZabbixStats` index (an existing index is left unchanged), then imports through the API the saved fields (`fields/`), the drilldown widget and shortcut (`drilldowns/`) and the dashboards (`dashboards/`). Objects are matched by name, so running it again updates them in place. Options: `--skip-fields`, `--skip-drilldowns`, `--skip-dashboards`.

---

##  Configuration (`config.json`)

```jsonc
{
    // URL of the Zabbix API endpoint (HTTPS strongly recommended)
    "zabbix_host": "https://zabbix.example.com",

    // Additional part of the Zabbix API endpoint
    "zabbix_api_base": "/api_jsonrpc.php",

    // Zabbix API user
    "zabbix_login": "Admin",

    // Password for the above API user
    "zabbix_pass": "",

    // URL of the Sycope API endpoint (HTTPS strongly recommended)
    "sycope_host": "https://sycope.example.com",

    // Additional part of the Sycope API endpoint
    "api_base": "/npm/api/v1/",

    // Sycope API user (must have rights to inject data into custom indexes)
    "sycope_login": "admin",

    // Password for the above API user
    "sycope_pass": "",

    // Name of the Lookup in Sucope (for inventory data synchronization)
    "lookup_name": "integration-zabbix",

    // Name of the custom index defined in Sycope (for statistics)
    "index_name": "ZabbixStats",

    // Custom index rotation
    "index_rotation": "daily",

    // Custom index time period (amount of data to be synchronized)
    // Script will check for duplicate data and will not save it twice
    "period_minutes": 120

    // Examples for IPs to be synchronized
    // The Zabbix API is quite fast, allowing you to synchronize all IPs;
    // however, it may be wise to consider limiting them for efficiency or control.
    "target_ips": [
      "192.0.2.1",
      "192.0.2.2"
    ]
}

```

>  JSON does not support comments natively — this format is shown for documentation purposes only. Use a standard `config.json` file without comments in production.

---

##  Script Usage

| Script                    | Purpose                                    | Example                                             |
|---------------------------|--------------------------------------------|-----------------------------------------------------|
| **install.py**            | Create index, import fields, drilldowns and dashboards | `python3 install.py [--sycope-3.2]`       |
| **zabbix_lookup_sync.py** | Synchronization of the Inventory data      | `python3 zabbix_lookup_sync.py` (e.g., via systemd) |
| **zabbix_statistics.py**  | Synchronization of the Statistics data     | `python3 zabbix_statistics.py` (e.g., via systemd)  |

---

##  Running the Script

Run manually:
```bash
python3 zabbix_lookup_sync.py
python3 zabbix_statistics.py
```
Or run as a service (recommended)

---

##  Notes

- The script requires a valid custom index in Sycope with matching column definitions.
- Running the script on the Sycope appliance is not supported due to security isolation.
- Each index in Sycope has a **retention period**. Set it in **Settings → Indices → Retention** according to your storage policy.

---

##  Dashboard Import

`install.py` imports the dashboards, fields and drilldowns. The steps below are only needed for a manual import from the GUI.

1. In Sycope UI, go to **Dashboards → Add dashboard ▾ → Import dashboard**
2. Upload `dashboards/zabbix_statistics_dashboard.json`, click **Save and close**
3. Repeat for `dashboards/zabbix_inventory.json`

**Sycope 3.2 (legacy):** the files use the Sycope 3.3 export format. Convert them first, then import the converted files from the GUI. Run the command from the repository root:

```bash
python3 -m sycope.scripts.convert_dashboard --to 3.2 zabbix/dashboards/*.json -o zabbix/dashboards-3.2
```

Then import the files from `zabbix/dashboards-3.2/`.

##  Fields Import

1. In Sycope UI, go to **Settings → Objects → Fields → Add field ▾ → Import field**
2. Upload a file from `fields/` (for example `field_zabbix_graph_url.json`). The field opens in the editor; click **Save**.
3. Repeat for the other files in `fields/`

##  Drilldown Import

Import the widget first, because the shortcut points to it:

1. **Configuration → Widgets → Add widget ▾ → Import widget**: upload `drilldowns/zabbix_inventory_drilldown_widget.json` and save it
2. **Configuration → Shortcuts → Add shortcut ▾ → Import shortcut**: upload `drilldowns/zabbix_inventory_drilldown_action.json`, check that **Widget** is set to *Zabbix Inventory - Drilldown*, and save it

The field, widget and shortcut files work in Sycope 3.2 and 3.3 without conversion. GUI import was checked on 3.3.1.

---

## Troubleshooting

If you encounter any issues while running the integration scripts, enable debug logging to get more detailed information:

1. Open the `config.json` file
2. Change the `log_level` setting from `"info"` to `"debug"`:
   ```json
   {
     "log_level": "debug",
     ...
   }
   ```
3. Run the script again and review the detailed output in the log file (e.g., `zabbix_statistics.log` or `zabbix_lookup_sync.log`)

---

## Notice

This integration **does not install or configure Zabbix for you**.
You must install, configure, and run Zabbix **independently**.
The provided Python scripts are intended **only for integrating** Zabbix data with **Sycope** using its REST API.
