# Zabbix Integration with Sycope

This integration enables sending monitoring statistics and inventory data from Zabbix to a custom index and dedicated Lookup in **Sycope** for further correlation, search and visualization.

An example of the Zabbix Statistics Dashboard

<img width="1870" alt="image" src="https://github.com/user-attachments/assets/4c16e0d5-91c2-41a4-8a9a-877e06085b30" />


An example of the Zabbix Inventory Dashboard

<img width="1865" alt="image" src="https://github.com/user-attachments/assets/44f602c4-821e-478b-88c3-15aa4e256f73" />

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
├── dashboards                       # Optional dashboards to import into Sycope
├── drilldowns                       # Optional drilldown action to import into Sycope
├── fields                           # Optional custom fields to import into Sycope
├── config.json                      # Configuration file
├── install.py                       # Creates new Sycope custom index and custom Lookup
├── uninstall.py                     # Optional cleanup for custom indexes and custom Lookups
├── zabbix_statistics_sync.py        # Main processing script for synchronizing metrics data
├── zabbix_lookup_sync.py            # Main processing script for synchronizing inventory data
```

---

## Requirements

- Python 3.8+
- Zabbix 7.0+
- Sycope >= 3.1 with API access
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
python3 install.py
```

Edit the `config.json` as described below.

---

##  Configuration (`config.json`)

```jsonc
{
    // URL of the Zabbix API endpoint (HTTPS strongly recommended)
    "zabbix_host": "http://192.168.1.46:8080",

    // Additional part of the Zabbix API endpoint
    "zabbix_api_base": "/api_jsonrpc.php",

    // Zabbix API user
    "zabbix_login": "Admin",

    // Password for the above API user
    "zabbix_pass": "",

    // URL of the Sycope API endpoint (HTTPS strongly recommended)
    "sycope_host": "https://192.168.1.14",

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
      "8.8.8.8",
      "192.168.1.1"
    ]
}

```

>  JSON does not support comments natively — this format is shown for documentation purposes only. Use a standard `config.json` file without comments in production.

---

##  Script Usage

| Script                    | Purpose                                    | Example                                             |
|---------------------------|--------------------------------------------|-----------------------------------------------------|
| **install.py**            | Create index                               | `python3 install.py`                                |
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

1. In Sycope UI, go to **Dashboards → Import**
2. Upload `zabbix_statistics_dashboard.json`
3. Upload `zabbix_inventory.json`

##  Fields Import

1. In Sycope UI, go to **Settings → Objects → Fields → Import Field**
2. Upload `field_zabbix_graph_url.json` and others from fields directory

##  Drilldown Import

1. In Sycope UI, go to **Configuration → Shortcuts → Import Shortcut**
2. Upload `zabbix_inventory_drilldown_action.json`
3. Upload `zabbix_inventory_drilldown_widget.json`

---

## Notice

This integration **does not install or configure Zabbix for you**.
You must install, configure, and run Zabbix **independently**.
The provided Python scripts are intended **only for integrating** Zabbix data with **Sycope** using its REST API.
