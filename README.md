# Sycope Integration Templates

Welcome to the official repository for custom **Sycope integration templates**!  
This repository is designed to help end users seamlessly synchronize data between Sycope and third-party platforms such as **Suricata**, **Zabbix**, **Keysight IxFlow**, and others.

> **Sycope is available as a [free version](https://free.sycope.com/)** supporting up to 5,000 flows/second with no limitations on data sources, subnetworks, or number of monitored hosts. The free version includes threat detection, anomaly detection, and personalized dashboards — making it viable for production use without a license cost. The main differences vs. the paid version are data retention (14 days vs. unlimited), access management (single admin role vs. full RBAC), and probes monitoring availability.


Each integration includes:
- Detailed manuals
- In-line comments and documentation
- Ready-to-use scripts for rapid deployment

We’re excited to share these resources with the community and support efficient, flexible integrations tailored to your needs.

---

## Integrations

| Directory | Integration |
|---|---|
| [`keysight`](keysight) | Keysight IxFlow (AppStack) IPFIX: custom fields, traffic profile, flow verification and dashboards |
| [`nprobe`](nprobe) | ntop nProbe IPFIX with L7/DNS/HTTP/JA3/latency fields: traffic profile, exporter binding, flow verification |
| [`phpipam`](phpipam) | phpIPAM subnets and addresses synchronized to the Hosts & Subnets lookup |
| [`suricata`](suricata) | Suricata alerts and anomaly events in a Sycope custom index |
| [`zabbix`](zabbix) | Zabbix statistics and inventory in Sycope, and Sycope monitoring template for Zabbix |
| [`webhooks`](webhooks) | Alert notifications to Jira, Slack and Microsoft Teams |
| [`sycope`](sycope) | Shared Python library for the Sycope REST API used by the integrations (API client, NetFlow traffic profiles, dashboards) |

---

## Sycope versions

Dashboards in this repository use the **Sycope 3.3** export format. For **Sycope 3.2** (legacy), convert them with the shared library before importing them from the GUI:

```bash
python3 -m sycope.scripts.convert_dashboard --to 3.2 <integration>/dashboards/*.json -o dashboards-3.2/
```

**Old 3.2 exports in Sycope 3.3:** no conversion is needed. The Sycope 3.3.1 GUI imports 3.2 export files directly, and so do the `install.py` scripts. `--to 3.3` is available if you want to keep your files in the current format.

The converter works offline and needs Python 3.8+ with `requests`, like the integrations. The `install.py` scripts of the integrations import the dashboards (and, where the integration has them, saved fields and drilldowns) through the API; for Sycope 3.2 run them with `--sycope-3.2`. Python code can use `sycope.dashboards` (`to_32()`, `to_33()`, `import_dashboard()`, `install_components()`).

---

## Troubleshooting

If you encounter any issues while running the integration scripts, enable debug logging to get more detailed information:

1. Open the `config.json` file in the integration directory
2. Change the `log_level` setting from `"info"` to `"debug"`:
   ```json
   {
     "log_level": "debug",
     ...
   }
   ```
3. Run the script again and review the detailed output in the log file
