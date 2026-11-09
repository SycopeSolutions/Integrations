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
| [`phpipam`](phpipam) | phpIPAM subnets and addresses synchronized to the Hosts & Subnets lookup |
| [`suricata`](suricata) | Suricata alerts and anomaly events in a Sycope custom index |
| [`zabbix`](zabbix) | Zabbix statistics and inventory in Sycope, and Sycope monitoring template for Zabbix |
| [`webhooks`](webhooks) | Alert notifications to Jira, Slack and Microsoft Teams |
| [`sycope`](sycope) | Shared Python library for the Sycope REST API used by the integrations |

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
