# Sycope Integration Templates

Welcome to the official repository for custom **Sycope integration templates**!  
This repository is designed to help end users seamlessly synchronize data between Sycope and third-party platforms such as **Suricata**, **Zabbix**, and others.

Each integration includes:
- Detailed manuals
- In-line comments and documentation
- Ready-to-use scripts for rapid deployment

We’re excited to share these resources with the community and support efficient, flexible integrations tailored to your needs.

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
