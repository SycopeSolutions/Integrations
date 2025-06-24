# Suricata Integration with Sycope

This integration enables sending Suricata alert and anomaly events to a custom index in **Sycope** for further correlation, search, and visualization.

---

##  Components

The integration consists of three components:

1. **Sycope** – Receives data through the REST API.
2. **Suricata** – Generates JSON-based security events in `eve.json` format.
3. **Integration Script** – A Python-based injector that parses logs and sends them to Sycope.

>  **You can run the script on the same host as Suricata**, but **do not run it on the Sycope appliance** – due to permission and isolation limitations.

---


##  How the Integration Works

The `eve_processor.py` script:

- Reads Suricata logs from `eve.json`
- Filters for `alert` and `anomaly` event types
- Applies optional whitelists/blacklists
- Transforms each event into a row matching the field structure of a predefined **custom index** in Sycope
- Sends rows via Sycope REST API
- Maintains a `last_timestamp.txt` file to avoid duplicate processing

---

##  Repository Contents

```
.
├── Suricata_Dashboard_Sycope.json   # Optional dashboard to import into Sycope
├── config.json                      # Configuration file
├── eve_processor.py                 # Main processing script
├── install.py                       # Creates a new Sycope index with proper fields
├── uninstall.py                     # Optional cleanup for custom indexes
├── last_timestamp.txt               # Timestamp tracking file (auto-generated)
```
![image](https://github.com/user-attachments/assets/315fc208-17df-42db-9d11-e2135fd7b720)

---

##  Requirements

- Python 3.8+
- Suricata 6.0+
- Sycope >= 3.1 with API access
- `requests` module:
  ```bash
  pip3 install requests
  ```

---

##  Installation

```bash
git clone https://github.com/SycopeSolutions/Integrations.git
cd Integrations/Suricata
pip3 install -r requirements.txt
```

Edit the `config.json` as described below.

---

##  User & Role Setup in Sycope

After creating new index, add a dedicated user and role in Sycope for log ingestion:

1. **Create a Role**  
   Go to **Configuration → Roles**, create a role (e.g., `SuricataInject`) with:
   - Permission to inject data only into custom indexes

2. **Create a User**  
   Go to **Configuration → Users**, create a user (e.g., `suricata_ingestor`) and assign the above role.

---

##  Configuration (`config.json`)

```jsonc
{
  // URL of the Sycope API endpoint (HTTPS strongly recommended)
  "sycope_host": "https://<sycope-ip>",

  // Sycope API user (must have rights to inject data into custom indexes)
  "sycope_login": "suricata_ingestor",

  // Password for the above API user
  "sycope_pass": "your_password",

  // Name of the custom index defined in Sycope
  "index_name": "suricata",

  // Path to the Suricata eve.json log file
  "suricata_eve_json_path": "/var/log/suricata/eve.json",

  // File to track the timestamp of the last processed event
  "last_timestamp_file": "last_timestamp.txt",

  // List of event types to process (e.g., "alert", "anomaly", "dns", etc.)
  "event_types": ["alert", "anomaly"],

  // If true: only process anomalies listed in anomaly_whitelist
  "anomaly_whitelist": false,

  // If true: only process alerts (signatures) listed in alert_whitelist
  "alert_whitelist": false,

  // List of anomaly event names to exclude (only used if whitelist is false)
  "anomaly_blacklist": [],

  // List of Suricata signature IDs to exclude (only used if whitelist is false)
  "alert_blacklist": []
}
```

>  JSON does not support comments natively — this format is shown for documentation purposes only. Use a standard `config.json` file without comments in production.

---

##  Script Usage

| Script               | Purpose                                    | Example                                        |
|----------------------|--------------------------------------------|------------------------------------------------|
| **install.py**       | Create index & mappings                    | `python3 install.py`                           |
| **eve_processor.py** | Parse & inject new events                  | `python3 eve_processor.py` (e.g., via systemd) |

---

##  Running the Script

Run manually:
```bash
python3 eve_processor.py
```
Or run as a service (recommended)

---

##  Notes

- The script requires a valid custom index in Sycope with matching column definitions.
- Running the script on the Sycope appliance is not supported due to security isolation.
- Supports filtering of unwanted events via whitelists or blacklists.
- Each index in Sycope has a **retention period**. Set it in **Settings → Indices → Retention** according to your storage policy.

---

##  Dashboard Import

1. In Sycope UI, go to **Dashboards → Import**
2. Upload `Suricata_Dashboard_Sycope.json`
3. Link it to the `suricata` index

You get:
- Alert trends over time
- Top signatures
- Top source and destination IPs

---

## Notice

This integration **does not install or configure Suricata for you**.

You must install, configure, and run Suricata **independently**, including:
- System installation (e.g., `apt install suricata`)
- Enabling `eve.json` output
- Running Suricata as a system service

The provided Python scripts are intended **only for integrating** Suricata logs with **Sycope** using its REST API.

> Think of this as a log shipping and parsing layer, not a full IDS/IPS setup.


##  Suricata Setup

1. Install Suricata:
```bash
apt-get install suricata
```

2. Enable EVE JSON output in `/etc/suricata/suricata.yaml`:
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
```

Make sure Suricata logs to the path defined in `config.json`.

---

##  Troubleshooting

- Check log: `eve_processor.log` or `journalctl -u suricata_eve_processor`
- Make sure the Sycope user has proper API rights
- Confirm `eve.json` contains supported event types (`alert`, `anomaly`)
