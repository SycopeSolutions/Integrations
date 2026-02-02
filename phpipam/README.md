# phpIPAM Integration with Sycope

Integration between **Sycope** and **phpIPAM** enables zero-configuration of the primary Lookup **Hosts & Subnets**, delivering inventory details of network infrastructure used by Host & Subnet dashboards, filters, rules, and many other features.

With this integration, you can maintain an always up-to-date Sycope infrastructure configuration by continuously synchronizing it with your IPAM software.

The example below demonstrates how **individual IP addresses** are synchronized. The **Hostname** field from **phpIPAM** is stored in the **Name** field in **Sycope**, while the **Description** field is stored in **Description**.

<img width="1918" height="1168" alt="image" src="https://github.com/user-attachments/assets/f692b605-67ac-4ec6-bcdc-97089fe63a1f" />

The screenshot below demonstrates how **subnets** are synchronized. The **Description** field from **phpIPAM** is stored in the **Name** field in **Sycope**.

<img width="1920" height="1168" alt="image" src="https://github.com/user-attachments/assets/11bb7120-a1c8-4406-be92-11dff47f7072" />

Finally, the example below shows how **inventory data** from **phpIPAM** can be used for filtering within **Sycope**.

<img width="1919" height="1168" alt="image" src="https://github.com/user-attachments/assets/4d7c3416-8bb2-4113-a345-7166e85067fb" />

---

## Requirements

- Python 3.8+
- Sycope >= 3.1 with API access
- phpIPAM 1.5+
  - API enabled
  - API application (`App ID`) configured on each phpIPAM instance
- `requests` module:
  ```bash
  pip3 install requests
  ```

- `urllib3` module:
  ```bash
  pip3 install urllib3
  ```
You can install all dependencies in a single command:

```bash
pip3 install requests urllib3
```


---

##  Configuring phpIPAM

Before starting the integration, configure API access in your **phpIPAM** instance.

1. Log in to **phpIPAM**.
2. Navigate to **Administration** → **Server management** → **API**.
3. Click **Create API key** and configure it using the following parameters:

- App ID:           **sycope** (or any name of your choice)
- App Code:         _Automatically generated_
- App Permissions:  **Read**
- App Security:     **User token**

All other settings can be left at their default values or adjusted to meet your specific security and operational requirements.

<img width="1254" height="829" alt="image" src="https://github.com/user-attachments/assets/319390c0-ec66-451b-bdb1-a3c120f76da7" />


You can verify phpIPAM API using the following `curl` command:

```bash
root@integration:~# curl -X POST -u Admin:ipamadmin123 "http://192.168.1.87/api/sycope/user/"
{"code":200,"success":true,"data":{"token":"YOUR_TOKEN","expires":"2026-01-21 15:23:24"},"time":0.005}
root@integration:~#
```

Your **phpIPAM** instance uses a username and password to generate a **temporary authentication token**.  
This token is then used to authenticate all subsequent API requests for the duration of the session.

---

##  User & Role Setup in Sycope

After creating new index, add a dedicated user and role in Sycope for log ingestion:

1. **Create a Role**  
   Go to **Configuration → Roles**, create a role (e.g., `phpIPAMInject`) with:
   - Permission to Edit and View Lookup values: Settings -> Configuration -> Mapping -> Lookups

2. **Create a User**  
   Go to **Configuration → Users**, create a user (e.g., `phpIPAM_ingestor`) and assign the above role.

---

##  Installation

```bash
git clone https://github.com/SycopeSolutions/Integrations.git
cd Integrations/phpipam
pip3 install -r requirements.txt
```

Edit the `config.json`.

---

##  Configuration (`config.json`)

```jsonc
{
  // Logging verbosity level - info or debug
  "log_level": "info",

  // List of phpIPAM instances to synchronize data from
  // The integration supports multiple instances
  // In case of duplicates, the instance higher on the list takes priority
  "phpipam_hosts": [
    {
      // Base URL of the phpIPAM instance
      // HTTPS is strongly recommended in production environments
      "host": "http://192.168.1.87/",

      // phpIPAM API application ID
      // Must match the App ID configured in phpIPAM API settings
      "app_id": "sycope",

      // phpIPAM username used to generate a temporary API token
      "username": "Admin",

      // Password for the above phpIPAM user
      "password": "",

      // Base path of the phpIPAM API endpoint
      "api_base": "/api"
    },
    {
      // Base URL of an additional phpIPAM instance
      "host": "http://192.168.1.88/",

      // phpIPAM API application ID
      "app_id": "sycope",

      // phpIPAM API username
      "username": "Admin",

      // Password for the above phpIPAM user
      "password": "",

      // Base path of the phpIPAM API endpoint
      "api_base": "/api"
    }
  ],

  // URL of the Sycope API endpoint
  // HTTPS is strongly recommended
  "sycope_host": "https://192.168.1.14",

  // Sycope API user
  // Must have permissions to create and update Lookup entries
  "sycope_login": "admin",

  // Password for the above Sycope API user
  "sycope_pass": "",

  // Base path of the Sycope API
  "api_base": "/npm/api/v1/",

  // Name of the Lookup in Sycope
  // Used for synchronizing phpIPAM inventory data
  "lookup_name": "hosts & subnets",

  // Synchronization mode
  "sync_mode": "addresses",

  // List of phpIPAM section names or IDs to explicitly include
  // Empty array means all sections are included
  "include_sections": [],

  // List of phpIPAM section names or IDs to exclude from synchronization
  "exclude_sections": [],

  // Exclude objects whose description starts with any of the defined prefixes
  // Useful for filtering technical, temporary, or reserved entries
  "exclude_description": [
    "prefix1",
    "prefix2"
  ],

  // Include inactive IP addresses in synchronization
  "include_inactive": false,

  // Include reserved IP addresses
  "include_reserved": true,

  // Include DHCP-managed addresses
  "include_dhcp": true
}


```

>  JSON does not support comments natively — this format is shown for documentation purposes only. Use a standard `config.json` file without comments in production.

---

##  Script Usage

| Script               | Purpose                                      | Example                                   |
|----------------------|----------------------------------------------|-------------------------------------------|
| **phpipam_api.py**   | Contains shared phpIPAM API helper functions | n/a                                       |
| **phpipam_sync.py**  | Synchronizes IPAM data from phpIPAM to Sycope | `python3 phpipam_sync.py` (e.g. via systemd) |

---

##  Running the Script

Run manually:
```bash
python3 phpipam_sync.py
```
Or run as a service (recommended)

---

##  Notes

- The script **does not overwrite** Hosts & Subnets Lookup entries that are not managed by the IPAM configuration.
- Running the script directly on the Sycope appliance is not supported due to security isolation constraints.

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
3. Run the script again and review the detailed output in the log file (`phpipam_sync.log`)

---

## Notice

This integration **does not install or configure phpIPAM for you**.
You must install, configure, and run phpIPAM **independently**.
The provided Python scripts are intended **only for integrating** phpIPAM data with **Sycope** using its REST API.
