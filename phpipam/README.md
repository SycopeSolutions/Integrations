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

```text
App ID:           **sycope** (or any name of your choice)
App Code:         _Automatically generated_
App Permissions:  **Read**
App Security:     **User token**

All other settings can be left at their default values or adjusted to meet your specific security and operational requirements.

<img width="1277" height="829" alt="image" src="https://github.com/user-attachments/assets/aec8cd62-3b52-4d30-8af7-668f34ea0d6c" />


You can verify phpIPAM API using the following `curl` command:

```bash
root@integration:~# curl -X POST -u Admin:ipamadmin123 "http://192.168.1.87/api/sycope/user/"
{"code":200,"success":true,"data":{"token":"YOUR_TOKEN","expires":"2026-01-21 15:23:24"},"time":0.005}
root@integration:~#
```

Your **phpIPAM** instance uses a username and password to generate a **temporary authentication token**.  
This token is then used to authenticate all subsequent API requests for the duration of the session.

---

##  Installation

```bash
git clone https://github.com/SycopeSolutions/Integrations.git
cd Integrations/phpipam
pip3 install -r requirements.txt
```

Edit the `config.json`.

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

