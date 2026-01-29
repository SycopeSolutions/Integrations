# phpIPAM Integration with Sycope - Beta

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
- `pandas` module:
  ```bash
  pip3 install pandas
  ```
- `urllib3` module:
  ```bash
  pip3 install urllib3
  ```
You can install all dependencies in a single command:

```bash
pip3 install requests pandas urllib3
```

---

##  Configuring phpIPAM

<img width="1277" height="829" alt="image" src="https://github.com/user-attachments/assets/aec8cd62-3b52-4d30-8af7-668f34ea0d6c" />


You can verify phpIPAM API using the following `curl` command:

```bash
root@integration:~# curl -X POST -u Admin:ipamadmin123 "http://192.168.1.87/api/sycope/user/"
{"code":200,"success":true,"data":{"token":"YOUR_TOKEN","expires":"2026-01-21 15:23:24"},"time":0.005}
root@integration:~#
```

---

##  Installation

```bash
git clone https://github.com/SycopeSolutions/Integrations.git
cd Integrations/phpipam
pip3 install -r requirements.txt
```

Edit the `config.json`.

---

