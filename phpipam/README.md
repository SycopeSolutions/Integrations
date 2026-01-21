# phpIPAM Integration with Sycope - Beta

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

