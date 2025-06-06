# Sycope Suricata Integration

**A set of scripts + dashboard to index Suricata EVE JSON into Sycope and visualize alerts.**

---

##  Overview
- **new_index.py** – create a Sycope “suricata” index with all relevant fields  
- **eve_processor.py** – tail & parse `/var/log/suricata/eve.json`, inject new events  
- **delete_indexes.py** – clean up old “userIndex.index” entries in Sycope  
- **config.json** – connection & filter settings  
- **Suricata_Dashboard_Sycope.json** – pre-built Sycope dashboard
![image](https://github.com/user-attachments/assets/05651483-587e-442c-a877-240cdb92a4a7)

>  _We recommend isolating Suricata data in its own index (“suricata”) for clarity._

> **WARNING:** In Sycope, each stream has a retention period—the duration after which data is deleted. Set the retention period that meets your needs [here](https://documentation.sycope.com/User-Guide/Settings/Indices/Retention)
---

##  Prerequisites
- **Sycope** >= v3.1 with API access  
- **Python 3.8+**  
- **Requests** library (`pip3 install requests`)  
- **Suricata** 6.0+  
- Network tap/span or NFLOG/iptables redirect to feed Suricata  

---

##  Installation
1. `git clone https://github.com/SycopeSolutions/Integrations.git`  
2. `cd Integrations/Suricata`  
3. `pip3 install -r requirements.txt` 
4. Edit **config.json** (see next)

---

##  Configuration (`config.json`)
| Key                     | Description                                                       | Default            |
|-------------------------|-------------------------------------------------------------------|--------------------|
| `sycope_host`           | https://sycope.example.com:port                                   | `""`               |
| `sycope_login`          | API user                                                          | `admin`            |
| `sycope_pass`           | API password                                                      | `""`               |
| `index_name`            | Index name in Sycope                                              | `suricata`         |
| `suricata_eve_json_path`| Path to Suricata’s EVE JSON log                                   | `/var/log/suricata/eve.json` |
| `last_timestamp_file`   | File to persist last‐processed timestamp                          | `last_timestamp.txt` |
| `event_types`           | Which events to ingest (`alert`,`anomaly`)                        | `["anomaly","alert"]` |
| `*_whitelist`/`blacklist`| Fine‐grained filtering by signature ID or anomaly name            | `false` / `[]`     |

>  Use whitelists sparingly – blacklists are safer to start.

---

## ▶ Script Usage

| Script               | Purpose                                    | Example                                        |
|----------------------|--------------------------------------------|------------------------------------------------|
| **new_index.py**     | Create index & mappings                    | `python3 new_index.py`                          |
| **eve_processor.py** | Parse & inject new events                  | `python3 eve_processor.py` *(cron every min)*   |
| **delete_indexes.py**| Remove stale custom indexes                | `python3 delete_indexes.py`                     |

---

##  Dashboard Import

1. In Sycope UI, go to **Dashboards → Import**  
2. Upload **Suricata_Dashboard_Sycope.json**  
3. Link to “suricata” index  

>  This gives you:  
> - Event-type trends over time  
> - Top signatures, source & destination IPs  

---

##  Suricata Setup
1. **Install**:  
   ```bash
   apt-get install suricata

2. **Enable EVE JSON in /etc/suricata/suricata.yaml:**
   ```
   outputs:
     - eve-log:
         enabled: yes
         filetype: regular
         filename: /var/log/suricata/eve.json
