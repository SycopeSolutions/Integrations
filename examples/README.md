# Examples: custom index and data injection

Two minimal scripts that show how to use the shared [`sycope`](../sycope) library:

| Script | What it does |
|---|---|
| `install.py` | Creates the custom index `<index_name>_<user_number>` with fields for host statistics (timestamp, IP, hostname, response time, CPU load, memory usage, packet loss). |
| `index_load.py` | Loads `new_data.json`, shifts its timestamps so the newest sample is "now", and injects the rows into that index. |

```bash
cd Integrations/examples
pip3 install requests
# set sycope_host, sycope_login and sycope_pass in config.json
python3 install.py
python3 index_load.py
```

The scripts can be run from any directory: `config.json`, `new_data.json` and the log files are read and written next to the scripts.

To remove the index afterwards, run this from the repository root:

```bash
python3 -m sycope.scripts.uninstall_index examples/config.json custom_index_1
```
