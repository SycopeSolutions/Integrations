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

