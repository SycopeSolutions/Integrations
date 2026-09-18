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

- Reads Suricata logs from `eve.json`, resuming from a saved byte offset
  (not by rescanning the whole file every run - see "Progress tracking" below)
- Filters events by `event_types`, plus a per-event-type whitelist/blacklist
  (works for `alert`/`anomaly` as before, and for any other event type listed
  in `filter_keys`, e.g. `smb`)
- Transforms each event into a row matching the field structure of a predefined **custom index** in Sycope
- Sends rows via Sycope REST API
- Tracks progress in `state.json` (device/inode/offset), surviving log rotation

---

##  Repository Contents

```
.
├── Suricata_Dashboard_Sycope.json   # Optional dashboard to import into Sycope
├── config.json                      # Configuration file
├── eve_processor.py                 # Main processing script
├── install.py                       # Creates a new Sycope index with proper fields
├── uninstall.py                     # Optional cleanup for custom indexes
├── state.json                       # Offset-tracking state file (auto-generated)
├── tools/
│   ├── gen_synthetic_eve.py         # Generates a synthetic eve.json for benchmarking
│   └── bench_json.py                # Benchmarks stdlib json vs orjson vs pysimdjson
├── tests/
│   └── test_eve_processor.py        # Rotation, offset, flattening, compat tests
```
![image](https://github.com/user-attachments/assets/315fc208-17df-42db-9d11-e2135fd7b720)

---

##  Requirements and version support

| Component | Version | Notes |
|-----------|---------|-------|
| Python    | 3.8+    | |
| Suricata  | 7.0.x or 8.0.x (tested on 8.0.6) | 7.0 is EOL as of July 2026 - upgrade to 8.0 when possible |
| Sycope    | >= 3.1 with API access | |

Suricata 8.0 adds several event types (`ldap`, `pop3`, `mdns`, `websocket`,
`doh2`) and new TLS fields (`ja4`, `client_alpns`, `subjectaltname`). Running
against a 7.0.x `eve.json` still works - fields introduced in 8.0 simply come
back as `None`/empty instead of raising.

Install dependencies:
```bash
pip3 install requests
```

`orjson` is an optional dependency for faster JSON parsing on large log
files - see "JSON parsing performance" below. It's listed in
`requirements.txt`; if it isn't installed, the processor falls back to
stdlib `json` automatically.

---

##  Installing Suricata 8.0 on Debian 13 (trixie)

Debian 13 ships Suricata 7.x in its main repository. To get 8.0.x, enable
`trixie-backports`:

```bash
echo "deb http://deb.debian.org/debian trixie-backports main" | \
    sudo tee /etc/apt/sources.list.d/backports.list
sudo apt-get update
sudo apt-get install -t trixie-backports suricata
suricata --build-info | head -1   # confirm 8.0.x
```

If `trixie-backports` doesn't yet carry a Suricata 8.0.x build (backports
lag upstream releases), build from the official Suricata source tarball per
the [upstream Debian install docs](https://docs.suricata.io/en/suricata-8.0.4/install/debian.html),
or track the OISF release announcements for when the backport lands.

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

  // File that stores offset-tracking progress (dev/inode/offset/size).
  // Auto-created and auto-migrated from last_timestamp_file on first run.
  "state_file": "state.json",

  // Legacy timestamp-tracking file. Only read once, to migrate an existing
  // install to offset-based tracking. Safe to leave as-is.
  "last_timestamp_file": "last_timestamp.txt",

  // List of event types to process
  "event_types": ["alert", "anomaly", "ldap", "pop3", "mdns", "websocket", "doh2"],

  // Per-event-type field path used for whitelist/blacklist filtering.
  // Add an entry here for any event type you want to filter beyond
  // alert/anomaly (the value must resolve to a scalar in the event).
  "filter_keys": {
    "alert": ["alert", "signature_id"],
    "anomaly": ["anomaly", "event"],
    "smb": ["smb", "command"]
  },

  // If non-empty: only process anomalies listed here (whitelist wins over blacklist)
  "anomaly_whitelist": [],

  // If non-empty: only process alerts (signatures) listed here
  "alert_whitelist": [],

  // If non-empty: only process SMB commands listed here
  "smb_whitelist": [],

  // Anomaly event names to exclude (only used if the whitelist is empty)
  "anomaly_blacklist": [],

  // Suricata signature IDs to exclude (only used if the whitelist is empty)
  "alert_blacklist": [],

  // SMB commands to exclude - defaults to the three highest-volume,
  // lowest-security-value commands (~85% of SMB traffic in practice)
  "smb_blacklist": ["SMB2_COMMAND_CREATE", "SMB2_COMMAND_CLOSE", "SMB2_COMMAND_FIND"]
}
```

>  JSON does not support comments natively — this format is shown for documentation purposes only. Use a standard `config.json` file without comments in production.

Any event type can be filtered this way, not just `alert`/`anomaly`/`smb` -
add its field path to `filter_keys` and a matching `<type>_whitelist` /
`<type>_blacklist` list.

---

##  Script Usage

| Script               | Purpose                                    | Example                                                |
|----------------------|--------------------------------------------|---------------------------------------------------------|
| **install.py**       | Create index & mappings                    | `python3 install.py` or `python3 install.py --profile all-protocols` |
| **eve_processor.py** | Parse & inject new events                  | `python3 eve_processor.py` (e.g., via systemd)         |

`install.py --profile basic` (the default, same as omitting the flag)
creates the original common/alert/anomaly/TLS field set - no behavior
change for existing installs. `--profile all-protocols` additionally
creates columns for `smb`, `krb5`, `dhcp`, `snmp`, `dcerpc`, `ssh`, `smtp`,
`rdp`, `sip`, `nfs`, `ftp`, `tftp`, `telnet`, `ldap`, `pop3` - useful when
an RFP or compliance requirement calls for that metadata. `eve_processor.py`
has no CLI flags; it reads everything from `config.json`.

---

##  Progress Tracking and Log Rotation

Earlier versions tracked progress by comparing each event's `timestamp`
against a saved high-water mark, which meant every run re-read the entire
`eve.json` from the start. On a busy sensor with a multi-GB log, a single
cycle could take longer than the systemd timer interval, causing cycles to
stack up until the disk filled.

The processor now tracks a byte offset instead (`state.json`: device,
inode, offset, file size), so each run only reads what's new since the
last run.

- **Rotation detection**: a different inode means the log was rotated with
  `create` (a new file replaced the old one, which logrotate renamed to
  `eve.json.1`). The same inode but a smaller file size means `copytruncate`
  (the file was truncated in place).
- On rotation, the processor searches `eve.json.1` through `eve.json.5`
  for the file it was previously tracking, then queues every numbered file
  between that match and the live file (oldest first) plus the live file
  itself, so a processor outage spanning several logrotate cycles doesn't
  silently drop the files in between. Only if no match is found within
  that 5-file lookback does it log a warning and resume at the current
  file, accepting the gap.
- Each file is read up to a fixed size cap per cycle (256 MB by default).
  If a queued file is larger than that, the processor reads what it can,
  saves progress in `state.json`, and picks up where it left off on the
  next cycle rather than trying to load an unbounded backlog into memory
  or send an oversized batch to the Sycope API in one call.
- An incomplete last line (a write still in progress) is never parsed or
  counted; it's re-read, complete, on the next cycle.
- A single malformed event (e.g. a truncated or otherwise unparseable
  `timestamp` field) is rejected like any other invalid line - it never
  crashes the run. A crash here would mean `state.json` never gets
  updated, so the same byte offset would be re-read and re-crash on every
  subsequent cycle, wedging ingestion permanently at that line.
- `state.json` is written atomically (temp file + rename), so a crash or
  power loss mid-write can't leave a corrupt state file. A state file that
  somehow does fail to parse is treated as "no saved state" rather than a
  fatal error - the processor falls back to a full re-read of the current
  file rather than refusing to run.
- `last_timestamp` is still recorded in `state.json` for log/telemetry
  purposes only - it's never used to decide where to resume reading.

---

##  JSON Parsing Performance

`tools/gen_synthetic_eve.py` generates a synthetic `eve.json` (SMB-heavy
mix, matching production traffic shape) and `tools/bench_json.py`
benchmarks parsing approaches against it. Measured on a 500 MB / ~1.5M-line
file:

| Approach                                | Time (parse every line) | Time (with prefilter, `event_types=alert,anomaly`) |
|------------------------------------------|--------------------------|------------------------------------------------------|
| stdlib `json`                            | 5.4s (~284k lines/s)     | 1.41s                                                 |
| `orjson`                                  | 1.8s (~870k lines/s)     | 1.13s                                                 |
| `pysimdjson` (reused `Parser()`)          | 0.65s (~2.4M lines/s)    | 1.05s                                                  |

Two findings:

1. **The prefilter matters more than the parser.** Skipping `json.loads`
   entirely for lines whose raw text doesn't contain any configured
   `event_type` marker (e.g. `"event_type":"smb"`) cuts stdlib parse time
   from 5.4s to 1.4s with a realistic `alert,anomaly` filter - a ~4x win
   with zero new dependencies. `eve_processor.py` applies this prefilter
   before calling `json.loads`/`orjson.loads` on every line.
2. **Once the prefilter is in place, the parser choice is a smaller,
   secondary win.** `orjson` still shaves off another ~20-25% on top of the
   prefilter, for the cost of one pure-Python-wheel dependency (no compiler
   needed at install time). `pysimdjson` is faster on raw parsing but needs
   a C++ toolchain to build and its reused-`Parser()` advantage mostly
   applies to large multi-KB documents, not the short single-line records
   here - the gap versus `orjson` narrows to a few percent once the
   prefilter dominates the runtime.

Given that, `eve_processor.py` uses `orjson` when available
(`try: import orjson` guard, no hard dependency) and falls back to stdlib
`json` otherwise. `pysimdjson` wasn't adopted - its extra build complexity
isn't justified by the marginal gain once the prefilter is applied.

Re-run the benchmark against your own traffic mix:
```bash
python3 tools/gen_synthetic_eve.py /tmp/eve_bench.json --target-mb 500
python3 tools/bench_json.py /tmp/eve_bench.json --event-types alert,anomaly
```

---

##  Running the Script

Run manually:
```bash
python3 eve_processor.py
```
Or run as a service (recommended)

---

##  Running as a System Service

For automated processing, set up a systemd service with a timer:

### 1. Create Service File
Create `/etc/systemd/system/suricata-eve-processor.service`:
```ini
[Unit]
Description=Suricata EVE Log Processor
After=network.target

[Service]
Type=oneshot
TimeoutStartSec=90
User=suricata
Group=suricata
WorkingDirectory=/opt/suricata-integration
ExecStart=/usr/bin/python3 /opt/suricata-integration/eve_processor.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

`TimeoutStartSec` kills a cycle that runs too long instead of letting it
run forever alongside the next timer fire. Size it to comfortably exceed
your typical cycle time (see step 4).

### 2. Create Timer File
Create `/etc/systemd/system/suricata-eve-processor.timer`:
```ini
[Unit]
Description=Run Suricata EVE Processor every 90 seconds
Requires=suricata-eve-processor.service

[Timer]
OnBootSec=90sec
OnUnitActiveSec=90sec
AccuracySec=1sec

[Install]
WantedBy=timers.target
```

> **Important**: `OnUnitActiveSec` must be larger than one processing
> cycle's typical runtime, or invocations will stack up and pile onto each
> other (this is what caused the original production incident, back when
> progress was tracked by re-scanning the whole file every 30s). 90 seconds
> is a reasonable starting point for offset-based tracking (1-2 minutes is
> the recommended range); check actual cycle duration via
> `journalctl -u suricata-eve-processor.service` and adjust upward if
> cycles are taking longer, especially right after enabling `--profile
> all-protocols` or a broad `event_types` list.

### 3. Enable and Start
```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable and start the timer
sudo systemctl enable suricata-eve-processor.timer
sudo systemctl start suricata-eve-processor.timer

# Check status
sudo systemctl status suricata-eve-processor.timer
```

### 4. Monitor Logs
```bash
# View service logs
sudo journalctl -u suricata-eve-processor.service -f

# View timer logs
sudo journalctl -u suricata-eve-processor.timer -f
```

>  **Note**: Adjust the `WorkingDirectory` and script path to match your installation location. The service runs under the `suricata` user for security isolation.

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

##  Migrating from a Previous Version

This version changed the custom index's field definitions (new TLS fields,
and optionally the full protocol-metadata field set), which requires
rebuilding the index:

```bash
python3 uninstall.py   # deletes the existing index and its historical data
python3 install.py     # or: python3 install.py --profile all-protocols
```

**This deletes all historical data in the index.** Export or archive
anything you need to keep before rebuilding.

Progress tracking migrates itself, no manual step needed: on its first run,
`eve_processor.py` looks for the old `last_timestamp.txt`. If found (and no
`state.json` exists yet), it starts the new offset-based tracking from the
current end of `eve.json` and logs a warning. Events logged between the
last processed timestamp and the moment of migration may be skipped once,
since there's no reliable way to map an old timestamp back to a byte
offset. `last_timestamp.txt` is removed after migrating so the warning
only fires once.

---

##  Running Tests

```bash
pip3 install pytest
cd suricata
python3 -m pytest tests/ -v
```

Covers: log rotation (`copytruncate`, `create`, and multi-cycle rotation
chains), incomplete trailing lines, value flattening (lists/bools/dicts),
list-indexed column paths, the generic whitelist/blacklist filter,
Suricata 7.0 backward compatibility (missing 8.0-only fields don't raise),
malformed/poison-pill events not crashing the run, the per-cycle read cap,
and atomic `state.json` writes.

---

##  Troubleshooting

- Check log: `eve_processor.log` or `journalctl -u suricata_eve_processor`
- Make sure the Sycope user has proper API rights
- Confirm `eve.json` contains supported event types (see `event_types` in `config.json`)
- If a cycle seems to be reprocessing old data after a crash or disk issue,
  check `state.json` - deleting it forces a resume from the current end of
  `eve.json` (equivalent to the legacy-migration behavior)
- If `state.json` has a `pending_backlog` entry that isn't shrinking across
  runs, the processor is draining a large rotated-file backlog gradually
  (see "Progress Tracking" above) - this is expected after an extended
  outage, not a bug; check the `Processed=/Skipped=/Invalid=` counts in the
  log to confirm progress
- A `WARNING - Column action failed for '<col>' ...` in the log points at
  a specific column and value that a Suricata field-shape change broke -
  fix the mapping in `eve_processor.py`'s `column_map` rather than
  ignoring a rising `Invalid` count
- Feel free to contact our engineers via dedicated Discord Channel: https://discord.gg/dFjTv854
