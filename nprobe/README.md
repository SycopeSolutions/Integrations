# nProbe Integration with Sycope

Use **[ntop nProbe](https://www.ntop.org/products/netflow/nprobe/)** as a NetFlow/IPFIX probe for **Sycope** with Layer 7 visibility: nDPI application, DNS queries and responses, HTTP URL/host/user agent, TLS server name (SNI), JA4/JA3 fingerprints, TLS version and cipher, client/server network latency, application latency and TCP retransmissions.

Sycope decodes these fields only for exporters bound to a **traffic profile** that lists them. This integration creates that profile, named `nProbe`, and binds it to your nProbe exporters:
- 30 of the profile's fields are built into Sycope;
- 4 TLS fields (SNI, JA4, TLS version, TLS cipher) are created by `install.py` as custom NetFlow fields.

> **Sycope is available as a [free version](https://free.sycope.com/)** supporting up to 5,000 flows/second with no limitations on data sources, subnetworks, or number of monitored hosts. The free version includes threat detection, anomaly detection, and personalized dashboards — making it viable for production use without a license cost. The main differences vs. the paid version are data retention (14 days vs. unlimited), access management (single admin role vs. full RBAC), and probes monitoring availability.

---

## Repository Content

```
nprobe/
├── README.md
├── config.json                 # Sycope connection and nProbe exporter IPs
├── requirements.txt
├── install.py                  # Creates/updates the traffic profile and binds it to the exporters
├── uninstall.py                # Removes the bindings and the profile
├── verify_flows.py             # Checks binding, templates and field fill rates per exporter
└── profiles/
    └── nprobe_profile.json     # Traffic profile export: source type "probe", 30 built-in + 4 custom TLS fields
```

The scripts use the shared library [`../sycope`](../sycope): `sycope.netflow` handles traffic profiles and exporters. The same profile file can also be imported with the generic command `python3 -m sycope.scripts.traffic_profile`.

---

## Requirements

- nProbe with nDPI. Tested with nProbe 11.0 (nDPI 5.0). Without a license nProbe runs in demo mode and stops after a few minutes.
- Sycope 3.2 or 3.3 with REST API access, user with permission to change NetFlow settings
- Python 3.8+ and `requests` (`pip3 install -r requirements.txt`)

---

## 1. Configure nProbe

Export IPFIX (`-V 10`) to the Sycope collector (UDP 2055) with a template that contains the L7 elements. This template (nProbe 11.0) fills every field of the profile except JA3 and `httpVia`:

```bash
nprobe -i eth0 -n <sycope-ip>:2055 -V 10 -t 60 -d 15 \
  -T "%IPV4_SRC_ADDR %IPV4_DST_ADDR %L4_SRC_PORT %L4_DST_PORT %PROTOCOL %INPUT_SNMP %OUTPUT_SNMP \
%IN_PKTS %OUT_PKTS %IN_BYTES %OUT_BYTES %FLOW_START_MILLISECONDS %FLOW_END_MILLISECONDS \
%CLIENT_TCP_FLAGS %SERVER_TCP_FLAGS %CLIENT_NW_LATENCY_MS %SERVER_NW_LATENCY_MS %APPL_LATENCY_MS \
%RETRANSMITTED_IN_BYTES %RETRANSMITTED_IN_PKTS %RETRANSMITTED_OUT_BYTES %RETRANSMITTED_OUT_PKTS \
%APPLICATION_ID %L7_PROTO %DNS_QUERY %DNS_QUERY_ID %DNS_QUERY_TYPE %DNS_RET_CODE %DNS_NUM_ANSWERS \
%DNS_TTL_ANSWER %DNS_RESPONSE %HTTP_URL %HTTP_METHOD %HTTP_RET_CODE %HTTP_REFERER %HTTP_USER_AGENT \
%HTTP_MIME %HTTP_HOST %HTTP_SITE %HTTP_X_FORWARDED_FOR %IN_SRC_MAC %MAX_TTL \
%TLS_SERVER_NAME %JA4C_HASH %TLS_CIPHER %TLS_VERSION"
```

Notes:
- With several `-n` collectors nProbe sends flows **round-robin** between them. To send all flows to every collector, add `-a` (`--all-collectors`).
- Sycope binds the profile to the **source IP of the IPFIX packets**. On a multi-homed host that is the address of the interface that routes to Sycope, which may differ from the management address.
- **Template size limit:** the whole template must fit into one export packet (1472 bytes payload). With a template that is too long nProbe logs `ERROR: This template is longer than the max NetFlow packet lenght (1634 > 1472)` and **exports nothing**. Variable-length elements count with their maximum size. Adding `%HTTP_VIA` (up to 256 bytes) to the template above exceeds the limit, so it is left out. To get `httpVia`, remove other elements, for example the DNS group. After changing `-T`, check the nProbe log or run `verify_flows.py`.
- **JA3:** nProbe 11 replaced the JA3 elements with JA4 (`%JA4C_HASH`). `%JA3C_HASH` / `%JA3S_HASH` are not in its element list (`nprobe -H`), and an unknown element in `-T` is silently ignored. The profile keeps Sycope's built-in `ja3cHash` / `ja3sHash` fields for older nProbe versions that still export them.
- TLS fields are filled only for TLS traffic, DNS fields only for DNS, and so on. `nprobe -H` lists every element your version supports.

| nProbe element | Sycope field | |
|---|---|---|
| `%L7_PROTO`, `%APPLICATION_ID` | `dpiAppId`, `applicationId` | built-in |
| `%CLIENT_NW_LATENCY_MS`, `%SERVER_NW_LATENCY_MS`, `%APPL_LATENCY_MS` | `clientNetworkTime`, `serverNetworkTime`, `initialServerResponseTime` | built-in |
| `%RETRANSMITTED_{IN,OUT}_{BYTES,PKTS}` | `retransmitted{In,Out}{Bytes,Packets}` | built-in |
| `%DNS_*` (7) | `dnsQuery`, `dnsQueryId`, `dnsQueryType`, `dnsRetCode`, `dnsNumAnswers`, `dnsTtlAnswer`, `dnsResponse` | built-in |
| `%HTTP_*` (10) | `httpUrl`, `httpMethod`, `httpRetCode`, `httpReferer`, `httpUa`, `httpMime`, `httpHost`, `httpSite`, `httpXForwardedFor`, `httpVia` | built-in |
| `%IN_SRC_MAC`, `%MAX_TTL` | `sourceMacAddress`, `clientMaxTtl` | built-in |
| `%JA3C_HASH`, `%JA3S_HASH` (older nProbe) | `ja3cHash`, `ja3sHash` | built-in |
| `%TLS_SERVER_NAME` | `tlsServerName` (element 188) | custom, created by `install.py` |
| `%JA4C_HASH` | `ja4cHash` (576) | custom |
| `%TLS_CIPHER`, `%TLS_VERSION` | `tlsCipher` (493), `tlsVersion` (495) | custom |

Sycope ignores the enterprise number of IPFIX elements. If another integration already uses one of the custom element ids on your Sycope, for example Keysight IxFlow's `ixTransactionLatency` (188), `install.py` skips that field with a warning and installs the rest.

---

## 2. Install

```bash
cd Integrations/nprobe
pip3 install -r requirements.txt
# config.json: sycope_host, sycope_login, sycope_pass, exporter_ips (nProbe source IPs)
python3 install.py --dry-run
python3 install.py
```

`install.py`:
1. creates the 4 custom TLS fields, unless their element ids are taken;
2. creates the traffic profile `nProbe` (source type *probe*), or updates it if it exists;
3. binds it to every IP in `exporter_ips`. An exporter that already uses another profile is reported and not changed.

**Exporter IP changes** (new interface, readdressing, NAT): Sycope sees nProbe under a new IP, the profile is not bound to it, and the L7 fields stop being stored. Templates and flows still arrive, so this is easy to miss. Add the new IP to `exporter_ips` and run `install.py` again; the old bindings stay in place. `verify_flows.py` reports this case as `[FAIL] ... uses no profile`.

Running it again changes nothing if everything is in place. In the GUI the profile is under **Settings → NetFlow → Template Based Settings**.

| `config.json` key | Description |
|---|---|
| `sycope_host`, `sycope_login`, `sycope_pass` | Sycope URL and API credentials |
| `exporter_ips` | nProbe exporter IPs as seen by Sycope |
| `traffic_profile_name` | Profile name (default `nProbe`) |
| `profile_file` | Profile export to install (default `profiles/nprobe_profile.json`) |
| `verify_minutes` | Time window of `verify_flows.py` |

---

## 3. Verify

```bash
python3 verify_flows.py                      # exporters from config.json
python3 verify_flows.py --exporter 10.0.0.5 --minutes 30
```

For each exporter the script checks:
- that the profile is bound to that IP;
- that templates arrived and which profile fields they contain;
- how many flows in the time window carry each field. DNS, HTTP and TLS fields appear only when that traffic is present.

Example output, from an exporter whose IP was not bound to the profile:

```
Exporter 10.0.0.5
  [FAIL] 10.0.0.5 uses no profile instead of 'nProbe' - bind it (install.py) to the exporter IP that Sycope sees
  [OK  ] 6 template(s), 25/30 profile fields sent
  [OK  ] 4912 flows from 10.0.0.5 in the last 30 min
  [WARN] sent but never filled: applicationId, dpiAppId, clientNetworkTime, serverNetworkTime, ...
```

The L7 and latency fields arrive in the templates, but Sycope does not store them until the profile is bound to the exporter IP.

---

## Copying a profile between Sycope systems

`profiles/nprobe_profile.json` was exported with the generic tool from the shared library. The tool works for any traffic profile, including ones with custom fields:

```bash
# from the repository root; connection from --config <file> or --host/--user/--password
python3 -m sycope.scripts.traffic_profile --config nprobe/config.json export --name nProbe -o my_profile.json
python3 -m sycope.scripts.traffic_profile --config nprobe/config.json import my_profile.json --exporter 10.0.0.5 --dry-run
python3 -m sycope.scripts.traffic_profile --config nprobe/config.json check my_profile.json --exporter 10.0.0.5
```

On import, fields are matched by name. Missing custom fields are created, unless their element id is already used by another field. Element ids that are already taken are never redefined.

---

## Uninstall

```bash
python3 uninstall.py --dry-run
python3 uninstall.py            # --yes to skip the confirmation
```

The script removes the exporter bindings and the profile. The custom TLS fields and the built-in fields stay: custom fields may be used by other profiles, and stored data refers to them. Flow data already stored is not deleted.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| `[FAIL] ... uses no profile` | Put the IP shown by `verify_flows.py` (the IPFIX source IP) into `exporter_ips` and run `install.py` again. |
| `[FAIL] no templates received` | `-n` target and port, firewall, NAT between nProbe and Sycope. |
| L7 fields never filled although bound | Wait for the next template refresh (`-t`/`-d` timeouts) and check that nProbe runs with nDPI and a valid license. Demo mode stops exporting after a few minutes. |
| Only half of the flows arrive | Several `-n` collectors without `-a`: nProbe balances flows round-robin. |
