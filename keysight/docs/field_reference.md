# Keysight IxFlow field reference

Keysight IxFlow (AppStack) exports its metadata as IPFIX enterprise elements with **PEN 3054** (Ixia). This page lists how each element of the IxFlow data template is handled by this integration.

Reference capture: NVOS 6.4.1.3, AppStack 4.9.2, IPv4 data template 257 (97 elements: 21 IANA + 76 PEN 3054). Field names and descriptions follow the Keysight *IxFlow metadata fields* document; elements marked *undocumented* are not in that document and their meaning was inferred from the data. "Fill" is the share of flows in the reference capture where the element had a value.

## 1. Supported elements (created by `install.py`)

| PEN 3054 element | IxFlow name | Sycope field | Type | Indexed | Unit | Fill |
|---:|---|---|---|:-:|---|---:|
| 111 | Application | `ixApplication` | string | yes |  | 100% |
| 120 | Client IP Country Code | `ixClientIpCountryCode` | string | yes |  | 100% |
| 121 | Client IP Country Name | `ixClientIpCountryName` | string | yes |  | 100% |
| 122 | Client IP Region Code | `ixClientIpRegionCode` | string | yes |  | 100% |
| 140 | Server IP Country Code | `ixServerIpCountryCode` | string | yes |  | 100% |
| 141 | Server IP Country Name | `ixServerIpCountryName` | string | yes |  | 100% |
| 142 | Server IP Region Code | `ixServerIpRegionCode` | string | yes |  | 100% |
| 143 | Server IP Region Name | `ixServerIpRegionName` | string | yes |  | 100% |
| 145 | Server IP City Name | `ixServerIpCityName` | string | yes |  | 100% |
| 161 | OS Device Name | `ixOsDeviceName` | string | yes |  | 100% |
| 163 | Browser Name | `ixBrowserName` | string | yes |  | 100% |
| 186 | Client AS name (e.g. "CLOUDFLARENET - CloudFlare, Inc., US") | `ixClientAsName` | string | no |  | 76% |
| 188 | Transaction Latency | `ixTransactionLatency` | long | no | µs | 60% |
| 189 | DNS Query HostName | `ixDnsQueryHostname` | string | yes |  | 13% |
| 190 | DNS Response HostName | `ixDnsResponseHostname` | string | yes |  | 13% |
| 191 | DNS Class | `ixDnsClass` | string | no |  | 13% |
| 201 | SNI | `ixSni` | string | yes |  | <1% |
| 202 | DHCP Client ID | `ixDhcpClientId` | mac | yes |  | 64% |
| 214 | Service Type | `ixServiceType` | long | no |  | 41% |
| 215 | Framed Protocol | `ixFramedProtocol` | long | no |  | 47% |
| 279 | JA3 | `ixJA3` | string | yes |  | <1% |
| 281 | TCP App Response Time | `ixTcpAppResponseTime` | long | no | µs | 76% |
| 284 | UDP App Response Time | `ixUdpAppResponseTime` | long | no | µs | 14% |
| 285 | QUIC Connection Setup Time | `ixQuicConnectionSetupTime` | long | no | µs | 62% |
| 286 | QUIC Connection Round Trip Time | `ixQuicConnectionRoundTripTime` | long | no | µs | 55% |
| 287 | QUIC App Response Time | `ixQuicAppResponseTime` | long | no | µs | 58% |
| 288 | Traffic classification (e.g. "Unmatched traffic") | `ixTrafficClassification` | string | no |  | 100% |
| 321 | Unidirectional Flow | `ixUnidirectionalFlow` | short | no |  | 6% |

Saved fields `ixTcpAppResponseTimeMs`, `ixUdpAppResponseTimeMs` and `ixTransactionLatencyMs` expose the three main latency metrics in milliseconds.

**Value notes**

* Country and region codes are fixed 4-byte fields padded with `\0` (e.g. `TH\0\0`). For filters and grouping prefer the country/region *name* fields.
* All latency/KPI elements are in **microseconds**; `0` means "not measured for this flow" - exclude zeros (`ixTcpAppResponseTime > 0`) before averaging.
* In the reference capture `ixDhcpClientId`, `ixServiceType`, `ixFramedProtocol` and the three `ixQuic*` elements carry unrelated bytes for non-DHCP/RADIUS/QUIC flows. Filter on the matching application before using them.

## 2. Elements that cannot be stored (element id collision)

Sycope identifies NetFlow fields by element id only and ignores the PEN. An IxFlow element whose id is already a Sycope built-in field is decoded as that built-in field (wrong meaning), and ids 176-179 are reserved for ICMP type/code. These elements are **not** defined by `install.py`.

| PEN 3054 element | IxFlow name | Sycope field with that id | Fill | Impact |
|---:|---|---|---:|---|
| 110 | Application ID | `retransmittedOutPackets` | 90% | use `ixApplication` (name) instead of the numeric id |
| 123 | Client IP Region Name | `clientNetworkTime` | 100% | client region name not available |
| 125 | Client IP City Name | `initialServerResponseTime` | 100% | client city not available |
| 127 | Client IP Longitude | `retransmittedInBytes` | 100% | client longitude not available |
| 160 | OS Device ID | `systemInitTime` | 16% | use `ixOsDeviceName` |
| 176 | IxReverse Octet Delta Count | reserved (ICMP type/code range) | 94% | **server->client bytes lost** - see README, Known limitations |
| 177 | IxReverse Packet Delta Count | `icmpIpv4Code` | 94% | **server->client packets lost** |
| 178 | Connection Encryption Type | reserved (ICMP type/code range) | 100% | TLS encryption type not available |
| 179 | Encryption Cipher Name | `icmpIpv6Code` | 100% | TLS cipher not available |
| 180 | Encryption Key Length | `httpUrl` | <1% | rarely filled |
| 182 | HTTP User Agent | `httpReferer` | 44% | HTTP user agent not available |
| 183 | HTTP Hostname | `httpUa` | 46% | HTTP host name not available |
| 184 | HTTP URI | `httpMime` | 46% | HTTP URI not available |
| 187 | Server AS name | `httpHost` | 51% | server AS name not available |
| 203 | DHCP Client MAC | `mplsTopLabelExp` | 66% | DHCP client MAC: use `ixDhcpClientId` |
| 207 | Lease Duration | `dnsQueryType` | 34% | DHCP lease time not available |
| 208 | DHCP Hostname | `dnsRetCode` | 0% | empty in reference capture |
| 209 | RADIUS Events | `dnsNumAnswers` | 100% | empty list in reference capture |
| 225 | Calling Station | `postNatSrcIp` | 0% | empty in reference capture |

## 3. Elements not mapped

**Structured lists (RFC 6313 `subTemplateList` / `basicList`)** - HTTP sessions, DNS records/packets/questions, DHCP events, RADIUS events, TLS server certificate. Sycope does not decode nested IPFIX lists, so per-transaction HTTP/DNS/TLS details are not available:

195 (HTTP Sessions), 197 (DNS Records), 204 (DHCP Events), 209 (RADIUS Events), 229 (structured list (RFC 6313)), 238 (Server Certificate), 253 (DNS Packets), 271 (DNSQuestion).

**Other elements** - numeric ids/coordinates duplicated by name fields, or never filled in the reference capture. You can add any of them with the same pattern as `fields/netflow_fields.json` if your probe fills them:

| PEN 3054 element | IxFlow name | Length | Fill |
|---:|---|---|---:|
| 126 | Client IP Latitude | 4 | 100% |
| 146 | Server Latitude | 4 | 100% |
| 147 | Server Longitude | 4 | 100% |
| 162 | Browser ID | 1 | 0% |
| 185 | DNS Txt | var | 0% |
| 212 | Username | var | 0% |
| 213 | NAS IP Address | 4 | 0% |
| 218 | Called Station | var | 0% |
| 261 | Framed IP | var | 0% |
| 278 | Agent Circuit ID | var | 0% |
| 280 | TCP Connection Setup Time | 4 | 0% |
| 282 | TCP Retransmitted Packets | 4 | 0% |
| 283 | Connection Round Trip Time | 4 | 0% |
| 322 | Server Random | var | <1% |
| 323 | Session ID | var | <1% |
| 324 | To | var | 0% |
| 325 | From | var | 0% |
| 326 | Call-ID | var | 0% |
| 327 | Content-Type | var | 0% |
| 328 | Route | var | 0% |
| 329 | Geolocation | var | 0% |

The standard IANA elements of the template (addresses, ports, protocol, bytes/packets, MAC addresses, TCP flags, AS numbers, flow start/end, flowEndReason) are decoded by Sycope without configuration. `sourceMacAddress` (56) is added to the traffic profile by default (`profile_extra_fields` in `config.json`).
