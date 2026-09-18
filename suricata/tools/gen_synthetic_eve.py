#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate a synthetic Suricata eve.json file for benchmarking the log
processor's JSON parsing and prefiltering.

Event mix approximates production traffic: SMB dominates (~50%), and most
SMB events are the high-volume, low-security-value commands
(SMB2_COMMAND_CREATE/CLOSE/FIND) that the default blacklist filters out.
The remainder is spread across alert/dns/tls/http/ssh/ftp/etc.

Usage:
    python3 gen_synthetic_eve.py OUTPUT_PATH [--target-mb 500] [--seed 42]
"""

import argparse
import json
import random
import sys

SMB_NOISY_COMMANDS = ["SMB2_COMMAND_CREATE", "SMB2_COMMAND_CLOSE", "SMB2_COMMAND_FIND"]
SMB_OTHER_COMMANDS = ["SMB2_COMMAND_READ", "SMB2_COMMAND_WRITE", "SMB2_COMMAND_IOCTL"]

# (event_type, relative weight)
EVENT_TYPE_WEIGHTS = [
    ("smb", 50),
    ("dns", 15),
    ("tls", 10),
    ("http", 8),
    ("alert", 5),
    ("ssh", 3),
    ("ftp", 3),
    ("anomaly", 2),
    ("krb5", 2),
    ("dhcp", 2),
]


def random_ip(rng):
    return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def make_event(rng, event_type, idx):
    base = {
        "timestamp": f"2026-09-18T10:{idx % 60:02d}:{idx % 60:02d}.{idx % 1000:03d}+0000",
        "flow_id": 1000000 + idx,
        "in_iface": "eth0",
        "event_type": event_type,
        "src_ip": random_ip(rng),
        "src_port": rng.randint(1024, 65535),
        "dest_ip": random_ip(rng),
        "dest_port": rng.choice([80, 443, 445, 22, 21, 53, 88]),
        "proto": "TCP",
        "app_proto": event_type,
    }

    if event_type == "smb":
        command = rng.choice(SMB_NOISY_COMMANDS) if rng.random() < 0.85 else rng.choice(SMB_OTHER_COMMANDS)
        base["smb"] = {
            "command": command,
            "status": "STATUS_SUCCESS",
            "dialect": "3.1.1",
            "session_id": rng.randint(1, 999999),
            "tree_id": rng.randint(1, 100),
            "access": "read",
            "filename": f"\\\\share\\file_{idx}.dat",
        }
    elif event_type == "alert":
        base["alert"] = {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2000000 + (idx % 500),
            "rev": 1,
            "signature": "SYNTHETIC TEST SIGNATURE",
            "category": "Generic",
            "severity": rng.randint(1, 3),
        }
    elif event_type == "anomaly":
        base["anomaly"] = {"type": "applayer", "event": "generic_anomaly"}
    elif event_type == "tls":
        base["tls"] = {
            "ja4": f"t13d{idx % 1000:04d}",
            "client_alpns": ["h2", "http/1.1"],
            "subjectaltname": [f"DNS:host{idx % 50}.example.com"],
        }
    elif event_type == "dns":
        base["dns"] = {"rrname": f"host{idx % 200}.example.com", "rrtype": "A"}
    elif event_type == "http":
        base["http"] = {"hostname": f"host{idx % 200}.example.com", "url": "/index.html"}
    elif event_type == "ssh":
        base["ssh"] = {"client": {"software_version": "OpenSSH_8.4"}, "server": {"software_version": "OpenSSH_8.9"}}
    elif event_type == "ftp":
        base["ftp"] = {"command": "RETR", "reply": "150 Opening data connection"}
    elif event_type == "krb5":
        base["krb5"] = {"msg_type": "AS-REQ", "cname": f"user{idx % 100}", "realm": "EXAMPLE.COM"}
    elif event_type == "dhcp":
        base["dhcp"] = {"dhcp_type": "request", "client_mac": "aa:bb:cc:dd:ee:ff", "assigned_ip": random_ip(rng)}

    return base


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", help="Path to write the generated eve.json")
    parser.add_argument("--target-mb", type=int, default=500, help="Approximate output size in MB (default: 500)")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for reproducibility")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    types, weights = zip(*EVENT_TYPE_WEIGHTS)

    target_bytes = args.target_mb * 1024 * 1024
    written = 0
    idx = 0

    with open(args.output, "w", encoding="utf-8") as f:
        while written < target_bytes:
            event_type = rng.choices(types, weights=weights, k=1)[0]
            # Suricata's own eve.json output has no whitespace around
            # separators; match that so the prefilter benchmark reflects
            # real-world line shape.
            line = json.dumps(make_event(rng, event_type, idx), separators=(",", ":")) + "\n"
            f.write(line)
            written += len(line)
            idx += 1
            if idx % 100000 == 0:
                print(f"  ...{idx} lines, {written / (1024 * 1024):.0f} MB", file=sys.stderr)

    print(f"Wrote {idx} lines, {written / (1024 * 1024):.1f} MB to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
