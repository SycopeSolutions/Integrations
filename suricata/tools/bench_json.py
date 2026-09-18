#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Benchmark line-by-line JSON parsing approaches against a real-sized eve.json,
to decide whether eve_processor.py should use an optional faster JSON library.

Variants measured:
  - json (stdlib)
  - orjson (if installed)
  - pysimdjson, with a single reused Parser() instance (if installed)
  - each of the above combined with a raw-string prefilter that skips lines
    not containing any of the configured event_type markers, to separate the
    prefilter's contribution from the parser's.

Usage:
    python3 bench_json.py PATH_TO_EVE_JSON [--event-types smb,alert,anomaly]
"""

import argparse
import json
import sys
import time

try:
    import orjson
except ImportError:
    orjson = None

try:
    import simdjson
except ImportError:
    simdjson = None


def build_needles(event_types):
    return [f'"event_type":"{et}"' for et in event_types]


def passes_prefilter(line, needles):
    return any(n in line for n in needles)


def read_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.readlines()


def bench(name, lines, parse_fn, needles=None):
    start = time.perf_counter()
    parsed = 0
    skipped = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if needles is not None and not passes_prefilter(line, needles):
            skipped += 1
            continue
        parse_fn(line)
        parsed += 1
    elapsed = time.perf_counter() - start
    rate = parsed / elapsed if elapsed > 0 else 0
    print(f"{name:40s} parsed={parsed:>8d} skipped={skipped:>8d} time={elapsed:7.3f}s rate={rate:>10.0f} lines/s")
    return elapsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("eve_path", help="Path to the eve.json file to benchmark against")
    parser.add_argument(
        "--event-types",
        default="smb,alert,anomaly",
        help="Comma-separated event_type values used for the prefilter (default: smb,alert,anomaly)",
    )
    args = parser.parse_args()

    print(f"Loading lines from {args.eve_path} ...", file=sys.stderr)
    lines = read_lines(args.eve_path)
    print(f"{len(lines)} lines loaded\n", file=sys.stderr)

    needles = build_needles(args.event_types.split(","))

    print("=== No prefilter (parse every line) ===")
    bench("stdlib json", lines, json.loads)
    if orjson is not None:
        bench("orjson", lines, orjson.loads)
    else:
        print("orjson: not installed, skipped")
    if simdjson is not None:
        sj_parser = simdjson.Parser()
        bench("pysimdjson (reused Parser)", lines, sj_parser.parse)
    else:
        print("pysimdjson: not installed, skipped")

    print("\n=== With raw-string prefilter (skip non-matching lines) ===")
    bench("stdlib json + prefilter", lines, json.loads, needles=needles)
    if orjson is not None:
        bench("orjson + prefilter", lines, orjson.loads, needles=needles)
    if simdjson is not None:
        sj_parser = simdjson.Parser()
        bench("pysimdjson + prefilter", lines, sj_parser.parse, needles=needles)


if __name__ == "__main__":
    main()
