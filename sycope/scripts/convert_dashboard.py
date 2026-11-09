#!/usr/bin/env python3
"""
Convert Sycope dashboard exports between the 3.3 and 3.2 formats.

Dashboards in this repository use the Sycope 3.3 format. To import one into
Sycope 3.2 (legacy) from the GUI, convert it first:

    python3 -m sycope.scripts.convert_dashboard --to 3.2 keysight/dashboards/*.json -o dashboards-3.2/

Run the command from the repository root. Converting an old 3.2 export to 3.3
works the same way with ``--to 3.3``. Files are only read and written locally;
nothing is sent to Sycope.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from sycope.dashboards import convert, detect_format  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="dashboard export files (.json)")
    ap.add_argument("--to", required=True, choices=["3.2", "3.3"], help="target Sycope version")
    ap.add_argument("-o", "--outdir", required=True,
                    help="output directory (files keep their names; must differ from the input directory)")
    args = ap.parse_args(argv)

    os.makedirs(args.outdir, exist_ok=True)
    rc = 0
    for path in args.files:
        if os.path.abspath(os.path.dirname(path)) == os.path.abspath(args.outdir):
            print(f"SKIP {path}: output directory is the input directory", file=sys.stderr)
            rc = 1
            continue
        warnings = []
        try:
            with open(path, encoding="utf-8") as fp:
                doc = json.load(fp)
            source = detect_format(doc)
            out = convert(doc, args.to, warn=warnings.append)
        except (OSError, ValueError) as e:
            print(f"SKIP {path}: {e}", file=sys.stderr)
            rc = 1
            continue
        dst = os.path.join(args.outdir, os.path.basename(path))
        with open(dst, "w", encoding="utf-8") as fp:
            json.dump(out, fp, indent=2, ensure_ascii=False)
            fp.write("\n")
        note = "unchanged" if source == args.to else f"{source} -> {args.to}"
        print(f"OK   {path} -> {dst} ({note})")
        for w in warnings:
            print(f"     ! {w}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
