#!/usr/bin/env python3
"""
Export and import Sycope traffic profiles (Settings -> NetFlow -> Template Based Settings).

    # save a profile (its settings and fields) to a portable JSON file
    python3 -m sycope.scripts.traffic_profile export --name nProbe -o nprobe_profile.json

    # create or update it on another Sycope and bind it to exporters
    python3 -m sycope.scripts.traffic_profile import nprobe_profile.json --exporter 10.0.0.5 [--dry-run]

    # check which of the profile's fields an exporter actually sends
    python3 -m sycope.scripts.traffic_profile check nprobe_profile.json --exporter 10.0.0.5

Run from the repository root. Connection settings come from a JSON config file with
sycope_host, sycope_login, sycope_pass (and optionally api_base), default ./config.json,
or from the options --host / --user / --password.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import requests  # noqa: E402

from sycope.api import SycopeApi  # noqa: E402
from sycope.config import load_config  # noqa: E402
from sycope.exceptions import SycopeError  # noqa: E402
from sycope.logging import suppress_ssl_warnings  # noqa: E402
from sycope import netflow  # noqa: E402


def connect(args, session):
    cfg = {}
    if os.path.exists(args.config):
        cfg = load_config(args.config)
    host = args.host or cfg.get("sycope_host")
    user = args.user or cfg.get("sycope_login")
    password = args.password if args.password is not None else cfg.get("sycope_pass")
    if not host or not user or password is None:
        raise SystemExit("Sycope connection not configured: use --config or --host/--user/--password")
    if not host.startswith("http"):
        host = "https://" + host
    return SycopeApi(session=session, host=host, login=user, password=password,
                     api_endpoint=cfg.get("api_base", "/npm/api/v1/"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config.json", help="JSON file with sycope_host/sycope_login/sycope_pass")
    ap.add_argument("--host")
    ap.add_argument("--user")
    ap.add_argument("--password")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("export", help="save a traffic profile to a JSON file")
    ex.add_argument("--name", required=True, help="traffic profile name")
    ex.add_argument("-o", "--output", required=True)
    im = sub.add_parser("import", help="create/update a traffic profile from a JSON file")
    im.add_argument("file")
    im.add_argument("--name", help="profile name on the target (default: the exported name)")
    im.add_argument("--exporter", action="append", default=[], help="exporter IP to bind (repeatable)")
    im.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    ck = sub.add_parser("check", help="compare an exporter's templates with a profile file")
    ck.add_argument("file")
    ck.add_argument("--exporter", action="append", required=True)
    args = ap.parse_args(argv)

    suppress_ssl_warnings()
    api = None
    with requests.Session() as session:
        try:
            api = connect(args, session)
            if args.cmd == "export":
                doc = netflow.export_profile(api, args.name)
                with open(args.output, "w", encoding="utf-8") as fp:
                    json.dump(doc, fp, indent=2, ensure_ascii=False)
                    fp.write("\n")
                custom = sum(1 for f in doc["fields"] if not f["builtIn"])
                print(f"Exported '{args.name}' ({doc['profile']['sourceType']}, {len(doc['fields'])} fields, "
                      f"{custom} custom) to {args.output}")
            elif args.cmd == "import":
                doc = netflow.load_profile(args.file)
                res = netflow.import_profile(api, doc, args.exporter, name=args.name, dry_run=args.dry_run,
                                             log=print)
                return 1 if res["skipped"] else 0
            else:
                doc = netflow.load_profile(args.file)
                rc = 0
                for ip in args.exporter:
                    r = netflow.check_exporter(api, doc, ip)
                    print(f"Exporter {ip}: profile {r['bound_profile'] or 'none'}, {r['templates']} template(s), "
                          f"{len(r['sent'])}/{len(r['sent']) + len(r['not_sent'])} profile fields sent")
                    if r["bound_profile"] != r["profile"]:
                        print(f"  ! not bound to '{r['profile']}'")
                        rc = 1
                    if r["not_sent"]:
                        print(f"  not sent: {', '.join(r['not_sent'])}")
                return rc
        except (SycopeError, ValueError, OSError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        finally:
            if api is not None:
                api.log_out()
    return 0


if __name__ == "__main__":
    sys.exit(main())
