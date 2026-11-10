"""Offline CLI. Exit 1 means HOLD, exit 2 means invalid input or execution failure."""
import argparse
import json
from pathlib import Path
from .core import diff, markdown, run_suite, summary, verify, write_private
from .fixtures import Fixture, suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo")
    demo.add_argument("--mode", choices=["guarded", "vulnerable", "deny_all"], default="guarded")
    demo.add_argument("--out", default="runs/demo")
    export = sub.add_parser("export-suite")
    export.add_argument("--out", default="runs/suite.json")
    check = sub.add_parser("verify")
    check.add_argument("bundle")
    check.add_argument("--expected-head")
    compare = sub.add_parser("diff")
    compare.add_argument("before")
    compare.add_argument("after")
    args = parser.parse_args()
    try:
        if args.command == "demo":
            bundle = run_suite(suite(), lambda c: Fixture(args.mode, c.get("setup")), target="synthetic:" + args.mode)
            write_private(Path(args.out) / "evidence.json", json.dumps(bundle, indent=2))
            write_private(Path(args.out) / "report.md", markdown(bundle))
            print(json.dumps(summary(bundle), indent=2))
            print("Evidence head:", bundle["head"])
            return 0 if summary(bundle)["release_gate"] == "PASS" else 1
        if args.command == "export-suite":
            write_private(args.out, json.dumps(suite(), indent=2))
            print(args.out)
            return 0
        read = lambda p: json.loads(Path(p).read_text(encoding="utf-8"))
        if args.command == "verify":
            valid = verify(read(args.bundle), args.expected_head)
            print(json.dumps({"integrity_valid": valid, "external_head_supplied": args.expected_head is not None}))
            return 0 if valid else 1
        print(json.dumps(diff(read(args.before), read(args.after)), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("Operation failed:", type(exc).__name__)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
