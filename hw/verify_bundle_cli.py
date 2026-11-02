"""Verify a provenance bundle offline, with no gateway.

    python hw/verify_bundle_cli.py out/bundles/<session>.json
    python hw/verify_bundle_cli.py out/bundles/<session>.json --tamper   # edit frame 0 first
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from keyless_trust import protocol as p  # noqa: E402
from keyless_trust import verify_bundle  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle")
    ap.add_argument("--tamper", action="store_true", help="change one reading in memory before verifying")
    args = ap.parse_args()
    with open(args.bundle) as f:
        bundle = json.load(f)
    if args.tamper:
        bundle["frames"][0]["payload"] = p.b64e(b'{"metric":"temp_c","value":20.0}')
        print("(frame 0 payload edited in memory)")
    problems = verify_bundle(bundle)
    print(f"frames: {len(bundle['frames'])}")
    print("RESULT:", "intact" if not problems else f"FAILED {problems}")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
