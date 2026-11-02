"""Factory step, run once on the sensor board over a trusted bench connection.

    python3 hw/factory_enroll.py --id sensor-a --puf-file puf.seed --count 32 > sensor-a.crps.json

Copy the JSON to the gateway machine. The PUF response itself never leaves the
board except as these one-time challenge/response pairs.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from keyless_trust import SimulatedPUF  # noqa: E402
from keyless_trust import protocol as p  # noqa: E402
from keyless_trust.enrollment import CHALLENGE_SIZE  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--puf-file", required=True)
    ap.add_argument("--count", type=int, default=32)
    ap.add_argument("--out", help="write here instead of stdout (PowerShell's > writes UTF-16, which breaks JSON)")
    args = ap.parse_args()

    puf = SimulatedPUF(args.puf_file)
    crps = []
    for _ in range(args.count):
        challenge = os.urandom(CHALLENGE_SIZE)
        crps.append([p.b64e(challenge), p.b64e(puf.respond(challenge))])
    doc = {"sensor_id": args.id, "crps": crps}
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f)
    else:
        json.dump(doc, sys.stdout)


if __name__ == "__main__":
    main()
