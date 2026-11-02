"""Sensor process. Reads the board's own temperature and streams signed frames.

    python3 hw/sensor_main.py --id sensor-a --puf-file puf.seed --gateway 192.168.1.10:9000
    python3 hw/sensor_main.py --id sensor-b --puf-file b.seed --gateway HOST:9000 --source sim

``--fault 8=999`` replaces frame 8's reading (a failing probe).
``--fault 12=text:...`` sends raw text instead of a reading.
``--tap frames.jsonl`` records the wire frames, which stand in for what an
eavesdropper on the network would see (used by attack.py).
"""

import argparse
import asyncio
import json
import math
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from keyless_trust import Rejected, Sensor, SimulatedPUF, encode_reading  # noqa: E402
from keyless_trust.transport import SensorClient  # noqa: E402

THERMAL = "/sys/class/thermal/thermal_zone0/temp"


def cpu_temp_c() -> float:
    try:
        with open(THERMAL) as f:
            return int(f.read()) / 1000
    except OSError:
        out = subprocess.check_output(["vcgencmd", "measure_temp"], text=True)  # temp=48.3'C
        return float(out.split("=")[1].split("'")[0])


def sim_temp_c(n: int) -> float:
    return 48 + 0.6 * math.sin(n / 3)


class TappedClient(SensorClient):
    def __init__(self, *args, tap: str | None = None) -> None:
        super().__init__(*args)
        self._tap = tap

    async def call(self, msg: dict) -> dict:
        if self._tap and msg.get("type") == "frame":
            with open(self._tap, "a") as f:
                f.write(json.dumps(msg) + "\n")
        return await super().call(msg)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--puf-file", required=True)
    ap.add_argument("--gateway", required=True, help="host:port")
    ap.add_argument("--source", choices=["cpu", "sim"], default="cpu")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--fault", action="append", default=[], metavar="N=VALUE")
    ap.add_argument("--tap")
    args = ap.parse_args()

    host, port = args.gateway.rsplit(":", 1)
    faults = dict(f.split("=", 1) for f in args.fault)
    sensor = Sensor(args.id, SimulatedPUF(args.puf_file))

    async with TappedClient(sensor, host, int(port), tap=args.tap) as client:
        n = 0
        while True:
            fault = faults.get(str(n))
            if fault is None:
                payload = encode_reading("temp_c", round(cpu_temp_c() if args.source == "cpu" else sim_temp_c(n), 2))
            elif fault.startswith("text:"):
                payload = fault[5:].encode()
            else:
                payload = encode_reading("temp_c", float(fault))
            try:
                ack = await client.send(payload)
                flags = ",".join(ack["flags"]) or "ok"
                print(f"#{n} {payload.decode()} -> ack seq {ack['seq']} [{flags}]", flush=True)
            except Rejected as exc:
                print(f"#{n} REJECTED by gateway: {exc.reason}", flush=True)
            n += 1
            await asyncio.sleep(args.interval)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
