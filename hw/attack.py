"""Attacker on the network. Needs no keys, only what a network eavesdropper sees.

    python hw/attack.py --gateway 192.168.1.10:9000 --tap frames.jsonl

``frames.jsonl`` is the wire capture written by ``sensor_main.py --tap``.
"""

import argparse
import asyncio
import json
import os
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from keyless_trust import Sensor, SimulatedPUF, encode_reading  # noqa: E402
from keyless_trust import protocol as p  # noqa: E402


async def raw_call(host: str, port: int, msg: dict) -> dict:
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(json.dumps(msg).encode() + b"\n")
    await writer.drain()
    reply = json.loads(await reader.readline())
    writer.close()
    return reply


def show(label: str, reply: dict) -> None:
    verdict = f"REJECTED ({reply['reason']})" if reply.get("type") == "error" else "ACCEPTED!"
    print(f"  {label:<46} -> {verdict}", flush=True)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", required=True)
    ap.add_argument("--tap", required=True)
    ap.add_argument("--victim", default="sensor-a")
    args = ap.parse_args()
    host, port = args.gateway.rsplit(":", 1)
    port = int(port)

    with open(args.tap) as f:
        captured = json.loads(f.readlines()[-1])

    age = time.time() - captured["ts"] / 1000
    print(f"== attacks (captured frame is {age:.0f}s old) ==")
    if age > 5:
        print("  warning: the capture is stale; if its session has ended, replay/tamper/forge are rejected as "
              "unknown_session instead of bad_sequence/bad_signature. Run this next to the sensor, while it is streaming.")
    clone = Sensor(args.victim, SimulatedPUF())  # different silicon, same name
    challenge = await raw_call(host, port, clone.hello())
    show(f"cloned board claims to be {args.victim}", await raw_call(host, port, clone.respond(challenge)))
    show("unenrolled sensor-x says hello", await raw_call(host, port, {"type": "hello", "sensor_id": "sensor-x"}))
    show("replay a captured frame", await raw_call(host, port, captured))
    tampered = dict(captured, payload=p.b64e(encode_reading("temp_c", 20.0)))
    show("tamper with the captured reading", await raw_call(host, port, tampered))
    forged = {**captured, "seq": captured["seq"] + 1, "prev": p.b64e(p.frame_hash(captured))}
    forged["sig"] = p.b64e(Ed25519PrivateKey.generate().sign(p.frame_signing_bytes(forged)))
    show("inject a forged frame into the live session", await raw_call(host, port, forged))
    for i in range(5):
        reply = await raw_call(host, port, {"type": "hello", "sensor_id": args.victim})
    print(f"  5 rogue hellos for {args.victim} (handshake flood)    -> last reply: {reply.get('reason', reply.get('type'))}")


if __name__ == "__main__":
    asyncio.run(main())
