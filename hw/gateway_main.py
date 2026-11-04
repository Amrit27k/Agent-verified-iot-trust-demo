"""Gateway process. Verifies every frame and publishes read-only snapshots for the agents.

    python hw/gateway_main.py --crps sensor-a.crps.json sensor-b.crps.json --ttl 10

Snapshots go to ``--out`` (default ./out) every 2 s. The agents only ever read
those files. A human approves a revocation by appending the sensor id to
``out/approved_revocations.txt``; the gateway acts on it at the next tick.
"""

import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from keyless_trust import Gateway, MetricSpec, QualityMonitor  # noqa: E402
from keyless_trust import protocol as p  # noqa: E402
from keyless_trust.transport import serve  # noqa: E402

# CPU temperature range; a real Pi 4 throttles near 80 C.
SPECS = {"temp_c": MetricSpec(0, 100, max_step=5, flatline_after=30, cross_tolerance=8)}


def write(out: str, name: str, data) -> None:
    path = os.path.join(out, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "w") as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(path + ".tmp", path)


def read_approvals(path: str) -> set[str]:
    """Sensor ids a human approved for revocation. Tolerates the UTF-16 that
    Windows PowerShell's `>>` writes, and drops anything that is not a plain id."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return set()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig", errors="replace")
    return {line.strip() for line in text.splitlines() if line.strip()}


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--crps", nargs="+", required=True)
    ap.add_argument("--ttl", type=float, default=10.0, help="session key lifetime, seconds")
    ap.add_argument("--out", default="out")
    args = ap.parse_args()

    quality = QualityMonitor(SPECS)
    alerts: list[dict] = []

    def on_alert(name: str, details: dict) -> None:
        alerts.append({"alert": name, **details})
        print(f"  ALERT {name}: {details}", flush=True)

    gateway = Gateway(session_ttl=args.ttl, quality=quality, low_crp_threshold=6, on_alert=on_alert)
    sensors = []
    for path in args.crps:
        with open(path) as f:
            data = json.load(f)
        crps = {p.b64d(c): p.b64d(r) for c, r in data["crps"]}
        gateway.register(data["sensor_id"], crps)
        sensors.append(data["sensor_id"])
        print(f"enrolled {data['sensor_id']} with {len(crps)} CRPs")

    sessions: dict[str, str] = {}

    def on_frame(frame) -> None:
        sessions[frame.session_id] = frame.sensor_id
        status = "usable     " if frame.usable else "QUARANTINED"
        verdict = ",".join(frame.flags) or "ok"
        print(f"  {frame.sensor_id} #{frame.seq} {status} [{verdict}] {frame.payload[:60].decode(errors='replace')}", flush=True)

    server = await serve(gateway, args.host, args.port, on_frame)
    print(f"gateway listening on {args.host}:{args.port}, session TTL {args.ttl}s")

    approved: set[str] = set()
    approval_file = os.path.join(args.out, "approved_revocations.txt")
    seen_rejections = 0
    while True:
        for sensor_id in read_approvals(approval_file) - approved:
            approved.add(sensor_id)
            if sensor_id not in sensors:
                print(f"  IGNORED revocation of unknown sensor id {sensor_id!r}", flush=True)
                continue
            gateway.revoke_sensor(sensor_id, "approved by human operator")
            print(f"  REVOKED {sensor_id} (human approval)", flush=True)

        entries = list(gateway.audit)
        for e in entries[seen_rejections:]:
            if e["event"] == "rejected":
                print(f"  REJECTED {e.get('reason')} {e.get('detail', '')}", flush=True)
        seen_rejections = len(entries)

        write(args.out, "audit.json", {"chain_intact": gateway.audit.verify(), "head": gateway.audit.head, "entries": entries})
        write(args.out, "keys.json", {
            "live_session_keys": gateway.key_inventory(),
            "enrollment": {s: gateway.enrollment_status(s) for s in sensors},
            "alerts": alerts,
        })
        write(args.out, "quality.json", quality.report())
        write(args.out, "provenance.json", {
            "chain_intact": gateway.provenance.verify(),
            "head": gateway.provenance.head,
            "sessions": sessions,
        })
        for session_id in list(sessions):
            try:
                write(args.out, f"bundles/{session_id}.json", gateway.provenance.export_session(session_id))
            except Exception as exc:  # a session with no frames yet
                print(f"  (no bundle for {session_id[:8]}: {exc})", flush=True)
        await asyncio.sleep(2)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
