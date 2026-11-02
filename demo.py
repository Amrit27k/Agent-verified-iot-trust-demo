"""Two sensors stream to one gateway over TCP. Shows, in order:

  1. streaming with data-quality checks   (Data quality)
  2. attacks, all rejected                (Security)
  3. key inventory and revocation         (Key management)
  4. a verifiable provenance export       (Provenance)

    python3 demo.py
"""

import asyncio
import copy
import json
import math

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyless_trust import (
    Gateway,
    MetricSpec,
    QualityMonitor,
    Rejected,
    Sensor,
    SimulatedPUF,
    encode_reading,
    enroll,
    verify_bundle,
)
from keyless_trust import protocol as p
from keyless_trust.transport import SensorClient, serve

HOST = "127.0.0.1"
SPECS = {"temp_c": MetricSpec(-20, 60, max_step=5, flatline_after=8, cross_tolerance=2.5)}


def reading(sensor_id: str, n: int) -> bytes:
    """Healthy readings, except two deliberate faults."""
    value = 22 + 0.4 * math.sin(n) + (0.3 if sensor_id == "sensor-b" else 0)
    if sensor_id == "sensor-a" and n == 3:
        value = 999.0  # failing probe
    if sensor_id == "sensor-b" and n == 4:
        value = 30.0  # glitch
    return encode_reading("temp_c", round(value, 2))


async def raw_call(port: int, msg: dict) -> dict:
    reader, writer = await asyncio.open_connection(HOST, port)
    writer.write(json.dumps(msg).encode() + b"\n")
    await writer.drain()
    reply = json.loads(await reader.readline())
    writer.close()
    return reply


async def stream(client: SensorClient, count: int, interval: float) -> None:
    async with client:
        for n in range(count):
            await client.send(reading(client.sensor.sensor_id, n))
            await asyncio.sleep(interval)


def heading(text: str) -> None:
    print(f"\n== {text} ==")


async def main() -> None:
    quality = QualityMonitor(SPECS)
    alerts = []
    # Short sessions so the demo shows key rotation.
    gateway = Gateway(
        session_ttl=2.0,
        quality=quality,
        low_crp_threshold=12,
        on_alert=lambda name, details: alerts.append((name, details)),
    )
    pufs = {"sensor-a": SimulatedPUF(), "sensor-b": SimulatedPUF()}
    for sensor_id, puf in pufs.items():
        enroll(gateway, sensor_id, puf, count=16)  # factory step, done once

    sessions_seen: dict[str, set[str]] = {}

    def on_frame(frame):
        sessions_seen.setdefault(frame.sensor_id, set()).add(frame.session_id)
        verdict = "ok" if not frame.flags else ",".join(frame.flags)
        status = "usable     " if frame.usable else "QUARANTINED"
        print(f"  {frame.sensor_id} #{frame.seq} {status} [{verdict}] {frame.payload.decode()}")

    server = await serve(gateway, HOST, 0, on_frame)
    port = server.sockets[0].getsockname()[1]

    heading("1. Streaming + data quality (origin verified on every frame)")
    sensor_a = Sensor("sensor-a", pufs["sensor-a"])
    sensor_b = Sensor("sensor-b", pufs["sensor-b"])
    await asyncio.gather(
        stream(SensorClient(sensor_a, HOST, port), count=6, interval=0.5),
        stream(SensorClient(sensor_b, HOST, port), count=6, interval=0.5),
    )
    for sensor_id, ids in sessions_seen.items():
        print(f"  {sensor_id}: {len(ids)} sessions (ephemeral key rotated {len(ids) - 1}x)")
    for sensor_id, row in quality.report().items():
        print(f"  quality {sensor_id}: score {row['score']} ({row['usable']}/{row['frames']} usable) flags {row['flags']}")

    heading("2. Attacks")

    def outcome(label: str, reply: dict) -> None:
        verdict = f"REJECTED ({reply['reason']})" if reply.get("type") == "error" else "ACCEPTED!"
        print(f"  {label:<52} -> {verdict}")

    impostor = Sensor("sensor-b", SimulatedPUF())
    challenge = await raw_call(port, impostor.hello())
    outcome("impostor attests as sensor-b", await raw_call(port, impostor.respond(challenge)))
    outcome("unenrolled sensor-x says hello", await raw_call(port, {"type": "hello", "sensor_id": "sensor-x"}))

    # A stranger spamming hello for sensor-a must not break sensor-a's handshake.
    async with SensorClient(sensor_a, HOST, port) as client_a:
        challenge = await client_a.call(sensor_a.hello())
        attest = sensor_a.respond(challenge)
        for _ in range(5):
            await raw_call(port, {"type": "hello", "sensor_id": "sensor-a"})
        client_a.sensor.establish(await client_a.call(attest))
        print("  handshake DoS (5 rogue hellos mid-handshake)         -> sensor-a still attested")

        captured = sensor_a.frame(reading("sensor-a", 100))
        await client_a.call(captured)
        outcome("replay captured sensor-a frame", await raw_call(port, captured))
        tampered = dict(captured, payload=p.b64e(b'{"metric":"temp_c","value":-19}'))
        outcome("tamper with sensor-a payload", await raw_call(port, tampered))
        forged = {**captured, "seq": 1, "prev": p.b64e(p.frame_hash(captured))}
        forged["sig"] = p.b64e(Ed25519PrivateKey.generate().sign(p.frame_signing_bytes(forged)))
        outcome("inject forged frame into sensor-a session", await raw_call(port, forged))

        async with SensorClient(sensor_b, HOST, port) as client_b:
            await client_b.attest()
            spoof = sensor_b.frame(reading("sensor-a", 999))
            spoof.update(session_id=sensor_a.session_id, seq=1, prev=forged["prev"])
            outcome("sensor-b masquerades as sensor-a", await raw_call(port, spoof))

        ack = await client_a.call(sensor_a.frame(reading("sensor-a", 101)))
        print(f"  sensor-a keeps streaming afterwards                  -> ack seq {ack['seq']}")
        proven_session = sensor_a.session_id

    heading("3. Key management")
    print("  live session keys (public material only):")
    for row in gateway.key_inventory():
        print(f"    {row['sensor_id']}: key {row['key_fingerprint']}  CRP {row['challenge_id']}  "
              f"frames {row['frames']}/{row['max_frames']}  expires in {row['expires_in_s']:.1f}s")
    for sensor_id in pufs:
        status = gateway.enrollment_status(sensor_id)
        print(f"  {sensor_id}: {status['available']} CRPs available, {status['outstanding']} in flight")
    for name, details in alerts:
        print(f"  ALERT {name}: {details}")

    gateway.revoke_sensor("sensor-b", "suspected tampering")
    outcome("sensor-b after revocation says hello", await raw_call(port, sensor_b.hello()))
    print(f"  sensor-b enrollment after revocation: {gateway.enrollment_status('sensor-b')}")

    server.close()
    await server.wait_closed()

    heading("4. Provenance")
    lineage = gateway.provenance.lineage(proven_session, 0)
    record, session = lineage["record"], lineage["session"]
    print(f"  frame #0 of session {proven_session[:8]}: sensor {record['sensor_id']}, key {session['key_fingerprint']}, "
          f"CRP {session['challenge_id']}, payload sha256 {record['payload_sha256'][:16]}...")
    bundle = gateway.provenance.export_session(proven_session)
    print(f"  exported {len(bundle['frames'])} frames; verified standalone: {verify_bundle(bundle) or 'intact'}")
    forged_bundle = copy.deepcopy(bundle)
    forged_bundle["frames"][0]["payload"] = p.b64e(b'{"metric":"temp_c","value":-19}')
    print(f"  after editing a reading in the bundle:  {verify_bundle(forged_bundle)}")
    print(f"  ledger chain intact: {gateway.provenance.verify()}   head (anchor this): {gateway.provenance.head[:24]}...")

    heading("Audit log")
    rejected = [e for e in gateway.audit if e["event"] == "rejected"]
    print(f"  {len(gateway.audit)} entries, {len(rejected)} rejections, chain intact: {gateway.audit.verify()}")


if __name__ == "__main__":
    asyncio.run(main())
