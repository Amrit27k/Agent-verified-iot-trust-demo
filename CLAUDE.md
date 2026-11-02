# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Requires Python 3 and `cryptography` (Ed25519). No build step, no lint config.

```bash
python3 demo.py                                   # 2 sensors + gateway over TCP: quality, attacks, keys, provenance
python3 -m unittest discover -s tests -v          # full suite
python3 -m unittest tests.test_trust              # one module
python3 -m unittest tests.test_trust.SomeClass.test_name   # one test
```

Multi-process hardware flow (`hw/`): `factory_enroll.py` (writes one-time CRPs JSON) → `gateway_main.py --crps ...` (serves over TCP, writes snapshots to `out/` every 2s) → `sensor_main.py --id ... --puf-file ... --gateway HOST:9000` → optionally `attack.py` (network attacker using a `--tap` capture) and `agents.py` (headless read-only `claude -p` auditors over `out/`). `verify_bundle_cli.py <bundle>` verifies a provenance bundle offline (`--tamper` demonstrates failure). Scripts in `hw/` add the repo root to `sys.path` themselves.

## Architecture

Keyless sensor→gateway trust: no long-lived keys exist. Identity is a (simulated) PUF; the gateway holds one-time challenge–response pairs (CRPs); each session uses an ephemeral RAM-only Ed25519 key bound to the PUF via an HMAC attestation. README.md has the full protocol diagram and threat table.

`keyless_trust/` modules:
- `protocol.py` – wire formats, HMAC proofs, frame signing bytes/hash, `Rejected` exception. Shared by both sides, so protocol changes touch sensor, gateway and provenance verification together.
- `gateway.py` – the core. `handle_hello` → `handle_attest` establish sessions; `verify_frame` runs the ordered checks (session → signature → expiry/frame cap → seq → hash-chain → timestamp). **Order matters**: signature is verified first so forged frames never touch session state. Only after origin is proven does the frame advance the chain, then quality runs, then provenance is recorded. Handlers are wrapped in `_guard` (malformed input → `Rejected("malformed")`). All rejections go through `_reject`, which also writes the audit log.
- `sensor.py`, `puf.py`, `enrollment.py` – device side, simulated PUF, factory CRP enrollment.
- `quality.py` – `QualityMonitor` with per-metric `MetricSpec`; runs only on authenticated frames. Unusable readings are quarantined (`usable=False`) but still advance the chain.
- `provenance.py` – hash-chained ledger plus `export_session` / `verify_bundle` (offline verification without the gateway).
- `audit.py` – hash-chained gateway audit log (`verify()`).
- `transport.py` – asyncio TCP server/client (`serve`, `SensorClient`) with per-connection rate limiting.

Key design invariants to preserve: a frame's `sensor_id` comes from the attested session, never the frame; a failed attestation must not consume or cancel a pending challenge (handshake-flood resistance, cap via `max_outstanding_challenges`, `busy` when full); a CRP is consumed only on successful attestation (`_release` returns unanswered ones to the pool).

## Testing

Tests subclass `TrustTestCase` in `tests/helpers.py`, which builds a `Gateway` with a `FakeClock` (inject `clock=` to control time; `self.clock.advance(s)`), two enrolled sensors `a`/`b` (`self.a`, `self.b`), and helpers `attest(sensor)` and `assertRejected(reason, fn, *args)`. Override `gateway_args()` to configure the gateway. Gateway/Sensor take an injectable `clock` — use it rather than sleeping.

## Notes

- `out/` holds generated snapshots (audit, keys, provenance, quality, bundles); `__pycache__` is checked in the tree — both are artifacts, not source.
- `hw/agents.py` treats everything in `out/` as untrusted data and restricts the agents to Read plus the bundle verifier; keep that restriction when editing it.
