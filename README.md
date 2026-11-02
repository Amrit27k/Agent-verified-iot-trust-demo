# Keyless sensor → gateway trust

Two sensors stream to one gateway. The gateway verifies the origin of **every frame**.
No long-lived keys exist anywhere, so there is nothing to provision, store, rotate or revoke.

```bash
python3 demo.py                              # 2 sensors + gateway over TCP: quality, attacks, keys, provenance
python3 -m unittest discover -s tests -v     # 85 tests
```

Requires `cryptography` (Ed25519).

## Coverage of the four topics

| Topic | What the system does | Where |
|---|---|---|
| **Security** | Mutual attestation; per-frame signature, sequence, hash-chain and timestamp checks; replay, tamper, spoof and clone defences; handshake-flood resistance; per-connection rate limit; tamper-evident audit log | `gateway.py`, `sensor.py`, `transport.py`, `audit.py` |
| **Provenance** | Ledger of which sensor, session key and enrollment CRP vouched for each frame, with payload digest and quality verdict; exportable bundles anyone can verify offline | `provenance.py` |
| **Key management** | PUF root instead of stored keys; ephemeral per-session keys; rotation by time *and* frame count; revocation; key inventory; CRP-pool alerts | `gateway.py`, `puf.py`, `enrollment.py` |
| **Data quality** | Schema, range, spike, flatline, gap and cross-sensor agreement checks; bad readings are quarantined, never silently dropped | `quality.py` |

## How "keyless" works

| Usually a key… | Here instead |
|---|---|
| Device private key in flash | **PUF**: the identity comes from silicon variation and is never stored |
| Certificate per device | **One-time enrollment**: the gateway records challenge–response pairs (CRPs) at the factory |
| Long-lived signing key | **Ephemeral Ed25519 key** per session, RAM-only, bound to the PUF at attestation |
| Key rotation / revocation | Sessions expire → the sensor re-attests with a new CRP and key. Revoking is one call |

## Protocol

```
Sensor                                        Gateway
  hello{sensor_id}                    ─────►  reserve unused CRP (c, r)
                                      ◄─────  challenge{c, nonce}
  new ephemeral key k, pub K
  r = PUF(c)
  attest{c, K, HMAC_r(id‖c‖nonce‖K)}  ─────►  check HMAC → K belongs to sensor_id; consume CRP
                                      ◄─────  session{sid, exp, max_frames, HMAC_r(sid‖K‖exp‖max_frames)}
  check gateway proof (mutual auth; limits are authenticated too)

  frame{sid, seq, ts, prev, payload,
        sig = Sign_k(all fields)}     ─────►  for every frame:
                                                1. session exists
                                                2. Ed25519 signature valid under K
                                                3. session not expired / not out of frames
                                                4. seq == expected       (replay / drop / reorder)
                                                5. prev == hash(last)    (hash-chained stream)
                                                6. ts within skew and monotonic
                                                ── origin proven ──
                                                7. quality checks on the payload
                                                8. provenance record written
                                      ◄─────  ack{seq, usable, flags}
```

The PUF response `r` never goes over the wire. Only HMACs keyed by it do. A frame's `sensor_id`
comes from the attested session, never from the frame itself.

## Security

Each of these is tested:

- Cloned device using a known sensor ID → `bad_attestation`; unenrolled device → `unknown_sensor`
- Sensor B speaking for sensor A, or an injected or forged frame → `bad_signature`
- Payload tampered in flight → `bad_signature`
- Replayed, dropped or reordered frame → `bad_sequence`
- Replayed attestation → `no_challenge`; public key swapped during attestation → `bad_attestation`
- Rogue gateway → the sensor raises `GatewayNotTrusted`; session limits can't be loosened in transit
- Expired session or clock skew → `session_expired` / `bad_timestamp`
- Forged frames are rejected before touching session state, so they cannot disrupt the victim
- **Handshake flooding:** several challenges can be outstanding per sensor (cap 4), a failed attestation
  doesn't cancel or burn the real one, and when the cap is full new hellos get `busy` instead of evicting
  an in-flight handshake
- **Per-connection** token-bucket rate limit, and a connection is dropped after repeated errors
- Gateway audit log is hash-chained: `gateway.audit.verify()` detects edits or deletions

## Key management

| Lifecycle step | Mechanism |
|---|---|
| Creation | Sensor generates an Ed25519 key per session; it exists only in RAM |
| Binding | Attestation HMAC ties the public key to the PUF response of an enrolled CRP |
| Rotation | `session_ttl` **and** `max_frames_per_session`; both enforced by the gateway, not just the sensor |
| Revocation | `revoke_session(id)` ends one key; `revoke_sensor(id)` also destroys its CRPs and refuses further hellos; `reinstate_sensor` + re-enrollment to undo |
| Inventory | `key_inventory()` lists live keys with fingerprint, CRP id, age, expiry and frame counts. Only public material exists on the gateway |
| Capacity | `crps_low` alert (once per sensor, re-armed by re-enrollment); `crps_exhausted` rejection |
| Destruction | Session ends → the gateway drops the public key from its state; `Sensor.drop_session()` drops the private key |

## Provenance

- `gateway.provenance.lineage(session_id, seq)` answers "where did this reading come from": sensor,
  key fingerprint, the CRP that attested the session, payload SHA-256, chain position, quality verdict.
- `export_session(session_id)` produces a JSON-serialisable bundle; `verify_bundle(bundle)` checks it **without the gateway**:
  every frame is signed by the session key, in order, unmodified, and the records match the frames.
- Ledger entries are hash-chained. Anchor `provenance.head` somewhere external (a log, another system)
  to make later rewriting of history detectable.
- Quarantined frames are recorded too, with their flags.

## Data quality

Authenticity and quality are separate: an authentic frame can still carry garbage.
Quality runs **only on frames whose origin is proven**, so an attacker cannot skew the statistics.
Readings are `{"metric": "temp_c", "value": 22.4}` (`encode_reading`).

| Flag | Meaning | Effect |
|---|---|---|
| `unparseable`, `bad_schema`, `unknown_metric`, `out_of_range` | Reading is unusable | **Quarantined** (`usable=False`); baselines untouched |
| `spike` | Jump larger than `max_step` | Kept, flagged |
| `flatline` | `flatline_after` identical readings in a row | Kept, flagged |
| `gap` | No frame for longer than `max_gap` | Kept, flagged |
| `disagrees:<sensor>` | Another sensor measuring the same metric differs by more than `cross_tolerance` | Kept, flagged |

A quarantined frame still advances the sequence and chain, because it is authentic.
`quality.report()` gives per-sensor frame counts, usable ratio and flag totals.

## Limits and next steps for production

- **The PUF is simulated.** Real PUFs are noisy and need a fuzzy extractor and helper data.
- **The CRP database is the crown jewel.** It is not a signing key (each entry works once), but a copy lets an
  attacker impersonate a sensor until those CRPs are used. Protect it with a secure element or HSM and encrypt it at rest; this code keeps it in memory.
- **CRPs run out.** Re-enrollment is a trusted bench step. Remote replenishment needs an encrypted channel (ECDH + AEAD), which is not built.
- **Provenance binds frames to a session key, and the key to a sensor only via the gateway's record.** With no
  long-lived key, nothing lets a third party check that second link without trusting the gateway. Anchoring the ledger head limits what the gateway can rewrite later, not what it claims now.
- **Hello flooding is mitigated, not solved.** An attacker holding all four slots can still delay a sensor's *next* handshake until the challenges expire (`challenge_ttl`). Real fixes need per-peer admission control (allow-lists, mTLS-less network ACLs, or per-IP limits), since the gateway can't tell strangers from the sensor before attestation.
- **Origin and integrity only, no confidentiality.** Add ECDH + AEAD or run over TLS if payloads are secret.
- **Memory:** the provenance ledger keeps every frame in memory; add retention or a persistent store.
- **Quality thresholds are per-metric config**, not learned. Cross-sensor checks flag the later reading, since the gateway can't tell which sensor is wrong.
