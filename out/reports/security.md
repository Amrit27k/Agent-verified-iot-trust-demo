**Verdict:** The hash chain is intact (`chain_intact: true`, head `c7e64305…db6db4`, entries 0–83). Every attack in the log was rejected, but entries 78–79 show malformed revocation records that need human review.

**Chain check:** I read `prev` against the previous entry's `hash` for the whole log and the links are continuous. I did not recompute the hashes, so `chain_intact` is the file's own claim.

**Rejections by reason (16 total)**
- `bad_attestation` (1, idx 52, sensor-a): a cloned device, or a swapped public key, tried to attest as an enrolled sensor.
- `unknown_sensor` (1, idx 53, sensor-x): an unenrolled device tried to say hello.
- `bad_sequence` (1, idx 54, sensor-a, "expected 8, got 7"): a replayed or reordered frame.
- `bad_signature` (2, idx 55–56, sensor-a): forged, injected or tampered frames, or sensor-b speaking for sensor-a.
- `busy` (11, idx 57–59, 61, 64–70, all sensor-a): a handshake flood that filled the challenge cap. There was no eviction, and sensor-a re-established a session at idx 71, so it recovered.

**Attacks accepted:** None. Each attack has a matching `rejected` entry. The audit log doesn't record accepted frames, so this covers handshakes and rejections only.

**Anomalies (idx 78–79, `sensor_revoked`)**
- Idx 78 has `sensor_id` `"\u0000"`.
- Idx 79 has a UTF-16-style id (`\u00ff\u00fes\u0000e\u0000n…b\u0000`, apparently "sensor-b" with a BOM and null bytes).
- Neither matches an enrolled id, so neither revocation looks like it took effect. sensor-b kept getting new sessions (idx 83), and sensor-a did too (idx 81).
- Both entries carry the reason "approved by human operator", which I can't verify from the audit log. A malformed or injected revocation input is likely.
- Neither entry contains instructions, so there was nothing to refuse.

**Proposed actions**
- Check whatever fed the operator-approval revocation path (not read here, per my scope). Confirm who approved what, and whether the intended target was sensor-b.
- Validate and normalise sensor ids in `revoke_sensor`: reject nulls, a BOM, non-ASCII, and ids that aren't enrolled.
- If sensor-b is meant to be revoked, redo the revocation with the exact id `sensor-b` and confirm it ends its sessions.
- Consider alerting on `sensor_revoked` for an id that was never enrolled.
- Consider per-peer admission limits for the `busy` flood on sensor-a, as the README suggests.
