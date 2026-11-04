**Verdict:** sensor-a is revoked (audit #28, "approved by human operator") and has no live keys and no CRPs. The audit chain is intact. Sensor-a needs re-enrollment only if it is meant to return to service. No other sensor appears in either snapshot.

- **Live session keys:** none (`live_session_keys` is empty). Sensor-a had five sessions in total: fingerprints `b8ac2cd35cafa422` (#1), `18c36c932723d7a2` (#3), `e1b29ec22a1ff8a4` (#22), `6e3ed87df93b2a91` (#24) and `147d15c4de700f7a` (#26). All are ended; the last, `147d15c4de700f7a`, was ended by the revocation at #27. Each lived about 19s of a 20s expiry. Frame counts are not in these snapshots. The only hint is #6, where sequence 19 was expected, so about 18 frames went through the first session.
- **Rotation:** keys are rotating. Four of the five sessions were replaced by a fresh attestation (#2, #23, #25 and the revocation at #27), and one expired (#12). The `max_frames` cap of 10000 was never close to being reached.
- **CRPs:** 100 were enrolled at #0. `keys.json` now shows `available: 0`, `outstanding: 0`, `enrolled: false`, `revoked: true`. Five successful attestations should have consumed only 5, leaving about 95, so the zero is presumably the revocation purging the pool. `alerts` is empty even though the sensor has no CRPs left, so no low-CRP alert exists for this state.
- **Attack traffic before revocation:** #4 `bad_attestation`, #5 `unknown_sensor` (sensor-x), #6 `bad_sequence`, and #7 and #8 `bad_signature`. Each was rejected. Handshake-flood protection also fired: 13 `busy` rejections at #9–#21 left sensor-a unable to attest between expiry at #12 and re-establishment at #22 (about 9s).
- **After revocation:** 20 `revoked` rejections at #29–#48, one per second. The connection was then closed with `too_many_errors` at #49 (peer `192.168.3.18:41928`). The gateway enforced the revocation correctly.
- **Injection check:** I found no instruction-like text in the sensor ids, details or reasons.

**Proposed actions (none performed):**
1. Keep sensor-a revoked. Re-enroll it only after the device is physically verified, using a fresh factory CRP set.
2. Investigate the source at 192.168.3.18, since a legitimate device would not keep retrying after being revoked. Consider blocking it at the network edge.
3. Add an alert for a sensor whose CRPs are exhausted or revoked, since `alerts` stayed empty here.
4. Review the 13 `busy` rejections at #9–#21 to see whether the outstanding-challenge cap blocked the legitimate sensor-a during the flood.
