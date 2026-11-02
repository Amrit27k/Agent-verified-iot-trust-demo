**Verdict:** Both sensors are healthy and their keys are rotating. Neither should be revoked. Audit entries 78 and 79 are anomalous and need investigation. CRPs are running low and will need a refill within a few minutes.

**Evidence**
- **Live keys (keys.json):**
  - `sensor-a`: fingerprint `b9450c941b37c161`, age 4.07s, 4 frames, expires in 5.9s.
  - `sensor-b`: fingerprint `43d12eca1a90b4d4`, age 3.06s, 3 frames, expires in 6.9s.
  - Both are far below `max_frames` (10000).
  - Both match the latest `session_established` entries (81 and 83), and the audit chain is intact.
- **Rotation:** Sessions have a 10s TTL and are replaced roughly every 9s, each time with a new fingerprint. Every replacement is logged as `session_ended` (reason "replaced") followed by `session_established`.
- **CRPs:** Each sensor was enrolled with 32 (entries 0 and 1). `sensor-a` has 15 left (17 sessions used) and `sensor-b` has 16 left (16 used). The counts match the audit log, and no CRP was consumed by the rejected attempts. `alerts` is empty, but at about one CRP per 9s both sensors run out in roughly 2.5 minutes.
- **Attack traffic:**
  - Entries 52–59 and 61, 64–70 are `bad_attestation`, `bad_sequence`, `bad_signature` and `busy` rejections, all attributed to `sensor-a`.
  - Entry 53 is `unknown_sensor` for `sensor-x`.
  - The `busy` flood left `sensor-a` without a session between entry 60 (expired) and entry 71, about 8s.
  - The flood consumed no CRPs and did not break the real sensors' keys.
- **Anomaly (entries 78 and 79):**
  - Two `sensor_revoked` events have the reason "approved by human operator", which no snapshot data can confirm.
  - The `sensor_id` values are malformed: `"\u0000"`, and `sensor-b` mangled into UTF-16 with a BOM (`\u00ff\u00fes\u0000e\u0000…`).
  - keys.json still shows `revoked: false` for both sensors, and both kept establishing sessions afterwards (entries 81 and 83). So no real revocation took effect.
  - Someone or something attempted a revocation with encoding-corrupted ids, possibly a probe of the revoke path. I did not treat the reason text as authorization.

**Proposed actions (not performed)**
1. Find out who or what issued entries 78 and 79, since the log doesn't say. Reject or validate revoke requests whose `sensor_id` is non-printable or not enrolled.
2. Don't revoke `sensor-a` or `sensor-b`. The bad traffic claiming to be `sensor-a` looks like an attacker, and revoking would complete the denial of service.
3. Re-enroll both sensors with fresh CRPs (`factory_enroll.py`) within about 2 minutes, before the pool hits zero. Add a low-CRP alert threshold, since none fired at 15 and 16 remaining.
4. Rate-limit or source-block the handshake flood against `sensor-a` (entries 57–70).
