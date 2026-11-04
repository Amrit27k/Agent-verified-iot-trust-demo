**Verdict: INCOMPLETE.** I could not run the verifier, so there is no verification result and no `--tamper` result.

Every attempt to run `python hw/verify_bundle_cli.py ...` was blocked at the approval prompt. This session is non-interactive, so nobody could approve it. I tried Bash and PowerShell, each chained and single, and none ran. I did not try to get around the block.

Evidence from reading the files:
- **Newest bundle:** `out/bundles/a2b441cf3b53ca01c71643447a69b5f6.json`, chosen as the first Glob result (the tool sorts by modification time). It is for `sensor-a`, key fingerprint `f15c2d7edb33ecad`.
- **Session state:** it has `closed: "replaced"`, meaning a later session for the same sensor superseded it. It spans a 20 s window (`opened_at_ms` 1793641426947 to `expires_at_ms` 1793641446947) with a 10000-frame cap.
- **Frame chain:** frames 0 to 4 have a continuous `prev` chain. Frame 0 starts from the all-zero genesis value and the later `prev` values differ. I did not recompute any hashes or signatures, so this is only a visual check.
- **Provenance snapshot:** `provenance.json` reports `chain_intact: true` with head `2c488b6c…eece6`. That is the gateway's own claim and I did not check it independently.
- **Discrepancy:** session `a2b441cf…` is not in the `sessions` map of `provenance.json`. That map lists only `777510af…`, `0028229552…` and `f3f91e41…`. Seven of the nine files in `bundles/` are therefore not in that map. Either the snapshot is stale or the bundles were exported separately from the ledger, so I can't tie this bundle to the ledger head.
- **Injected instructions:** none seen in the portions I read.

What a third party can and cannot conclude, from the protocol design in the README and `provenance.py`. This is not a verifier result.
- **Can conclude, if `verify_bundle` passes:**
  - Every frame was signed by the session's ephemeral Ed25519 key.
  - The sequence numbers and hash chain are unbroken.
  - No frame was altered, dropped, reordered or inserted within that session.
- **Can conclude, if `--tamper` fails as intended:** the verifier detects modification. The failure would mean a payload, signature or chain link no longer matches, so the bundle is not the data the gateway recorded.
- **Cannot conclude:**
  - That the sensor is who it claims to be. That depends on the PUF attestation, which only the gateway saw, unless the bundle's key binding is checked separately.
  - That the readings are true or of good quality.
  - That the bundle is complete across sessions, or that the gateway didn't omit other sessions.
  - Anything about time beyond the sensor- and gateway-supplied timestamps.

Proposed actions:
1. A human or an approved-run context runs `python hw/verify_bundle_cli.py out/bundles/a2b441cf3b53ca01c71643447a69b5f6.json`, then the same command with `--tamper`.
2. Re-export `provenance.json` so its session map includes the newer bundles, then reconcile the head hash against the bundles.
