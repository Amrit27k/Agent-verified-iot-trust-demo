import copy
import hashlib
import json
import unittest

from helpers import TrustTestCase
from keyless_trust import MetricSpec, QualityMonitor, encode_reading, verify_bundle
from keyless_trust import protocol as p


class Provenance(TrustTestCase):
    def gateway_args(self):
        return {"quality": QualityMonitor({"temp_c": MetricSpec(-20, 60)})}

    def setUp(self):
        super().setUp()
        self.attest(self.a)
        self.attest(self.b)
        self.sid = self.a.session_id
        for value in (20, 21, 999):
            self.gateway.verify_frame(self.a.frame(encode_reading("temp_c", value)))
        self.gateway.verify_frame(self.b.frame(encode_reading("temp_c", 20)))

    def bundle(self):
        return self.gateway.provenance.export_session(self.sid)

    def test_lineage_names_sensor_key_and_crp(self):
        info = self.gateway.provenance.lineage(self.sid, 1)
        self.assertEqual(info["record"]["sensor_id"], "a")
        self.assertEqual(info["record"]["payload_sha256"], hashlib.sha256(encode_reading("temp_c", 21)).hexdigest())
        self.assertEqual(info["session"]["key_fingerprint"], p.key_fingerprint(p.b64d(info["session"]["eph_pub"])))
        established = next(e for e in self.gateway.audit if e.get("session_id") == self.sid and e["event"] == "session_established")
        self.assertEqual(info["session"]["challenge_id"], established["challenge_id"])

    def test_lineage_of_unknown_frame_is_none(self):
        self.assertIsNone(self.gateway.provenance.lineage(self.sid, 99))

    def test_quarantined_frames_are_recorded_with_their_verdict(self):
        record = self.gateway.provenance.lineage(self.sid, 2)["record"]
        self.assertEqual((record["usable"], record["flags"]), (False, ["out_of_range"]))

    def test_rejected_frames_leave_no_provenance(self):
        before = len(self.gateway.provenance._log)
        frame = self.a.frame(b"x")
        frame["payload"] = p.b64e(b"tampered")
        self.assertRejected("bad_signature", self.gateway.verify_frame, frame)
        self.assertEqual(len(self.gateway.provenance._log), before)

    def test_session_close_reason_is_recorded(self):
        self.gateway.revoke_session(self.sid, "rotated by operator")
        self.assertEqual(self.bundle()["session"]["closed"], "rotated by operator")

    def test_ledger_chain_detects_tampering(self):
        self.assertTrue(self.gateway.provenance.verify())
        self.gateway.provenance._log[1]["payload_sha256"] = "0" * 64
        self.assertFalse(self.gateway.provenance.verify())

    def test_head_changes_with_every_record(self):
        head = self.gateway.provenance.head
        self.gateway.verify_frame(self.b.frame(encode_reading("temp_c", 21)))
        self.assertNotEqual(self.gateway.provenance.head, head)


class Bundles(Provenance):
    def test_bundle_verifies_standalone_after_json_round_trip(self):
        bundle = json.loads(json.dumps(self.bundle()))
        self.assertEqual(len(bundle["frames"]), 3)
        self.assertEqual(verify_bundle(bundle), [])

    def test_only_this_sessions_frames_are_exported(self):
        self.assertTrue(all(f["session_id"] == self.sid for f in self.bundle()["frames"]))

    def test_tampered_payload(self):
        bundle = self.bundle()
        bundle["frames"][1]["payload"] = p.b64e(b"forged")
        problems = verify_bundle(bundle)
        self.assertIn("frame 1: bad_signature", problems)
        self.assertIn("frame 1: record_payload_mismatch", problems)

    def test_deleted_frame(self):
        bundle = self.bundle()
        del bundle["frames"][1]
        problems = verify_bundle(bundle)
        self.assertIn("record_count_mismatch", problems)
        self.assertTrue(any("bad_sequence" in x or "broken_chain" in x for x in problems))

    def test_reordered_frames(self):
        bundle = self.bundle()
        bundle["frames"][0], bundle["frames"][1] = bundle["frames"][1], bundle["frames"][0]
        self.assertTrue(any("bad_sequence" in x for x in verify_bundle(bundle)))

    def test_swapped_session_key(self):
        bundle = self.bundle()
        other = copy.deepcopy(self.gateway.provenance.export_session(self.b.session_id))
        bundle["session"]["eph_pub"] = other["session"]["eph_pub"]
        problems = verify_bundle(bundle)
        self.assertIn("fingerprint_mismatch", problems)
        self.assertIn("frame 0: bad_signature", problems)

    def test_edited_record(self):
        bundle = self.bundle()
        bundle["records"][2]["usable"] = True  # hide the quarantine verdict
        self.assertIn("frame 2: record_tampered", verify_bundle(bundle))

    def test_garbage_bundle(self):
        self.assertEqual(verify_bundle({}), ["malformed_bundle"])
        bundle = self.bundle()
        bundle["frames"][0]["sig"] = "!!"
        self.assertEqual(verify_bundle(bundle)[-1], "malformed_bundle")


if __name__ == "__main__":
    unittest.main()
