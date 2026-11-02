import unittest

from helpers import TrustTestCase
from keyless_trust import GatewayNotTrusted, Rejected, enroll
from keyless_trust import protocol as p


class KeyLifecycle(TrustTestCase):
    def gateway_args(self):
        self.alerts = []
        return {
            "max_frames_per_session": 3,
            "low_crp_threshold": 4,
            "on_alert": lambda name, details: self.alerts.append((name, details)),
        }

    def test_session_key_is_exhausted_after_max_frames(self):
        self.attest(self.a)
        for _ in range(3):
            self.gateway.verify_frame(self.a.frame(b"x"))
        self.assertTrue(self.a.needs_attestation)
        with self.assertRaises(RuntimeError):
            self.a.frame(b"too many")

    def test_gateway_enforces_frame_limit_even_if_sensor_ignores_it(self):
        self.attest(self.a)
        self.a._session.max_frames = 100  # misbehaving sensor
        for _ in range(3):
            self.gateway.verify_frame(self.a.frame(b"x"))
        self.assertRejected("session_exhausted", self.gateway.verify_frame, self.a.frame(b"x"))
        self.assertIsNone(self.gateway.active_session("a"))

    def test_session_limits_are_authenticated(self):
        challenge = self.gateway.handle_hello(self.a.hello())
        session = self.gateway.handle_attest(self.a.respond(challenge))
        session["max_frames"] = 10**9  # attacker in the middle loosens the limit
        with self.assertRaises(GatewayNotTrusted):
            self.a.establish(session)

    def test_inventory_lists_public_material_only(self):
        self.attest(self.a)
        self.attest(self.b)
        self.gateway.verify_frame(self.a.frame(b"x"))
        inventory = {row["sensor_id"]: row for row in self.gateway.key_inventory()}
        self.assertEqual(set(inventory), {"a", "b"})
        row = inventory["a"]
        self.assertEqual(row["frames"], 1)
        self.assertEqual(row["max_frames"], 3)
        self.assertAlmostEqual(row["expires_in_s"], 60, delta=1)
        self.assertEqual(len(row["key_fingerprint"]), 16)
        self.assertNotIn("private", " ".join(row))

    def test_expired_sessions_leave_inventory_and_are_logged(self):
        self.attest(self.a)
        self.clock.advance(61)
        self.gateway.handle_hello(self.b.hello())  # any hello sweeps expired sessions
        self.assertEqual(self.gateway.key_inventory(), [])
        ended = [e for e in self.gateway.audit if e["event"] == "session_ended"]
        self.assertEqual(ended[-1]["reason"], "expired")

    def test_low_crp_alert_fires_once(self):
        for _ in range(4):  # 8 -> 4 left: not yet below the threshold of 4
            self.attest(self.a)
        self.assertEqual(self.alerts, [])
        self.attest(self.a)  # 3 left
        self.attest(self.a)  # 2 left
        self.assertEqual([name for name, _ in self.alerts], ["crps_low"])
        self.assertEqual(self.alerts[0][1], {"sensor_id": "a", "remaining": 3})

    def test_re_enrollment_rearms_the_low_crp_alert(self):
        for _ in range(5):
            self.attest(self.a)
        enroll(self.gateway, "a", self.pufs["a"], count=8)
        for _ in range(8):
            self.attest(self.a)
        self.assertEqual([name for name, _ in self.alerts], ["crps_low", "crps_low"])

    def test_crp_ids_in_audit_do_not_leak_challenges(self):
        self.attest(self.a)
        event = next(e for e in self.gateway.audit if e["event"] == "session_established")
        self.assertEqual(len(event["challenge_id"]), 16)


class Revocation(TrustTestCase):
    def test_revoke_session_stops_frames_but_sensor_can_reattest(self):
        self.attest(self.a)
        frame = self.a.frame(b"x")
        self.assertTrue(self.gateway.revoke_session(self.a.session_id, "suspected leak"))
        self.assertRejected("unknown_session", self.gateway.verify_frame, frame)
        self.attest(self.a)
        self.gateway.verify_frame(self.a.frame(b"y"))

    def test_revoke_unknown_session_is_a_no_op(self):
        self.assertFalse(self.gateway.revoke_session("nope"))

    def test_revoke_sensor_ends_everything(self):
        self.attest(self.a)
        challenge = self.gateway.handle_hello(self.a.hello())  # a handshake in flight
        in_flight = self.a.respond(challenge)
        frame = self.a.frame(b"x")
        self.gateway.revoke_sensor("a", "stolen device")

        self.assertRejected("unknown_session", self.gateway.verify_frame, frame)
        self.assertRejected("revoked", self.gateway.handle_hello, self.a.hello())
        self.assertRejected("revoked", self.gateway.handle_attest, in_flight)
        status = self.gateway.enrollment_status("a")
        self.assertEqual((status["available"], status["outstanding"], status["revoked"]), (0, 0, True))
        # The other sensor is untouched.
        self.attest(self.b)

    def test_revoked_sensor_cannot_be_quietly_re_enrolled(self):
        self.gateway.revoke_sensor("a")
        with self.assertRaises(ValueError):
            enroll(self.gateway, "a", self.pufs["a"])

    def test_reinstate_requires_fresh_enrollment(self):
        self.gateway.revoke_sensor("a")
        self.gateway.reinstate_sensor("a")
        self.assertRejected("unknown_sensor", self.gateway.handle_hello, self.a.hello())
        enroll(self.gateway, "a", self.pufs["a"], count=2)
        self.attest(self.a)

    def test_revocation_is_audited(self):
        self.attest(self.a)
        self.gateway.revoke_sensor("a", "lost")
        events = [(e["event"], e.get("reason")) for e in self.gateway.audit]
        self.assertIn(("sensor_revoked", "lost"), events)
        self.assertIn(("session_ended", "sensor_revoked: lost"), events)
        self.assertTrue(self.gateway.audit.verify())


if __name__ == "__main__":
    unittest.main()
