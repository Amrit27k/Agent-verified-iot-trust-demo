import asyncio
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from helpers import TrustTestCase
from keyless_trust import Gateway, GatewayNotTrusted, Rejected, Sensor, SimulatedPUF, enroll
from keyless_trust import protocol as p
from keyless_trust.transport import SensorClient, serve


class HappyPath(TrustTestCase):
    def test_two_sensors_stream_and_origin_is_verified(self):
        self.attest(self.a)
        self.attest(self.b)
        for n in range(3):
            fa = self.gateway.verify_frame(self.a.frame(b"a%d" % n))
            fb = self.gateway.verify_frame(self.b.frame(b"b%d" % n))
            self.assertEqual((fa.sensor_id, fa.seq, fa.payload), ("a", n, b"a%d" % n))
            self.assertEqual((fb.sensor_id, fb.seq, fb.payload), ("b", n, b"b%d" % n))
        self.assertTrue(self.gateway.audit.verify())

    def test_stream_digest_matches_sensor_chain(self):
        self.attest(self.a)
        frame = None
        for n in range(3):
            frame = self.a.frame(b"x")
            self.gateway.verify_frame(frame)
        self.assertEqual(self.gateway.stream_digest("a"), p.frame_hash(frame))

    def test_each_session_uses_a_new_key_and_crp(self):
        keys = set()
        for _ in range(3):
            challenge = self.gateway.handle_hello(self.a.hello())
            attest = self.a.respond(challenge)
            keys.add(attest["eph_pub"])
            self.a.establish(self.gateway.handle_attest(attest))
        self.assertEqual(len(keys), 3)
        self.assertEqual(self.gateway.crps_remaining("a"), 5)


class Attestation(TrustTestCase):
    def test_unknown_sensor(self):
        self.assertRejected("unknown_sensor", self.gateway.handle_hello, {"type": "hello", "sensor_id": "x"})

    def test_cloned_identity_with_different_puf(self):
        impostor = Sensor("a", SimulatedPUF(), clock=self.clock)
        challenge = self.gateway.handle_hello(impostor.hello())
        self.assertRejected("bad_attestation", self.gateway.handle_attest, impostor.respond(challenge))
        self.assertIsNone(self.gateway.active_session("a"))

    def test_attestation_cannot_be_replayed(self):
        challenge = self.gateway.handle_hello(self.a.hello())
        attest = self.a.respond(challenge)
        self.gateway.handle_attest(attest)
        self.assertRejected("no_challenge", self.gateway.handle_attest, attest)

    def test_key_substitution_in_attest_is_detected(self):
        challenge = self.gateway.handle_hello(self.a.hello())
        attest = self.a.respond(challenge)
        attacker_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        attest["eph_pub"] = p.b64e(attacker_pub)
        self.assertRejected("bad_attestation", self.gateway.handle_attest, attest)

    def test_stale_challenge_is_refused_and_crp_returned(self):
        challenge = self.gateway.handle_hello(self.a.hello())
        self.clock.advance(6)
        self.assertRejected("challenge_expired", self.gateway.handle_attest, self.a.respond(challenge))
        self.assertEqual(self.gateway.crps_remaining("a"), 8)

    def test_unanswered_challenges_expire_back_into_the_pool(self):
        self.gateway.handle_hello(self.a.hello())
        self.assertEqual(self.gateway.enrollment_status("a")["outstanding"], 1)
        self.assertEqual(self.gateway.crps_remaining("a"), 7)
        self.clock.advance(6)
        self.gateway.handle_hello(self.a.hello())
        self.assertEqual(self.gateway.enrollment_status("a")["outstanding"], 1)
        self.assertEqual(self.gateway.crps_remaining("a"), 7)

    def test_outstanding_challenges_are_capped_and_excess_hellos_refused(self):
        for _ in range(4):
            self.gateway.handle_hello(self.a.hello())
        for _ in range(6):
            self.assertRejected("busy", self.gateway.handle_hello, self.a.hello())
        status = self.gateway.enrollment_status("a")
        self.assertEqual((status["outstanding"], status["available"]), (4, 4))

    def test_hello_flood_cannot_cancel_a_handshake_already_in_flight(self):
        challenge = self.gateway.handle_hello(self.a.hello())
        attest = self.a.respond(challenge)
        for _ in range(20):  # attacker floods hello for the same sensor id
            try:
                self.gateway.handle_hello({"type": "hello", "sensor_id": "a"})
            except Rejected:
                pass
        self.a.establish(self.gateway.handle_attest(attest))
        self.assertIsNotNone(self.a.session_id)

    def test_flooded_slots_free_up_after_the_challenge_ttl(self):
        for _ in range(4):
            self.gateway.handle_hello(self.a.hello())
        self.assertRejected("busy", self.gateway.handle_hello, self.a.hello())
        self.clock.advance(6)
        self.attest(self.a)  # sensor can handshake again once stale challenges lapse
        self.assertEqual(self.gateway.crps_remaining("a"), 7)  # stale ones returned, only one consumed

    def test_failed_attestation_does_not_burn_or_cancel_the_challenge(self):
        challenge = self.gateway.handle_hello(self.a.hello())
        attest = self.a.respond(challenge)
        spoiled = dict(attest, proof=p.b64e(b"\x00" * 32))
        self.assertRejected("bad_attestation", self.gateway.handle_attest, spoiled)
        self.assertEqual(self.gateway.enrollment_status("a")["outstanding"], 1)
        self.a.establish(self.gateway.handle_attest(attest))  # the real one still works

    def test_crps_exhausted(self):
        for _ in range(8):
            self.attest(self.a)
        self.assertRejected("crps_exhausted", self.gateway.handle_hello, self.a.hello())

    def test_sensor_rejects_gateway_without_enrollment_record(self):
        # A rogue gateway can relay a challenge, but without this sensor's
        # CRPs it cannot produce the gateway proof.
        rogue = Gateway(clock=self.clock)
        enroll(rogue, "a", SimulatedPUF(), count=1)
        self.a.respond(rogue.handle_hello(self.a.hello()))
        fake_session = {"session_id": "f" * 32, "expires_at_ms": 0, "max_frames": 10, "proof": p.b64e(b"\x00" * 32)}
        with self.assertRaises(GatewayNotTrusted):
            self.a.establish(fake_session)
        self.assertIsNone(self.a.session_id)

    def test_new_session_revokes_old(self):
        self.attest(self.a)
        old_frame = self.a.frame(b"old")
        self.attest(self.a)
        self.assertRejected("unknown_session", self.gateway.verify_frame, old_frame)
        self.gateway.verify_frame(self.a.frame(b"new"))

    def test_malformed_messages(self):
        self.assertRejected("malformed", self.gateway.handle_hello, {})
        self.assertRejected("malformed", self.gateway.handle_hello, {"sensor_id": ["a"]})
        self.gateway.handle_hello(self.a.hello())
        self.assertRejected("malformed", self.gateway.handle_attest, {"sensor_id": "a", "eph_pub": "!!", "proof": ""})
        self.assertRejected("malformed", self.gateway.verify_frame, {"session_id": {}})


class FrameOrigin(TrustTestCase):
    def setUp(self):
        super().setUp()
        self.attest(self.a)
        self.attest(self.b)

    def test_tampered_payload(self):
        frame = self.a.frame(b"22.5C")
        frame["payload"] = p.b64e(b"99.9C")
        self.assertRejected("bad_signature", self.gateway.verify_frame, frame)

    def test_sensor_b_cannot_speak_for_sensor_a(self):
        frame = self.b.frame(b"pretending to be a")
        frame["session_id"] = self.a.session_id
        self.assertRejected("bad_signature", self.gateway.verify_frame, frame)

    def test_forged_frame_with_attacker_key(self):
        frame = self.a.frame(b"real")
        frame["sig"] = p.b64e(Ed25519PrivateKey.generate().sign(p.frame_signing_bytes(frame)))
        self.assertRejected("bad_signature", self.gateway.verify_frame, frame)

    def test_forged_frames_do_not_disrupt_victim_session(self):
        good = self.a.frame(b"good")
        forged = dict(good, sig=p.b64e(b"\x00" * 64))
        for _ in range(5):
            self.assertRejected("bad_signature", self.gateway.verify_frame, forged)
        self.assertEqual(self.gateway.verify_frame(good).seq, 0)

    def test_replay(self):
        frame = self.a.frame(b"once")
        self.gateway.verify_frame(frame)
        self.assertRejected("bad_sequence", self.gateway.verify_frame, frame)

    def test_dropped_or_reordered_frame(self):
        f0, f1 = self.a.frame(b"0"), self.a.frame(b"1")
        self.assertRejected("bad_sequence", self.gateway.verify_frame, f1)
        self.gateway.verify_frame(f0)
        self.gateway.verify_frame(f1)

    def test_session_expiry_then_reattest(self):
        self.clock.advance(61)
        self.assertTrue(self.a.needs_attestation)
        with self.assertRaises(RuntimeError):
            self.a.frame(b"late")
        self.attest(self.a)
        self.assertEqual(self.gateway.verify_frame(self.a.frame(b"fresh")).seq, 0)

    def test_gateway_enforces_expiry_even_if_sensor_clock_lags(self):
        lagging = Sensor("a", self.pufs["a"], clock=lambda: self.clock.now - 30)
        self.attest(lagging)
        frame = lagging.frame(b"x")
        self.clock.advance(61)
        self.assertRejected("session_expired", self.gateway.verify_frame, frame)

    def test_timestamp_outside_skew(self):
        skewed = Sensor("a", self.pufs["a"], clock=lambda: self.clock.now + 20)
        self.attest(skewed)
        self.assertRejected("bad_timestamp", self.gateway.verify_frame, skewed.frame(b"x"))


class AuditLogIntegrity(TrustTestCase):
    def test_tampering_breaks_chain(self):
        self.attest(self.a)
        self.assertTrue(self.gateway.audit.verify())
        established = next(e for e in self.gateway.audit if e["event"] == "session_established")
        established["key_fingerprint"] = "0" * 16
        self.assertFalse(self.gateway.audit.verify())

    def test_deletion_breaks_chain(self):
        self.attest(self.a)
        self.attest(self.b)
        del self.gateway.audit._entries[1]
        self.assertFalse(self.gateway.audit.verify())


class OverTcp(unittest.IsolatedAsyncioTestCase):
    async def test_two_sensors_with_rotation_and_rejection(self):
        gateway = Gateway(session_ttl=0.3)
        pufs = {"a": SimulatedPUF(), "b": SimulatedPUF()}
        for sensor_id, puf in pufs.items():
            enroll(gateway, sensor_id, puf, count=16)
        received = []
        server = await serve(gateway, "127.0.0.1", 0, received.append)
        port = server.sockets[0].getsockname()[1]

        async def run(sensor_id):
            sensor = Sensor(sensor_id, pufs[sensor_id], renew_margin=0.1)
            async with SensorClient(sensor, "127.0.0.1", port) as client:
                for n in range(4):
                    await client.send(b"%d" % n)
                    await asyncio.sleep(0.15)

        await asyncio.gather(run("a"), run("b"))

        impostor = Sensor("a", SimulatedPUF())
        async with SensorClient(impostor, "127.0.0.1", port) as client:
            with self.assertRaises(Rejected) as ctx:
                await client.send(b"evil")
            self.assertEqual(ctx.exception.reason, "bad_attestation")

        server.close()
        await server.wait_closed()

        self.assertEqual(sorted((f.sensor_id, f.payload) for f in received),
                         [(s, b"%d" % n) for s in "ab" for n in range(4)])
        self.assertGreater(len({f.session_id for f in received if f.sensor_id == "a"}), 1)
        self.assertTrue(gateway.audit.verify())


if __name__ == "__main__":
    unittest.main()
