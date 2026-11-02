import unittest

from helpers import TrustTestCase
from keyless_trust import MetricSpec, QualityMonitor, encode_reading

SPECS = {"temp_c": MetricSpec(-20, 60, max_step=5, flatline_after=4, cross_tolerance=2)}


class DataQuality(TrustTestCase):
    def gateway_args(self):
        return {"quality": QualityMonitor(SPECS, max_gap=20, cross_window=5)}

    def setUp(self):
        super().setUp()
        self.attest(self.a)
        self.attest(self.b)

    def send(self, sensor, value, metric="temp_c"):
        return self.gateway.verify_frame(sensor.frame(encode_reading(metric, value)))

    def test_clean_reading(self):
        frame = self.send(self.a, 21.5)
        self.assertEqual((frame.flags, frame.usable), ((), True))

    def test_out_of_range_is_quarantined(self):
        frame = self.send(self.a, 999)
        self.assertEqual((frame.flags, frame.usable), (("out_of_range",), False))

    def test_unparseable_and_bad_schema_and_unknown_metric(self):
        cases = {
            b"\xff\xfe": "unparseable",
            b"not json": "unparseable",
            b"[1, 2]": "bad_schema",
            b'{"metric":"temp_c"}': "bad_schema",
            b'{"metric":"temp_c","value":"22"}': "bad_schema",
            b'{"metric":"temp_c","value":true}': "bad_schema",
            b'{"metric":"temp_c","value":NaN}': "bad_schema",
            b'{"metric":"temp_c","value":1e999}': "bad_schema",
            encode_reading("humidity", 50): "unknown_metric",
        }
        for payload, flag in cases.items():
            with self.subTest(payload=payload):
                frame = self.gateway.verify_frame(self.a.frame(payload))
                self.assertEqual(frame.flags, (flag,))
                self.assertFalse(frame.usable)

    def test_quarantined_frame_is_still_authentic_and_advances_the_chain(self):
        bad = self.send(self.a, 999)
        good = self.send(self.a, 21)
        self.assertEqual((bad.seq, good.seq), (0, 1))
        self.assertTrue(good.usable)

    def test_quarantined_reading_does_not_poison_the_baseline(self):
        self.send(self.a, 20)
        self.send(self.a, 999)
        self.assertEqual(self.send(self.a, 21).flags, ())  # no spike against 999

    def test_spike_is_flagged_but_kept(self):
        self.send(self.a, 20)
        frame = self.send(self.a, 30)
        self.assertEqual((frame.flags, frame.usable), (("spike",), True))

    def test_flatline(self):
        results = [self.send(self.a, 21.0).flags for _ in range(5)]
        self.assertEqual(results, [(), (), (), ("flatline",), ("flatline",)])
        self.assertEqual(self.send(self.a, 21.1).flags, ())

    def test_gap_between_frames(self):
        self.send(self.a, 21)
        self.clock.advance(21)
        self.assertEqual(self.send(self.a, 21.2).flags, ("gap",))

    def test_sensors_that_disagree_are_flagged(self):
        self.send(self.a, 20)
        frame = self.send(self.b, 25)
        self.assertEqual((frame.flags, frame.usable), (("disagrees:a",), True))

    def test_agreeing_or_stale_peers_are_not_flagged(self):
        self.send(self.a, 20)
        self.assertEqual(self.send(self.b, 21).flags, ())
        self.clock.advance(6)  # a's reading is now outside the cross window
        self.assertEqual(self.send(self.b, 27).flags, ("spike",))  # +6 > max_step, and no stale-peer "disagrees"

    def test_report_scores_each_sensor(self):
        self.send(self.a, 20)
        self.send(self.a, 999)
        self.send(self.a, 20.5)
        self.send(self.b, 20)
        report = self.gateway.quality.report()
        self.assertEqual(report["a"], {"frames": 3, "usable": 2, "score": 0.667, "flags": {"out_of_range": 1}})
        self.assertEqual(report["b"]["score"], 1.0)

    def test_forged_frames_never_reach_the_quality_monitor(self):
        frame = self.a.frame(encode_reading("temp_c", 20))
        forged = dict(frame, payload=encode_reading("temp_c", 999).decode().encode())
        from keyless_trust import protocol as p

        forged["payload"] = p.b64e(encode_reading("temp_c", 999))
        self.assertRejected("bad_signature", self.gateway.verify_frame, forged)
        self.assertEqual(self.gateway.quality.report(), {})


class WithoutMonitor(TrustTestCase):
    def test_frames_are_usable_and_unflagged(self):
        self.attest(self.a)
        frame = self.gateway.verify_frame(self.a.frame(b"anything"))
        self.assertEqual((frame.flags, frame.usable), ((), True))


if __name__ == "__main__":
    unittest.main()
