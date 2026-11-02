import unittest

from keyless_trust import Gateway, Rejected, Sensor, SimulatedPUF, enroll


class FakeClock:
    def __init__(self, now: float = 1_700_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TrustTestCase(unittest.TestCase):
    crps = 8

    def gateway_args(self) -> dict:
        """Override to configure the gateway under test."""
        return {}

    def setUp(self) -> None:
        self.clock = FakeClock()
        args = dict(session_ttl=60, challenge_ttl=5, max_clock_skew=10, clock=self.clock)
        args.update(self.gateway_args())
        self.gateway = Gateway(**args)
        self.pufs = {"a": SimulatedPUF(), "b": SimulatedPUF()}
        for sensor_id, puf in self.pufs.items():
            enroll(self.gateway, sensor_id, puf, count=self.crps)
        self.a = Sensor("a", self.pufs["a"], clock=self.clock)
        self.b = Sensor("b", self.pufs["b"], clock=self.clock)

    def attest(self, sensor: Sensor) -> None:
        challenge = self.gateway.handle_hello(sensor.hello())
        sensor.establish(self.gateway.handle_attest(sensor.respond(challenge)))

    def assertRejected(self, reason: str, fn, *args) -> None:
        with self.assertRaises(Rejected) as ctx:
            fn(*args)
        self.assertEqual(ctx.exception.reason, reason)
