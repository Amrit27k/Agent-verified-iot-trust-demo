import asyncio
import json
import unittest

from keyless_trust import (
    Gateway,
    MetricSpec,
    QualityMonitor,
    Rejected,
    Sensor,
    SimulatedPUF,
    encode_reading,
    enroll,
)
from keyless_trust.transport import SensorClient, TokenBucket, serve


async def exchange(port: int, lines: list[dict]) -> list[dict]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    for line in lines:
        writer.write(json.dumps(line).encode() + b"\n")
    await writer.drain()
    replies = []
    while data := await asyncio.wait_for(reader.readline(), 2):
        replies.append(json.loads(data))
        if len(replies) == len(lines):
            break
    writer.close()
    return replies


class Transport(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.puf = SimulatedPUF()
        self.gateway = Gateway(quality=QualityMonitor({"temp_c": MetricSpec(-20, 60)}))
        enroll(self.gateway, "a", self.puf, count=8)
        self.server = None

    async def asyncTearDown(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def start(self, **kwargs):
        self.server = await serve(self.gateway, "127.0.0.1", 0, **kwargs)
        return self.server.sockets[0].getsockname()[1]

    async def test_ack_reports_quality_verdict(self):
        port = await self.start()
        async with SensorClient(Sensor("a", self.puf), "127.0.0.1", port) as client:
            ok = await client.send(encode_reading("temp_c", 21))
            bad = await client.send(encode_reading("temp_c", 500))
        self.assertEqual((ok["usable"], ok["flags"]), (True, []))
        self.assertEqual((bad["usable"], bad["flags"]), (False, ["out_of_range"]))

    async def test_rate_limit(self):
        port = await self.start(rate=0.001, burst=3)
        replies = await exchange(port, [{"type": "hello", "sensor_id": "a"}] * 6)
        reasons = [r.get("reason") for r in replies]
        self.assertEqual(reasons[:3], [None, None, None])
        self.assertEqual(reasons[3:], ["rate_limited"] * 3)

    async def test_connection_dropped_after_repeated_errors(self):
        port = await self.start(max_consecutive_errors=3)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        for _ in range(5):
            writer.write(b'{"type":"hello","sensor_id":"nobody"}\n')
        await writer.drain()
        lines = []
        while data := await asyncio.wait_for(reader.readline(), 2):
            lines.append(data)
        writer.close()
        self.assertEqual(len(lines), 3)  # three replies, then the gateway hangs up
        self.assertTrue(any(e["event"] == "connection_closed" for e in self.gateway.audit))

    async def test_success_resets_the_error_count(self):
        port = await self.start(max_consecutive_errors=2)
        bad = {"type": "hello", "sensor_id": "nobody"}
        good = {"type": "hello", "sensor_id": "a"}
        replies = await exchange(port, [bad, good, bad, good, bad, good])
        self.assertEqual(len(replies), 6)

    async def test_garbage_lines_get_an_error_not_a_crash(self):
        port = await self.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"{not json\n[]\n")
        await writer.drain()
        first = json.loads(await reader.readline())
        second = json.loads(await reader.readline())
        writer.close()
        self.assertEqual((first["reason"], second["reason"]), ("malformed", "malformed"))

    async def test_revoked_sensor_is_cut_off_mid_stream(self):
        port = await self.start()
        sensor = Sensor("a", self.puf)
        async with SensorClient(sensor, "127.0.0.1", port) as client:
            await client.send(encode_reading("temp_c", 21))
            self.gateway.revoke_sensor("a", "stolen")
            with self.assertRaises(Rejected):
                await client.send(encode_reading("temp_c", 21))
            with self.assertRaises(Rejected) as ctx:
                await client.send(encode_reading("temp_c", 21))
            self.assertEqual(ctx.exception.reason, "revoked")


class TokenBucketTest(unittest.TestCase):
    def test_refills_over_time(self):
        now = [0.0]
        bucket = TokenBucket(rate=2, burst=2, clock=lambda: now[0])
        self.assertEqual([bucket.allow() for _ in range(3)], [True, True, False])
        now[0] += 0.5
        self.assertEqual([bucket.allow() for _ in range(2)], [True, False])


if __name__ == "__main__":
    unittest.main()
