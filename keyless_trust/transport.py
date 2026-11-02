"""Newline-delimited JSON over TCP between sensors and the gateway."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable

from .gateway import Gateway, VerifiedFrame
from .protocol import Rejected
from .sensor import Sensor

MAX_LINE = 64 * 1024


class TokenBucket:
    def __init__(self, rate: float, burst: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.rate, self.burst, self._clock = rate, burst, clock
        self._tokens, self._last = burst, clock()

    def allow(self) -> bool:
        now = self._clock()
        self._tokens = min(self.burst, self._tokens + (now - self._last) * self.rate)
        self._last = now
        if self._tokens >= 1:
            self._tokens -= 1
            return True
        return False


def _dispatch(gateway: Gateway, msg: dict, on_frame: Callable[[VerifiedFrame], None]) -> dict:
    kind = msg.get("type") if isinstance(msg, dict) else None
    if kind == "hello":
        return gateway.handle_hello(msg)
    if kind == "attest":
        return gateway.handle_attest(msg)
    if kind == "frame":
        frame = gateway.verify_frame(msg)
        on_frame(frame)
        return {"type": "ack", "seq": frame.seq, "usable": frame.usable, "flags": list(frame.flags)}
    raise Rejected("malformed", f"unknown message type {kind!r}")


async def serve(
    gateway: Gateway,
    host: str = "127.0.0.1",
    port: int = 0,
    on_frame: Callable[[VerifiedFrame], None] = lambda frame: None,
    *,
    rate: float = 100.0,
    burst: float = 200.0,
    max_consecutive_errors: int = 20,
) -> asyncio.Server:
    """Serve the gateway. Each connection gets a rate limit and is dropped
    after ``max_consecutive_errors`` failures in a row."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        bucket = TokenBucket(rate, burst)
        errors = 0
        try:
            while line := await reader.readline():
                if not bucket.allow():
                    reply = {"type": "error", "reason": "rate_limited", "detail": ""}
                else:
                    try:
                        reply = _dispatch(gateway, json.loads(line), on_frame)
                    except json.JSONDecodeError:
                        reply = {"type": "error", "reason": "malformed", "detail": "invalid JSON"}
                    except Rejected as exc:
                        reply = {"type": "error", "reason": exc.reason, "detail": exc.detail}
                errors = errors + 1 if reply["type"] == "error" else 0
                writer.write(json.dumps(reply).encode() + b"\n")
                await writer.drain()
                if errors >= max_consecutive_errors:
                    gateway.audit.append(
                        "connection_closed",
                        reason="too_many_errors",
                        peer=str(writer.get_extra_info("peername")),
                    )
                    break
        except (ConnectionError, asyncio.LimitOverrunError, ValueError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(handle, host, port, limit=MAX_LINE)


class SensorClient:
    """Drives a ``Sensor`` over TCP, re-attesting whenever its session runs out."""

    def __init__(self, sensor: Sensor, host: str, port: int) -> None:
        self.sensor = sensor
        self._addr = (host, port)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def __aenter__(self) -> SensorClient:
        self._reader, self._writer = await asyncio.open_connection(*self._addr, limit=MAX_LINE)
        return self

    async def __aexit__(self, *exc) -> None:
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()

    async def call(self, msg: dict) -> dict:
        self._writer.write(json.dumps(msg).encode() + b"\n")
        await self._writer.drain()
        reply = json.loads(await self._reader.readline())
        if reply.get("type") == "error":
            raise Rejected(reply["reason"], reply.get("detail", ""))
        return reply

    async def attest(self) -> None:
        challenge = await self.call(self.sensor.hello())
        session = await self.call(self.sensor.respond(challenge))
        self.sensor.establish(session)

    async def send(self, payload: bytes) -> dict:
        if self.sensor.needs_attestation:
            await self.attest()
        try:
            return await self.call(self.sensor.frame(payload))
        except Rejected:
            # Our view of the session no longer matches the gateway's
            # (expired, replaced, revoked, lost frame). Start a fresh one next time.
            self.sensor.drop_session()
            raise
