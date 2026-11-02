"""Sensor side: attest with the PUF, then sign every frame with an ephemeral key."""

from __future__ import annotations

import hmac
import time
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import protocol as p
from .protocol import GatewayNotTrusted
from .puf import SimulatedPUF


@dataclass
class _Handshake:
    key: Ed25519PrivateKey
    eph_pub: bytes
    response: bytes


@dataclass
class _Session:
    session_id: str
    key: Ed25519PrivateKey
    expires_at_ms: int
    max_frames: int
    seq: int = 0
    prev: bytes = p.GENESIS


class Sensor:
    def __init__(
        self,
        sensor_id: str,
        puf: SimulatedPUF,
        *,
        renew_margin: float = 1.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.sensor_id = sensor_id
        self._puf = puf
        self._renew_margin_ms = int(renew_margin * 1000)
        self._clock = clock
        self._handshake: _Handshake | None = None
        self._session: _Session | None = None

    @property
    def session_id(self) -> str | None:
        return self._session.session_id if self._session else None

    @property
    def needs_attestation(self) -> bool:
        session = self._session
        if session is None:
            return True
        return (
            self._now_ms() >= session.expires_at_ms - self._renew_margin_ms
            or session.seq >= session.max_frames
        )

    def hello(self) -> dict:
        return {"type": "hello", "sensor_id": self.sensor_id}

    def respond(self, challenge_msg: dict) -> dict:
        if challenge_msg.get("sensor_id") != self.sensor_id:
            raise ValueError("challenge addressed to a different sensor")
        challenge = p.b64d(challenge_msg["challenge"])
        nonce = p.b64d(challenge_msg["nonce"])

        # Fresh key per session, held only in RAM. It is never written to
        # storage and is dropped when the session ends.
        key = Ed25519PrivateKey.generate()
        eph_pub = key.public_key().public_bytes_raw()
        response = self._puf.respond(challenge)
        self._handshake = _Handshake(key, eph_pub, response)

        proof = p.attestation_proof(response, self.sensor_id, challenge, nonce, eph_pub)
        return {
            "type": "attest",
            "sensor_id": self.sensor_id,
            "challenge": challenge_msg["challenge"],
            "eph_pub": p.b64e(eph_pub),
            "proof": p.b64e(proof),
        }

    def establish(self, session_msg: dict) -> None:
        handshake, self._handshake = self._handshake, None
        if handshake is None:
            raise RuntimeError("no attestation in progress")
        expected = p.gateway_proof(
            handshake.response,
            session_msg["session_id"],
            handshake.eph_pub,
            session_msg["expires_at_ms"],
            session_msg["max_frames"],
        )
        if not hmac.compare_digest(expected, p.b64d(session_msg["proof"])):
            raise GatewayNotTrusted(self.sensor_id)
        self._session = _Session(
            session_msg["session_id"],
            handshake.key,
            session_msg["expires_at_ms"],
            session_msg["max_frames"],
        )

    def frame(self, payload: bytes) -> dict:
        session = self._session
        if session is None or self._now_ms() >= session.expires_at_ms or session.seq >= session.max_frames:
            raise RuntimeError("no valid session; attest first")
        frame = {
            "type": "frame",
            "session_id": session.session_id,
            "seq": session.seq,
            "ts": self._now_ms(),
            "prev": p.b64e(session.prev),
            "payload": p.b64e(payload),
        }
        frame["sig"] = p.b64e(session.key.sign(p.frame_signing_bytes(frame)))
        session.seq += 1
        session.prev = p.frame_hash(frame)
        return frame

    def drop_session(self) -> None:
        """Forget the session key. (CPython cannot guarantee the bytes are
        wiped; on real firmware the key lives in a zeroisable buffer.)"""
        self._session = None
        self._handshake = None

    def _now_ms(self) -> int:
        return int(self._clock() * 1000)
