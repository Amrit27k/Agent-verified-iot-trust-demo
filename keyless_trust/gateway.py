"""Gateway: attests sensors, manages session keys and verifies the origin of
every stream frame, then records quality and provenance for what it accepts."""

from __future__ import annotations

import functools
import hmac
import os
import time
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import protocol as p
from .audit import AuditLog
from .protocol import Rejected
from .provenance import ProvenanceLedger
from .quality import Assessment, QualityMonitor


@dataclass(frozen=True)
class VerifiedFrame:
    """A frame whose origin has been proven. ``sensor_id`` comes from the
    attested session, never from anything the frame claims about itself.

    ``usable`` is the data-quality verdict: an authentic frame can still be
    quarantined (``usable=False``) when its reading is garbage."""

    sensor_id: str
    session_id: str
    seq: int
    ts: int
    payload: bytes
    frame_hash: bytes = b""
    flags: tuple[str, ...] = ()
    usable: bool = True


@dataclass
class _Pending:
    response: bytes
    nonce: bytes
    issued_at: float


@dataclass
class _Session:
    session_id: str
    sensor_id: str
    public_key: Ed25519PublicKey
    eph_pub: bytes
    challenge_id: str
    established_at_ms: int
    expires_at_ms: int
    max_frames: int
    next_seq: int = 0
    prev_hash: bytes = p.GENESIS
    last_ts: int = 0


def _guard(handler):
    """Turn malformed input into a ``Rejected`` instead of a crash."""

    @functools.wraps(handler)
    def wrapper(self: Gateway, msg: dict):
        try:
            return handler(self, msg)
        except Rejected:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            self._reject("malformed", f"{handler.__name__}: {exc!r}")

    return wrapper


class Gateway:
    def __init__(
        self,
        *,
        session_ttl: float = 300.0,
        max_frames_per_session: int = 10_000,
        challenge_ttl: float = 10.0,
        max_outstanding_challenges: int = 4,
        max_clock_skew: float = 30.0,
        low_crp_threshold: int = 4,
        quality: QualityMonitor | None = None,
        on_alert: Callable[[str, dict], None] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.session_ttl = session_ttl
        self.max_frames_per_session = max_frames_per_session
        self.challenge_ttl = challenge_ttl
        self.max_outstanding_challenges = max_outstanding_challenges
        self.max_clock_skew = max_clock_skew
        self.low_crp_threshold = low_crp_threshold
        self.quality = quality
        self._on_alert = on_alert
        self._clock = clock
        self._crps: dict[str, dict[bytes, bytes]] = {}
        # Several challenges may be outstanding per sensor, so a stranger
        # sending "hello" cannot knock the real sensor's handshake over.
        self._pending: dict[str, dict[bytes, _Pending]] = {}
        self._sessions: dict[str, _Session] = {}
        self._active: dict[str, str] = {}  # sensor_id -> session_id
        self._revoked: set[str] = set()
        self._low_alerted: set[str] = set()
        self.audit = AuditLog(clock)
        self.provenance = ProvenanceLedger(clock)

    # -- enrollment & key management ---------------------------------------

    def register(self, sensor_id: str, crps: dict[bytes, bytes]) -> None:
        if sensor_id in self._revoked:
            raise ValueError(f"{sensor_id} is revoked; reinstate it before re-enrolling")
        pool = self._crps.setdefault(sensor_id, {})
        pool.update(crps)
        if len(pool) >= self.low_crp_threshold:
            self._low_alerted.discard(sensor_id)
        self.audit.append("enrolled", sensor_id=sensor_id, crps=len(crps))

    def crps_remaining(self, sensor_id: str) -> int:
        return len(self._crps.get(sensor_id, {}))

    def enrollment_status(self, sensor_id: str) -> dict:
        return {
            "enrolled": sensor_id in self._crps,
            "available": self.crps_remaining(sensor_id),
            "outstanding": len(self._pending.get(sensor_id, {})),
            "revoked": sensor_id in self._revoked,
        }

    def active_session(self, sensor_id: str) -> str | None:
        return self._active.get(sensor_id)

    def key_inventory(self) -> list[dict]:
        """Every live session key. Only public material exists on the gateway."""
        now_ms = int(self._clock() * 1000)
        return [
            {
                "sensor_id": s.sensor_id,
                "session_id": s.session_id,
                "key_fingerprint": p.key_fingerprint(s.eph_pub),
                "challenge_id": s.challenge_id,
                "age_s": round((now_ms - s.established_at_ms) / 1000, 3),
                "expires_in_s": round((s.expires_at_ms - now_ms) / 1000, 3),
                "frames": s.next_seq,
                "max_frames": s.max_frames,
            }
            for s in self._sessions.values()
        ]

    def revoke_session(self, session_id: str, reason: str = "revoked") -> bool:
        session = self._sessions.get(session_id)
        if session is None:
            return False
        self._end_session(session, reason)
        return True

    def revoke_sensor(self, sensor_id: str, reason: str = "revoked") -> None:
        """Cut a sensor off: end its session, destroy its enrollment, refuse
        any further hello. Needs ``reinstate_sensor`` plus re-enrollment to undo."""
        self._revoked.add(sensor_id)
        session_id = self._active.get(sensor_id)
        if session_id in self._sessions:
            self._end_session(self._sessions[session_id], f"sensor_revoked: {reason}")
        self._pending.pop(sensor_id, None)
        self._crps.pop(sensor_id, None)
        self._low_alerted.discard(sensor_id)
        self.audit.append("sensor_revoked", sensor_id=sensor_id, reason=reason)

    def reinstate_sensor(self, sensor_id: str) -> None:
        self._revoked.discard(sensor_id)
        self.audit.append("sensor_reinstated", sensor_id=sensor_id)

    # -- attestation -------------------------------------------------------

    @_guard
    def handle_hello(self, msg: dict) -> dict:
        sensor_id = msg["sensor_id"]
        if sensor_id in self._revoked:
            self._reject("revoked", sensor_id)
        pool = self._crps.get(sensor_id)
        if pool is None:
            self._reject("unknown_sensor", sensor_id)

        self._expire_sessions()
        outstanding = self._pending.setdefault(sensor_id, {})
        now = self._clock()
        for challenge, pending in list(outstanding.items()):
            if now - pending.issued_at > self.challenge_ttl:
                self._release(sensor_id, challenge)
        if len(outstanding) >= self.max_outstanding_challenges:
            # Refuse rather than evict: evicting would let a flood of hellos
            # push out a handshake the real sensor already has in flight.
            self._reject("busy", sensor_id)
        if not pool:
            self._reject("crps_exhausted", sensor_id)

        challenge, response = pool.popitem()
        nonce = os.urandom(16)
        outstanding[challenge] = _Pending(response, nonce, now)
        if len(pool) < self.low_crp_threshold and sensor_id not in self._low_alerted:
            self._low_alerted.add(sensor_id)
            self._alert("crps_low", sensor_id=sensor_id, remaining=len(pool))
        return {
            "type": "challenge",
            "sensor_id": sensor_id,
            "challenge": p.b64e(challenge),
            "nonce": p.b64e(nonce),
        }

    @_guard
    def handle_attest(self, msg: dict) -> dict:
        sensor_id = msg["sensor_id"]
        if sensor_id in self._revoked:
            self._reject("revoked", sensor_id)
        challenge = p.b64d(msg["challenge"])
        pending = self._pending.get(sensor_id, {}).get(challenge)
        if pending is None:
            self._reject("no_challenge", sensor_id)
        if self._clock() - pending.issued_at > self.challenge_ttl:
            self._release(sensor_id, challenge)
            self._reject("challenge_expired", sensor_id)

        eph_pub = p.b64d(msg["eph_pub"])
        expected = p.attestation_proof(pending.response, sensor_id, challenge, pending.nonce, eph_pub)
        if not hmac.compare_digest(expected, p.b64d(msg["proof"])):
            # Leave the challenge in place: whoever failed learned nothing
            # about the response, and a stranger must not be able to cancel
            # the real sensor's handshake by spoiling it.
            self._reject("bad_attestation", sensor_id)
        public_key = Ed25519PublicKey.from_public_bytes(eph_pub)

        # Success consumes the CRP for good.
        del self._pending[sensor_id][challenge]
        previous = self._active.get(sensor_id)
        if previous in self._sessions:
            self._end_session(self._sessions[previous], "replaced")

        session_id = os.urandom(16).hex()
        now_ms = int(self._clock() * 1000)
        session = _Session(
            session_id=session_id,
            sensor_id=sensor_id,
            public_key=public_key,
            eph_pub=eph_pub,
            challenge_id=p.challenge_id(challenge),
            established_at_ms=now_ms,
            expires_at_ms=now_ms + int(self.session_ttl * 1000),
            max_frames=self.max_frames_per_session,
        )
        self._sessions[session_id] = session
        self._active[sensor_id] = session_id
        self.audit.append(
            "session_established",
            sensor_id=sensor_id,
            session_id=session_id,
            key_fingerprint=p.key_fingerprint(eph_pub),
            challenge_id=session.challenge_id,
            expires_at=session.expires_at_ms,
            max_frames=session.max_frames,
            replaced=previous,
        )
        self.provenance.open_session(
            sensor_id=sensor_id,
            session_id=session_id,
            eph_pub=eph_pub,
            challenge_id=session.challenge_id,
            expires_at_ms=session.expires_at_ms,
            max_frames=session.max_frames,
        )
        proof = p.gateway_proof(
            pending.response, session_id, eph_pub, session.expires_at_ms, session.max_frames
        )
        return {
            "type": "session",
            "session_id": session_id,
            "expires_at_ms": session.expires_at_ms,
            "max_frames": session.max_frames,
            "proof": p.b64e(proof),
        }

    # -- streaming ---------------------------------------------------------

    @_guard
    def verify_frame(self, msg: dict) -> VerifiedFrame:
        session = self._sessions.get(msg["session_id"])
        if session is None:
            self._reject("unknown_session", str(msg["session_id"]))

        # Signature first: until it checks out the frame could come from
        # anyone, so it must not touch session state.
        try:
            session.public_key.verify(p.b64d(msg["sig"]), p.frame_signing_bytes(msg))
        except InvalidSignature:
            self._reject("bad_signature", session.sensor_id)
        payload = p.b64d(msg["payload"])

        now_ms = int(self._clock() * 1000)
        if now_ms >= session.expires_at_ms:
            self._end_session(session, "expired")
            self._reject("session_expired", session.sensor_id)
        if session.next_seq >= session.max_frames:
            self._end_session(session, "exhausted")
            self._reject("session_exhausted", session.sensor_id)

        seq, ts, prev = msg["seq"], msg["ts"], p.b64d(msg["prev"])
        if seq != session.next_seq:
            self._reject("bad_sequence", f"{session.sensor_id}: expected {session.next_seq}, got {seq}")
        if not hmac.compare_digest(prev, session.prev_hash):
            self._reject("broken_chain", session.sensor_id)
        if ts < session.last_ts or abs(now_ms - ts) > self.max_clock_skew * 1000:
            self._reject("bad_timestamp", f"{session.sensor_id}: ts={ts} now={now_ms}")

        # Origin is proven. From here the frame is authentic whatever its
        # content, so it advances the chain even if the data is quarantined.
        frame_hash = p.frame_hash(msg)
        session.next_seq += 1
        session.prev_hash = frame_hash
        session.last_ts = ts

        verdict = (
            self.quality.assess(session.sensor_id, payload, now_ms) if self.quality else Assessment()
        )
        self.provenance.record_frame(session.session_id, msg, frame_hash, verdict.flags, verdict.usable)
        return VerifiedFrame(
            session.sensor_id,
            session.session_id,
            seq,
            ts,
            payload,
            frame_hash,
            verdict.flags,
            verdict.usable,
        )

    def stream_digest(self, sensor_id: str) -> bytes | None:
        """Hash of the latest verified frame; commits to the whole session stream."""
        session = self._sessions.get(self._active.get(sensor_id, ""))
        return session.prev_hash if session else None

    # -- internals ---------------------------------------------------------

    def _release(self, sensor_id: str, challenge: bytes) -> None:
        # An unanswered or failed challenge never revealed its response, so
        # the CRP can safely go back into the pool.
        pending = self._pending.get(sensor_id, {}).pop(challenge, None)
        if pending is not None and sensor_id in self._crps:
            self._crps[sensor_id][challenge] = pending.response

    def _expire_sessions(self) -> None:
        now_ms = int(self._clock() * 1000)
        for session in list(self._sessions.values()):
            if now_ms >= session.expires_at_ms:
                self._end_session(session, "expired")

    def _end_session(self, session: _Session, reason: str) -> None:
        self._sessions.pop(session.session_id, None)
        if self._active.get(session.sensor_id) == session.session_id:
            del self._active[session.sensor_id]
        self.audit.append(
            "session_ended", sensor_id=session.sensor_id, session_id=session.session_id, reason=reason
        )
        self.provenance.close_session(session.session_id, reason)

    def _alert(self, name: str, **details) -> None:
        self.audit.append("alert", name=name, **details)
        if self._on_alert is not None:
            self._on_alert(name, details)

    def _reject(self, reason: str, detail: str = ""):
        self.audit.append("rejected", reason=reason, detail=detail)
        raise Rejected(reason, detail)
