"""Provenance: where every datum came from, and a way to prove it later.

For each session the ledger records which sensor, which ephemeral key and
which enrollment CRP vouched for it; for each frame, a digest of its payload,
its place in the hash chain and its quality verdict. Records are themselves
hash-chained, so the ledger head can be anchored somewhere external
(a log, a printout, another system) to make later rewriting detectable.

``export_session`` produces a self-contained bundle. ``verify_bundle`` checks
it with no access to the gateway: frames really were signed, in order and
unmodified, by the session key. Linking that key to a *sensor* rests on the
gateway's attestation record (``challenge_id`` names the CRP it used), because
the system deliberately has no long-lived key to sign that claim with.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import protocol as p
from .audit import AuditLog, entry_hash_ok


class ProvenanceLedger:
    def __init__(self, clock: Callable[[], float]) -> None:
        self._log = AuditLog(clock)
        self._sessions: dict[str, dict] = {}
        self._frames: dict[str, list[dict]] = {}
        self._index: dict[tuple[str, int], int] = {}

    @property
    def head(self) -> str:
        return self._log.head

    def verify(self) -> bool:
        return self._log.verify()

    def open_session(
        self,
        *,
        sensor_id: str,
        session_id: str,
        eph_pub: bytes,
        challenge_id: str,
        expires_at_ms: int,
        max_frames: int,
    ) -> None:
        info = {
            "sensor_id": sensor_id,
            "session_id": session_id,
            "eph_pub": p.b64e(eph_pub),
            "key_fingerprint": p.key_fingerprint(eph_pub),
            "challenge_id": challenge_id,
            "expires_at_ms": expires_at_ms,
            "max_frames": max_frames,
        }
        entry = self._log.append("session_open", **info)
        self._sessions[session_id] = {**info, "opened_at_ms": entry["ts"], "closed": None}
        self._frames[session_id] = []

    def close_session(self, session_id: str, reason: str) -> None:
        info = self._sessions.get(session_id)
        if info is not None and info["closed"] is None:
            info["closed"] = reason
            self._log.append(
                "session_close", sensor_id=info["sensor_id"], session_id=session_id, reason=reason
            )

    def record_frame(
        self, session_id: str, frame: dict, frame_hash: bytes, flags: tuple[str, ...], usable: bool
    ) -> None:
        info = self._sessions[session_id]
        entry = self._log.append(
            "frame",
            sensor_id=info["sensor_id"],
            session_id=session_id,
            seq=frame["seq"],
            frame_ts=frame["ts"],
            payload_sha256=hashlib.sha256(p.b64d(frame["payload"])).hexdigest(),
            frame_hash=frame_hash.hex(),
            flags=list(flags),
            usable=usable,
        )
        self._frames[session_id].append(dict(frame))
        self._index[(session_id, frame["seq"])] = entry["index"]

    def lineage(self, session_id: str, seq: int) -> dict | None:
        """Everything known about one frame's origin, or None."""
        index = self._index.get((session_id, seq))
        if index is None:
            return None
        return {"record": dict(self._log[index]), "session": dict(self._sessions[session_id])}

    def export_session(self, session_id: str) -> dict:
        info = self._sessions[session_id]
        frames = self._frames[session_id]
        return {
            "version": 1,
            "session": dict(info),
            "frames": [dict(f) for f in frames],
            "records": [dict(self._log[self._index[(session_id, f["seq"])]]) for f in frames],
            "ledger_head": self.head,
        }


def verify_bundle(bundle: dict) -> list[str]:
    """Check an exported bundle on its own. Returns problems; empty means intact."""
    problems: list[str] = []
    try:
        session = bundle["session"]
        frames, records = bundle["frames"], bundle["records"]
        pub = p.b64d(session["eph_pub"])
        key = Ed25519PublicKey.from_public_bytes(pub)
        if p.key_fingerprint(pub) != session["key_fingerprint"]:
            problems.append("fingerprint_mismatch")
        if len(records) != len(frames):
            problems.append("record_count_mismatch")

        prev = p.GENESIS
        for i, frame in enumerate(frames):
            label = f"frame {i}"
            if frame["session_id"] != session["session_id"]:
                problems.append(f"{label}: wrong_session")
            if frame["seq"] != i:
                problems.append(f"{label}: bad_sequence")
            if p.b64d(frame["prev"]) != prev:
                problems.append(f"{label}: broken_chain")
            try:
                key.verify(p.b64d(frame["sig"]), p.frame_signing_bytes(frame))
            except InvalidSignature:
                problems.append(f"{label}: bad_signature")
            frame_hash = p.frame_hash(frame)
            prev = frame_hash

            if i < len(records):
                record = records[i]
                if not entry_hash_ok(record):
                    problems.append(f"{label}: record_tampered")
                if record.get("payload_sha256") != hashlib.sha256(p.b64d(frame["payload"])).hexdigest():
                    problems.append(f"{label}: record_payload_mismatch")
                if record.get("frame_hash") != frame_hash.hex() or record.get("seq") != frame["seq"]:
                    problems.append(f"{label}: record_frame_mismatch")
    except (KeyError, TypeError, ValueError, AttributeError):
        problems.append("malformed_bundle")
    return problems
