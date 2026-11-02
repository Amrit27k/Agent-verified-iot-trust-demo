"""Wire format, canonical encoding and errors shared by sensors and the gateway.

All messages are JSON objects. Binary fields are base64, times are integer
milliseconds, and anything that is MACed or signed is first serialised with
``canonical`` so both sides hash identical bytes.
"""

import base64
import hashlib
import hmac
import json

GENESIS = b"\x00" * 32

ATTEST_CTX = "keyless-trust/attest/v1"
GATEWAY_CTX = "keyless-trust/gateway/v1"
FRAME_CTX = "keyless-trust/frame/v1"
FRAME_FIELDS = ("type", "session_id", "seq", "ts", "prev", "payload")


class Rejected(Exception):
    """The gateway refused a message. ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class GatewayNotTrusted(Exception):
    """The gateway could not prove it holds this sensor's enrollment record."""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def attestation_proof(
    response: bytes, sensor_id: str, challenge: bytes, nonce: bytes, eph_pub: bytes
) -> bytes:
    """Sensor -> gateway: binds the session public key to the PUF response."""
    msg = canonical(
        {
            "ctx": ATTEST_CTX,
            "sensor_id": sensor_id,
            "challenge": b64e(challenge),
            "nonce": b64e(nonce),
            "eph_pub": b64e(eph_pub),
        }
    )
    return hmac.new(response, msg, hashlib.sha256).digest()


def gateway_proof(
    response: bytes, session_id: str, eph_pub: bytes, expires_at_ms: int, max_frames: int
) -> bytes:
    """Gateway -> sensor: proves the gateway holds the enrolled CRP and fixes
    the session limits, so they cannot be altered in transit."""
    msg = canonical(
        {
            "ctx": GATEWAY_CTX,
            "session_id": session_id,
            "eph_pub": b64e(eph_pub),
            "expires_at_ms": expires_at_ms,
            "max_frames": max_frames,
        }
    )
    return hmac.new(response, msg, hashlib.sha256).digest()


def key_fingerprint(pub: bytes) -> str:
    return hashlib.sha256(pub).hexdigest()[:16]


def challenge_id(challenge: bytes) -> str:
    """Stable label for the CRP that attested a session (reveals nothing about the response)."""
    return hashlib.sha256(challenge).hexdigest()[:16]


def frame_signing_bytes(frame: dict) -> bytes:
    return canonical({"ctx": FRAME_CTX, **{k: frame[k] for k in FRAME_FIELDS}})


def frame_hash(frame: dict) -> bytes:
    """Chain link: the next frame's ``prev`` must equal this."""
    return hashlib.sha256(frame_signing_bytes(frame) + b64d(frame["sig"])).digest()
