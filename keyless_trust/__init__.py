"""Keyless sensor -> gateway trust.

No long-lived keys exist anywhere in the system. A sensor's identity is rooted
in its PUF (physically unclonable function); each session it proves that
identity to the gateway and binds a fresh, RAM-only Ed25519 key to it. Every
stream frame is signed with that ephemeral key and verified by the gateway,
then checked for data quality and recorded in a provenance ledger.
"""

from .enrollment import enroll
from .gateway import Gateway, VerifiedFrame
from .protocol import GatewayNotTrusted, Rejected
from .provenance import ProvenanceLedger, verify_bundle
from .puf import SimulatedPUF
from .quality import Assessment, MetricSpec, QualityMonitor, encode_reading
from .sensor import Sensor

__all__ = [
    "Assessment",
    "Gateway",
    "GatewayNotTrusted",
    "MetricSpec",
    "ProvenanceLedger",
    "QualityMonitor",
    "Rejected",
    "Sensor",
    "SimulatedPUF",
    "VerifiedFrame",
    "encode_reading",
    "enroll",
    "verify_bundle",
]
