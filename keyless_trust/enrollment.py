"""One-time factory enrollment of a sensor with the gateway."""

import os

from .gateway import Gateway
from .puf import SimulatedPUF

CHALLENGE_SIZE = 16


def enroll(gateway: Gateway, sensor_id: str, puf: SimulatedPUF, count: int = 64) -> None:
    """Record ``count`` challenge-response pairs (CRPs) for a sensor.

    Run once over a trusted bench connection before deployment. Each CRP is
    used for at most one attestation, so ``count`` bounds how many sessions
    the sensor can open before it needs re-enrolling.
    """
    crps = {}
    while len(crps) < count:
        challenge = os.urandom(CHALLENGE_SIZE)
        crps[challenge] = puf.respond(challenge)
    gateway.register(sensor_id, crps)
