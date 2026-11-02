"""Simulated Physically Unclonable Function (PUF).

A real PUF derives a device-unique response from manufacturing variation in
the silicon (SRAM start-up state, ring-oscillator delays, ...). Nothing is
stored: the secret only exists while the circuit is measured and cannot be
copied into another device. That is what makes the sensors keyless: there is
no private key in flash to provision, rotate, leak or revoke.

This class stands in for that hardware. ``__silicon`` models the physical
variation; firmware can only call ``respond``.
"""

import hashlib
import hmac
import os


class SimulatedPUF:
    def __init__(self, seed_file: str | None = None) -> None:
        """``seed_file`` keeps the simulated silicon across reboots on a real
        board. That file IS a stored secret, which a real PUF would not need;
        it exists only so a hardware demo keeps its identity."""
        if seed_file is None:
            self.__silicon = os.urandom(32)
        elif os.path.exists(seed_file):
            with open(seed_file, "rb") as f:
                self.__silicon = f.read()
        else:
            self.__silicon = os.urandom(32)
            with open(os.open(seed_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                f.write(self.__silicon)

    def respond(self, challenge: bytes) -> bytes:
        return hmac.new(self.__silicon, challenge, hashlib.sha256).digest()

    def __repr__(self) -> str:
        return "SimulatedPUF(<unreadable>)"
