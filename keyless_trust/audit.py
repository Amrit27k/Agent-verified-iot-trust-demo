"""Append-only, hash-chained audit log kept by the gateway."""

import hashlib
from collections.abc import Callable, Iterator

from .protocol import GENESIS, canonical


def entry_hash_ok(entry: dict) -> bool:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(canonical(body)).hexdigest() == entry.get("hash")


class AuditLog:
    """Every entry commits to the previous one, so any edit, insertion or
    deletion after the fact makes ``verify`` fail."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._entries: list[dict] = []

    def append(self, event: str, **fields) -> dict:
        body = {
            "index": len(self._entries),
            "ts": int(self._clock() * 1000),
            "event": event,
            **fields,
            "prev": self.head,
        }
        entry = {**body, "hash": hashlib.sha256(canonical(body)).hexdigest()}
        self._entries.append(entry)
        return entry

    @property
    def head(self) -> str:
        return self._entries[-1]["hash"] if self._entries else GENESIS.hex()

    def verify(self) -> bool:
        prev = GENESIS.hex()
        for index, entry in enumerate(self._entries):
            if entry.get("index") != index or entry.get("prev") != prev:
                return False
            if not entry_hash_ok(entry):
                return False
            prev = entry["hash"]
        return True

    def __getitem__(self, index: int) -> dict:
        return self._entries[index]

    def __iter__(self) -> Iterator[dict]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)
