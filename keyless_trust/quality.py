"""Data-quality checks on readings whose origin is already proven.

Authenticity and quality are separate questions: a frame can come from the
right sensor and still carry garbage (a failing probe, a stuck value, a
glitch). The monitor sees only frames that passed signature, sequence and
chain checks, so an attacker cannot use it to poison per-sensor statistics.

Readings are JSON objects: ``{"metric": "temp_c", "value": 22.4}``.

Findings are either
  * quarantine flags - the reading is unusable (``usable=False``), or
  * warning flags - the reading is kept but marked suspect.
Quarantined readings never update the baselines used for later checks.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass, field

QUARANTINE = frozenset({"unparseable", "bad_schema", "unknown_metric", "out_of_range"})


def encode_reading(metric: str, value: float, unit: str | None = None) -> bytes:
    body = {"metric": metric, "value": value}
    if unit:
        body["unit"] = unit
    return json.dumps(body, separators=(",", ":")).encode()


@dataclass(frozen=True)
class MetricSpec:
    min: float
    max: float
    max_step: float | None = None  # largest believable change between consecutive readings
    flatline_after: int | None = 10  # identical consecutive readings before "flatline"
    cross_tolerance: float | None = None  # max difference between sensors reading the same metric


@dataclass(frozen=True)
class Assessment:
    flags: tuple[str, ...] = ()
    usable: bool = True


@dataclass
class SensorQuality:
    frames: int = 0
    usable: int = 0
    flags: Counter = field(default_factory=Counter)

    @property
    def score(self) -> float:
        return self.usable / self.frames if self.frames else 1.0


@dataclass
class _Last:
    value: float
    at_ms: int
    repeats: int = 1


class QualityMonitor:
    def __init__(
        self,
        specs: dict[str, MetricSpec],
        *,
        max_gap: float = 30.0,
        cross_window: float = 5.0,
    ) -> None:
        self.specs = specs
        self.max_gap = max_gap
        self.cross_window = cross_window
        self._last: dict[tuple[str, str], _Last] = {}
        self._seen_at: dict[str, int] = {}
        self._stats: dict[str, SensorQuality] = {}

    def assess(self, sensor_id: str, payload: bytes, now_ms: int) -> Assessment:
        flags: list[str] = []

        seen = self._seen_at.get(sensor_id)
        self._seen_at[sensor_id] = now_ms
        if seen is not None and now_ms - seen > self.max_gap * 1000:
            flags.append("gap")

        parsed = self._parse(payload)
        if isinstance(parsed, str):
            flags.append(parsed)
        else:
            metric, value = parsed
            spec = self.specs.get(metric)
            if spec is None:
                flags.append("unknown_metric")
            elif not spec.min <= value <= spec.max:
                flags.append("out_of_range")
            else:
                flags += self._plausibility(sensor_id, metric, value, spec, now_ms)

        assessment = Assessment(tuple(flags), usable=QUARANTINE.isdisjoint(flags))
        stats = self._stats.setdefault(sensor_id, SensorQuality())
        stats.frames += 1
        stats.usable += assessment.usable
        stats.flags.update(flag.split(":")[0] for flag in flags)
        return assessment

    def report(self) -> dict[str, dict]:
        return {
            sensor_id: {
                "frames": s.frames,
                "usable": s.usable,
                "score": round(s.score, 3),
                "flags": dict(s.flags),
            }
            for sensor_id, s in self._stats.items()
        }

    @staticmethod
    def _parse(payload: bytes) -> tuple[str, float] | str:
        try:
            body = json.loads(payload)
        except ValueError:  # includes bad UTF-8 and bad JSON
            return "unparseable"
        if not isinstance(body, dict):
            return "bad_schema"
        metric, raw = body.get("metric"), body.get("value")
        if not isinstance(metric, str) or isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return "bad_schema"
        try:
            value = float(raw)
        except OverflowError:
            return "bad_schema"
        return (metric, value) if math.isfinite(value) else "bad_schema"

    def _plausibility(
        self, sensor_id: str, metric: str, value: float, spec: MetricSpec, now_ms: int
    ) -> list[str]:
        flags: list[str] = []
        last = self._last.get((sensor_id, metric))
        repeats = 1
        if last is not None:
            if spec.max_step is not None and abs(value - last.value) > spec.max_step:
                flags.append("spike")
            if value == last.value:
                repeats = last.repeats + 1
        if spec.flatline_after and repeats >= spec.flatline_after:
            flags.append("flatline")

        if spec.cross_tolerance is not None:
            window_ms = self.cross_window * 1000
            for (other, other_metric), peer in self._last.items():
                if (
                    other_metric == metric
                    and other != sensor_id
                    and now_ms - peer.at_ms <= window_ms
                    and abs(peer.value - value) > spec.cross_tolerance
                ):
                    flags.append(f"disagrees:{other}")

        self._last[(sensor_id, metric)] = _Last(value, now_ms, repeats)
        return flags
