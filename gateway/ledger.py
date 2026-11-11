from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import challenge

__all__ = [
    "Ledger",
    "CounterVerdict",
    "NonceVerdict",
]

DEVICE_ID_LEN = challenge.DEVICE_ID_LEN
NONCE_LEN = challenge.NONCE_LEN
COUNTER_MAX = challenge.COUNTER_MAX

# How long an issued nonce stays burnable before it is swept.
DEFAULT_TTL_SECONDS = 120.0

# Sweep at most this often, to keep burn() cheap under load.
SWEEP_INTERVAL_SECONDS = 30.0


@dataclass(frozen=True)
class NonceVerdict:
    ok: bool
    reason: str = "accepted"

    def __bool__(self) -> bool:
        return self.ok


@dataclass(frozen=True)
class CounterVerdict:
    ok: bool
    reason: str = "accepted"
    previous: int | None = None

    def __bool__(self) -> bool:
        return self.ok


@dataclass
class _Stats:
    issued: int = 0
    burned: int = 0
    replays: int = 0
    expired: int = 0
    unknown: int = 0
    counter_rejects: int = 0


class Ledger:
    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        clock=time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()

        self._open: dict[bytes, float] = {}
        self._counters: dict[bytes, int] = {}
        self._last_sweep: float = clock()
        self._stats = _Stats()

    # nonces

    def issue_nonce(self) -> bytes:
        nonce = challenge.new_nonce()
        now = self._clock()

        with self._lock:
            self._maybe_sweep(now)
            self._open[nonce] = now + self._ttl
            self._stats.issued += 1

        return nonce

    def check_and_burn_nonce(self, nonce: bytes) -> NonceVerdict:
        nonce = _validate_nonce(nonce)
        now = self._clock()

        with self._lock:
            expires_at = self._open.pop(nonce, None)
            self._maybe_sweep(now)

            if expires_at is None:
                self._stats.replays += 1
                return NonceVerdict(False, "unknown or already used")

            if expires_at <= now:
                self._stats.expired += 1
                return NonceVerdict(False, "expired")

            self._stats.burned += 1
            return NonceVerdict(True)

    def is_outstanding(self, nonce: bytes) -> bool:
        nonce = _validate_nonce(nonce)
        now = self._clock()
        with self._lock:
            expires_at = self._open.get(nonce)
            return expires_at is not None and expires_at > now

    #counters

    def check_and_advance_counter(
        self, device_id: bytes, counter: int
    ) -> CounterVerdict:
        device_id = _validate_device_id(device_id)
        counter = _validate_counter(counter)

        with self._lock:
            previous = self._counters.get(device_id)

            if previous is None:
                self._counters[device_id] = counter
                return CounterVerdict(True, "first seen", None)

            if counter <= previous:
                self._stats.counter_rejects += 1
                return CounterVerdict(
                    False,
                    f"counter {counter} is not greater than {previous}",
                    previous,
                )

            self._counters[device_id] = counter
            return CounterVerdict(True, "accepted", previous)

    def last_counter(self, device_id: bytes) -> int | None:
        device_id = _validate_device_id(device_id)
        with self._lock:
            return self._counters.get(device_id)

    def forget_device(self, device_id: bytes) -> None:
        """Drop counter state. Call this when a device is unregistered, so a
        re-enrolled unit starting from zero is not rejected forever."""
        device_id = _validate_device_id(device_id)
        with self._lock:
            self._counters.pop(device_id, None)

    #housekeeping

    def sweep(self) -> int:
        now = self._clock()
        with self._lock:
            return self._sweep_locked(now)

    def _maybe_sweep(self, now: float) -> None:
        """Caller must hold the lock."""
        if now - self._last_sweep >= SWEEP_INTERVAL_SECONDS:
            self._sweep_locked(now)

    def _sweep_locked(self, now: float) -> int:
        dead = [n for n, exp in self._open.items() if exp <= now]
        for n in dead:
            del self._open[n]
        self._last_sweep = now
        return len(dead)

    @property
    def outstanding(self) -> int:
        with self._lock:
            return len(self._open)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "issued": self._stats.issued,
                "burned": self._stats.burned,
                "replays": self._stats.replays,
                "expired": self._stats.expired,
                "unknown": self._stats.unknown,
                "counter_rejects": self._stats.counter_rejects,
                "outstanding": len(self._open),
                "devices_tracked": len(self._counters),
            }


# validation


def _validate_nonce(nonce: bytes) -> bytes:
    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError(f"nonce must be bytes, got {type(nonce).__name__}")
    if len(nonce) != NONCE_LEN:
        raise ValueError(
            f"nonce must be exactly {NONCE_LEN} bytes, got {len(nonce)}"
        )
    return bytes(nonce)


def _validate_device_id(device_id: bytes) -> bytes:
    if not isinstance(device_id, (bytes, bytearray)):
        raise TypeError(
            f"device_id must be bytes, got {type(device_id).__name__}"
        )
    if len(device_id) != DEVICE_ID_LEN:
        raise ValueError(
            f"device_id must be exactly {DEVICE_ID_LEN} bytes, "
            f"got {len(device_id)}"
        )
    return bytes(device_id)


def _validate_counter(counter: int) -> int:
    if not isinstance(counter, int) or isinstance(counter, bool):
        raise TypeError("counter must be an int")
    if not 0 <= counter <= COUNTER_MAX:
        raise ValueError(f"counter must be in 0..{COUNTER_MAX}, got {counter}")
    return counter