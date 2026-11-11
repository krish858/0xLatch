from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = ["AuditLog", "Entry", "GENESIS"]


GENESIS = bytes(32)


@dataclass(frozen=True)
class Entry:
    seq: int
    timestamp: str
    event: str
    detail: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


def _hash_entry(seq: int, timestamp: str, event: str,
                detail: dict[str, Any], prev_hash: bytes) -> bytes:
    payload = json.dumps(
        {
            "seq": seq,
            "timestamp": timestamp,
            "event": event,
            "detail": detail,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(prev_hash + payload).digest()


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self._entries: list[Entry] = []
        self._last_hash: bytes = GENESIS
        self._lock = threading.Lock()
        self._path = Path(path) if path else None

    def record(self, event: str, **detail: Any) -> Entry:
        timestamp = datetime.now(timezone.utc).isoformat()

        with self._lock:
            seq = len(self._entries)
            prev = self._last_hash
            digest = _hash_entry(seq, timestamp, event, detail, prev)

            entry = Entry(
                seq=seq,
                timestamp=timestamp,
                event=event,
                detail=detail,
                prev_hash=prev.hex(),
                entry_hash=digest.hex(),
            )

            self._entries.append(entry)
            self._last_hash = digest

            if self._path is not None:
                with self._path.open("a") as fh:
                    fh.write(entry.to_json() + "\n")

        return entry

    def verify_chain(self) -> tuple[bool, int | None]:
        prev = GENESIS
        with self._lock:
            entries = list(self._entries)

        for entry in entries:
            if entry.prev_hash != prev.hex():
                return False, entry.seq
            digest = _hash_entry(
                entry.seq, entry.timestamp, entry.event, entry.detail, prev
            )
            if digest.hex() != entry.entry_hash:
                return False, entry.seq
            prev = digest

        return True, None

    @property
    def head(self) -> str:
        with self._lock:
            return self._last_hash.hex()

    def entries(self) -> list[Entry]:
        with self._lock:
            return list(self._entries)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)