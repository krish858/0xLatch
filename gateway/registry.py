from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone

import challenge

__all__ = [
    "UnknownDevice",
    "DeviceAlreadyRegistered",
    "Device",
    "Registry",
]

DEVICE_ID_LEN = challenge.DEVICE_ID_LEN


class UnknownDevice(LookupError):
    """No device is enrolled under that id.

    Deliberately an exception rather than a None return. A None public key
    flowing into verify() becomes a skipped signature check, and a skipped
    check is an approval.
    """


class DeviceAlreadyRegistered(ValueError):
    """Something is already enrolled under that id.

    Silently overwriting a key is how a device gets hijacked, so replacing
    one has to be explicit.
    """


@dataclass(frozen=True)
class Device:
    device_id: bytes
    public_key: bytes
    label: str
    enrolled_at: datetime

    @property
    def device_id_hex(self) -> str:
        return self.device_id.hex().upper()

    def __repr__(self) -> str:  # keeps key material out of logs
        return f"<Device {self.label!r} {self.device_id_hex}>"


class Registry:
    """In-memory device registry.

    Swap the storage later (JSON file, SQLite) without changing callers —
    that is why this is a class with a narrow interface rather than a
    module-level dict.
    """

    def __init__(self) -> None:
        self._devices: dict[bytes, Device] = {}
        self._lock = threading.Lock()

    # enrollment 

    def register(
        self,
        device_id: bytes,
        public_key: bytes,
        label: str = "",
        *,
        replace: bool = False,
    ) -> Device:
        """Enroll a device.

        Validates the key by parsing it. Better to reject junk at enrollment,
        at a desk, than at 3am when somebody presses approve.
        """
        device_id = _validate_device_id(device_id)

        if not isinstance(public_key, (bytes, bytearray)):
            raise TypeError("public_key must be bytes")
        public_key = bytes(public_key)

        # Raises if this is not a usable secp256r1 key.
        challenge.load_public_key(public_key)

        device = Device(
            device_id=device_id,
            public_key=public_key,
            label=label,
            enrolled_at=datetime.now(timezone.utc),
        )

        with self._lock:
            if device_id in self._devices and not replace:
                raise DeviceAlreadyRegistered(
                    f"{device_id.hex().upper()} is already enrolled; "
                    f"pass replace=True to overwrite"
                )
            self._devices[device_id] = device

        return device

    def unregister(self, device_id: bytes) -> None:
        """Remove a device. Revocation — a lost or retired unit.

        Remember to call ledger.forget_device() too, or a re-enrolled unit
        starting from counter 0 will be rejected forever.
        """
        device_id = _validate_device_id(device_id)
        with self._lock:
            if self._devices.pop(device_id, None) is None:
                raise UnknownDevice(device_id.hex().upper())

    # lookup

    def public_key_for(self, device_id: bytes) -> bytes:
        """The enrolled public key. Raises UnknownDevice if there isn't one."""
        return self.get(device_id).public_key

    def get(self, device_id: bytes) -> Device:
        device_id = _validate_device_id(device_id)
        with self._lock:
            device = self._devices.get(device_id)
        if device is None:
            raise UnknownDevice(device_id.hex().upper())
        return device

    def is_registered(self, device_id: bytes) -> bool:
        try:
            self.get(device_id)
        except (UnknownDevice, ValueError, TypeError):
            return False
        return True

    def devices(self) -> list[Device]:
        """Everything enrolled, for the admin console."""
        with self._lock:
            return sorted(self._devices.values(), key=lambda d: d.enrolled_at)

    def __len__(self) -> int:
        with self._lock:
            return len(self._devices)

    def __contains__(self, device_id: object) -> bool:
        return isinstance(device_id, (bytes, bytearray)) and self.is_registered(
            bytes(device_id)
        )


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