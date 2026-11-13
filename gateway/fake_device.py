from __future__ import annotations

import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

import challenge


class FakeDevice:

    def __init__(
        self,
        device_id: bytes,
        *,
        label: str = "fake device",
        auto_approve: bool | None = True,
        start_counter: int = 0,
        verbose: bool = True,
        private_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> None:
        if len(device_id) != challenge.DEVICE_ID_LEN:
            raise ValueError(
                f"device_id must be {challenge.DEVICE_ID_LEN} bytes"
            )

        self.device_id = bytes(device_id)
        self.label = label
        self.auto_approve = auto_approve
        self.verbose = verbose

        self._key = private_key or ec.generate_private_key(ec.SECP256R1())
        self._counter = start_counter
        self._lock = threading.Lock()


    def public_key_bytes(self) -> bytes:
        """Raw uncompressed point, matching what the SE051 returns."""
        return self._key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    def private_key_pem(self) -> bytes:
        return self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @classmethod
    def from_pem(cls, pem: bytes, device_id: bytes, **kwargs) -> "FakeDevice":
        key = serialization.load_pem_private_key(pem, password=None)
        return cls(device_id, private_key=key, **kwargs)


    def handle_request(
        self,
        *,
        action_bytes: bytes,
        action_hash: bytes,
        nonce: bytes,
        session_id: bytes,
    ) -> dict | None:
        rendered = action_bytes.decode("utf-8", errors="replace")

        if self.verbose:
            print(f"  [{self.label}] APPROVAL REQUESTED")
            print(f"  [{self.label}]   {rendered}")

        own_hash = challenge.action_hash(action_bytes)
        if own_hash != action_hash:
            # The gateway's hash disagrees with what we were shown. Refuse
            # outright: somebody is trying to get us to sign for a different
            # action than the one on screen.
            if self.verbose:
                print(f"  [{self.label}]   REFUSING: action hash mismatch")
            return None

        if self.auto_approve is None:
            if self.verbose:
                print(f"  [{self.label}]   (no answer)")
            return None

        decision = (
            challenge.Decision.APPROVE
            if self.auto_approve
            else challenge.Decision.REJECT
        )

        with self._lock:
            self._counter += 1
            counter = self._counter

        digest = challenge.challenge(
            device_id=self.device_id,
            nonce=nonce,
            action_hash=own_hash,
            session_id=session_id,
            decision=decision,
            counter=counter,
        )

        signature = self._key.sign(
            digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )

        if self.verbose:
            print(f"  [{self.label}]   {decision.name} (counter {counter})")

        return {
            "device_id": self.device_id,
            "decision": decision,
            "counter": counter,
            "signature": signature,
        }