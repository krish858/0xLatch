from __future__ import annotations

import threading

from cryptography.hazmat.primitives import hashes, serialization #type: ignore
from cryptography.hazmat.primitives.asymmetric import ec, utils #type: ignore

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
    ) -> None:
        if len(device_id) != challenge.DEVICE_ID_LEN:
            raise ValueError(
                f"device_id must be {challenge.DEVICE_ID_LEN} bytes"
            )

        self.device_id = bytes(device_id)
        self.label = label

        #: True = always approve, False = always reject, None = never answer.
        #: None exists so you can test the timeout path, which must deny.
        self.auto_approve = auto_approve
        self.verbose = verbose

        self._key = ec.generate_private_key(ec.SECP256R1())
        self._counter = start_counter
        self._lock = threading.Lock()

    # -- enrollment ------------------------------------------------------

    def public_key_bytes(self) -> bytes:
        """Raw uncompressed point, matching what the SE051 returns."""
        return self._key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    # -- the approval flow ------------------------------------------------

    def handle_request(
        self,
        *,
        action_bytes: bytes,
        action_hash: bytes,
        nonce: bytes,
        session_id: bytes,
    ) -> dict | None:
        """Render, decide, sign. None means no answer, which must deny.

        Note that it hashes action_bytes itself rather than trusting the
        action_hash it was handed. That is the what-you-see-is-what-you-sign
        property: the device signs a hash of the bytes it actually rendered,
        never one the server supplied alongside a different display string.
        """
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