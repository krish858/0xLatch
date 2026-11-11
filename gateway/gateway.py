from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import audit as audit_mod
import challenge
import ledger as ledger_mod
import registry as registry_mod

__all__ = ["Gateway", "Tier", "Policy", "Outcome", "Denied"]


class Tier(Enum):
    ROUTINE = "routine"
    CONSEQUENTIAL = "consequential"
    FORBIDDEN = "forbidden"


@dataclass(frozen=True)
class Policy:

    approval_above: int = 10_000
    ceiling: int = 5_000_000

    def classify(self, amount_minor: int) -> Tier:
        if amount_minor > self.ceiling:
            return Tier.FORBIDDEN
        if amount_minor > self.approval_above:
            return Tier.CONSEQUENTIAL
        return Tier.ROUTINE


class Denied(Exception):

    def __init__(self, reason: str, tier: Tier | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.tier = tier


@dataclass(frozen=True)
class Outcome:
    allowed: bool
    tier: Tier
    reason: str
    counter: int | None = None


class Gateway:
    def __init__(
        self,
        *,
        registry: registry_mod.Registry,
        ledger: ledger_mod.Ledger,
        audit: audit_mod.AuditLog,
        policy: Policy | None = None,
        device=None,
    ) -> None:
        self.registry = registry
        self.ledger = ledger
        self.audit = audit
        self.policy = policy or Policy()

        self.device = device


    def request_payment(
        self,
        *,
        reference: str,
        amount_minor: int,
        currency: str,
        counterparty: str,
        session_id: bytes,
    ) -> Outcome:
        action_bytes = challenge.canonical_action(
            "PAY", reference, amount_minor, currency, counterparty
        )
        tier = self.policy.classify(amount_minor)

        self.audit.record(
            "request.received",
            action=action_bytes.decode(),
            tier=tier.value,
            session_id=session_id.hex(),
        )

        if tier is Tier.FORBIDDEN:
            self.audit.record(
                "request.denied",
                reason="above ceiling",
                tier=tier.value,
                action=action_bytes.decode(),
            )
            raise Denied(
                f"amount {amount_minor} exceeds the ceiling "
                f"{self.policy.ceiling}; no approval can authorise this",
                tier,
            )

        if tier is Tier.ROUTINE:
            self.audit.record(
                "request.allowed",
                reason="routine tier",
                tier=tier.value,
                action=action_bytes.decode(),
            )
            return Outcome(True, tier, "routine, no approval needed")

        return self._seek_approval(action_bytes, session_id, tier)


    def _seek_approval(
        self, action_bytes: bytes, session_id: bytes, tier: Tier
    ) -> Outcome:
        if self.device is None:
            self._deny(action_bytes, tier, "no device connected")

        action_hash = challenge.action_hash(action_bytes)
        nonce = self.ledger.issue_nonce()

        self.audit.record(
            "approval.requested",
            action=action_bytes.decode(),
            nonce=nonce.hex(),
            action_hash=action_hash.hex(),
        )

        response = self.device.handle_request(
            action_bytes=action_bytes,
            action_hash=action_hash,
            nonce=nonce,
            session_id=session_id,
        )

        if response is None:
            self._deny(action_bytes, tier, "no response from device")

        device_id = response["device_id"]
        decision = response["decision"]
        counter = response["counter"]
        signature = response["signature"]

        try:
            public_key = self.registry.public_key_for(device_id)
        except (registry_mod.UnknownDevice, ValueError, TypeError):
            self._deny(
                action_bytes, tier,
                f"unknown device {bytes(device_id).hex().upper()}",
            )
        digest = challenge.challenge(
            device_id=device_id,
            nonce=nonce,
            action_hash=action_hash,
            session_id=session_id,
            decision=decision,
            counter=counter,
        )

        if not challenge.verify(public_key, signature, digest):
            self._deny(action_bytes, tier, "signature did not verify")

        nonce_verdict = self.ledger.check_and_burn_nonce(nonce)
        if not nonce_verdict:
            self._deny(action_bytes, tier, f"nonce: {nonce_verdict.reason}")

        counter_verdict = self.ledger.check_and_advance_counter(
            device_id, counter
        )
        if not counter_verdict:
            self._deny(action_bytes, tier, f"counter: {counter_verdict.reason}")

        if decision is not challenge.Decision.APPROVE:
            self.audit.record(
                "approval.rejected",
                action=action_bytes.decode(),
                device_id=bytes(device_id).hex().upper(),
                counter=counter,
                signature=signature.hex(),
            )
            raise Denied("rejected by the operator", tier)

        self.audit.record(
            "approval.granted",
            action=action_bytes.decode(),
            device_id=bytes(device_id).hex().upper(),
            counter=counter,
            signature=signature.hex(),
        )
        return Outcome(True, tier, "approved by operator", counter)

    def _deny(self, action_bytes: bytes, tier: Tier, reason: str):
        self.audit.record(
            "approval.denied",
            action=action_bytes.decode(),
            reason=reason,
            tier=tier.value,
        )
        raise Denied(reason, tier)