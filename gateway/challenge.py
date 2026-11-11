from __future__ import annotations

import hashlib
import secrets
from enum import IntEnum

from cryptography.exceptions import InvalidSignature # type: ignore
from cryptography.hazmat.primitives import hashes # type: ignore
from cryptography.hazmat.primitives.asymmetric import ec, utils #type: ignore
from cryptography.hazmat.primitives.serialization import load_der_public_key #type: ignore

__all__ = [
    "SCHEMA_VERSION",
    "DOMAIN",
    "PREIMAGE_LEN",
    "Decision",
    "new_nonce",
    "canonical_action",
    "action_hash",
    "build_preimage",
    "challenge",
    "load_public_key",
    "verify",
]

# Schema constants. Changing any of these is a breaking change: bump the
# version string, and update the C side in the same commit.

SCHEMA_VERSION = "v1"
DOMAIN = b"latch/approval/v1"

DOMAIN_LEN = 17
DEVICE_ID_LEN = 16
NONCE_LEN = 32
ACTION_HASH_LEN = 32
SESSION_ID_LEN = 16
DECISION_LEN = 1
COUNTER_LEN = 4

PREIMAGE_LEN = (
    DOMAIN_LEN
    + DEVICE_ID_LEN
    + NONCE_LEN
    + ACTION_HASH_LEN
    + SESSION_ID_LEN
    + DECISION_LEN
    + COUNTER_LEN
)

# Fail loudly at import time rather than silently producing wrong bytes.
assert len(DOMAIN) == DOMAIN_LEN, f"DOMAIN is {len(DOMAIN)} bytes, expected {DOMAIN_LEN}"
assert PREIMAGE_LEN == 118, f"preimage is {PREIMAGE_LEN} bytes, expected 118"

COUNTER_MAX = (1 << (COUNTER_LEN * 8)) - 1

# P-256 uncompressed point: 0x04 || X (32) || Y (32)
RAW_POINT_LEN = 65
RAW_POINT_PREFIX = 0x04


class Decision(IntEnum):
    REJECT = 0x00
    APPROVE = 0x01


# Field validation


def _fixed(name: str, value: bytes, expected: int) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    if len(value) != expected:
        raise ValueError(f"{name} must be exactly {expected} bytes, got {len(value)}")
    return bytes(value)


# Building blocks


def new_nonce() -> bytes:
    return secrets.token_bytes(NONCE_LEN)


def canonical_action(
    verb: str,
    reference: str,
    amount_minor: int,
    currency: str,
    counterparty: str,
) -> bytes:
    if not isinstance(amount_minor, int) or isinstance(amount_minor, bool):
        raise TypeError("amount_minor must be an int (minor units)")
    if amount_minor < 0:
        raise ValueError("amount_minor must not be negative")

    fields = (verb, reference, str(amount_minor), currency, counterparty)
    for field in fields:
        if "|" in field:
            raise ValueError(
                "'|' is not allowed in an action field under the v1 encoding"
            )

    return "|".join(fields).encode("utf-8")


def action_hash(action_bytes: bytes) -> bytes:
    if not isinstance(action_bytes, (bytes, bytearray)):
        raise TypeError("action_bytes must be bytes")
    return hashlib.sha256(bytes(action_bytes)).digest()


def build_preimage(
    *,
    device_id: bytes,
    nonce: bytes,
    action_hash: bytes,
    session_id: bytes,
    decision: Decision,
    counter: int,
) -> bytes:
    decision = Decision(decision)  # rejects anything that is not 0 or 1

    if not isinstance(counter, int) or isinstance(counter, bool):
        raise TypeError("counter must be an int")
    if not 0 <= counter <= COUNTER_MAX:
        raise ValueError(f"counter must be in 0..{COUNTER_MAX}, got {counter}")

    preimage = b"".join(
        (
            DOMAIN,
            _fixed("device_id", device_id, DEVICE_ID_LEN),
            _fixed("nonce", nonce, NONCE_LEN),
            _fixed("action_hash", action_hash, ACTION_HASH_LEN),
            _fixed("session_id", session_id, SESSION_ID_LEN),
            bytes((decision,)),
            counter.to_bytes(COUNTER_LEN, "big"),
        )
    )
    assert len(preimage) == PREIMAGE_LEN, (
        f"preimage is {len(preimage)} bytes, expected {PREIMAGE_LEN}"
    )
    return preimage


def challenge(
    *,
    device_id: bytes,
    nonce: bytes,
    action_hash: bytes,
    session_id: bytes,
    decision: Decision,
    counter: int,
) -> bytes:
    """The 32 bytes the SE051 actually signs."""
    return hashlib.sha256(
        build_preimage(
            device_id=device_id,
            nonce=nonce,
            action_hash=action_hash,
            session_id=session_id,
            decision=decision,
            counter=counter,
        )
    ).digest()


# Verification


def load_public_key(key_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Accept either format the SE051 hands back.

    Depending on how the key object's type fields are populated,
    sss_key_store_get_key returns either a raw uncompressed EC point
    (65 bytes, 0x04 prefix) or a DER SubjectPublicKeyInfo. Both are the
    same key.
    """
    if not isinstance(key_bytes, (bytes, bytearray)):
        raise TypeError("key_bytes must be bytes")
    key_bytes = bytes(key_bytes)

    if len(key_bytes) == RAW_POINT_LEN and key_bytes[0] == RAW_POINT_PREFIX:
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), key_bytes
        )

    key = load_der_public_key(key_bytes)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("not an EC public key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError(f"expected secp256r1, got {key.curve.name}")
    return key


def verify(
    public_key: bytes | ec.EllipticCurvePublicKey,
    signature: bytes,
    challenge_digest: bytes,
) -> bool:
    """True if the signature is valid over this challenge.

    Returns a bool rather than raising, because on the gateway a bad
    signature is an expected outcome to be logged and denied, not an
    exception to be caught. Signatures are DER-encoded ECDSA and vary in
    length — never assume a fixed size.

    Malformed signature bytes return False rather than raising: this is
    data arriving from a network, and a crash on bad input is a denial of
    service vector.
    """
    if not isinstance(signature, (bytes, bytearray)):
        return False

    key = (
        public_key
        if isinstance(public_key, ec.EllipticCurvePublicKey)
        else load_public_key(public_key)
    )

    _fixed("challenge_digest", challenge_digest, 32)

    try:
        key.verify(
            bytes(signature),
            bytes(challenge_digest),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except InvalidSignature:
        return False
    return True