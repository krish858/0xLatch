import pytest #type: ignore
from cryptography.hazmat.primitives import serialization #type:ignore

import challenge as c

# --------------------------------------------------------------------------
# Hardware vectors
# --------------------------------------------------------------------------

PUB = bytes.fromhex(
    "041467802B03DDB6D97F95B74357D19425B796BCB1D13EF93E4B6FFF4C3B35A27F"
    "38117632BF115DD6EA44C927538688DBC5F80102114BFAC6015F2351DE1F6467"
)

DEVICE_ID = bytes.fromhex("DE71CE00000000010000000000000001")
NONCE = bytes.fromhex(
    "A1B2C3D4E5F60718293A4B5C6D7E8F90112233445566778899AABBCCDDEEFF00"
)
SESSION_ID = bytes.fromhex("5E55100000000000000000000000002A")
COUNTER = 7

ACTION_TEXT = "PAY|INV-4471|482000|USD|Northwind Supply"
ACTION_HASH = bytes.fromhex(
    "9A32B0901DFDCF3A49109A854CD83F578E2D6514809C1CBF523398F39829CBE1"
)

CHALLENGE_APPROVE = bytes.fromhex(
    "7BC55F0F3EA9578D8A9FA2C413EF506B517752C26576F41F9C63FA1E79EC202F"
)
SIG_APPROVE = bytes.fromhex(
    "3045022100B207646B94E14CEC8C362200E3D76E565C2D4C046DE868419958F430"
    "B3FA500902207A648CA57BC96A6D343E4AC94AB3B833FB1FEE82EDDECDAC199947"
    "D2ADED1533"
)

CHALLENGE_REJECT = bytes.fromhex(
    "CD8FF38B6E7C8EF5A847EA21B500E33E6FE8E12291ED1E38361CE30F68F3726F"
)
SIG_REJECT = bytes.fromhex(
    "3044022038B73E2245BF5C0AE7CA62677BD09575207E63C108865C2FEF37EE138B"
    "7255B702206CEC72E3AD1E66CE689E29D61875D476EC2CF72CAEBCA49ECD2E4D94"
    "E96721B7"
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def make_challenge(decision, *, action_hash=None, counter=None,
                   device_id=None, nonce=None, session_id=None):
    """Build a challenge, overriding one field at a time for negative tests."""
    return c.challenge(
        device_id=device_id if device_id is not None else DEVICE_ID,
        nonce=nonce if nonce is not None else NONCE,
        action_hash=action_hash if action_hash is not None else ACTION_HASH,
        session_id=session_id if session_id is not None else SESSION_ID,
        decision=decision,
        counter=counter if counter is not None else COUNTER,
    )


# --------------------------------------------------------------------------
# Agreement with the firmware
# --------------------------------------------------------------------------


def test_canonical_action_matches_firmware():
    built = c.canonical_action(
        "PAY", "INV-4471", 482000, "USD", "Northwind Supply"
    )
    assert built == ACTION_TEXT.encode()


def test_action_hash_matches_firmware():
    assert c.action_hash(ACTION_TEXT.encode()) == ACTION_HASH


def test_preimage_is_118_bytes():
    preimage = c.build_preimage(
        device_id=DEVICE_ID,
        nonce=NONCE,
        action_hash=ACTION_HASH,
        session_id=SESSION_ID,
        decision=c.Decision.APPROVE,
        counter=COUNTER,
    )
    assert len(preimage) == 118


def test_approve_challenge_matches_firmware():
    assert make_challenge(c.Decision.APPROVE) == CHALLENGE_APPROVE


def test_reject_challenge_matches_firmware():
    assert make_challenge(c.Decision.REJECT) == CHALLENGE_REJECT


# --------------------------------------------------------------------------
# Signatures verify
# --------------------------------------------------------------------------


def test_approve_signature_verifies():
    # Note: verify against a challenge WE built, not the one the device
    # reported. Otherwise this only tests the device against itself.
    assert c.verify(PUB, SIG_APPROVE, make_challenge(c.Decision.APPROVE))


def test_reject_signature_verifies():
    assert c.verify(PUB, SIG_REJECT, make_challenge(c.Decision.REJECT))


# --------------------------------------------------------------------------
# Negative tests — a signature must not verify against a changed challenge
# --------------------------------------------------------------------------


def test_approve_sig_does_not_verify_as_reject():
    assert not c.verify(PUB, SIG_APPROVE, make_challenge(c.Decision.REJECT))


def test_approve_sig_does_not_verify_after_amount_tampering():
    tampered = c.canonical_action(
        "PAY", "INV-4471", 48200000, "USD", "Northwind Supply"
    )
    assert not c.verify(
        PUB, SIG_APPROVE,
        make_challenge(
            c.Decision.APPROVE, action_hash=c.action_hash(tampered)
        ),
    )


def test_approve_sig_does_not_verify_with_bumped_counter():
    assert not c.verify(
        PUB, SIG_APPROVE,
        make_challenge(c.Decision.APPROVE, counter=COUNTER + 1),
    )


def test_approve_sig_does_not_verify_with_different_device_id():
    other = bytes.fromhex("DE71CE00000000010000000000000002")
    assert not c.verify(
        PUB, SIG_APPROVE,
        make_challenge(c.Decision.APPROVE, device_id=other),
    )


def test_approve_sig_does_not_verify_with_different_nonce():
    other = bytes.fromhex(
        "00112233445566778899AABBCCDDEEFF"
        "102132435465768798A9BACBDCEDFE0F"
    )
    assert not c.verify(
        PUB, SIG_APPROVE,
        make_challenge(c.Decision.APPROVE, nonce=other),
    )


def test_approve_sig_does_not_verify_with_different_session_id():
    other = bytes.fromhex("5E55100000000000000000000000002B")
    assert not c.verify(
        PUB, SIG_APPROVE,
        make_challenge(c.Decision.APPROVE, session_id=other),
    )


@pytest.mark.parametrize(
    "bad_sig", [b"", b"\x01\x02\x03", "a string", None, 12345]
)
def test_malformed_signature_returns_false(bad_sig):
    """Signatures arrive from a network. A crash on bad input is a denial
    of service vector, so verify() must refuse rather than raise."""
    assert not c.verify(PUB, bad_sig, make_challenge(c.Decision.APPROVE))


# --------------------------------------------------------------------------
# Input validation — malformed fields must raise, never silently pad
# --------------------------------------------------------------------------


def test_short_device_id_raises():
    with pytest.raises(ValueError):
        make_challenge(c.Decision.APPROVE, device_id=b"too short")


@pytest.mark.parametrize("bad_counter", [-1, 2**32, 2**40])
def test_out_of_range_counter_raises(bad_counter):
    with pytest.raises(ValueError):
        make_challenge(c.Decision.APPROVE, counter=bad_counter)


def test_invalid_decision_raises():
    with pytest.raises(ValueError):
        c.challenge(
            device_id=DEVICE_ID,
            nonce=NONCE,
            action_hash=ACTION_HASH,
            session_id=SESSION_ID,
            decision=7,
            counter=COUNTER,
        )


def test_wrong_length_nonce_raises():
    with pytest.raises(ValueError):
        make_challenge(c.Decision.APPROVE, nonce=b"too short")


def test_pipe_in_action_field_raises():
    with pytest.raises(ValueError):
        c.canonical_action("PAY", "INV|X", 1, "USD", "Acme")


def test_float_amount_raises():
    with pytest.raises((TypeError, ValueError)):
        c.canonical_action("PAY", "INV-1", 4820.00, "USD", "Acme")


# --------------------------------------------------------------------------
# Public key handling
# --------------------------------------------------------------------------


def test_raw_point_public_key_loads():
    key = c.load_public_key(PUB)
    assert key.curve.name == "secp256r1"


def test_der_public_key_loads():

    key = c.load_public_key(PUB)
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    loaded = c.load_public_key(der)
    assert loaded.curve.name == "secp256r1"
    assert loaded.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    ) == PUB