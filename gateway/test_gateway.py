import pytest #type: ignore

import audit as audit_mod
import challenge
import gateway as gw_mod
import ledger as ledger_mod
import registry as registry_mod
from fake_device import FakeDevice

DEVICE_ID = bytes.fromhex("DE71CE00000000010000000000000001")
SESSION_ID = bytes.fromhex("5E55100000000000000000000000002A")

SMALL = 5_000         # 50.00   — routine
MEDIUM = 482_000      # 4820.00 — needs approval
HUGE = 9_000_000      # 90000.00 — above ceiling


def build(auto_approve=True):
    """A gateway with one enrolled fake device."""
    reg = registry_mod.Registry()
    led = ledger_mod.Ledger()
    log = audit_mod.AuditLog()

    dev = FakeDevice(
        DEVICE_ID, label="test", auto_approve=auto_approve, verbose=False
    )
    reg.register(DEVICE_ID, dev.public_key_bytes(), "test unit")

    gw = gw_mod.Gateway(registry=reg, ledger=led, audit=log, device=dev)
    return gw, dev, log


def pay(gw, amount, reference="INV-1", counterparty="Acme"):
    return gw.request_payment(
        reference=reference,
        amount_minor=amount,
        currency="USD",
        counterparty=counterparty,
        session_id=SESSION_ID,
    )


# --------------------------------------------------------------------------
# Policy tiers
# --------------------------------------------------------------------------


def test_routine_does_not_prompt():
    gw, dev, _ = build()
    out = pay(gw, SMALL)
    assert out.allowed
    assert out.tier is gw_mod.Tier.ROUTINE
    # The device was never contacted.
    assert dev._counter == 0


def test_consequential_requires_approval_and_is_granted():
    gw, dev, _ = build(auto_approve=True)
    out = pay(gw, MEDIUM)
    assert out.allowed
    assert out.tier is gw_mod.Tier.CONSEQUENTIAL
    assert dev._counter == 1


def test_forbidden_never_reaches_the_device():
    """Above the ceiling, no button press can authorise it. The device is
    not even asked — a stolen device plus a coerced human is still bounded
    by a number the team set in advance."""
    gw, dev, _ = build()
    with pytest.raises(gw_mod.Denied) as excinfo:
        pay(gw, HUGE)
    assert excinfo.value.tier is gw_mod.Tier.FORBIDDEN
    assert dev._counter == 0


# --------------------------------------------------------------------------
# Fail closed
# --------------------------------------------------------------------------


def test_operator_rejection_denies():
    gw, _, _ = build(auto_approve=False)
    with pytest.raises(gw_mod.Denied, match="rejected by the operator"):
        pay(gw, MEDIUM)


def test_no_response_denies():
    """Silence is never consent."""
    gw, _, _ = build(auto_approve=None)
    with pytest.raises(gw_mod.Denied, match="no response"):
        pay(gw, MEDIUM)


def test_no_device_denies():
    gw, _, _ = build()
    gw.device = None
    with pytest.raises(gw_mod.Denied, match="no device"):
        pay(gw, MEDIUM)


# --------------------------------------------------------------------------
# Attacks
# --------------------------------------------------------------------------


def test_unenrolled_key_is_rejected():
    """A device signing with a key nobody registered."""
    gw, _, _ = build()
    gw.device = FakeDevice(DEVICE_ID, auto_approve=True, verbose=False)
    with pytest.raises(gw_mod.Denied, match="signature did not verify"):
        pay(gw, MEDIUM)


def test_unknown_device_id_is_rejected():
    gw, dev, _ = build()
    dev.device_id = bytes.fromhex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    with pytest.raises(gw_mod.Denied, match="unknown device"):
        pay(gw, MEDIUM)


def test_device_signing_a_different_action_is_rejected():
    """What-you-see-is-what-you-sign, from the gateway's side.

    A device that renders one action and signs another gets caught, because
    the gateway rebuilds the challenge from the action IT holds.
    """
    gw, _, _ = build()

    class Swapper(FakeDevice):
        def handle_request(self, *, action_bytes, action_hash, nonce,
                           session_id):
            evil = challenge.canonical_action(
                "PAY", "INV-X", HUGE, "USD", "Attacker"
            )
            return super().handle_request(
                action_bytes=evil,
                action_hash=challenge.action_hash(evil),
                nonce=nonce,
                session_id=session_id,
            )

    swapper = Swapper(DEVICE_ID, auto_approve=True, verbose=False)
    gw.registry.register(
        DEVICE_ID, swapper.public_key_bytes(), "swapper", replace=True
    )
    gw.device = swapper

    with pytest.raises(gw_mod.Denied, match="signature did not verify"):
        pay(gw, MEDIUM)


def test_replayed_counter_is_rejected():
    gw, dev, _ = build()
    assert pay(gw, MEDIUM, reference="INV-A").allowed

    dev._counter = 0          # device rolls its counter back
    with pytest.raises(gw_mod.Denied, match="counter"):
        pay(gw, MEDIUM, reference="INV-B")


def test_nonce_is_burned_after_use():
    gw, _, _ = build()
    pay(gw, MEDIUM)
    assert gw.ledger.outstanding == 0


def test_failed_verification_does_not_burn_the_nonce():
    """Verify before burn.

    If a bad signature consumed the nonce, anyone who learned a nonce could
    spend it with garbage and the genuine approval would then fail. Free
    denial of service.
    """
    gw, _, _ = build()
    gw.device = FakeDevice(DEVICE_ID, auto_approve=True, verbose=False)

    with pytest.raises(gw_mod.Denied):
        pay(gw, MEDIUM)

    assert gw.ledger.outstanding == 1


def test_failed_verification_does_not_advance_the_counter():
    """Same ordering argument. A forged high counter must not be able to
    lock out the real device."""
    gw, dev, _ = build()
    gw.device = FakeDevice(
        DEVICE_ID, auto_approve=True, start_counter=999, verbose=False
    )

    with pytest.raises(gw_mod.Denied):
        pay(gw, MEDIUM)

    assert gw.ledger.last_counter(DEVICE_ID) is None

    # The genuine device still works afterwards.
    gw.device = dev
    assert pay(gw, MEDIUM).allowed


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------


def test_every_outcome_is_logged():
    gw, _, log = build()
    pay(gw, SMALL)
    pay(gw, MEDIUM)
    events = [e.event for e in log.entries()]
    assert "request.received" in events
    assert "approval.granted" in events


def test_denials_are_logged():
    gw, _, log = build(auto_approve=False)
    with pytest.raises(gw_mod.Denied):
        pay(gw, MEDIUM)
    assert "approval.rejected" in [e.event for e in log.entries()]


def test_chain_is_valid():
    gw, _, log = build()
    pay(gw, MEDIUM)
    ok, bad = log.verify_chain()
    assert ok and bad is None


def test_tampering_breaks_the_chain_at_that_entry():
    gw, _, log = build()
    pay(gw, MEDIUM)

    victim = log.entries()[0]
    object.__setattr__(
        victim, "detail", dict(victim.detail, action="PAY|INV-X|1|USD|Evil")
    )

    ok, bad = log.verify_chain()
    assert not ok
    assert bad == victim.seq