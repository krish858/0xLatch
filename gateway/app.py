from __future__ import annotations

import asyncio
import json
import logging
import os

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect #type: ignore
from pydantic import BaseModel, Field #type: ignore

import audit as audit_mod
import challenge
import device_link as link_mod #type: ignore
import gateway as gw_mod
import ledger as ledger_mod
import registry as registry_mod

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
)
log = logging.getLogger("latch.app")

# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------

registry = registry_mod.Registry()
ledger = ledger_mod.Ledger()
audit = audit_mod.AuditLog(path=os.environ.get("LATCH_AUDIT_PATH"))
hub = link_mod.DeviceHub()


APPROVAL_TIMEOUT = float(
    os.environ.get("LATCH_APPROVAL_TIMEOUT", link_mod.DEFAULT_TIMEOUT_SECONDS)
)

gateway = gw_mod.Gateway(
    registry=registry,
    ledger=ledger,
    audit=audit,
    policy=gw_mod.Policy(
        approval_above=int(os.environ.get("LATCH_APPROVAL_ABOVE", 10_000)),
        ceiling=int(os.environ.get("LATCH_CEILING", 5_000_000)),
    ),
    device=hub,
)

app = FastAPI(title="Latch Gateway", version="0.1.0")


class PaymentRequest(BaseModel):
    reference: str
    amount_minor: int = Field(ge=0, description="integer minor units, never a float")
    currency: str
    counterparty: str
    session_id: str = Field(description="32 hex chars (16 bytes)")


class PaymentResponse(BaseModel):
    allowed: bool
    tier: str
    reason: str
    counter: int | None = None


class EnrollRequest(BaseModel):
    device_id: str
    public_key: str
    label: str = ""
    replace: bool = False




@app.post("/v1/request", response_model=PaymentResponse)
def request_payment(body: PaymentRequest) -> PaymentResponse:
    try:
        session_id = bytes.fromhex(body.session_id)
    except ValueError:
        raise HTTPException(400, "session_id must be hex")

    if len(session_id) != challenge.SESSION_ID_LEN:
        raise HTTPException(
            400, f"session_id must be {challenge.SESSION_ID_LEN} bytes"
        )

    try:
        outcome = gateway.request_payment(
            reference=body.reference,
            amount_minor=body.amount_minor,
            currency=body.currency,
            counterparty=body.counterparty,
            session_id=session_id,
        )
    except gw_mod.Denied as denied:
        raise HTTPException(
            403,
            detail={
                "allowed": False,
                "tier": denied.tier.value if denied.tier else None,
                "reason": denied.reason,
            },
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc))

    return PaymentResponse(
        allowed=outcome.allowed,
        tier=outcome.tier.value,
        reason=outcome.reason,
        counter=outcome.counter,
    )



@app.websocket("/v1/device")
async def device_socket(websocket: WebSocket) -> None:
    """The device dials in and holds this open.

    First frame must be a hello naming the device. It is accepted onto the
    hub only if it is enrolled — an unenrolled device could not produce a
    verifiable signature anyway, but refusing at connect keeps the audit log
    honest about what was actually talking to us.
    """
    await websocket.accept()
    loop = asyncio.get_running_loop()
    link: link_mod.DeviceLink | None = None

    try:
        raw = await websocket.receive_text()
        hello = json.loads(raw)

        if hello.get("type") != "hello":
            await websocket.close(code=4000, reason="expected hello")
            return

        device_id = bytes.fromhex(hello["device_id"])

        if not registry.is_registered(device_id):
            audit.record(
                "device.rejected",
                device_id=device_id.hex().upper(),
                reason="not enrolled",
            )
            await websocket.close(code=4003, reason="not enrolled")
            return

        link = link_mod.DeviceLink(
            device_id, websocket, loop, timeout=APPROVAL_TIMEOUT
        )
        hub.attach(link)
        audit.record("device.connected", device_id=link.device_id_hex)

        await websocket.send_text(json.dumps({"type": "ready"}))

        while True:
            message = json.loads(await websocket.receive_text())
            if message.get("type") == "decision":
                link.deliver(message)
            elif message.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))

    except WebSocketDisconnect:
        pass
    except (KeyError, ValueError, json.JSONDecodeError) as exc:
        log.warning("device socket error: %s", exc)
    finally:
        if link is not None:
            hub.detach(link)
            audit.record("device.disconnected", device_id=link.device_id_hex)


@app.post("/v1/devices")
def enroll(body: EnrollRequest) -> dict:
    """Enrollment over HTTP, for development only.

    In production this is a USB operation: the key is read off the device
    over serial by someone holding it. A device that can enroll itself over
    the network is a device an attacker can enroll.
    """
    try:
        device = registry.register(
            bytes.fromhex(body.device_id),
            bytes.fromhex(body.public_key),
            body.label,
            replace=body.replace,
        )
    except registry_mod.DeviceAlreadyRegistered as exc:
        raise HTTPException(409, str(exc))
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc))

    audit.record(
        "device.enrolled", device_id=device.device_id_hex, label=device.label
    )
    return {"device_id": device.device_id_hex, "label": device.label}


@app.get("/v1/devices")
def list_devices() -> dict:
    connected = set(hub.connected())
    return {
        "devices": [
            {
                "device_id": d.device_id_hex,
                "label": d.label,
                "enrolled_at": d.enrolled_at.isoformat(),
                "connected": d.device_id_hex in connected,
                "last_counter": ledger.last_counter(d.device_id),
            }
            for d in registry.devices()
        ]
    }


@app.get("/v1/audit")
def read_audit(limit: int = 100) -> dict:
    """The log, plus whether its chain still verifies.

    chain_valid is the interesting field. False means somebody edited
    history, and first_bad_seq says where.
    """
    ok, bad = audit.verify_chain()
    entries = audit.entries()[-limit:]
    return {
        "chain_valid": ok,
        "first_bad_seq": bad,
        "head": audit.head,
        "count": len(audit),
        "entries": [
            {
                "seq": e.seq,
                "timestamp": e.timestamp,
                "event": e.event,
                "detail": e.detail,
                "entry_hash": e.entry_hash,
            }
            for e in entries
        ],
    }


@app.get("/v1/health")
def health() -> dict:
    ok, _ = audit.verify_chain()
    return {
        "status": "ok",
        "devices_enrolled": len(registry),
        "devices_connected": hub.connected(),
        "audit_chain_valid": ok,
        "ledger": ledger.stats(),
    }