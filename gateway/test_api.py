from __future__ import annotations

import asyncio
import json
import threading
import time

import httpx
import pytest
import uvicorn
import websockets

import challenge
from fake_device import FakeDevice

PORT = 8111
BASE = f"http://127.0.0.1:{PORT}"
WS = f"ws://127.0.0.1:{PORT}/v1/device"

DEVICE_ID = bytes.fromhex("DE71CE00000000010000000000000001")
SESSION_ID = "5E55100000000000000000000000002A"

SMALL = 5_000
MEDIUM = 482_000
HUGE = 9_000_000


@pytest.fixture(scope="module")
def server():
    """A real uvicorn server in a background thread."""
    import app as app_mod

    config = uvicorn.Config(
        app_mod.app, host="127.0.0.1", port=PORT, log_level="error"
    )
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()

    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("server did not start")

    yield app_mod

    srv.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
def clean(server):
    """Fresh state per test. The app wires singletons at import, so reach in
    and reset them rather than re-importing."""
    import audit as audit_mod
    import ledger as ledger_mod
    import registry as registry_mod

    server.registry.__init__()
    server.ledger.__init__()
    server.audit.__init__()
    server.gateway.registry = server.registry
    server.gateway.ledger = server.ledger
    server.gateway.audit = server.audit
    return server


class DeviceClient:
    """Runs a FakeDevice against the server on its own thread.

    Shutdown is deliberate rather than abrupt. Stopping the event loop out
    from under an open websocket leaves its close handshake and keepalive
    tasks half-finished, and the resulting cascade of "Event loop is closed"
    tracebacks buries any real failure. Instead stop() closes the socket,
    which ends the read loop naturally, and only then joins the thread.
    """

    def __init__(self, device: FakeDevice):
        self.device = device
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._ready = threading.Event()   # connected and accepted
        self._done = threading.Event()    # _serve returned, either way
        self._ws = None

    def _run(self):
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        finally:
            try:
                self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            except Exception:
                pass
            self._loop.close()
            self._done.set()

    async def _serve(self):
        try:
            async with websockets.connect(WS) as ws:
                self._ws = ws
                await ws.send(json.dumps(
                    {"type": "hello", "device_id": self.device.device_id.hex()}
                ))

                ack = json.loads(await ws.recv())
                if ack.get("type") != "ready":
                    return
                self._ready.set()

                async for raw in ws:
                    msg = json.loads(raw)
                    if msg.get("type") != "approval_request":
                        continue

                    action_bytes = bytes.fromhex(msg["action"])
                    response = self.device.handle_request(
                        action_bytes=action_bytes,
                        action_hash=bytes.fromhex(msg["action_hash"]),
                        nonce=bytes.fromhex(msg["nonce"]),
                        session_id=bytes.fromhex(msg["session_id"]),
                    )
                    if response is None:
                        continue

                    await ws.send(json.dumps({
                        "type": "decision",
                        "request_id": msg["request_id"],
                        "device_id": response["device_id"].hex(),
                        "decision": int(response["decision"]),
                        "counter": response["counter"],
                        "signature": response["signature"].hex(),
                    }))

        except (websockets.exceptions.WebSocketException, OSError):
            # A refused or dropped connection is an outcome some tests are
            # asserting on, not a crash. Swallow it here so it does not
            # surface as an unhandled exception in this thread.
            pass
        finally:
            self._ws = None

    def start(self, timeout=5.0):
        self._thread.start()
        if not self._ready.wait(timeout):
            self.stop()
            raise RuntimeError("device did not connect")

    def stop(self, timeout=5.0):
        ws = self._ws
        if ws is not None:
            try:
                asyncio.run_coroutine_threadsafe(
                    ws.close(), self._loop
                ).result(timeout=2.0)
            except Exception:
                pass

        self._thread.join(timeout=timeout)
        self._done.wait(timeout=1.0)


def enroll(device: FakeDevice, label="test"):
    r = httpx.post(f"{BASE}/v1/devices", json={
        "device_id": device.device_id.hex(),
        "public_key": device.public_key_bytes().hex(),
        "label": label,
        "replace": True,
    })
    r.raise_for_status()


def pay(amount, reference="INV-1", timeout=30.0):
    return httpx.post(
        f"{BASE}/v1/request",
        json={
            "reference": reference,
            "amount_minor": amount,
            "currency": "USD",
            "counterparty": "Northwind",
            "session_id": SESSION_ID,
        },
        timeout=timeout,
    )


# --------------------------------------------------------------------------


def test_health(clean):
    r = httpx.get(f"{BASE}/v1/health")
    assert r.status_code == 200
    assert r.json()["audit_chain_valid"] is True


def test_routine_needs_no_device(clean):
    """Below the threshold nothing is asked, so no device need be connected."""
    r = pay(SMALL)
    assert r.status_code == 200
    assert r.json()["tier"] == "routine"


def test_approval_denied_with_no_device_connected(clean):
    """Fail closed. An unplugged box has not approved anything."""
    r = pay(MEDIUM)
    assert r.status_code == 403
    assert "no response" in r.json()["detail"]["reason"]


def test_unenrolled_device_cannot_connect(clean):
    device = FakeDevice(DEVICE_ID, verbose=False)
    client = DeviceClient(device)
    with pytest.raises(RuntimeError):
        client.start(timeout=3.0)


def test_full_approval_over_the_socket(clean):
    device = FakeDevice(DEVICE_ID, auto_approve=True, verbose=False)
    enroll(device)

    client = DeviceClient(device)
    client.start()
    try:
        r = pay(MEDIUM)
        assert r.status_code == 200
        body = r.json()
        assert body["allowed"] is True
        assert body["tier"] == "consequential"
        assert body["counter"] == 1
    finally:
        client.stop()


def test_rejection_over_the_socket(clean):
    device = FakeDevice(DEVICE_ID, auto_approve=False, verbose=False)
    enroll(device)

    client = DeviceClient(device)
    client.start()
    try:
        r = pay(MEDIUM)
        assert r.status_code == 403
        assert "rejected by the operator" in r.json()["detail"]["reason"]
    finally:
        client.stop()


def test_forbidden_is_refused_without_asking(clean):
    device = FakeDevice(DEVICE_ID, auto_approve=True, verbose=False)
    enroll(device)

    client = DeviceClient(device)
    client.start()
    try:
        r = pay(HUGE)
        assert r.status_code == 403
        assert r.json()["detail"]["tier"] == "forbidden"
        assert device._counter == 0       # never contacted
    finally:
        client.stop()


def test_timeout_denies(clean):
    """A device that never answers must not hold the request open forever,
    and must not result in an approval."""
    import app as app_mod

    original = app_mod.APPROVAL_TIMEOUT
    app_mod.APPROVAL_TIMEOUT = 1.0
    try:
        device = FakeDevice(DEVICE_ID, auto_approve=None, verbose=False)
        enroll(device)

        client = DeviceClient(device)
        client.start()
        try:
            started = time.monotonic()
            r = pay(MEDIUM, timeout=15.0)
            elapsed = time.monotonic() - started

            assert r.status_code == 403
            assert elapsed < 10
        finally:
            client.stop()
    finally:
        app_mod.APPROVAL_TIMEOUT = original


def test_audit_endpoint_reports_a_valid_chain(clean):
    device = FakeDevice(DEVICE_ID, auto_approve=True, verbose=False)
    enroll(device)

    client = DeviceClient(device)
    client.start()
    try:
        pay(MEDIUM)
    finally:
        client.stop()

    r = httpx.get(f"{BASE}/v1/audit")
    assert r.status_code == 200
    body = r.json()
    assert body["chain_valid"] is True
    events = [e["event"] for e in body["entries"]]
    assert "approval.granted" in events
    assert "device.connected" in events


def test_malformed_session_id_is_a_400(clean):
    r = httpx.post(f"{BASE}/v1/request", json={
        "reference": "INV-1",
        "amount_minor": MEDIUM,
        "currency": "USD",
        "counterparty": "Acme",
        "session_id": "not hex",
    })
    assert r.status_code == 400