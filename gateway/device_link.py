from __future__ import annotations

import asyncio
import json
import logging
import threading
import uuid
from dataclasses import dataclass

import challenge

log = logging.getLogger("latch.device")

DEFAULT_TIMEOUT_SECONDS = 90.0


@dataclass
class _Pending:
    request_id: str
    event: threading.Event
    response: dict | None = None


class DeviceLink:
    def __init__(
        self,
        device_id: bytes,
        websocket,
        loop: asyncio.AbstractEventLoop,
        *,
        timeout: float | None = None,
    ) -> None:
        self.device_id = bytes(device_id)
        self.timeout = (
            timeout if timeout is not None else DEFAULT_TIMEOUT_SECONDS
        )

        self._ws = websocket
        self._loop = loop
        self._lock = threading.Lock()
        self._pending: _Pending | None = None

    @property
    def device_id_hex(self) -> str:
        return self.device_id.hex().upper()

    def handle_request(
        self,
        *,
        action_bytes: bytes,
        action_hash: bytes,
        nonce: bytes,
        session_id: bytes,
    ) -> dict | None:
        request_id = uuid.uuid4().hex
        with self._lock:
            if self._pending is not None:
                log.warning(
                    "device %s is busy; refusing concurrent request",
                    self.device_id_hex,
                )
                return None
            pending = _Pending(request_id, threading.Event())
            self._pending = pending

        try:
            message = {
                "type": "approval_request",
                "request_id": request_id,
                "action": action_bytes.hex(),
                "action_hash": action_hash.hex(),
                "nonce": nonce.hex(),
                "session_id": session_id.hex(),
                "expires_in": self.timeout,
                "correlation": action_hash.hex()[:6].upper(),
            }

            try:
                future = asyncio.run_coroutine_threadsafe(
                    self._ws.send_text(json.dumps(message)), self._loop
                )
                future.result(timeout=5.0)
            except Exception as exc:
                log.warning("send to %s failed: %s", self.device_id_hex, exc)
                return None

            if not pending.event.wait(self.timeout):
                log.warning(
                    "device %s did not answer within %.0fs",
                    self.device_id_hex,
                    self.timeout,
                )
                return None

            return pending.response

        finally:
            with self._lock:
                if self._pending is pending:
                    self._pending = None


    def deliver(self, message: dict) -> None:
        with self._lock:
            pending = self._pending

        if pending is None:
            log.warning("decision from %s with nothing pending", self.device_id_hex)
            return

        if message.get("request_id") != pending.request_id:
            log.warning(
                "decision from %s for request %s, expected %s",
                self.device_id_hex,
                message.get("request_id"),
                pending.request_id,
            )
            return

        try:
            response = {
                "device_id": bytes.fromhex(message["device_id"]),
                "decision": challenge.Decision(int(message["decision"])),
                "counter": int(message["counter"]),
                "signature": bytes.fromhex(message["signature"]),
            }
        except (KeyError, ValueError, TypeError) as exc:
            log.warning("malformed decision from %s: %s", self.device_id_hex, exc)
            return

        pending.response = response
        pending.event.set()

    def abandon(self) -> None:
        with self._lock:
            pending = self._pending
        if pending is not None:
            pending.event.set()


class DeviceHub:

    def __init__(self) -> None:
        self._links: dict[bytes, DeviceLink] = {}
        self._lock = threading.Lock()

    def attach(self, link: DeviceLink) -> None:
        with self._lock:
            existing = self._links.get(link.device_id)
            if existing is not None:
                existing.abandon()
            self._links[link.device_id] = link
        log.info("device %s connected", link.device_id_hex)

    def detach(self, link: DeviceLink) -> None:
        with self._lock:
            if self._links.get(link.device_id) is link:
                del self._links[link.device_id]
        link.abandon()
        log.info("device %s disconnected", link.device_id_hex)

    def get(self, device_id: bytes) -> DeviceLink | None:
        with self._lock:
            return self._links.get(bytes(device_id))

    def connected(self) -> list[str]:
        with self._lock:
            return [link.device_id_hex for link in self._links.values()]


    def handle_request(self, **kwargs) -> dict | None:
        with self._lock:
            links = list(self._links.values())

        if not links:
            log.warning("approval requested with no device connected")
            return None

        return links[0].handle_request(**kwargs)