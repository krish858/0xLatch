from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import websockets

import challenge
from fake_device import FakeDevice

DEFAULT_URL = "ws://localhost:8000/v1/device"
DEVICE_ID = bytes.fromhex("DE71CE00000000010000000000000001")

DEFAULT_KEY_FILE = Path(".latch-device-key.pem")


def load_or_create(key_file: Path, device_id: bytes, **kwargs) -> FakeDevice:
    if key_file.exists():
        return FakeDevice.from_pem(key_file.read_bytes(), device_id, **kwargs)
    device = FakeDevice(device_id, **kwargs)
    key_file.write_bytes(device.private_key_pem())
    key_file.chmod(0o600)
    print(f"new key written to {key_file}")
    return device


async def run(url: str, device: FakeDevice) -> None:
    async with websockets.connect(url) as ws:
        await ws.send(
            json.dumps(
                {"type": "hello", "device_id": device.device_id.hex()}
            )
        )

        ack = json.loads(await ws.recv())
        if ack.get("type") != "ready":
            print(f"gateway refused us: {ack}")
            return

        print(f"connected as {device.device_id.hex().upper()}")
        print("waiting for approval requests\n")

        async for raw in ws:
            message = json.loads(raw)
            if message.get("type") != "approval_request":
                continue

            # Decode for display. The firmware renders this on the screen.
            action_bytes = bytes.fromhex(message["action"])
            rendered = action_bytes.decode("utf-8", errors="replace")

            print("  ┌─ APPROVAL REQUESTED")
            print(f"  │  {rendered}")
            print(f"  │  code {message['correlation']}   "
                  f"expires in {message['expires_in']:.0f}s")

            response = device.handle_request(
                action_bytes=action_bytes,
                action_hash=bytes.fromhex(message["action_hash"]),
                nonce=bytes.fromhex(message["nonce"]),
                session_id=bytes.fromhex(message["session_id"]),
            )

            if response is None:
                print("  └─ no answer\n")
                continue

            decision = challenge.Decision(response["decision"])
            print(f"  └─ {decision.name}  (counter {response['counter']})\n")

            await ws.send(
                json.dumps(
                    {
                        "type": "decision",
                        "request_id": message["request_id"],
                        "device_id": response["device_id"].hex(),
                        "decision": int(response["decision"]),
                        "counter": response["counter"],
                        "signature": response["signature"].hex(),
                    }
                )
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Latch software device")
    parser.add_argument("url", nargs="?", default=DEFAULT_URL)
    parser.add_argument("--reject", action="store_true", help="always decline")
    parser.add_argument(
        "--silent", action="store_true", help="never answer (tests fail-closed)"
    )
    parser.add_argument("--print-key", action="store_true")
    parser.add_argument("--key-file", default=str(DEFAULT_KEY_FILE))
    args = parser.parse_args()

    auto = None if args.silent else (not args.reject)
    device = load_or_create(
        Path(args.key_file), DEVICE_ID,
        label="ws", auto_approve=auto, verbose=False,
    )

    if args.print_key:
        print(f"device_id:  {device.device_id.hex()}")
        print(f"public_key: {device.public_key_bytes().hex()}")
        print()

    try:
        asyncio.run(run(args.url, device))
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()