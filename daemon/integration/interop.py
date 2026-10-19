#!/usr/bin/env python3
"""Independent python-fido2 host test over the daemon's root-only raw HID RPC.

Run only against a fresh, isolated ``serve --no-usb`` instance. The explicit
--approve-test-requests flag permits this test process to answer its own test
ceremonies; the daemon itself never bypasses its normal approval broker.
Install the independent client with: python -m pip install fido2==2.2.1
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import json
import os
import secrets
import socket
import threading
import time
from pathlib import Path

from fido2.attestation import PackedAttestation
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import PinProtocolV1
from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor


class RPC:
    def __init__(self, path: str):
        self.path = path

    def call(self, op: str, **kwargs):
        request = json.dumps({"op": op, **kwargs}, separators=(",", ":")).encode()
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(45)
            conn.connect(self.path)
            conn.sendall(request)
            conn.shutdown(socket.SHUT_WR)
            chunks = bytearray()
            while part := conn.recv(8192):
                chunks.extend(part)
                if len(chunks) > 65536:
                    raise RuntimeError("oversized control response")
        response = json.loads(chunks)
        if not response["ok"]:
            raise RuntimeError(response.get("error", "control request failed"))
        return response.get("data")


class RPCConnection(CtapHidConnection):
    """Only the packet I/O is adapted; Yubico owns HID and CTAP encoding."""

    def __init__(self, rpc: RPC):
        self.rpc = rpc
        self.session = secrets.token_hex(16)
        self.closed = False

    def read_packet(self) -> bytes:
        data = self.rpc.call("hid-read", session=self.session, timeout_ms=10000)
        packet = base64.b64decode(data["packet"], validate=True)
        assert len(packet) == 64
        return packet

    def write_packet(self, data: bytes) -> None:
        assert len(data) == 64
        self.rpc.call("hid-write", session=self.session,
                      data=base64.b64encode(data).decode())

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.rpc.call("hid-close", session=self.session)


def new_device(rpc: RPC) -> CtapHidDevice:
    descriptor = HidDescriptor("isolated-unix-rpc", 0, 0, 64, 64,
                               "ABK independent host test", None)
    return CtapHidDevice(descriptor, RPCConnection(rpc))


class Test:
    def __init__(self, rpc: RPC):
        self.rpc = rpc
        self.rp_id = "interop-" + secrets.token_hex(8) + ".example.test"
        self.checks: list[str] = []

    def check(self, name: str):
        self.checks.append(name)
        print("PASS " + name, flush=True)

    def ceremony(self, call, decision: str = "allow"):
        result = {}
        done = threading.Event()
        cancel = threading.Event()
        keepalives = []

        def worker():
            try:
                result["value"] = call(cancel, keepalives.append)
            except BaseException as exc:
                result["error"] = exc
            finally:
                done.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        pending = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not done.is_set():
            pending = self.rpc.call("auth-pending")
            if pending:
                break
            time.sleep(0.01)
        if not pending:
            cancel.set()
            thread.join(3)
            raise AssertionError(f"ceremony did not request approval: {result}")
        assert pending["rp_id"] == self.rp_id, "refusing another RP's approval"
        assert pending["command"] in ("makeCredential", "getAssertion")
        assert pending["uv"] is True
        # Observe that simply connecting a client does not grant presence/UV.
        assert not done.wait(0.2), "ceremony completed without an explicit decision"
        if decision == "cancel":
            cancel.set()  # Real python-fido2 sends CTAPHID_CANCEL on next read.
        else:
            self.rpc.call("auth-decision", id=pending["request_id"],
                          allow=decision == "allow")
        if not done.wait(5):
            cancel.set()
            raise AssertionError("ceremony failed to terminate")
        thread.join()
        assert self.rpc.call("auth-pending") is None
        assert keepalives, "no HID keepalive while waiting for local approval"
        if decision != "allow":
            error = result.get("error")
            expected = (CtapError.ERR.KEEPALIVE_CANCEL if decision == "cancel"
                        else CtapError.ERR.OPERATION_DENIED)
            assert isinstance(error, CtapError) and error.code == expected, result
            return None
        if "error" in result:
            raise result["error"]
        return result["value"]

    def run(self):
        initial = self.rpc.call("status")
        if initial["credential_count"] != 0:
            raise RuntimeError("refusing nonempty store; start an isolated test daemon")
        assert initial["backend"] == "userspace" and initial["auth_gate_enabled"]
        device = new_device(self.rpc)
        second = None
        try:
            assert device.version == 2
            ping = os.urandom(7609)  # Largest legal fragmented message.
            assert device.ping(ping) == ping
            ctap = Ctap2(device)
            info = ctap.info
            assert "FIDO_2_0" in info.versions and "hmac-secret" in info.extensions
            assert info.options["uv"] and info.options["rk"]
            self.check("independent HID INIT, max-size PING, getInfo")

            def make(event, keepalive, suffix="primary", hmac_secret=True):
                return ctap.make_credential(
                    hashlib.sha256(("create-" + suffix).encode()).digest(),
                    {"id": self.rp_id, "name": "Isolated interoperability test"},
                    {"id": suffix.encode(), "name": suffix,
                     "displayName": "Temporary test credential"},
                    [{"type": "public-key", "alg": -7}],
                    extensions={"hmac-secret": True} if hmac_secret else None,
                    options={"rk": True, "uv": True},
                    event=event, on_keepalive=keepalive)

            client_hash = hashlib.sha256(b"create-primary").digest()
            made = self.ceremony(make)
            assert made.fmt == "packed"
            assert int(made.auth_data.flags) & 0xC5 == 0xC5
            assert made.auth_data.extensions["hmac-secret"] is True
            assert made.auth_data.rp_id_hash == hashlib.sha256(self.rp_id.encode()).digest()
            PackedAttestation().verify(made.att_stmt, made.auth_data, client_hash)
            credential = made.auth_data.credential_data
            assert credential is not None
            public_key = credential.public_key
            allow = [{"type": "public-key", "id": credential.credential_id}]
            self.check("makeCredential parses ED/AT/UV/UP flags and verifies self attestation")

            pin = PinProtocolV1()
            last_counter = made.auth_data.counter

            def assert_hmac(salts: bytes):
                nonlocal last_counter
                peer = ctap.client_pin(1, 2)[1]
                platform, shared = pin.encapsulate(peer)
                encrypted = pin.encrypt(shared, salts)
                extension = {"hmac-secret": {1: platform, 2: encrypted,
                             3: pin.authenticate(shared, encrypted), 4: 1}}
                challenge = os.urandom(32)
                response = self.ceremony(lambda e, k: ctap.get_assertion(
                    self.rp_id, challenge, allow, extensions=extension,
                    options={"uv": True}, event=e, on_keepalive=k))
                response.verify(challenge, public_key)
                assert response.credential["id"] == credential.credential_id
                assert response.auth_data.rp_id_hash == hashlib.sha256(self.rp_id.encode()).digest()
                assert int(response.auth_data.flags) & 0x85 == 0x85
                assert response.auth_data.counter > last_counter
                last_counter = response.auth_data.counter
                output = pin.decrypt(shared, response.auth_data.extensions["hmac-secret"])
                assert len(output) == len(salts)
                return output

            salt_a, salt_b = os.urandom(32), os.urandom(32)
            first = assert_hmac(salt_a)
            assert assert_hmac(salt_a) == first
            pair = assert_hmac(salt_a + salt_b)
            assert pair[:32] == first and pair[32:] != first
            self.check("getAssertion signatures, monotonic counters, hmac-secret ECDH/AES/HMAC one/two salts")

            challenge = os.urandom(32)
            resident = self.ceremony(lambda e, k: ctap.get_assertion(
                self.rp_id, challenge, options={"uv": True},
                event=e, on_keepalive=k))
            resident.verify(challenge, public_key)
            assert resident.user["id"] == b"primary"
            assert int(resident.auth_data.flags) & 0x85 == 0x05
            self.check("resident discovery and extension-free authenticatorData")

            count = self.rpc.call("status")["credential_count"]
            self.ceremony(lambda e, k: make(e, k, "denied"), "deny")
            self.ceremony(lambda e, k: make(e, k, "cancelled"), "cancel")
            assert self.rpc.call("status")["credential_count"] == count == 1
            assert device.ping(b"still-usable") == b"still-usable"
            self.check("explicit denial and CTAPHID cancellation do not persist credentials")

            second = new_device(self.rpc)
            assert Ctap2(second).get_info().aaguid == info.aaguid
            assert second.ping(b"separate-session") == b"separate-session"
            second.close()
            second = None
            assert device.ping(b"first-session-lives") == b"first-session-lives"
            self.check("independent local transport close isolation")

            snapshot = self.rpc.call("store-get")
            assert len(base64.b64decode(snapshot["blob"], validate=True)) == 15572
            assert snapshot["generation"] > 1 and snapshot["epoch"] == initial["epoch"]
            self.check("legacy-compatible store snapshot RPC")
            return {"ok": True, "python_fido2": importlib.metadata.version("fido2"),
                    "checks": self.checks, "credential_count": 1,
                    "backend": "isolated Unix raw HID RPC; no physical USB tested"}
        finally:
            if second is not None:
                second.close()
            device.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--approve-test-requests", action="store_true",
                        help="explicitly approve this script's isolated test ceremonies")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if not args.approve_test_requests:
        parser.error("isolated ceremonies require --approve-test-requests")
    report = Test(RPC(args.socket)).run()
    encoded = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
