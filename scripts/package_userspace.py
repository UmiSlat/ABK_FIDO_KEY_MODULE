#!/usr/bin/env python3
"""Package a prebuilt static Android arm64 daemon as a KernelSU module."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "kernelsu"


def validate_binary(data: bytes) -> None:
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("daemon must be a little-endian ELF64 binary")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    if machine != 183 or elf_type not in (2, 3):
        raise ValueError("daemon must be an arm64 executable")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if not phnum or phentsize < 56 or phoff + phentsize * phnum > len(data):
        raise ValueError("invalid executable program headers")
    for index in range(phnum):
        if struct.unpack_from("<I", data, phoff + index * phentsize)[0] == 3:
            raise ValueError("daemon must be statically linked (build with CGO_ENABLED=0)")


def add(archive: zipfile.ZipFile, name: str, data: bytes, mode: int) -> None:
    info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (0o100000 | mode) << 16
    archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def package(binary: Path, output: Path) -> None:
    data = binary.read_bytes()
    validate_binary(data)
    required = ("module.prop", "customize.sh", "service.sh", "service-lib.sh",
                "action.sh", "uninstall.sh", "skip_mount", "sepolicy.rule", "README.md")
    files = {}
    for name in required:
        source = MODULE / name
        if not source.is_file():
            raise ValueError(f"missing module file: {source}")
        files[name] = source.read_bytes().replace(b"\r\n", b"\n")
    manifest = json.dumps({
        "module_id": "abk_fido_userspace",
        "architecture": "arm64",
        "minimum_companion_version_code": 3,
        "minimum_companion_version": "0.4.0",
        "daemon_sha256": hashlib.sha256(data).hexdigest(),
        "custom_kernel_module": False,
    }, indent=2).encode() + b"\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        with zipfile.ZipFile(temporary, "w") as archive:
            for name, content in files.items():
                mode = 0o755 if name.endswith(".sh") else 0o644
                if name == "service-lib.sh":
                    mode = 0o600
                add(archive, name, content, mode)
            add(archive, "bin/abk-fidod", data, 0o700)
            add(archive, "manifest.json", manifest, 0o644)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        package(args.binary, args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, f"package_userspace: {error}\n")
    print(args.output.resolve())


if __name__ == "__main__":
    main()
