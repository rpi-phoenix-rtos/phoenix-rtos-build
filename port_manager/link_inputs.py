#
# Port management
#
# Link inputs: the static libraries every port links without naming them
#
# Copyright 2026 Phoenix Systems
#
# SPDX-License-Identifier: BSD-3-Clause
#

"""The libraries the compiler driver links into every port implicitly.

Ports are statically linked, so each program carries its own copy of the libc
(libphoenix.a, which libc.a/libm.a/libpthread.a point to) and of the toolchain
runtime (libgcc.a, and libstdc++.a/libsupc++.a for C++). None of the ports'
build systems lists these as a prerequisite, so after they change `make` finds
every program up to date and the port keeps shipping the one linked against
the previous library. The digest computed here is part of the build state;
when it changes the port is relinked (not rebuilt), see
PortManager.clean_stale_ports().
"""

from __future__ import annotations

import hashlib
import os
import subprocess

from pathlib import Path

# The toolchain-side runtime, located through the compiler driver. libphoenix.a
# is looked up separately: in LIBPHOENIX_DEVEL_MODE the sysroot copy wins.
TOOLCHAIN_LIBS = ("libgcc.a", "libstdc++.a", "libsupc++.a")
LIBC = "libphoenix.a"

ET_EXEC = 2


def _driver_lookup(name: str, env: os._Environ[str] | dict[str, str]) -> Path | None:
    """Path the cross compiler driver links for `name`, or None."""
    cross = env.get("CROSS")
    if not cross:
        return None
    cmd = [f"{cross}gcc"]
    sysroot = env.get("PREFIX_SYSROOT")
    if sysroot:
        # The same options setup-sysroot.mk adds to every port's CFLAGS.
        cmd += [f"--sysroot={sysroot}/", f"-B{sysroot}/lib/"]
    try:
        out = subprocess.run(
            cmd + [f"-print-file-name={name}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    # gcc echoes the bare name back when it cannot find the file.
    path = Path(out)
    return path if path.is_absolute() and path.is_file() else None


def resolve(env: os._Environ[str] | dict[str, str]) -> dict[str, Path]:
    """The implicit link libraries that exist for this build, by name."""
    libs: dict[str, Path] = {}

    sysroot = env.get("PREFIX_SYSROOT")
    libc = Path(sysroot) / "lib" / LIBC if sysroot else None
    if libc is None or not libc.is_file():
        libc = _driver_lookup(LIBC, env)
    if libc is not None:
        libs[LIBC] = libc

    for name in TOOLCHAIN_LIBS:
        path = _driver_lookup(name, env)
        if path is not None:
            libs[name] = path
    return libs


def digest(libs: dict[str, Path]) -> dict[str, str]:
    """sha256 of each library's content.

    Content, not mtime: the core stage rewrites the sysroot libphoenix.a on every
    build, and the archive is deterministic (`ar D`), so an unchanged libc keeps
    its hash and triggers nothing.
    """
    out: dict[str, str] = {}
    for name, path in sorted(libs.items()):
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
        except OSError:
            out[name] = "unreadable"
            continue
        out[name] = h.hexdigest()
    return out


def exec_header(archive: Path) -> str | None:
    """Hex of ELF header bytes 16..19 (e_type = ET_EXEC, e_machine) for the
    target of `archive`, taken from its first ELF member.

    port_prepare.sh matches files against it to find the target executables in a
    port's work tree: host build helpers (another e_machine), objects (ET_REL)
    and shared objects (ET_DYN) do not match. Returns None if the archive holds
    no ELF member.
    """
    try:
        with open(archive, "rb") as f:
            if f.read(8) != b"!<arch>\n":
                return None
            while True:
                hdr = f.read(60)
                if len(hdr) < 60:
                    return None
                size = int(hdr[48:58].decode("ascii").strip())
                data = f.read(20)
                if len(data) == 20 and data[:4] == b"\x7fELF":
                    byteorder = "little" if data[5] == 1 else "big"
                    return (ET_EXEC.to_bytes(2, byteorder) + data[18:20]).hex()
                # Members are 2-byte aligned.
                f.seek(size + (size & 1) - len(data), os.SEEK_CUR)
    except (OSError, ValueError):
        return None
