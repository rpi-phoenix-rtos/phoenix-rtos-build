#
# Python build core
#
# SPDX v2.2 SBOM common utils
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

import re
import os
import subprocess
import __main__
import hashlib

from pathlib import Path
from datetime import datetime, timezone

from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.file import File, FileType
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm

from spdx_tools.common.spdx_licensing import spdx_licensing  # type: ignore[import-untyped]

from reuse.project import Project

from build_core.logger import logger


SPDX_DOMAIN = "https://phoenix-rtos.com/spdx"
SPDX_SYSTEM_PKG_ID = "SPDXRef-Package-Phoenix-RTOS-Firmware"
SPDX_DOCUMENT_NAME = "Phoenix-RTOS-Build-SBOM"
SPDX_PKG_NAME = "Phoenix-RTOS-Firmware-Image"
SPDX_PKG_VENDOR = "Phoenix Systems"


def name_to_pkg_spdx_id(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9.\-]", "-", name)
    return f"SPDXRef-Package-{safe}"


def name_to_lib_spdx_id(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9.\-]", "-", name)
    return f"SPDXRef-File-{safe}-a"


def libpath_to_spdx_id(libpath: str) -> str:
    path = Path(libpath)
    formatted_name = path.name.replace(".", "-")

    version = ""
    for part in path.parts:
        # Looks for a hyphen followed by a digit at the end of a folder name
        # (e.g., extracts "1.1.1a" from "openssl-1.1.1a")
        match = re.search(r"-(\d[\w.]*)$", part)
        if match:
            version = match.group(1)
            break

    if version:
        return f"SPDXRef-File-{formatted_name}-{version}"
    else:
        return f"SPDXRef-File-{formatted_name}"


def run_subprocess(filepath: Path, command: str) -> str:
    result = subprocess.run(
        [command, filepath.absolute()], capture_output=True, text=True, check=True
    )
    return result.stdout.split()[0]


def libpath_to_spdx_file(path: Path, license_spdx: str) -> File:
    def compute_file_hash(filepath: Path, algo: str) -> str:
        hasher = hashlib.new(algo)
        with filepath.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    lib_name = path.name
    spdx_id = libpath_to_spdx_id(str(path))

    if not os.path.isfile(path):
        raise FileNotFoundError(path)

    return File(
        name=lib_name,
        spdx_id=spdx_id,
        checksums=[
            Checksum(ChecksumAlgorithm.SHA1, compute_file_hash(path, "sha1")),
            Checksum(ChecksumAlgorithm.SHA256, compute_file_hash(path, "sha256")),
        ],
        file_types=[FileType.ARCHIVE],
        license_concluded=spdx_licensing.parse(license_spdx),
        license_info_in_file=[SpdxNoAssertion()],
        copyright_text=SpdxNoAssertion(),
    )


def create_phoenix_spdx_document(version: str) -> Document:
    # SPDX SBOM requires timestamps in UTC
    created = datetime.now(timezone.utc)

    doc = Document(
        creation_info=CreationInfo(
            spdx_version="SPDX-2.2",
            spdx_id="SPDXRef-DOCUMENT",
            name=SPDX_DOCUMENT_NAME,
            document_namespace=f"{SPDX_DOMAIN}/build-{created.strftime('%Y%m%d-%H%M%S')}",
            creators=[Actor(ActorType.TOOL, __main__.__file__)],
            created=created,
            creator_comment="SBOM Type: Build",
        )
    )

    license_expr = spdx_licensing.parse("BSD-3-Clause")
    system_pkg = Package(
        spdx_id=SPDX_SYSTEM_PKG_ID,
        name=SPDX_PKG_NAME,
        version=version,
        download_location=SpdxNoAssertion(),
        files_analyzed=False,  # TODO: we want "True"
        license_concluded=license_expr,
        license_declared=license_expr,
        copyright_text=f"Copyright {created.year} Phoenix Systems",
        supplier=Actor(ActorType.ORGANIZATION, SPDX_PKG_VENDOR),
    )
    doc.packages.append(system_pkg)
    doc.relationships.append(
        Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, SPDX_SYSTEM_PKG_ID)
    )
    return doc


def run_reuse_on_directory(directory_path: Path) -> tuple[str, str | None]:
    """Runs reuse tool on given path. Returns a pair of strings: copyrights
    field and licenses SPDX expression"""
    project = Project(directory_path)
    unique_copyrights: set[str] = set()
    unique_licenses: set[str] = set()
    licenses_expr = None

    for filepath in project.all_files():
        try:
            for reuse_info in project.reuse_info_of(filepath):
                unique_copyrights.update(map(str, reuse_info.copyright_notices))
                unique_licenses.update(map(str, reuse_info.spdx_expressions))
        except Exception as e:
            logger.warning(f"Could not parse {filepath}: {e}")

    if unique_licenses:
        licenses_expr = " AND ".join([f"({lic})" for lic in sorted(list(unique_licenses))])

    return "\n".join(sorted(list(unique_copyrights))), licenses_expr
