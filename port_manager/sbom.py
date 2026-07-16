#
# Port management
#
# SPDX v2.2 SBOM generation
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

from pathlib import Path

import os

from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.writer.json.json_writer import write_document_to_file
from spdx_tools.common.spdx_licensing import spdx_licensing  # type: ignore[import-untyped]
from spdx_tools.spdx.model.package import ExternalPackageRef, ExternalPackageRefCategory

from .candidates import Candidate, InstallableCandidate

from build_core.logger import logger
from build_core import sbom_utils


def cand_to_spdx_id(cand: Candidate):
    name = cand.name.replace("_", "-")  # spdx_id must not contain `_`
    return f"SPDXRef-Package-{name}"


def generate_ports_sbom(
    phoenix_version: str,
    ports_installed: list[InstallableCandidate],
    output_path: Path,
):
    doc = sbom_utils.create_phoenix_spdx_document(phoenix_version)

    for port in ports_installed:
        port_id = cand_to_spdx_id(port)
        port_name = port.name
        port_version = str(port.version)

        logger.info(f"generating SBOM for {port}")

        if not port.cpe23:
            locator = f"pkg:generic/{port_name}@{port_version}"
            logger.warning(f"no cpe23 defined, using fallback PURL: {locator}")
            pkg_ref = ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=locator,
            )
        else:
            pkg_ref = ExternalPackageRef(
                category=ExternalPackageRefCategory.SECURITY,
                reference_type="cpe23Type",
                locator=port.cpe23,
            )

        copyrights, licenses = sbom_utils.run_reuse_on_directory(
            Path(f"{os.environ['PREFIX_BUILD']}/port-sources/{str(port)}")
        )

        port_location = port.origin_source
        pkg = Package(
            spdx_id=port_id,
            name=port_name,
            version=port_version,
            download_location=port_location,
            files_analyzed=bool(port.built_libs),
            checksums=[Checksum(ChecksumAlgorithm.SHA256, port.sha256)],
            license_declared=spdx_licensing.parse(
                licenses if licenses else port.license
            ),
            # this is the final human-declared license expression from port.def.sh
            license_concluded=spdx_licensing.parse(port.license),
            copyright_text=copyrights,
            external_references=[pkg_ref],
            # TODO: pass explicit vendor in port defs?...
            supplier=Actor(ActorType.ORGANIZATION, port_name),
        )

        doc.packages.append(pkg)

        doc.relationships.append(
            Relationship(
                sbom_utils.SPDX_SYSTEM_PKG_ID, RelationshipType.CONTAINS, port_id
            )
        )

        for rdep in port.needed_by:
            doc.relationships.append(
                Relationship(
                    cand_to_spdx_id(rdep),
                    RelationshipType.DEPENDS_ON,
                    port_id,
                )
            )

        for lib_path in port.built_libs:
            static_lib_file = sbom_utils.libpath_to_spdx_file(lib_path, port.license)
            doc.files.append(static_lib_file)
            doc.relationships.append(
                Relationship(
                    port_id, RelationshipType.GENERATES, static_lib_file.spdx_id
                )
            )

    write_document_to_file(doc, str(output_path))
    logger.info("SBOM saved to", output_path.absolute())
