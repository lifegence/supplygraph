# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Map an SPDX 2.2 / 2.3 document to ParsedBom with spdx-tools."""

import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager

import frappe
from frappe import _
from spdx_tools.spdx.model import (
	ExternalPackageRefCategory,
	PackagePurpose,
	RelationshipType,
	SpdxNoAssertion,
	SpdxNone,
)
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.parse_anything import parse_file

from supplygraph.sg_bom.importer.model import (
	NOASSERTION,
	Issue,
	ParsedBom,
	ParsedComponent,
	clean,
	normalize_hash,
	parse_timestamp,
	split_purl,
)

SBOM_TYPE = re.compile(r"SBOM Type\s*:\s*(Design|Source|Build|Analyzed|Deployed|Runtime)", re.IGNORECASE)
PURPOSES = {
	PackagePurpose.APPLICATION: "application",
	PackagePurpose.FRAMEWORK: "framework",
	PackagePurpose.LIBRARY: "library",
	PackagePurpose.CONTAINER: "container",
	PackagePurpose.OPERATING_SYSTEM: "operating-system",
	PackagePurpose.DEVICE: "device",
	PackagePurpose.FIRMWARE: "firmware",
	PackagePurpose.FILE: "file",
}
# RelationshipType -> (SG Dependency.relationship, whether "from" and "to" are swapped)
RELATIONS = {
	RelationshipType.CONTAINS: ("contains", False),
	RelationshipType.CONTAINED_BY: ("contains", True),
	RelationshipType.DEPENDS_ON: ("depends-on", False),
	RelationshipType.DEPENDENCY_OF: ("depends-on", True),
	RelationshipType.STATIC_LINK: ("depends-on", False),
	RelationshipType.DYNAMIC_LINK: ("depends-on", False),
	RelationshipType.DEV_DEPENDENCY_OF: ("dev-dependency", True),
	RelationshipType.OPTIONAL_DEPENDENCY_OF: ("optional-dependency", True),
	RelationshipType.PROVIDED_DEPENDENCY_OF: ("provided-by", True),
	RelationshipType.GENERATED_FROM: ("generated-from", False),
	RelationshipType.DESCENDANT_OF: ("generated-from", False),
	RelationshipType.VARIANT_OF: ("variant-of", False),
}


@contextmanager
def spdx_temp_file(content: bytes, suffix: str) -> Iterator[str]:
	"""A temporary file with the content. spdx-tools chooses its parser by file extension and reads
	from a path."""
	handle, path = tempfile.mkstemp(suffix=suffix)
	try:
		with os.fdopen(handle, "wb") as temp_file:
			temp_file.write(content)
		yield path
	finally:
		os.unlink(path)


def parse_spdx_file(path: str) -> ParsedBom:
	try:
		document = parse_file(path)
	except SPDXParsingError as error:
		frappe.throw(_("The SPDX file could not be read: {0}").format("; ".join(error.get_messages())[:500]))

	info = document.creation_info
	bom = ParsedBom(
		format="SPDX",
		spec_version=info.spdx_version.replace("-", " "),
		serial_number=clean(info.document_namespace),
		timestamp=parse_timestamp(info.created),
		author_name=_author(info.creators),
	)
	match = SBOM_TYPE.search(info.creator_comment or "")
	if match:
		bom.lifecycle_phase = match.group(1).capitalize()

	refs = {package.spdx_id for package in document.packages}
	for package in document.packages:
		bom.components.append(_component(package, bom.issues))

	components = {component.ref: component for component in bom.components}
	documents = {item.document_ref_id: item.document_uri for item in info.external_document_refs}
	for relationship in document.relationships:
		_add_relationship(bom, relationship, refs, components, documents)
	return bom


def _component(package, issues: list[Issue]) -> ParsedComponent:
	purl, cpe = None, None
	for reference in package.external_references:
		if reference.reference_type == "purl":
			purl = reference.locator
		elif (
			reference.category == ExternalPackageRefCategory.SECURITY
			and reference.reference_type.startswith("cpe")
		):
			cpe = reference.locator
	versioned, base = split_purl(purl, package.spdx_id, issues)
	component = ParsedComponent(
		ref=package.spdx_id,
		name=clean(package.name) or NOASSERTION,
		version=clean(package.version) or NOASSERTION,
		component_type=PURPOSES.get(package.primary_package_purpose, "library"),
		purl=versioned,
		purl_base=base,
		cpe=clean(cpe),
		supplier=_actor(package.supplier),
		file_name=clean(package.file_name),
		download_location=_text(package.download_location),
		license_declared=_text(package.license_declared),
		license_concluded=_text(package.license_concluded),
		copyright_text=_text(package.copyright_text),
	)
	for checksum in package.checksums:
		algorithm = normalize_hash(checksum.algorithm.name)
		if algorithm:
			component.hashes.append((algorithm, checksum.value))
		else:
			issues.append(Issue("IMP-HASH", f"Skipped unsupported hash {checksum.algorithm.name}"))
	return component


def _add_relationship(bom, relationship, refs, components, documents) -> None:
	source = relationship.spdx_element_id
	target = relationship.related_spdx_element_id
	kind = relationship.relationship_type
	# Only packages become components; a document can also describe a file
	if kind == RelationshipType.DESCRIBES and source == "SPDXRef-DOCUMENT":
		if target in refs:
			bom.primary_ref = bom.primary_ref or target
		return
	if kind == RelationshipType.DESCRIBED_BY and target == "SPDXRef-DOCUMENT":
		if source in refs:
			bom.primary_ref = bom.primary_ref or source
		return
	# Framework 3.4.1 links a package to its own SBOM with DESCRIBED_BY DocumentRef-...
	if (
		kind == RelationshipType.DESCRIBED_BY
		and isinstance(target, str)
		and target.startswith("DocumentRef-")
	):
		document_id = target.split(":", 1)[0]
		if source in components and document_id in documents:
			components[source].external_bom_ref = documents[document_id]
		else:
			bom.issues.append(Issue("IMP-UNKNOWN-REF", f"Unknown external document {target}", source))
		return
	# CONTAINS NONE / NOASSERTION state how complete the relationships are; no dependency row to store
	if isinstance(target, SpdxNone | SpdxNoAssertion):
		return
	mapping = RELATIONS.get(kind)
	if not mapping or source not in refs or target not in refs:
		return
	relation, swapped = mapping
	bom.relations.append((target, source, relation) if swapped else (source, target, relation))


def _author(creators) -> str | None:
	organizations = [creator.name for creator in creators if creator.actor_type.name != "TOOL"]
	return clean(organizations[0]) if organizations else None


def _actor(actor) -> str | None:
	if actor is None or isinstance(actor, SpdxNoAssertion):
		return None
	return clean(actor.name)


def _text(value) -> str | None:
	if value is None:
		return None
	if isinstance(value, SpdxNone):
		return "NONE"
	if isinstance(value, SpdxNoAssertion):
		return NOASSERTION
	return clean(value)
