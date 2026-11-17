# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Format-independent content of an SBOM to export, read from SG BOM Document and its entries."""

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from spdx_tools.common.spdx_licensing import spdx_licensing
from spdx_tools.spdx.validation.uri_validators import validate_uri

LICENSE_REF = re.compile(r"^LicenseRef-[A-Za-z0-9.\-]+$")
UUID_URN = re.compile(
	r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
NOASSERTION = "NOASSERTION"
NONE = "NONE"
# Values that mean "no value" when a format has no such keyword (CycloneDX)
NO_VALUES = {NOASSERTION, NONE}
TOOL_NAME = "SupplyGraph"


@dataclass
class ExternalBom:
	"""The SBOM of a component, kept as another document (Framework 3.4.1)."""

	uri: str
	# (SG Hash algorithm, value) of the referenced file, when it is known
	checksum: tuple[str, str] | None = None


@dataclass
class ExportComponent:
	ref: str
	name: str
	version: str
	component_type: str = "library"
	purl: str | None = None
	cpe: str | None = None
	supplier: str | None = None
	file_name: str | None = None
	download_location: str | None = None
	license_declared: str | None = None
	license_concluded: str | None = None
	copyright_text: str | None = None
	# (SG Hash algorithm, value)
	hashes: list[tuple[str, str]] = field(default_factory=list)
	scope: str | None = None
	external_bom: ExternalBom | None = None


@dataclass
class ExportBom:
	name: str
	format: str
	serial_number: str | None
	bom_version: int | None
	lifecycle_phase: str | None
	author_name: str | None
	author_org: str | None
	supplier: str | None
	timestamp: datetime | None
	primary_ref: str | None
	components: list[ExportComponent] = field(default_factory=list)
	# (from_ref, to_ref, SG Dependency.relationship)
	relations: list[tuple[str, str, str]] = field(default_factory=list)
	tool_version: str = ""
	# Base of the namespaces made for documents that have none, such as https://sbom.example.com
	site_url: str = "http://localhost"
	# Found while reading the records, such as a dependency on an entry of another document
	notes: list[str] = field(default_factory=list)


@dataclass
class ExportResult:
	filename: str
	content: str
	# What could not be written as it is, such as a value the format does not accept
	warnings: list[str] = field(default_factory=list)


def cyclonedx_serial(bom: ExportBom) -> str:
	"""The serial number of the document when it is a UUID URN, otherwise one made from the document name.

	The same document always gets the same serial number, so that other SBOMs can refer to it.
	"""
	if bom.serial_number and UUID_URN.match(bom.serial_number):
		return bom.serial_number
	return f"urn:uuid:{document_uuid(bom.name, bom.site_url)}"


def spdx_namespace(bom: ExportBom) -> str:
	"""The namespace of a document imported from SPDX, otherwise one made from the site and the name."""
	if bom.format == "SPDX" and bom.serial_number and is_uri(bom.serial_number):
		return bom.serial_number
	return f"{bom.site_url.rstrip('/')}/spdx/{bom.name}-{document_uuid(bom.name, bom.site_url)}"


def is_uri(value: str) -> bool:
	"""An absolute URI without a fragment, which SPDX asks for in namespaces and document references."""
	return not validate_uri(value) and "#" not in value


def document_uuid(name: str, site_url: str) -> uuid.UUID:
	return uuid.uuid5(uuid.NAMESPACE_URL, f"{site_url.rstrip('/')}/sbom/{name}")


def parse_license(value: str) -> tuple[str, list[str]] | None:
	"""(normalized expression, LicenseRef- ids in it) for an SPDX license expression, else None.

	Symbols that are not on the SPDX license list are accepted only as LicenseRef- ids, which SPDX
	documents define themselves (such as LicenseRef-T-Proprietary).
	"""
	try:
		info = spdx_licensing.validate(value)
		unknown = list(dict.fromkeys(info.invalid_symbols))
		if info.errors and not unknown:
			return None
		if any(not LICENSE_REF.match(symbol) for symbol in unknown):
			return None
		parsed = spdx_licensing.parse(value, validate=False, strict=True)
	except Exception:
		# license-expression raises other errors than ExpressionError for some broken text, such as
		# AttributeError for "MIT AND"; any of them means the text is not an expression
		return None
	if parsed is None:
		return None
	return str(parsed), unknown


def is_compound_license(value: str) -> bool:
	"""An SPDX license expression with an operator, such as MIT OR Apache-2.0 or GPL-2.0-only WITH ..."""
	parsed = parse_license(value)
	return bool(parsed) and any(f" {operator} " in parsed[0] for operator in ("AND", "OR", "WITH"))


def has_value(value: str | None) -> bool:
	"""A value that is set and is not NONE or NOASSERTION."""
	return bool(value) and value.strip().upper() not in NO_VALUES


def format_timestamp(value: datetime | None) -> str | None:
	"""SG BOM Document.bom_timestamp is naive UTC; both formats want YYYY-MM-DDThh:mm:ssZ."""
	return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value else None
