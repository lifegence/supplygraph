# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Write an ExportBom as SPDX 2.3 JSON.

The dictionary is built directly, as for CycloneDX. Writing through the spdx-tools model validates the
whole document, which grows with the square of the packages. The tests check the output with
validate_full_spdx_document.

Values that SPDX does not accept as they are keep their text elsewhere in the document:
- a license that is not an SPDX expression becomes a LicenseRef- with the text in hasExtractedLicensingInfos
- a download location that is not a URL becomes NOASSERTION, and the text goes to the package comment
"""

import re
from collections import defaultdict

from spdx_tools.spdx.model import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.validation.checksum_validator import validate_checksum
from spdx_tools.spdx.validation.external_package_ref_validator import CPE22TYPE_REGEX, CPE23TYPE_REGEX
from spdx_tools.spdx.validation.uri_validators import validate_download_location

from supplygraph.sg_bom.export.model import (
	NOASSERTION,
	NONE,
	TOOL_NAME,
	ExportBom,
	ExportComponent,
	format_timestamp,
	has_value,
	is_uri,
	parse_license,
	spdx_namespace,
)

SPEC_VERSION = "SPDX-2.3"
DOCUMENT_ID = "SPDXRef-DOCUMENT"
SPDX_ID = re.compile(r"^SPDXRef-[A-Za-z0-9.\-]+$")
ID_CHARACTERS = re.compile(r"[^A-Za-z0-9.\-]+")
# SG Hash.algorithm -> SPDX checksum algorithm
CHECKSUMS = {
	"SHA-1": "SHA1",
	"SHA-256": "SHA256",
	"SHA-384": "SHA384",
	"SHA-512": "SHA512",
	"SHA3-256": "SHA3-256",
	"BLAKE3": "BLAKE3",
}
# SG Component.component_type -> primaryPackagePurpose
PURPOSES = {
	"library": "LIBRARY",
	"framework": "FRAMEWORK",
	"operating-system": "OPERATING-SYSTEM",
	"firmware": "FIRMWARE",
	"application": "APPLICATION",
	"container": "CONTAINER",
	"file": "FILE",
	"device": "DEVICE",
	"hardware": "DEVICE",
	"machine-learning-model": "OTHER",
	"data": "OTHER",
}
# SG Dependency.relationship -> (SPDX relationship type, whether "from" and "to" are swapped)
RELATIONSHIPS = {
	"depends-on": ("DEPENDS_ON", False),
	"contains": ("CONTAINS", False),
	"dev-dependency": ("DEV_DEPENDENCY_OF", True),
	"optional-dependency": ("OPTIONAL_DEPENDENCY_OF", True),
	"provided-by": ("PROVIDED_DEPENDENCY_OF", True),
	"generated-from": ("GENERATED_FROM", False),
	"variant-of": ("VARIANT_OF", False),
}


def build_spdx(bom: ExportBom) -> tuple[dict, list[str]]:
	return _Writer(bom).run()


class _Writer:
	def __init__(self, bom: ExportBom):
		self.bom = bom
		self.warnings: list[str] = []
		self.ids = self._spdx_ids()
		# license text that is not an expression -> LicenseRef- id made for it
		self.license_refs: dict[str, str] = {}
		# LicenseRef- id -> its text, for hasExtractedLicensingInfos
		self.license_texts: dict[str, str] = {}
		# document URI -> DocumentRef- id
		self.document_refs: dict[str, str] = {}
		self.external_documents: list[dict] = []
		self._collect_license_refs()

	def run(self) -> tuple[dict, list[str]]:
		bom = self.bom
		packages = [self._package(component) for component in bom.components]
		if not packages:
			# The document then describes nothing, which SPDX 2.3 does not allow
			self.warnings.append(
				"The document has no components: SPDX needs at least one package that the document describes"
			)
		data = {
			"spdxVersion": SPEC_VERSION,
			"dataLicense": "CC0-1.0",
			"SPDXID": DOCUMENT_ID,
			"name": self._document_name(),
			"documentNamespace": spdx_namespace(bom),
			"creationInfo": self._creation_info(),
		}
		if self.external_documents:
			data["externalDocumentRefs"] = self.external_documents
		data["packages"] = packages
		data["relationships"] = self._relationships()
		if self.license_texts:
			data["hasExtractedLicensingInfos"] = [
				{
					"licenseId": license_id,
					"extractedText": text,
					"name": license_id if text == NOASSERTION else text,
				}
				for license_id, text in self.license_texts.items()
			]
		return data, self.warnings

	def _collect_license_refs(self) -> None:
		"""LicenseRef- ids that the values use, before any is made, so that a made one never takes them."""
		for component in self.bom.components:
			for value in (component.license_declared, component.license_concluded):
				parsed = parse_license(value) if has_value(value) else None
				for license_id in parsed[1] if parsed else []:
					# The text of a LicenseRef- of the original file is not kept in SupplyGraph
					self.license_texts.setdefault(license_id, NOASSERTION)

	def _spdx_ids(self) -> dict[str, str]:
		"""SPDXID for each ref: the ref itself when it is a valid SPDX ID, otherwise made from it."""
		ids, used = {}, {DOCUMENT_ID}
		for component in self.bom.components:
			if SPDX_ID.match(component.ref):
				candidate = component.ref
			else:
				candidate = "SPDXRef-" + (ID_CHARACTERS.sub("-", component.ref).strip("-") or "Package")
			spdx_id, number = candidate, 1
			while spdx_id in used:
				number += 1
				spdx_id = f"{candidate}-{number}"
			used.add(spdx_id)
			ids[component.ref] = spdx_id
		return ids

	def _document_name(self) -> str:
		bom = self.bom
		primary = next((c for c in bom.components if c.ref == bom.primary_ref), None)
		if primary and has_value(primary.version):
			return f"{primary.name} {primary.version}"
		return primary.name if primary else bom.name

	def _creation_info(self) -> dict:
		bom = self.bom
		creators = [
			f"Organization: {_actor_name(name)}"
			for name in dict.fromkeys((bom.author_name, bom.author_org))
			if has_value(name)
		]
		creators.append(f"Tool: {TOOL_NAME}-{bom.tool_version}")
		info = {"created": format_timestamp(bom.timestamp), "creators": creators}
		if bom.lifecycle_phase:
			# Framework 3.2.1: SPDX 2.3 has no field for the SBOM type, so it goes to the comment
			info["comment"] = f"SBOM Type : {bom.lifecycle_phase}"
		return info

	def _package(self, component: ExportComponent) -> dict:
		comments = []
		package = {
			"name": component.name,
			"SPDXID": self.ids[component.ref],
			"versionInfo": component.version or NOASSERTION,
			"supplier": f"Organization: {_actor_name(component.supplier)}"
			if has_value(component.supplier)
			else NOASSERTION,
			"downloadLocation": self._download_location(component, comments),
			"filesAnalyzed": False,
			"licenseConcluded": self._license(component.license_concluded),
			"licenseDeclared": self._license(component.license_declared),
			"copyrightText": component.copyright_text or NOASSERTION,
		}
		if component.file_name:
			package["packageFileName"] = component.file_name
		purpose = PURPOSES.get(component.component_type)
		if purpose:
			package["primaryPackagePurpose"] = purpose
		checksums = []
		for algorithm, value in component.hashes:
			checksum = _checksum(algorithm, value)
			if checksum:
				checksums.append(checksum)
			else:
				comments.append(f"{algorithm} hash: {value}")
				self.warnings.append(
					f"{component.ref}: {algorithm} hash {value} is not accepted by SPDX; written in the comment"
				)
		if checksums:
			package["checksums"] = checksums
		references = self._external_refs(component, comments)
		if references:
			package["externalRefs"] = references
		if component.external_bom:
			self._external_document(component, comments)
		if comments:
			package["comment"] = "\n".join(comments)
		return package

	def _download_location(self, component: ExportComponent, comments: list[str]) -> str:
		location = component.download_location
		if not location:
			return NOASSERTION
		if location.strip().upper() in (NONE, NOASSERTION):
			return location.strip().upper()
		if not validate_download_location(location):
			return location
		comments.append(f"Download location: {location}")
		self.warnings.append(
			f"{component.ref}: download location {location} is not a URL; written as NOASSERTION"
		)
		return NOASSERTION

	def _license(self, value: str | None) -> str:
		"""An SPDX license expression, or a LicenseRef- whose text is the value."""
		if not value:
			return NOASSERTION
		if value.strip().upper() in (NONE, NOASSERTION):
			return value.strip().upper()
		parsed = parse_license(value)
		if parsed:
			return parsed[0]
		if value not in self.license_refs:
			candidate = "LicenseRef-" + (ID_CHARACTERS.sub("-", value).strip("-")[:60] or "License")
			license_id, number = candidate, 1
			while license_id in self.license_texts:
				number += 1
				license_id = f"{candidate}-{number}"
			self.license_refs[value] = license_id
			self.license_texts[license_id] = value
		return self.license_refs[value]

	def _external_refs(self, component: ExportComponent, comments: list[str]) -> list[dict]:
		references = []
		if component.purl:
			references.append(
				{
					"referenceCategory": "PACKAGE-MANAGER",
					"referenceType": "purl",
					"referenceLocator": component.purl,
				}
			)
		if component.cpe:
			for reference_type, pattern in (("cpe23Type", CPE23TYPE_REGEX), ("cpe22Type", CPE22TYPE_REGEX)):
				if re.match(pattern, component.cpe):
					references.append(
						{
							"referenceCategory": "SECURITY",
							"referenceType": reference_type,
							"referenceLocator": component.cpe,
						}
					)
					break
			else:
				comments.append(f"CPE: {component.cpe}")
				self.warnings.append(f"{component.ref}: CPE {component.cpe} is not a CPE 2.2 or 2.3 name")
		return references

	def _external_document(self, component: ExportComponent, comments: list[str]) -> None:
		"""The SBOM of the package, as an external document reference (Framework 3.4.1)."""
		external = component.external_bom
		checksum = _checksum(*external.checksum) if external.checksum else None
		if not is_uri(external.uri) or not checksum:
			# SPDX needs both a URI and the checksum of the document; keep what is known in the comment
			comments.append(f"External SBOM: {external.uri}")
			self.warnings.append(
				f"{component.ref}: external SBOM {external.uri} has no URI or checksum that SPDX accepts;"
				" written in the package comment"
			)
			return
		if external.uri not in self.document_refs:
			document_id = f"DocumentRef-{len(self.document_refs) + 1}"
			self.document_refs[external.uri] = document_id
			self.external_documents.append(
				{"externalDocumentId": document_id, "spdxDocument": external.uri, "checksum": checksum}
			)

	def _relationships(self) -> list[dict]:
		bom = self.bom
		relationships = [
			_relationship(DOCUMENT_ID, "DESCRIBES", self.ids[ref]) for ref in self._described_refs()
		]
		seen = set()
		for from_ref, to_ref, relationship in bom.relations:
			kind, swapped = RELATIONSHIPS[relationship]
			source, target = (to_ref, from_ref) if swapped else (from_ref, to_ref)
			key = (source, kind, target)
			if key in seen:
				continue
			seen.add(key)
			relationships.append(_relationship(self.ids[source], kind, self.ids[target]))
		for component in bom.components:
			external = component.external_bom
			if external and external.uri in self.document_refs:
				relationships.append(
					_relationship(
						self.ids[component.ref],
						"DESCRIBED_BY",
						f"{self.document_refs[external.uri]}:{DOCUMENT_ID}",
					)
				)
		return relationships

	def _described_refs(self) -> list[str]:
		"""The primary component, or the components that nothing else refers to when there is none."""
		bom = self.bom
		if bom.primary_ref:
			return [bom.primary_ref]
		targets = defaultdict(int)
		for _from_ref, to_ref, _relationship in bom.relations:
			targets[to_ref] += 1
		roots = [c.ref for c in bom.components if not targets[c.ref]]
		return roots or [c.ref for c in bom.components]


def _checksum(algorithm: str, value: str) -> dict | None:
	"""An SPDX checksum, or None when SPDX does not take the value.

	SPDX wants lower case hexadecimal digits of the length of the algorithm. spdx-tools 0.8.5 asks for at
	least 256 digits for BLAKE3, so a usual 64-digit BLAKE3 hash is not accepted.
	"""
	name = CHECKSUMS.get(algorithm)
	if not name or not value:
		return None
	value = value.strip().lower()
	checksum = Checksum(ChecksumAlgorithm[name.replace("-", "_")], value)
	if validate_checksum(checksum, "checksum", SPEC_VERSION):
		return None
	return {"algorithm": name, "checksumValue": value}


def _relationship(source: str, kind: str, target: str) -> dict:
	return {"spdxElementId": source, "relationshipType": kind, "relatedSpdxElement": target}


def _actor_name(name: str) -> str:
	"""spdx-tools reads "Organization: A (B)" as the name A with the email B. An empty "()" keeps a name
	that ends with a parenthesis whole."""
	return f"{name} ()" if name.rstrip().endswith(")") else name
