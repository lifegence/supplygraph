# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Export SG BOM Document as CycloneDX 1.6 or SPDX 2.3 JSON, for handing an SBOM to a business partner.

	bench --site supplygraph.localhost execute supplygraph.sg_bom.export.export_bom \
		--kwargs "{'bom_document': 'SGB-2026-00001', 'format': 'CycloneDX'}"

Before writing, the document is validated with validate_bom. A document with errors is not
exported unless force is set. The fields follow docs/spec/FrameworkV1ValidationRules.md.
"""

import json

import frappe
from frappe import _
from frappe.utils import cint, sbool
from spdx_tools.spdx.parser.parse_anything import parse_file

import supplygraph
from supplygraph.sg_bom.export.cyclonedx import build_cyclonedx
from supplygraph.sg_bom.export.model import (
	ExportBom,
	ExportComponent,
	ExportResult,
	ExternalBom,
	document_uuid,
)
from supplygraph.sg_bom.export.spdx import build_spdx
from supplygraph.sg_bom.importer.spdx import spdx_temp_file
from supplygraph.sg_bom.validation import source_content, validate_bom

FORMATS = {
	"CycloneDX": (build_cyclonedx, "cdx.json"),
	"SPDX": (build_spdx, "spdx.json"),
}
CHUNK = 1000
# Errors listed in the message when a document is not exported
SHOWN_ERRORS = 10


class SbomHasErrorsError(frappe.ValidationError):
	"""The document has validation errors. The form catches this type to offer exporting anyway."""


@frappe.whitelist(methods=["POST"])
def export_bom(bom_document: str, format: str, force: bool | str = False) -> dict:
	"""Return {"filename", "content", "warnings"} for the document in the format.

	POST only: the validation before the export records its result on the document.
	"""
	if format not in FORMATS:
		frappe.throw(
			_("Format {0} cannot be exported. Use one of: {1}").format(format, ", ".join(FORMATS)),
			title=_("Unsupported Format"),
		)
	# Without read permission on the DocType, a caller does not learn which documents exist
	frappe.has_permission("SG BOM Document", "read", throw=True)
	if not frappe.db.exists("SG BOM Document", bom_document):
		frappe.throw(_("SG BOM Document {0} not found").format(bom_document), frappe.DoesNotExistError)
	frappe.has_permission("SG BOM Document", "read", doc=bom_document, throw=True)
	# Not even with force: a cancelled SBOM is not handed to a business partner
	if frappe.db.get_value("SG BOM Document", bom_document, "docstatus") == 2:
		frappe.throw(
			_("SG BOM Document {0} is cancelled and is not exported").format(bom_document),
			title=_("Cancelled SBOM"),
		)
	if not sbool(force):
		_check_errors(bom_document)
	result = write_bom(load_bom(bom_document), format)
	return {"filename": result.filename, "content": result.content, "warnings": result.warnings}


def write_bom(bom: ExportBom, format: str) -> ExportResult:
	"""Write the content without validating it. The time of the export is measured on this."""
	build, extension = FORMATS[format]
	data, warnings = build(bom)
	content = json.dumps(data, indent=2, ensure_ascii=False)
	return ExportResult(filename=f"{bom.name}.{extension}", content=content, warnings=[*bom.notes, *warnings])


def _check_errors(bom_document: str) -> None:
	result = validate_bom(bom_document)
	if result.get("status") == "skipped" or not result.get("errors"):
		return
	rows = frappe.get_all(
		"SG BOM Validation Result",
		filters={"parent": bom_document, "parenttype": "SG BOM Document", "severity": "Error"},
		fields=["rule_code", "target_ref", "message"],
		order_by="idx",
		limit=SHOWN_ERRORS,
	)
	lines = [
		f"{row.rule_code}{f' ({row.target_ref})' if row.target_ref else ''}: {row.message}" for row in rows
	]
	if result["errors"] > len(rows):
		lines.append(_("and {0} more").format(result["errors"] - len(rows)))
	frappe.throw(
		_("SG BOM Document {0} has {1} validation errors and is not exported:").format(
			bom_document, result["errors"]
		)
		+ "<br>"
		+ "<br>".join(frappe.utils.escape_html(line) for line in lines),
		title=_("SBOM Has Errors"),
		exc=SbomHasErrorsError,
	)


def load_bom(bom_document: str) -> ExportBom:
	"""Read the document, its entries and their dependencies."""
	document = frappe.db.get_value(
		"SG BOM Document",
		bom_document,
		[
			"name",
			"format",
			"serial_number",
			"bom_version",
			"lifecycle_phase",
			"author_name",
			"author_org",
			"supplier_org",
			"bom_timestamp",
			"primary_component",
			"source_file",
		],
		as_dict=True,
	)
	entries = _entries(bom_document)
	refs = _refs(entries)
	relations, outside = _relations(bom_document, refs)
	versions = {entry.component_version for entry in entries}
	if document.primary_component:
		versions.add(document.primary_component)
	hashes = _hashes(versions)

	components = [_component(entry, refs[entry.name], hashes) for entry in entries]
	primary_ref = _primary_ref(document.primary_component, entries, refs, relations)
	if document.primary_component and not primary_ref:
		# The primary component is not an entry of the document: write it from SG Component Version
		primary = _version_row(document.primary_component)
		primary_ref = _unique_ref("primary", set(refs.values()))
		components.insert(0, _component(primary, primary_ref, hashes))
	else:
		# The primary component first, then the others by name
		components.sort(key=lambda component: component.ref != primary_ref)

	bom = ExportBom(
		name=document.name,
		format=document.format,
		serial_number=document.serial_number,
		bom_version=cint(document.bom_version) or None,
		lifecycle_phase=document.lifecycle_phase,
		author_name=document.author_name,
		author_org=document.author_org,
		supplier=document.supplier_org,
		timestamp=document.bom_timestamp,
		primary_ref=primary_ref,
		components=components,
		relations=relations,
		tool_version=supplygraph.__version__,
		# Not from the request's Host header: the serial number and namespace made from it must stay the
		# same however the site is reached
		site_url=frappe.utils.get_url(allow_header_override=False),
	)
	if outside:
		bom.notes.append(f"{outside} dependencies on entries of other documents are left out")
	_external_boms(bom, entries, refs, document)
	return bom


def _entries(bom_document: str) -> list:
	# Permission is checked on the document; its entries are read with it, as on the document's page
	return frappe.db.sql(
		"""
		select
			e.name, e.bom_ref, e.scope, e.supplier as entry_supplier,
			e.license_concluded as entry_license_concluded, e.external_bom, e.external_bom_ref,
			e.component_version, v.version, v.purl, v.cpe, v.supplier, v.file_name, v.download_location,
			v.license_declared, v.license_concluded, v.license_expression, v.copyright_text,
			c.component_name, c.component_type
		from `tabSG BOM Entry` e
		join `tabSG Component Version` v on v.name = e.component_version
		join `tabSG Component` c on c.name = v.component
		where e.bom_document = %s
		order by c.component_name, v.version, e.name
		""",
		(bom_document,),
		as_dict=True,
	)


def _version_row(version: str):
	"""A row like an entry's, for a component version that is not an entry of the document."""
	rows = frappe.db.sql(
		"""
		select
			v.name as component_version, v.version, v.purl, v.cpe, v.supplier, v.file_name,
			v.download_location, v.license_declared, v.license_concluded, v.license_expression,
			v.copyright_text, c.component_name, c.component_type
		from `tabSG Component Version` v
		join `tabSG Component` c on c.name = v.component
		where v.name = %s
		""",
		(version,),
		as_dict=True,
	)
	return rows[0]


def _refs(entries: list) -> dict[str, str]:
	"""{entry name: ref}: the bom-ref or SPDXID from the original file, or the entry name."""
	refs, used = {}, set()
	for entry in entries:
		ref = entry.bom_ref if entry.bom_ref and entry.bom_ref not in used else entry.name
		ref = _unique_ref(ref, used)
		used.add(ref)
		refs[entry.name] = ref
	return refs


def _unique_ref(ref: str, used: set[str]) -> str:
	candidate, number = ref, 1
	while candidate in used:
		number += 1
		candidate = f"{ref}-{number}"
	return candidate


def _relations(bom_document: str, refs: dict[str, str]) -> tuple[list[tuple[str, str, str]], int]:
	"""The dependencies between entries of the document, and how many point outside of it."""
	rows = frappe.db.sql(
		"""select from_entry, to_entry, relationship from `tabSG Dependency`
		where bom_document = %s order by from_entry, to_entry, relationship""",
		(bom_document,),
		as_dict=True,
	)
	relations, seen, outside = [], set(), 0
	for row in rows:
		# A dependency on an entry of another document has nothing to point to in this file
		if row.from_entry not in refs or row.to_entry not in refs:
			outside += 1
			continue
		key = (refs[row.from_entry], refs[row.to_entry], row.relationship)
		if key not in seen:
			seen.add(key)
			relations.append(key)
	return relations, outside


def _hashes(versions: set[str]) -> dict[str, list[tuple[str, str]]]:
	result: dict[str, list[tuple[str, str]]] = {}
	ordered = sorted(versions)
	for start in range(0, len(ordered), CHUNK):
		chunk = ordered[start : start + CHUNK]
		rows = frappe.get_all(
			"SG Hash",
			filters={"parenttype": "SG Component Version", "parent": ["in", chunk]},
			fields=["parent", "algorithm", "hash_value"],
			order_by="parent, idx",
		)
		for row in rows:
			result.setdefault(row.parent, []).append((row.algorithm, row.hash_value))
	return result


def _component(row, ref: str, hashes: dict) -> ExportComponent:
	return ExportComponent(
		ref=ref,
		name=row.component_name,
		version=row.version,
		component_type=row.component_type,
		purl=row.purl,
		cpe=row.cpe,
		# AS-2-3: the supplier of the entry, by default the one of the component version
		supplier=row.get("entry_supplier") or row.supplier,
		file_name=row.file_name,
		download_location=row.download_location,
		license_declared=row.license_declared,
		# AS-2-9: the license concluded for the entry, a known license, or an expression
		license_concluded=row.get("entry_license_concluded")
		or row.license_concluded
		or row.license_expression,
		copyright_text=row.copyright_text,
		hashes=hashes.get(row.component_version, []),
		scope=row.get("scope"),
	)


def _primary_ref(primary: str | None, entries: list, refs: dict, relations: list) -> str | None:
	"""The entry of the primary component. When it is there twice, the one nothing contains."""
	if not primary:
		return None
	candidates = [refs[entry.name] for entry in entries if entry.component_version == primary]
	if not candidates:
		return None
	targets = {to_ref for _from_ref, to_ref, _relationship in relations}
	return next((ref for ref in candidates if ref not in targets), candidates[0])


def _external_boms(bom: ExportBom, entries: list, refs: dict, document) -> None:
	"""The SBOM of each component that has one: the document it links to, or the reference in the file."""
	components = {component.ref: component for component in bom.components}
	targets = {entry.external_bom for entry in entries if entry.external_bom}
	documents = {}
	if targets:
		documents = {
			row.name: row
			for row in frappe.get_all(
				"SG BOM Document",
				filters={"name": ["in", list(targets)]},
				fields=["name", "format", "serial_number", "bom_version", "source_sha256"],
			)
			# What a document links to is written only when the user may read it too
			if frappe.has_permission("SG BOM Document", "read", doc=row.name)
		}
	original_checksums = None
	for entry in entries:
		if not entry.external_bom and not entry.external_bom_ref:
			continue
		target = documents.get(entry.external_bom)
		checksum = None
		if entry.external_bom_ref:
			uri = entry.external_bom_ref
		elif target and target.serial_number:
			uri = _document_uri(target)
		elif target:
			# A document without a serial number: the one its own CycloneDX export gets. The checksum of
			# its original file is not the checksum of that export, so there is none.
			uri = f"urn:cdx:{document_uuid(target.name, bom.site_url)}/{cint(target.bom_version) or 1}"
			target = None
		else:
			continue
		if target and target.source_sha256:
			checksum = ("SHA-256", target.source_sha256)
		if not checksum:
			if original_checksums is None:
				original_checksums = _original_checksums(document)
			checksum = original_checksums.get(uri)
		components[refs[entry.name]].external_bom = ExternalBom(uri=uri, checksum=checksum)


def _document_uri(target) -> str:
	"""How another SBOM refers to a document: a BOM-Link for CycloneDX, the namespace for SPDX."""
	serial = target.serial_number
	if target.format == "CycloneDX" and serial.startswith("urn:uuid:"):
		return f"urn:cdx:{serial.removeprefix('urn:uuid:')}/{cint(target.bom_version) or 1}"
	return serial


# SPDX checksum algorithm -> SG Hash.algorithm
SPDX_CHECKSUMS = {
	"SHA1": "SHA-1",
	"SHA256": "SHA-256",
	"SHA384": "SHA-384",
	"SHA512": "SHA-512",
	"SHA3_256": "SHA3-256",
	"BLAKE3": "BLAKE3",
}


def _original_checksums(document) -> dict[str, tuple[str, str]]:
	"""{document URI: checksum} of the external document references in the original SPDX file.

	The importer keeps the URI of an external SBOM but not its checksum, which SPDX needs.
	"""
	if document.format != "SPDX":
		return {}
	source = source_content(frappe._dict(source_file=document.source_file))
	if not source:
		return {}
	content, file_name = source
	suffix = ".spdx.json" if file_name.lower().endswith(".json") else ".spdx"
	try:
		with spdx_temp_file(content, suffix) as path:
			parsed = parse_file(path)
	except Exception:
		# The file is checked by the validation; here it only adds checksums when it can be read
		return {}
	result = {}
	for reference in parsed.creation_info.external_document_refs:
		algorithm = SPDX_CHECKSUMS.get(reference.checksum.algorithm.name)
		if algorithm:
			result[reference.document_uri] = (algorithm, reference.checksum.value)
	return result
