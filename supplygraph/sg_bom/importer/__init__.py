# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Import CycloneDX and SPDX files into SG BOM Document, SG BOM Entry and SG Dependency."""

import hashlib
import json

import frappe
from frappe import _

from supplygraph.sg_bom.importer.cyclonedx import parse_cyclonedx
from supplygraph.sg_bom.importer.loader import load_bom
from supplygraph.sg_bom.importer.model import ParsedBom
from supplygraph.sg_bom.importer.spdx import parse_spdx_file, spdx_temp_file
from supplygraph.sg_bom.validation import validate_bom


@frappe.whitelist(methods=["POST"])
def enqueue_import(file_url: str, bom_type: str = "SBOM", subject_release: str | None = None) -> dict:
	"""Queue the import of an uploaded file. The result is published to the user who started it."""
	frappe.has_permission("SG BOM Document", "create", throw=True)
	file_doc = frappe.get_doc("File", {"file_url": file_url})
	file_doc.check_permission("read")
	job = frappe.enqueue(
		"supplygraph.sg_bom.importer.run_import",
		queue="long",
		timeout=3600,
		file_url=file_url,
		bom_type=bom_type,
		subject_release=subject_release,
		user=frappe.session.user,
	)
	return {"job_id": job.id if job else None}


def run_import(file_url: str, bom_type: str, subject_release: str | None, user: str) -> None:
	try:
		name = import_file(file_url, bom_type, subject_release)
	except Exception as error:
		frappe.db.rollback()
		frappe.log_error(title=f"SBOM import failed: {file_url}")
		frappe.publish_realtime("sg_bom_import_done", {"error": str(error)}, user=user)
		raise
	# Keep the import when the validation fails: the document stays Parsed and can be validated again
	frappe.db.commit()  # nosemgrep
	try:
		validate_bom(name)
	except Exception as error:
		frappe.db.rollback()
		frappe.log_error(title=f"SBOM validation failed: {name}")
		frappe.publish_realtime(
			"sg_bom_import_done", {"bom_document": name, "validation_error": str(error)}, user=user
		)
		return
	frappe.publish_realtime(
		"sg_bom_import_done",
		{
			"bom_document": name,
			"import_status": frappe.db.get_value("SG BOM Document", name, "import_status"),
		},
		user=user,
		after_commit=True,
	)


def import_file(file_url: str, bom_type: str = "SBOM", subject_release: str | None = None) -> str:
	"""Import an uploaded file and return the SG BOM Document name."""
	file_doc = frappe.get_doc("File", {"file_url": file_url})
	content = file_doc.get_content()
	if isinstance(content, str):
		content = content.encode()
	return import_content(content, file_doc.file_name, bom_type, subject_release, file_url)


def import_content(
	content: bytes,
	file_name: str,
	bom_type: str = "SBOM",
	subject_release: str | None = None,
	source_file: str | None = None,
) -> str:
	"""Import a file given as bytes and return the SG BOM Document name."""
	sha256 = hashlib.sha256(content).hexdigest()
	existing = frappe.db.get_value("SG BOM Document", {"source_sha256": sha256, "bom_type": bom_type})
	if existing:
		frappe.throw(_("This file has already been imported as {0}").format(existing))
	parsed = parse_content(content, file_name)
	return load_bom(parsed, bom_type, sha256, subject_release, source_file)


def parse_content(content: bytes, file_name: str) -> ParsedBom:
	"""Parse by content, because many tools name both formats just .json."""
	lower_name = file_name.lower()
	if lower_name.endswith(".json"):
		try:
			data = json.loads(content)
		except ValueError as error:
			frappe.throw(_("The file is not valid JSON: {0}").format(str(error)))
		if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
			return parse_cyclonedx(data)
		if isinstance(data, dict) and "spdxVersion" in data:
			return _parse_spdx_bytes(content, ".spdx.json")
		if isinstance(data, dict) and "@graph" in data:
			frappe.throw(_("SPDX 3.0 is not supported yet. Use SPDX 2.2 or 2.3."))
	elif lower_name.endswith(".spdx"):
		return _parse_spdx_bytes(content, ".spdx")
	frappe.throw(
		_("Unsupported SBOM file: {0}. Use CycloneDX JSON, SPDX JSON or SPDX tag-value.").format(file_name)
	)


def _parse_spdx_bytes(content: bytes, suffix: str) -> ParsedBom:
	with spdx_temp_file(content, suffix) as path:
		return parse_spdx_file(path)
