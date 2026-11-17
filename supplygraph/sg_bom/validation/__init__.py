# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Validate an SG BOM Document with the rule set chosen by its SG BOM Type.

Rule sets are registered in hooks.py, so that an industry app can add one without changing the core:

	sg_bom_rule_sets = {"SBOM Syntax": "supplygraph.sg_bom.validation.syntax.run"}

A rule set is a function ``run(bom_document) -> RuleSetResult``. Run it in a background job, not in a
web request: checking a large SBOM takes minutes.

	bench --site supplygraph.localhost execute supplygraph.sg_bom.validation.validate_bom \
		--kwargs "{'bom_document': 'SGB-2026-00001'}"
"""

from dataclasses import dataclass, field

import frappe
from frappe import _
from frappe.model.document import Document

RULE_SET_HOOK = "sg_bom_rule_sets"
# Rows written by the importer start with this code and are kept when the document is validated again
IMPORT_PREFIX = "IMP-"
RESULT_DOCTYPE = "SG BOM Validation Result"
DATA_LENGTH = 140  # varchar size of a Data field
# One broken SBOM can break the schema thousands of times; more rows than this are summed up in one row
MAX_FINDINGS = 200


@dataclass
class Finding:
	rule_code: str
	severity: str  # Error, Warning or Info
	message: str
	target_ref: str | None = None


@dataclass
class RuleSetResult:
	findings: list[Finding] = field(default_factory=list)
	checked: int = 0
	passed: int = 0


def get_rule_sets() -> dict[str, str]:
	"""Registered rule sets by name. When two apps register the same name, the app loaded last wins."""
	hooks = frappe.get_hooks(RULE_SET_HOOK) or {}
	return {name: paths[-1] if isinstance(paths, list) else paths for name, paths in hooks.items()}


def validate_bom(bom_document: str) -> dict:
	"""Run the rule set of the document's SG BOM Type and record the result on the document."""
	document = frappe.get_doc("SG BOM Document", bom_document)
	if document.docstatus == 2:
		frappe.throw(_("SG BOM Document {0} is cancelled and cannot be validated").format(document.name))
	rule_set = frappe.db.get_value("SG BOM Type", document.bom_type, "validation_rule_set")
	if not rule_set:
		return {"status": "skipped", "bom_document": document.name}

	path = get_rule_sets().get(rule_set)
	if not path:
		frappe.throw(
			_("Validation rule set {0} of SG BOM Type {1} is not registered in hooks ({2})").format(
				rule_set, document.bom_type, RULE_SET_HOOK
			)
		)

	result = frappe.get_attr(path)(document)
	return _record(document, rule_set, result)


def _record(document: Document, rule_set: str, result: RuleSetResult) -> dict:
	bom_document = document.name
	findings = _limit(result.findings)
	frappe.db.delete(
		RESULT_DOCTYPE,
		{
			"parent": bom_document,
			"parenttype": "SG BOM Document",
			"parentfield": "validation_results",
			"rule_code": ("not like", f"{IMPORT_PREFIX}%"),
		},
	)
	last = frappe.get_all(
		RESULT_DOCTYPE,
		filters={"parent": bom_document, "parenttype": "SG BOM Document"},
		pluck="idx",
		order_by="idx desc",
		limit=1,
	)
	# Child rows share the docstatus of their parent
	_insert_findings(bom_document, findings, last[0] if last else 0, document.docstatus)

	errors = sum(finding.severity == "Error" for finding in result.findings)
	score = round(result.passed / result.checked * 100, 2) if result.checked else 0
	status = "Rejected" if errors else "Validated"
	values = {"validation_score": score}
	# A submitted document stays Accepted in the workflow; the result rows and the score show the outcome
	if document.docstatus == 0:
		values["import_status"] = status
	frappe.db.set_value("SG BOM Document", bom_document, values)
	return {
		"status": status,
		"bom_document": bom_document,
		"rule_set": rule_set,
		"errors": errors,
		"findings": len(result.findings),
		"validation_score": score,
	}


def _limit(findings: list[Finding]) -> list[Finding]:
	if len(findings) <= MAX_FINDINGS:
		return findings
	# Keep errors first, so that the rows that decide Rejected are the ones shown
	ordered = sorted(findings, key=lambda finding: finding.severity != "Error")
	rest = len(findings) - MAX_FINDINGS
	return [
		*ordered[:MAX_FINDINGS],
		Finding("VAL-MORE", "Info", f"{rest} more findings are not stored"),
	]


def _insert_findings(bom_document: str, findings: list[Finding], start: int, docstatus: int) -> None:
	if not findings:
		return
	now = frappe.utils.now()
	user = frappe.session.user
	fields = [
		"name",
		"parent",
		"parenttype",
		"parentfield",
		"idx",
		"rule_code",
		"severity",
		"target_ref",
		"message",
		"creation",
		"modified",
		"owner",
		"modified_by",
		"docstatus",
	]
	rows = [
		(
			frappe.generate_hash(length=10),
			bom_document,
			"SG BOM Document",
			"validation_results",
			start + index,
			finding.rule_code,
			finding.severity,
			finding.target_ref[:DATA_LENGTH] if finding.target_ref else None,
			finding.message,
			now,
			now,
			user,
			user,
			docstatus,
		)
		for index, finding in enumerate(findings, 1)
	]
	frappe.db.bulk_insert(RESULT_DOCTYPE, fields, rows)


def source_content(document: Document) -> tuple[bytes, str] | None:
	"""The original file of a document as (content, file name), or None when it cannot be found."""
	if not document.source_file:
		return None
	file_name = frappe.db.get_value("File", {"file_url": document.source_file})
	if not file_name:
		return None
	file_doc = frappe.get_doc("File", file_name)
	try:
		content = file_doc.get_content()
	except OSError:
		# The File record is there but the file on disk is gone
		return None
	if isinstance(content, str):
		content = content.encode()
	return content, file_doc.file_name or document.source_file
