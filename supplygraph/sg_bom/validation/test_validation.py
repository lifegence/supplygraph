# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import copy
import json
from pathlib import Path
from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase, UnitTestCase
from jsonschema.validators import Draft7Validator

from supplygraph.sg_bom import importer, validation
from supplygraph.sg_bom.validation import Finding, RuleSetResult, syntax

DATA = Path(__file__).parent.parent / "importer" / "test_data"
TEST_RULE_SET = "Test Rules From Another App"


def read_bytes(name: str) -> bytes:
	return (DATA / name).read_bytes()


def cyclonedx_sample() -> dict:
	return json.loads(read_bytes("cyclonedx_sample.json"))


def spdx_sample() -> dict:
	return json.loads(read_bytes("spdx_sample.spdx.json"))


def rule_set_for_test(bom_document) -> RuleSetResult:
	"""Stands for a rule set of an industry app, registered only through hooks."""
	return RuleSetResult(
		findings=[Finding("TEST-RULE", "Warning", f"checked {bom_document.name}", "lib-a")],
		checked=2,
		passed=1,
	)


class UnitTestUniqueItems(UnitTestCase):
	def test_json_equality(self):
		key = syntax._hashable
		self.assertEqual(key({"a": 1, "b": [1, 2]}), key({"b": [1.0, 2], "a": 1}))
		self.assertNotEqual(key(True), key(1))
		self.assertNotEqual(key([1, 2]), key([2, 1]))
		self.assertNotEqual(key("1"), key(1))
		self.assertNotEqual(key(None), key(False))

	def test_duplicates_are_found(self):
		validator = syntax._FastDraft7Validator({"type": "array", "uniqueItems": True})
		self.assertTrue(validator.is_valid([{"a": 1}, {"a": 2}]))
		self.assertFalse(validator.is_valid([{"a": 1}, {"b": 0}, {"a": 1.0}]))

	def test_many_findings_are_summed_up(self):
		findings = [Finding("X", "Warning", str(i)) for i in range(validation.MAX_FINDINGS)]
		findings += [Finding("Y", "Error", "e")] * 5
		limited = validation._limit(findings)
		self.assertEqual(len(limited), validation.MAX_FINDINGS + 1)
		self.assertEqual(sum(f.rule_code == "Y" for f in limited), 5)
		self.assertEqual(limited[-1].rule_code, "VAL-MORE")
		self.assertIn("5 more", limited[-1].message)


SPDX_TAG_VALUE = """SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: tag-value-sample
DocumentNamespace: https://example.com/spdx/tag-value-sample
Creator: Tool: test
Created: 2026-01-01T00:00:00Z

PackageName: a-lib
SPDXID: {package_id}
PackageVersion: 1.0
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false

Relationship: SPDXRef-DOCUMENT DESCRIBES {package_id}
"""


def spdx_with(**values) -> bytes:
	"""The SPDX sample with top-level values replaced, or removed when the value is DELETE."""
	data = spdx_sample()
	for key, value in values.items():
		if value is DELETE:
			data.pop(key)
		else:
			data[key] = value
	return json.dumps(data).encode()


DELETE = object()
TOO_DEEP = 100_000


def deep_cyclonedx_components(depth: int) -> bytes:
	"""Components nested in components: valid JSON, but deeper than the schema check can follow."""
	head = b'{"type": "library", "name": "x", "components": ['
	return (
		b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": ['
		+ head * depth
		+ b"]}" * depth
		+ b"]}"
	)


def minimal_cyclonedx(version: str, **component) -> bytes:
	component = {"type": "library", "name": "a-lib", "version": "1.0", **component}
	return json.dumps(
		{"bomFormat": "CycloneDX", "specVersion": version, "version": 1, "components": [component]}
	).encode()


class UnitTestSyntax(UnitTestCase):
	def test_every_supported_cyclonedx_version_is_checked(self):
		for version in syntax.CYCLONEDX_VERSIONS:
			# The license id is checked against the SPDX schema loaded through the registry
			valid = minimal_cyclonedx(version, licenses=[{"license": {"id": "MIT"}}])
			self.assertEqual(syntax.check_cyclonedx(valid), [], version)
			invalid = minimal_cyclonedx(version, licenses=[{"license": {"id": "Not-A-License"}}])
			self.assertEqual({f.rule_code for f in syntax.check_cyclonedx(invalid)}, {"SYN-CDX"}, version)

	def test_cyclonedx_1_7_is_checked_against_its_own_schema(self):
		# citations is new in 1.7, and the 1.6 schema allows no unknown top-level property
		citation = {
			"pointers": ["/components/0/name"],
			"timestamp": "2026-11-10T00:00:00Z",
			"attributedTo": "a",
		}
		data = json.loads(minimal_cyclonedx("1.7"))
		data["citations"] = [citation]
		self.assertEqual(syntax.check_cyclonedx(json.dumps(data).encode()), [])
		data["specVersion"] = "1.6"
		self.assertEqual(
			{f.rule_code for f in syntax.check_cyclonedx(json.dumps(data).encode())}, {"SYN-CDX"}
		)

	def test_spec_version_must_be_a_string(self):
		for value in (1.5, ["1.6"], None):
			data = json.loads(minimal_cyclonedx("1.6"))
			data["specVersion"] = value
			findings = syntax.check_cyclonedx(json.dumps(data).encode())
			self.assertEqual([(f.rule_code, f.severity) for f in findings], [("SYN-CDX", "Error")], value)
		self.assertEqual(
			[f.rule_code for f in syntax.check_cyclonedx(b"[1, 2]")],
			["SYN-CDX"],
		)

	def test_spdx_tag_value_is_checked(self):
		valid = SPDX_TAG_VALUE.format(package_id="SPDXRef-A").encode()
		self.assertEqual(syntax.check_spdx(valid, "sample.spdx"), [])
		invalid = SPDX_TAG_VALUE.format(package_id="SPDXRef-Not_Valid").encode()
		findings = syntax.check_spdx(invalid, "sample.spdx")
		self.assertTrue(findings)
		self.assertEqual({(f.rule_code, f.severity) for f in findings}, {("SYN-SPDX", "Error")})

	def test_other_spdx_versions_are_not_checked(self):
		old = SPDX_TAG_VALUE.format(package_id="SPDXRef-A").replace("SPDX-2.3", "SPDX-2.1").encode()
		self.assertEqual([f.rule_code for f in syntax.check_spdx(old, "old.spdx")], ["SYN-VERSION"])
		spdx3 = json.dumps({"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []})
		self.assertEqual(
			[f.rule_code for f in syntax.check_spdx(spdx3.encode(), "new.json")], ["SYN-VERSION"]
		)

	def assertOneError(self, findings, rule_code, case):
		self.assertEqual([(f.rule_code, f.severity) for f in findings], [(rule_code, "Error")], case)

	def test_spdx_whose_version_cannot_be_read_is_an_error(self):
		cases = {
			"broken JSON": (b"{not json", "a.spdx.json"),
			"not an object": (b"[]", "a.spdx.json"),
			"no spdxVersion": (spdx_with(spdxVersion=DELETE), "a.spdx.json"),
			"spdxVersion is a number": (spdx_with(spdxVersion=2.3), "a.spdx.json"),
			"spdxVersion is null": (spdx_with(spdxVersion=None), "a.spdx.json"),
			"not UTF-8 JSON": (b"\xff\xfe\x00" * 10, "a.spdx.json"),
			"JSON nested too deeply": (b"[" * TOO_DEEP + b"]" * TOO_DEEP, "a.spdx.json"),
			"no SPDXVersion line": (b"DataLicense: CC0-1.0\n", "a.spdx"),
			"empty tag-value": (b"", "a.spdx"),
			"Shift_JIS tag-value": (
				SPDX_TAG_VALUE.format(package_id="SPDXRef-A")
				.replace("tag-value-sample", "テスト")
				.encode("shift_jis"),
				"a.spdx",
			),
		}
		for case, (content, file_name) in cases.items():
			self.assertOneError(syntax.check_spdx(content, file_name), "SYN-SPDX", case)

	def test_spdx_with_values_of_a_wrong_type_is_an_error(self):
		# spdx-tools raises AttributeError or TypeError for these, not SPDXParsingError
		for case, content in {
			"creationInfo": spdx_with(creationInfo=1),
			"packages": spdx_with(packages=1),
			"package": spdx_with(packages=["a"]),
			"relationships": spdx_with(relationships="x"),
		}.items():
			findings = syntax.check_spdx(content, "a.spdx.json")
			self.assertTrue(findings, case)
			self.assertEqual({(f.rule_code, f.severity) for f in findings}, {("SYN-SPDX", "Error")}, case)

	def test_cyclonedx_that_cannot_be_read_is_an_error(self):
		cases = {
			"JSON nested too deeply": b'{"components": ' + b"[" * TOO_DEEP + b"]" * TOO_DEEP + b"}",
			"too deep for the schema check": deep_cyclonedx_components(3000),
			"Shift_JIS": '{"bomFormat": "CycloneDX", "specVersion": "1.6", "x": "テスト"}'.encode(
				"shift_jis"
			),
		}
		for case, content in cases.items():
			self.assertOneError(syntax.check_cyclonedx(content), "SYN-CDX", case)
		# Nesting that the check can follow is checked as usual
		self.assertEqual(syntax.check_cyclonedx(deep_cyclonedx_components(20)), [])

	def test_the_app_loaded_last_wins(self):
		hooks = {"Shared Rules": ["first_app.rules.run", "second_app.rules.run"], "Single": "x.run"}
		with patch.object(frappe, "get_hooks", lambda hook=None, *args, **kwargs: hooks):
			rule_sets = validation.get_rule_sets()
		self.assertEqual(rule_sets, {"Shared Rules": "second_app.rules.run", "Single": "x.run"})


class IntegrationTestValidation(IntegrationTestCase):
	def setUp(self):
		self.files = []
		for name, rule_set in (
			("Test Syntax", "SBOM Syntax"),
			("Test No Rules", None),
			("Test Unknown Rules", "No Such Rules"),
			("Test Other App", TEST_RULE_SET),
		):
			frappe.get_doc(
				{"doctype": "SG BOM Type", "bom_type_name": name, "validation_rule_set": rule_set}
			).insert()

	def tearDown(self):
		# Files are written to disk, which a rollback does not undo
		for file_name in self.files:
			frappe.delete_doc("File", file_name, force=True, ignore_permissions=True)
		frappe.db.rollback()

	def upload(self, content: bytes, file_name: str) -> str:
		file_doc = frappe.get_doc(
			{"doctype": "File", "file_name": file_name, "is_private": 1, "content": content}
		).insert(ignore_permissions=True)
		self.files.append(file_doc.name)
		return file_doc.file_url

	def import_bom(self, data: dict, file_name: str, bom_type: str = "Test Syntax") -> str:
		content = json.dumps(data).encode()
		return importer.import_content(content, file_name, bom_type, None, self.upload(content, file_name))

	def replace_file(self, bom_document: str, data: dict, file_name: str) -> None:
		"""Point the document to another file, for files that the importer would not read."""
		url = self.upload(json.dumps(data).encode(), file_name)
		frappe.db.set_value("SG BOM Document", bom_document, "source_file", url)

	def results(self, bom_document: str) -> list:
		return frappe.get_all(
			"SG BOM Validation Result",
			filters={"parent": bom_document},
			fields=["rule_code", "severity", "target_ref", "message"],
			order_by="idx",
		)

	def status(self, bom_document: str):
		return frappe.db.get_value(
			"SG BOM Document", bom_document, ["import_status", "validation_score"], as_dict=True
		)

	def run_import(self, data: dict, file_name: str = "job.cdx.json") -> list:
		"""run_import commits, so the commit is replaced and the realtime messages are returned."""
		url = self.upload(json.dumps(data).encode(), file_name)
		with (
			patch("supplygraph.sg_bom.importer.frappe.db.commit"),
			patch("supplygraph.sg_bom.importer.frappe.publish_realtime") as publish,
		):
			importer.run_import(url, "SBOM", None, "Administrator")
		# frappe.publish_realtime is replaced for every caller, so keep the messages of the import
		return [call.args[1] for call in publish.call_args_list if call.args[0] == "sg_bom_import_done"]

	def job_sbom(self) -> dict:
		return {
			"bomFormat": "CycloneDX",
			"specVersion": "1.6",
			"metadata": {"component": {"type": "application", "name": "job-root", "version": "1"}},
			"components": [{"type": "library", "name": "job-lib", "version": "1"}],
		}

	def test_import_job_validates_the_document(self):
		message = self.run_import(self.job_sbom())[0]
		self.assertEqual(message["import_status"], "Validated")
		self.assertEqual(self.status(message["bom_document"]).import_status, "Validated")

	def test_import_job_rejects_a_document_against_the_schema(self):
		data = self.job_sbom()
		data["components"][0]["scope"] = "nowhere"
		message = self.run_import(data)[0]
		self.assertEqual(message["import_status"], "Rejected")
		self.assertTrue(frappe.db.exists("SG BOM Document", message["bom_document"]))

	def test_import_job_reports_a_failed_validation(self):
		with (
			patch("supplygraph.sg_bom.importer.validate_bom", side_effect=RuntimeError("broken rule set")),
			patch("supplygraph.sg_bom.importer.frappe.db.rollback"),
			patch("supplygraph.sg_bom.importer.frappe.log_error") as log_error,
		):
			message = self.run_import(self.job_sbom())[0]
		self.assertEqual(message["validation_error"], "broken rule set")
		self.assertEqual(self.status(message["bom_document"]).import_status, "Parsed")
		log_error.assert_called_once()

	def test_submitted_document_stays_accepted_when_validated_again(self):
		url = self.upload(json.dumps(self.job_sbom()).encode(), "job.cdx.json")
		name = importer.import_file(url)
		validation.validate_bom(name)
		frappe.get_doc("SG BOM Document", name).submit()
		self.replace_file(name, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": 1}, "bad.json")
		result = validation.validate_bom(name)
		self.assertEqual(result["status"], "Rejected")
		self.assertEqual(self.status(name).import_status, "Accepted")
		self.assertEqual(self.status(name).validation_score, 0)
		self.assertTrue([row for row in self.results(name) if row.rule_code == "SYN-CDX"])

	def test_default_sbom_type_uses_the_syntax_rules(self):
		self.assertEqual(frappe.db.get_value("SG BOM Type", "SBOM", "validation_rule_set"), "SBOM Syntax")
		self.assertIn("SBOM Syntax", validation.get_rule_sets())

	def test_valid_cyclonedx_is_validated(self):
		name = self.import_bom(cyclonedx_sample(), "valid.cdx.json")
		result = validation.validate_bom(name)
		self.assertEqual(result["status"], "Validated")
		self.assertEqual(self.status(name).import_status, "Validated")
		self.assertEqual(self.status(name).validation_score, 100)
		self.assertFalse([row for row in self.results(name) if not row.rule_code.startswith("IMP-")])

	def test_valid_spdx_is_validated(self):
		name = self.import_bom(spdx_sample(), "valid.spdx.json")
		validation.validate_bom(name)
		self.assertEqual(self.status(name).import_status, "Validated")
		self.assertEqual(self.status(name).validation_score, 100)
		self.assertFalse([row for row in self.results(name) if not row.rule_code.startswith("IMP-")])

	def test_invalid_cyclonedx_is_rejected(self):
		name = self.import_bom(cyclonedx_sample(), "valid.cdx.json")
		broken = cyclonedx_sample()
		broken["components"][0]["type"] = "not-a-type"
		broken["components"].append(copy.deepcopy(broken["components"][1]))
		self.replace_file(name, broken, "broken.cdx.json")
		validation.validate_bom(name)
		self.assertEqual(self.status(name).import_status, "Rejected")
		self.assertEqual(self.status(name).validation_score, 0)
		errors = [row for row in self.results(name) if row.rule_code == "SYN-CDX"]
		self.assertEqual({row.severity for row in errors}, {"Error"})
		self.assertIn(broken["components"][0]["bom-ref"], {row.target_ref for row in errors})
		self.assertTrue(any("uniqueItems" in row.message for row in errors))

	def test_invalid_spdx_is_rejected(self):
		name = self.import_bom(spdx_sample(), "valid.spdx.json")
		broken = spdx_sample()
		broken["packages"][1]["SPDXID"] = "SPDXRef-Not Valid"
		self.replace_file(name, broken, "broken.spdx.json")
		validation.validate_bom(name)
		self.assertEqual(self.status(name).import_status, "Rejected")
		errors = [row for row in self.results(name) if row.rule_code == "SYN-SPDX"]
		self.assertTrue(errors)
		self.assertEqual({row.severity for row in errors}, {"Error"})

	def test_broken_files_are_recorded_and_do_not_stop_the_validation(self):
		spdx_name = self.import_bom(spdx_sample(), "valid.spdx.json")
		cyclonedx_name = self.import_bom(cyclonedx_sample(), "valid.cdx.json")
		for name, content, file_name, rule_code in (
			(spdx_name, b"{not json", "broken.spdx.json", "SYN-SPDX"),
			(spdx_name, spdx_with(packages=1), "wrong-type.spdx.json", "SYN-SPDX"),
			(
				spdx_name,
				"SPDXVersion: SPDX-2.3\nDocumentName: テスト\n".encode("shift_jis"),
				"sjis.spdx",
				"SYN-SPDX",
			),
			(cyclonedx_name, deep_cyclonedx_components(3000), "deep.cdx.json", "SYN-CDX"),
		):
			url = self.upload(content, file_name)
			frappe.db.set_value("SG BOM Document", name, "source_file", url)
			result = validation.validate_bom(name)
			self.assertEqual(result["status"], "Rejected", file_name)
			self.assertEqual(self.status(name).import_status, "Rejected", file_name)
			rows = [row for row in self.results(name) if not row.rule_code.startswith("IMP-")]
			self.assertEqual(
				[(row.rule_code, row.severity) for row in rows], [(rule_code, "Error")], file_name
			)

	def test_spdx_3_is_a_warning(self):
		name = self.import_bom(spdx_sample(), "valid.spdx.json")
		self.replace_file(
			name, {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}, "new.json"
		)
		validation.validate_bom(name)
		rows = [row for row in self.results(name) if not row.rule_code.startswith("IMP-")]
		self.assertEqual([(row.rule_code, row.severity) for row in rows], [("SYN-VERSION", "Warning")])
		self.assertEqual(self.status(name).import_status, "Validated")

	def test_unsupported_version_is_a_warning(self):
		data = cyclonedx_sample()
		data["specVersion"] = "1.3"
		name = self.import_bom(data, "old.cdx.json")
		validation.validate_bom(name)
		rows = [row for row in self.results(name) if row.rule_code == "SYN-VERSION"]
		self.assertEqual([row.severity for row in rows], ["Warning"])
		# A warning is not an error, but the check is not passed
		self.assertEqual(self.status(name).import_status, "Validated")
		self.assertEqual(self.status(name).validation_score, 0)

	def test_missing_file_is_an_error(self):
		name = self.import_bom(cyclonedx_sample(), "valid.cdx.json")
		frappe.db.set_value("SG BOM Document", name, "source_file", None)
		validation.validate_bom(name)
		rows = [row for row in self.results(name) if not row.rule_code.startswith("IMP-")]
		self.assertEqual([(row.rule_code, row.severity) for row in rows], [("SYN-NO-FILE", "Error")])
		self.assertEqual(self.status(name).import_status, "Rejected")

	def test_file_gone_from_disk_is_an_error(self):
		name = self.import_bom(cyclonedx_sample(), "valid.cdx.json")
		url = frappe.db.get_value("SG BOM Document", name, "source_file")
		file_doc = frappe.get_doc("File", {"file_url": url})
		Path(file_doc.get_full_path()).unlink()
		validation.validate_bom(name)
		rows = [row for row in self.results(name) if not row.rule_code.startswith("IMP-")]
		self.assertEqual([row.rule_code for row in rows], ["SYN-NO-FILE"])

	def test_cancelled_document_is_not_validated(self):
		name = self.import_bom(cyclonedx_sample(), "valid.cdx.json")
		frappe.db.set_value("SG BOM Document", name, "docstatus", 2)
		with self.assertRaisesRegex(frappe.ValidationError, "cancelled"):
			validation.validate_bom(name)
		self.assertEqual(self.status(name).import_status, "Parsed")

	def test_empty_rule_set_skips_validation(self):
		name = self.import_bom(cyclonedx_sample(), "valid.cdx.json", "Test No Rules")
		before = self.results(name)
		result = validation.validate_bom(name)
		self.assertEqual(result["status"], "skipped")
		self.assertEqual(self.status(name).import_status, "Parsed")
		self.assertEqual(self.results(name), before)

	def test_unknown_rule_set_raises(self):
		name = self.import_bom(cyclonedx_sample(), "valid.cdx.json", "Test Unknown Rules")
		with self.assertRaisesRegex(frappe.ValidationError, "No Such Rules"):
			validation.validate_bom(name)
		self.assertEqual(self.status(name).import_status, "Parsed")

	def test_rule_set_of_another_app_runs_without_changing_the_core(self):
		real_get_hooks = frappe.get_hooks

		def get_hooks(hook=None, *args, **kwargs):
			hooks = real_get_hooks(hook, *args, **kwargs)
			if hook == validation.RULE_SET_HOOK:
				hooks = {**hooks, TEST_RULE_SET: [f"{__name__}.rule_set_for_test"]}
			return hooks

		name = self.import_bom(cyclonedx_sample(), "valid.cdx.json", "Test Other App")
		with patch.object(frappe, "get_hooks", get_hooks):
			result = validation.validate_bom(name)
		self.assertEqual(result["rule_set"], TEST_RULE_SET)
		rows = self.results(name)
		self.assertIn(
			("TEST-RULE", "Warning", "lib-a"), {(r.rule_code, r.severity, r.target_ref) for r in rows}
		)
		self.assertEqual(self.status(name).validation_score, 50)
		self.assertEqual(self.status(name).import_status, "Validated")

	def test_running_twice_replaces_the_results_and_keeps_import_rows(self):
		data = cyclonedx_sample()
		data["metadata"] = {}  # the importer records IMP-LIFECYCLE, IMP-AUTHOR and IMP-TIMESTAMP
		data["components"][0]["type"] = "not-a-type"
		name = self.import_bom(data, "metadata.cdx.json")
		imported = [row for row in self.results(name) if row.rule_code.startswith("IMP-")]
		self.assertTrue(imported)

		validation.validate_bom(name)
		first = self.results(name)
		validation.validate_bom(name)
		second = self.results(name)

		self.assertEqual(len(second), len(first))
		self.assertEqual(second, first)
		self.assertEqual([row for row in second if row.rule_code.startswith("IMP-")], imported)
		self.assertTrue(any(row.rule_code == "SYN-CDX" for row in second))


class UnitTestIriReference(UnitTestCase):
	"""The fast check must agree with the slow parser it replaces, which took 20 ms per URL."""

	VALUES = (
		"https://example.com/a/b?c=d#e",
		"git+https://github.com/org/repo.git",
		"git+ssh://git@github.com/org/repo.git#v1",
		"git://github.com/org/repo.git",
		"mailto:a@example.com",
		"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		"../relative/path",
		"//example.com/a",
		"path:with-colon",
		"https://例え.テスト/パス",
		"https://example.com/a%20b",
		"",
		"https://example.com/a b",
		"https://example.com/<a>",
		'https://example.com/"a"',
		"https://example.com/{a}",
		"https://example.com/a|b",
		"https://example.com/a\\b",
		"https://example.com/a^b",
		"https://example.com/a`b",
		"https://example.com/%zz",
		"https://example.com/%2",
		"https://example.com/a#b#c",
		"https://example.com/[a]",
		"1http://example.com",
		"a b:c",
		":no-scheme",
		"not a url",
	)

	def test_agrees_with_the_parser_of_jsonschema(self):
		slow = Draft7Validator.FORMAT_CHECKER
		different = [
			value
			for value in self.VALUES
			if syntax.is_iri_reference(value) != slow.conforms(value, "iri-reference")
		]
		self.assertEqual(different, [])

	def test_ip_literal_is_accepted(self):
		# Valid by RFC 3987, although the parser of jsonschema refuses it
		self.assertTrue(syntax.is_iri_reference("http://[::1]:8080/a"))

	def test_the_schema_check_uses_the_fast_check(self):
		checker = syntax._cyclonedx_validator("1.6").format_checker
		self.assertIs(checker.checkers["iri-reference"][0], syntax.is_iri_reference)

	def test_other_formats_are_still_checked(self):
		checker = syntax._cyclonedx_validator("1.6").format_checker
		self.assertFalse(checker.conforms("not a date", "date-time"))

	def test_broken_url_is_reported(self):
		data = minimal_cyclonedx_with_url("https://example.com/a b")
		self.assertEqual({f.rule_code for f in syntax.check_cyclonedx(data)}, {"SYN-CDX"})
		self.assertEqual(syntax.check_cyclonedx(minimal_cyclonedx_with_url("https://example.com/a")), [])


def minimal_cyclonedx_with_url(url: str) -> bytes:
	return minimal_cyclonedx("1.6", externalReferences=[{"type": "website", "url": url}])
