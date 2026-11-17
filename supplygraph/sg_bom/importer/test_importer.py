# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import copy
import json
import os
from datetime import datetime

import frappe
from frappe.tests import IntegrationTestCase, UnitTestCase

from supplygraph.sg_bom import importer
from supplygraph.sg_bom.importer.cyclonedx import parse_cyclonedx
from supplygraph.sg_bom.importer.model import (
	Issue,
	is_version_constraint,
	normalize_hash,
	parse_timestamp,
	purl_version,
	split_purl,
)
from supplygraph.sg_bom.importer.spdx import parse_spdx_file

DATA = os.path.join(os.path.dirname(__file__), "test_data")


def read_bytes(name: str) -> bytes:
	with open(os.path.join(DATA, name), "rb") as file:
		return file.read()


def cyclonedx_sample() -> dict:
	return json.loads(read_bytes("cyclonedx_sample.json"))


class UnitTestParsing(UnitTestCase):
	def test_version_constraints(self):
		for version in (
			"^1.0.0",
			"~1.2",
			">=1.0",
			"<2",
			"=1.0.0",
			"!=1.0",
			"*",
			"1.x",
			"1.2.*",
			"X",
			"^2.0.0||^3.0.0",
			"1.0 - 2.0",
			"latest",
		):
			self.assertTrue(is_version_constraint(version), version)
		for version in (
			"1.0.0",
			"v1.2",
			"6",
			"2.14.1.Final",
			"1.0-beta",
			"x86",
			"1.x86",
			"a1b2c3",
			"NOASSERTION",
			"",
			None,
		):
			self.assertFalse(is_version_constraint(version), version)

	def test_purl_version(self):
		for purl, version in (
			("pkg:npm/lodash@4.17.21", "4.17.21"),
			("pkg:npm/lodash@%5E4.17.21", "^4.17.21"),
			("pkg:npm/%40babel/core@7.0.0#packages/core", "7.0.0"),
			("pkg:maven/a/b@1.0?type=jar", "1.0"),
			("pkg:npm/lodash", ""),
		):
			self.assertEqual(purl_version(purl), version, purl)

	def test_purl_is_normalized_without_qualifiers(self):
		issues: list[Issue] = []
		self.assertEqual(
			split_purl("PKG:PyPI/A_Lib@1.2.3?arch=x86#sub", "x", issues),
			("pkg:pypi/a-lib@1.2.3", "pkg:pypi/a-lib"),
		)
		self.assertEqual(issues, [])

	def test_invalid_purl_becomes_an_issue(self):
		issues: list[Issue] = []
		self.assertEqual(split_purl("not a purl", "x", issues), (None, None))
		self.assertEqual([issue.rule_code for issue in issues], ["IMP-PURL"])

	def test_hash_names(self):
		self.assertEqual(normalize_hash("sha_256"), "SHA-256")
		self.assertEqual(normalize_hash("SHA3-256"), "SHA3-256")
		self.assertIsNone(normalize_hash("MD5"))

	def test_timestamp_becomes_naive_utc(self):
		self.assertEqual(parse_timestamp("2026-01-01T09:00:00+09:00"), datetime(2026, 1, 1, 0, 0))
		self.assertIsNone(parse_timestamp("yesterday"))

	def test_cyclonedx_metadata(self):
		bom = parse_cyclonedx(cyclonedx_sample())
		self.assertEqual(bom.spec_version, "CycloneDX 1.6")
		self.assertEqual(bom.lifecycle_phase, "Build")
		self.assertEqual(bom.author_name, "T Company, Ltd.")
		self.assertEqual(bom.primary_ref, "app")
		self.assertEqual(bom.timestamp, datetime(2026, 11, 1, 5, 55, 55))

	def test_cyclonedx_component_fields(self):
		bom = parse_cyclonedx(cyclonedx_sample())
		component = next(c for c in bom.components if c.ref == "lib-a")
		self.assertEqual(component.purl, "pkg:pypi/a-lib@1.2.3")
		self.assertEqual(component.file_name, "a_lib.whl")
		self.assertEqual(component.download_location, "https://example.com/a.whl")
		self.assertEqual(component.license_declared, "MIT")
		self.assertEqual(component.license_concluded, "Apache-2.0")
		self.assertEqual([algorithm for algorithm, _value in component.hashes], ["SHA-256"])

	def test_cyclonedx_license_without_acknowledgement_is_declared(self):
		bom = parse_cyclonedx(cyclonedx_sample())
		component = next(c for c in bom.components if c.ref == "fw-b")
		self.assertEqual(component.license_declared, "MIT OR GPL-2.0-only")
		self.assertIsNone(component.license_concluded)

	def test_cyclonedx_nested_component_and_relations(self):
		bom = parse_cyclonedx(cyclonedx_sample())
		self.assertEqual({c.ref for c in bom.components}, {"app", "lib-a", "lib-a-child", "fw-b"})
		self.assertIn(("lib-a", "lib-a-child", "contains"), bom.relations)
		self.assertIn(("app", "fw-b", "depends-on"), bom.relations)

	def test_cyclonedx_problems_become_issues(self):
		bom = parse_cyclonedx(cyclonedx_sample())
		codes = [issue.rule_code for issue in bom.issues]
		self.assertIn("IMP-HASH", codes)
		self.assertIn("IMP-UNKNOWN-REF", codes)

	def test_cyclonedx_1_5_identity_object(self):
		data = cyclonedx_sample()
		data["components"][0]["evidence"]["identity"] = {
			"methods": [{"technique": "filename", "value": "one.whl"}]
		}
		component = next(c for c in parse_cyclonedx(data).components if c.ref == "lib-a")
		self.assertEqual(component.file_name, "one.whl")

	def test_cyclonedx_duplicate_ref_keeps_both_components(self):
		data = cyclonedx_sample()
		data["components"].append(copy.deepcopy(data["components"][1]))
		bom = parse_cyclonedx(data)
		self.assertEqual(sum(c.name == "b-firmware" for c in bom.components), 2)
		self.assertIn("IMP-DUPLICATE-REF", [issue.rule_code for issue in bom.issues])

	def test_spdx_document(self):
		bom = parse_spdx_file(os.path.join(DATA, "spdx_sample.spdx.json"))
		self.assertEqual(bom.spec_version, "SPDX 2.3")
		self.assertEqual(bom.serial_number, "https://example.com/spdx/T-Sample")
		self.assertEqual(bom.lifecycle_phase, "Build")
		self.assertEqual(bom.author_name, "T Company, Ltd.")
		self.assertEqual(bom.primary_ref, "SPDXRef-T")

	def test_spdx_primary_is_a_package(self):
		data = json.loads(read_bytes("spdx_sample.spdx.json"))
		data["relationships"].insert(
			0,
			{
				"spdxElementId": "SPDXRef-DOCUMENT",
				"relationshipType": "DESCRIBES",
				"relatedSpdxElement": "SPDXRef-Missing",
			},
		)
		bom = importer.parse_content(json.dumps(data).encode(), "t.spdx.json")
		self.assertEqual(bom.primary_ref, "SPDXRef-T")

	def test_spdx_package_and_relations(self):
		bom = parse_spdx_file(os.path.join(DATA, "spdx_sample.spdx.json"))
		components = {c.ref: c for c in bom.components}
		a_component = components["SPDXRef-A"]
		self.assertEqual(a_component.purl, "pkg:generic/a-component@2.0")
		self.assertEqual(a_component.license_declared, "NONE")
		self.assertEqual(a_component.license_concluded, "MIT")
		self.assertEqual(a_component.copyright_text, "NOASSERTION")
		self.assertEqual(components["SPDXRef-B"].external_bom_ref, "https://example.com/spdx/B-Component")
		self.assertIn(("SPDXRef-T", "SPDXRef-A", "contains"), bom.relations)
		# *_OF relationships point the other way
		self.assertIn(("SPDXRef-T", "SPDXRef-A", "dev-dependency"), bom.relations)
		# CONTAINS NOASSERTION has no row to store
		self.assertEqual(len(bom.relations), 3)


class IntegrationTestImport(IntegrationTestCase):
	def tearDown(self):
		frappe.db.rollback()

	def import_sample(self, data: dict | None = None, name: str = "sample.json") -> str:
		content = json.dumps(data or cyclonedx_sample()).encode()
		return importer.import_content(content, name)

	def test_cyclonedx_is_stored(self):
		document = frappe.get_doc("SG BOM Document", self.import_sample())
		self.assertEqual(document.format, "CycloneDX")
		self.assertEqual(document.import_status, "Parsed")
		self.assertEqual(document.entry_count, 4)
		self.assertEqual(frappe.db.count("SG BOM Entry", {"bom_document": document.name}), 4)
		self.assertEqual(frappe.db.count("SG Dependency", {"bom_document": document.name}), 3)
		primary = frappe.get_doc("SG Component Version", document.primary_component)
		self.assertEqual(primary.version, "1.0.0")

	def test_component_version_fields_are_stored(self):
		self.import_sample()
		name = frappe.db.get_value("SG Component Version", {"purl": "pkg:pypi/a-lib@1.2.3"})
		version = frappe.get_doc("SG Component Version", name)
		self.assertEqual(version.file_name, "a_lib.whl")
		self.assertEqual(version.license_declared, "MIT")
		self.assertEqual(version.license_expression, "Apache-2.0")
		self.assertEqual([row.algorithm for row in version.hashes], ["SHA-256"])
		self.assertEqual(
			frappe.db.get_value("SG Component", version.component, "purl_base"), "pkg:pypi/a-lib"
		)

	def test_direct_flag(self):
		document = self.import_sample()
		rows = frappe.get_all("SG BOM Entry", {"bom_document": document}, ["bom_ref", "is_direct"])
		self.assertEqual({row.bom_ref for row in rows if row.is_direct}, {"lib-a", "fw-b"})

	def test_same_file_is_rejected(self):
		self.import_sample()
		with self.assertRaises(frappe.ValidationError):
			self.import_sample()

	def test_components_are_shared_between_sboms(self):
		first = self.import_sample()
		data = cyclonedx_sample()
		data["serialNumber"] = "urn:uuid:aaaaaaaa-395b-41f5-a30f-a58921a69b79"
		second = self.import_sample(data)
		self.assertEqual(frappe.db.count("SG Component Version", {"purl": "pkg:pypi/a-lib@1.2.3"}), 1)
		self.assertEqual(frappe.db.count("SG BOM Entry", {"bom_document": first}), 4)
		self.assertEqual(frappe.db.count("SG BOM Entry", {"bom_document": second}), 4)

	def test_empty_fields_of_an_existing_version_are_filled(self):
		self.import_sample()
		data = cyclonedx_sample()
		data["serialNumber"] = "urn:uuid:bbbbbbbb-395b-41f5-a30f-a58921a69b79"
		lib = data["components"][0]
		lib["copyright"] = "changed"
		del lib["evidence"]
		name = frappe.db.get_value("SG Component Version", {"purl": "pkg:pypi/a-lib@1.2.3"})
		frappe.db.set_value("SG Component Version", name, {"copyright_text": None, "file_name": "kept.whl"})
		self.import_sample(data)
		values = frappe.db.get_value(
			"SG Component Version", name, ["copyright_text", "file_name"], as_dict=True
		)
		self.assertEqual(values.copyright_text, "changed")
		self.assertEqual(values.file_name, "kept.whl")

	def test_missing_metadata_is_recorded(self):
		data = cyclonedx_sample()
		data["metadata"] = {}
		document = frappe.get_doc("SG BOM Document", self.import_sample(data))
		codes = {row.rule_code for row in document.validation_results}
		self.assertTrue({"IMP-LIFECYCLE", "IMP-AUTHOR", "IMP-TIMESTAMP"} <= codes)
		self.assertEqual(document.author_name, "NOASSERTION")

	def test_version_constraint_is_recorded(self):
		data = cyclonedx_sample()
		data["components"][1]["version"] = "^1.0.0"
		data["components"][1]["purl"] = "pkg:npm/constraint-sample@%5E1.0.0"
		document = frappe.get_doc("SG BOM Document", self.import_sample(data))
		rows = [row for row in document.validation_results if row.rule_code == "IMP-VERSION-RANGE"]
		self.assertEqual(len(rows), 1)
		self.assertEqual(rows[0].severity, "Warning")

	def test_exact_versions_are_not_recorded_as_constraints(self):
		document = frappe.get_doc("SG BOM Document", self.import_sample(cyclonedx_sample()))
		self.assertNotIn("IMP-VERSION-RANGE", {row.rule_code for row in document.validation_results})

	def test_repeated_issues_are_merged(self):
		data = cyclonedx_sample()
		md5 = {"alg": "MD5", "content": "d41d8cd98f00b204e9800998ecf8427e"}
		data["components"][1]["hashes"] = [md5, md5]
		document = frappe.get_doc("SG BOM Document", self.import_sample(data))
		rows = [row for row in document.validation_results if row.rule_code == "IMP-HASH"]
		self.assertEqual(len(rows), 1)
		self.assertIn("(3 times)", rows[0].message)

	def test_too_long_purl_is_dropped_with_a_warning(self):
		data = cyclonedx_sample()
		data["components"][1]["purl"] = "pkg:generic/" + "x" * 200 + "@1"
		document = frappe.get_doc("SG BOM Document", self.import_sample(data))
		self.assertIn("IMP-LONG-PURL", {row.rule_code for row in document.validation_results})

	def test_spdx_is_stored(self):
		document = importer.import_content(read_bytes("spdx_sample.spdx.json"), "t.spdx.json")
		self.assertEqual(frappe.db.get_value("SG BOM Document", document, "format"), "SPDX")
		self.assertEqual(frappe.db.count("SG BOM Entry", {"bom_document": document}), 3)
		self.assertEqual(frappe.db.count("SG Dependency", {"bom_document": document}), 3)

	def test_external_bom_links_when_the_target_comes_later(self):
		parent = importer.import_content(read_bytes("spdx_sample.spdx.json"), "t.spdx.json")
		entry = {"bom_document": parent, "bom_ref": "SPDXRef-B"}
		self.assertIsNone(frappe.db.get_value("SG BOM Entry", entry, "external_bom"))
		child = json.loads(read_bytes("spdx_sample.spdx.json"))
		child["documentNamespace"] = "https://example.com/spdx/B-Component"
		child["externalDocumentRefs"] = []
		child["relationships"] = child["relationships"][:3]
		target = importer.import_content(json.dumps(child).encode(), "b.spdx.json")
		self.assertEqual(frappe.db.get_value("SG BOM Entry", entry, "external_bom"), target)

	def test_external_bom_links_when_the_target_exists(self):
		target_data = cyclonedx_sample()
		target_data["serialNumber"] = "urn:uuid:11111111-2222-3333-4444-555555555555"
		target = self.import_sample(target_data)
		parent = self.import_sample()
		entry = {"bom_document": parent, "bom_ref": "fw-b"}
		self.assertEqual(frappe.db.get_value("SG BOM Entry", entry, "external_bom"), target)

	def test_cyclonedx_target_arriving_later_links_by_urn(self):
		parent = self.import_sample()
		entry = {"bom_document": parent, "bom_ref": "fw-b"}
		self.assertIsNone(frappe.db.get_value("SG BOM Entry", entry, "external_bom"))
		target_data = cyclonedx_sample()
		target_data["serialNumber"] = "urn:uuid:11111111-2222-3333-4444-555555555555"
		target = self.import_sample(target_data)
		self.assertEqual(frappe.db.get_value("SG BOM Entry", entry, "external_bom"), target)

	def test_unsupported_files_are_rejected(self):
		for content, name in (
			(b"{}", "empty.json"),
			(b"not json", "bad.json"),
			(b"<bom/>", "bom.xml"),
			(b'{"@graph": []}', "spdx3.json"),
		):
			with self.assertRaises(frappe.ValidationError):
				importer.import_content(content, name)
