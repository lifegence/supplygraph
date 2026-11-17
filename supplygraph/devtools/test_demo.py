# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase

from supplygraph.devtools import demo
from supplygraph.sg_bom.importer import import_content
from supplygraph.sg_vulnerability.report.sg_vulnerability_impact import sg_vulnerability_impact as report


class IntegrationTestDemo(IntegrationTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		if demo.exists():
			self.skipTest("Demo data is loaded on this site; the test would remove it")
		self.result = demo.load()
		# Files are written to disk, which a rollback does not undo
		self.addCleanup(frappe.db.rollback)
		self.addCleanup(demo.purge)

	def release(self, code: str, version: str = "1.0") -> str:
		return frappe.db.get_value("SG Release", {"release_code": code, "version": version})

	def add_release(self, code: str) -> str:
		document = frappe.get_doc(
			{
				"doctype": "SG Release",
				"release_code": code,
				"version": "1",
				"release_type": "Firmware",
				"release_status": "Released",
			}
		)
		return document.insert().name

	def impact(self, cve: str = demo.LOG4SHELL, **filters) -> list[dict]:
		return report.execute({"vulnerability": cve, **filters})[1]

	def test_load_gives_the_numbers_in_the_scenario(self):
		self.assertEqual(self.result["releases"], 5)
		self.assertEqual(self.result["units"], 30)
		self.assertEqual(self.result["exact_matches"], 2)

	def test_report_shows_the_story(self):
		rows = {
			(row["release_code"], row["release_version"], row["product_model"]): row["units"]
			for row in self.impact()
		}
		self.assertEqual(
			rows,
			{
				("DEMO-IVI-FW", "1.0", demo.SEDAN): 12,
				("DEMO-IVI-FW", "1.0", demo.SUV): 10,
				("DEMO-IVI-NEXT", "2.0-rc1", None): 0,
			},
		)

	def test_not_affected_release_appears_only_when_asked(self):
		rows = self.impact(include_not_affected=1)
		self.assertEqual(
			{row["vex_status"] for row in rows if row["release_code"] == "DEMO-TCU-FW"},
			{"Not Affected"},
		)

	def test_spdx_and_cyclonedx_share_the_same_component_version(self):
		version = frappe.db.get_value("SG Component Version", {"purl": demo.VULNERABLE_LOG4J})
		formats = frappe.get_all(
			"SG BOM Entry",
			{"component_version": version},
			pluck="bom_document",
		)
		self.assertEqual(
			{frappe.db.get_value("SG BOM Document", name, "format") for name in formats},
			{"CycloneDX", "SPDX"},
		)

	def test_same_name_without_purl_waits_for_review(self):
		statuses = frappe.get_all(
			"SG Component", {"component_name": ["in", ["zlib", "ZLIB"]]}, pluck="review_status"
		)
		self.assertEqual(len(statuses), 2)
		self.assertTrue(all(statuses))

	def test_every_sbom_passes_validation_and_is_accepted(self):
		rows = frappe.get_all(
			"SG BOM Document",
			{"source_file": ["like", "%DEMO-%"]},
			["import_status", "validation_score", "docstatus"],
		)
		self.assertEqual(len(rows), 5)
		for row in rows:
			self.assertEqual((row.import_status, row.validation_score, row.docstatus), ("Accepted", 100, 1))

	def test_load_twice_is_refused(self):
		self.assertRaises(frappe.ValidationError, demo.load)

	def test_purge_leaves_nothing(self):
		demo.purge()
		self.assertFalse(demo.exists())
		for doctype, filters in (
			("SG Release", {"release_code": ["like", "DEMO-%"]}),
			("SG Product Unit", {"serial_no": ["like", "DEM%"]}),
			("SG Product Model", {"model_code": ["like", "DEMO-%"]}),
			("SG Unit Type", {"unit_part_number": ["like", "DEMO-%"]}),
			("SG Organization", {"organization_name": ["like", "DEMO%"]}),
			("SG Product Category", {"category_name": ["like", "DEMO%"]}),
			("SG Component Version", {"purl": demo.VULNERABLE_LOG4J}),
			("SG Component", {"component_name": "log4j-core"}),
			("SG Vulnerability", {"vuln_id": demo.LOG4SHELL}),
			("File", {"file_name": ["like", "DEMO-%"]}),
		):
			self.assertEqual(frappe.db.count(doctype, filters), 0, doctype)

	def test_purge_without_demo_data_touches_nothing(self):
		demo.purge()
		category = frappe.get_doc({"doctype": "SG Product Category", "category_name": "KEEP-CAT"}).insert()
		model = frappe.get_doc(
			{
				"doctype": "SG Product Model",
				"model_code": "KEEP-MODEL",
				"model_name": "KEEP-MODEL",
				"product_category": category.name,
			}
		).insert()
		frappe.get_doc(
			{"doctype": "SG Product Unit", "serial_no": "KEEP-1", "product_model": model.name}
		).insert()
		release = self.add_release("KEEP-FW")
		name = import_content(
			demo._cyclonedx("KEEP-FW", "1", [("keep-lib", "1", "pkg:npm/keep-lib@1")]),
			"keep.cdx.json",
			subject_release=release,
		)
		frappe.get_doc("SG BOM Document", name).submit()
		before = {
			doctype: frappe.db.count(doctype)
			for doctype in (
				"SG Product Unit",
				"SG BOM Document",
				"SG BOM Entry",
				"SG Dependency",
				"SG Release Component",
				"SG Release",
				"SG Component Version",
			)
		}
		demo.purge()
		self.assertEqual({doctype: frappe.db.count(doctype) for doctype in before}, before)

	def test_second_purge_keeps_a_document_without_a_release(self):
		name = import_content(
			demo._cyclonedx("KEEP-NO-RELEASE", "1", [("keep-lib", "1", "pkg:npm/keep-lib@1")]),
			"keep.cdx.json",
		)
		demo.purge()
		demo.purge()
		self.assertTrue(frappe.db.exists("SG BOM Document", name))
		self.assertTrue(frappe.db.exists("SG BOM Entry", {"bom_document": name}))

	def test_purge_keeps_what_other_data_uses(self):
		release = self.add_release("OTHER-FW")
		name = import_content(
			demo._cyclonedx("OTHER-FW", "1", [("log4j-core", "2.14.1", demo.VULNERABLE_LOG4J)]),
			"other.cdx.json",
			subject_release=release,
		)
		frappe.get_doc("SG BOM Document", name).submit()
		demo.purge()
		self.assertTrue(frappe.db.exists("SG Component Version", {"purl": demo.VULNERABLE_LOG4J}))
		self.assertTrue(frappe.db.exists("SG Vulnerability", demo.LOG4SHELL))
		self.assertEqual([row["release"] for row in self.impact()], [release])
		self.assertFalse(frappe.db.exists("SG Component", {"component_name": "demo-media-player"}))

	def test_only_on_development_sites(self):
		with patch.dict(frappe.conf, {"developer_mode": 0, "allow_tests": 0}):
			self.assertRaises(frappe.ValidationError, demo.load)
			self.assertRaises(frappe.ValidationError, demo.purge)
