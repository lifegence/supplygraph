# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import json

import frappe
from frappe.tests import IntegrationTestCase, UnitTestCase

from supplygraph.sg_bom import importer
from supplygraph.sg_catalog import component_merge


class UnitTestNames(UnitTestCase):
	def test_normalize_name(self):
		for name in ("OpenSSL", "open-ssl", "open_ssl", "Open SSL"):
			self.assertEqual(component_merge.normalize_name(name), "openssl")
		self.assertEqual(component_merge.normalize_name(None), "")


class IntegrationTestMerge(IntegrationTestCase):
	def tearDown(self):
		frappe.db.rollback()

	def component(self, name: str, purl_base: str | None = None) -> str:
		document = frappe.get_doc(
			{
				"doctype": "SG Component",
				"component_name": name,
				"component_type": "library",
				"purl_base": purl_base,
			}
		).insert()
		# Start like an imported record: a form or code gets the first option, Confirmed
		frappe.db.set_value("SG Component", document.name, "review_status", None)
		return document.name

	def version(self, component: str, version: str, purl: str | None = None, hashes=()) -> str:
		document = frappe.get_doc(
			{
				"doctype": "SG Component Version",
				"component": component,
				"version": version,
				"purl": purl,
				"hashes": [{"algorithm": "SHA-256", "hash_value": value} for value in hashes],
			}
		)
		return document.insert().name

	def vulnerability(self, name: str) -> str:
		return (
			frappe.get_doc({"doctype": "SG Vulnerability", "vuln_id": name, "source": "Manual"}).insert().name
		)

	def match(self, vulnerability: str, version: str) -> str:
		document = frappe.get_doc(
			{
				"doctype": "SG Vulnerability Match",
				"vulnerability": vulnerability,
				"component_version": version,
				"match_method": "Manual",
				"confidence": "High",
				"match_status": "Open",
			}
		)
		return document.insert().name

	def test_candidates_need_a_component_without_purl(self):
		with_purl = self.component("Merge-Lib", "pkg:npm/merge-lib")
		same_name_other_type = self.component("merge_lib", "pkg:pypi/merge-lib")
		groups = component_merge.find_duplicate_groups()
		self.assertFalse(any(with_purl in group for group in groups))
		without_purl = self.component("MERGE LIB")
		group = next(group for group in component_merge.find_duplicate_groups() if without_purl in group)
		self.assertEqual(set(group), {with_purl, same_name_other_type, without_purl})

	def test_mark_duplicates_fills_the_review_queue(self):
		first, second = self.component("queue-lib"), self.component("Queue_Lib")
		other = self.component("unrelated-lib")
		component_merge.mark_duplicates()
		statuses = dict(
			frappe.get_all(
				"SG Component",
				{"name": ["in", [first, second, other]]},
				["name", "review_status"],
				as_list=True,
			)
		)
		self.assertEqual(statuses[first], "Needs Review")
		self.assertEqual(statuses[second], "Needs Review")
		self.assertNotEqual(statuses[other], "Needs Review")

	def test_confirmed_record_does_not_come_back_to_the_queue(self):
		first, second = self.component("alike-lib"), self.component("Alike_Lib")
		self.assertFalse(frappe.db.get_value("SG Component", first, "review_status"))
		component_merge.mark_duplicates()
		frappe.db.set_value("SG Component", first, "review_status", "Confirmed")
		self.assertEqual(component_merge.mark_duplicates(), 0)
		self.assertEqual(frappe.db.get_value("SG Component", first, "review_status"), "Confirmed")
		self.assertEqual(frappe.db.get_value("SG Component", second, "review_status"), "Needs Review")

	def test_merge_moves_versions_and_records_the_alias(self):
		target = self.component("target-lib", "pkg:npm/target-lib")
		source = self.component("Target Lib")
		version = self.version(source, "9.0")
		component_merge.merge_components(target, [source])
		self.assertFalse(frappe.db.exists("SG Component", source))
		self.assertEqual(frappe.db.get_value("SG Component Version", version, "component"), target)
		document = frappe.get_doc("SG Component", target)
		self.assertEqual(document.review_status, "Confirmed")
		self.assertEqual([row.alias_name for row in document.aliases], ["Target Lib"])

	def test_merge_of_a_same_version_moves_links_and_removes_duplicates(self):
		target = self.component("same-lib", "pkg:npm/same-lib")
		source = self.component("Same Lib")
		kept = self.version(target, "1.0", "pkg:npm/same-lib@1.0", ["aa"])
		merged = self.version(source, "1.0", None, ["aa", "bb"])
		shared, moved = self.vulnerability("CVE-2099-1001"), self.vulnerability("CVE-2099-1002")
		self.match(shared, kept)
		self.match(shared, merged)
		moved_match = self.match(moved, merged)
		component_merge.merge_components(target, [source])
		self.assertFalse(frappe.db.exists("SG Component Version", merged))
		self.assertEqual(
			frappe.db.get_value("SG Vulnerability Match", moved_match, "component_version"), kept
		)
		self.assertEqual(frappe.db.count("SG Vulnerability Match", {"component_version": kept}), 2)
		version = frappe.get_doc("SG Component Version", kept)
		self.assertEqual(sorted(row.hash_value for row in version.hashes), ["aa", "bb"])

	def test_merge_keeps_aliases_of_the_source(self):
		first = self.component("chain-lib", "pkg:npm/chain-lib")
		second, third = self.component("Chain Lib"), self.component("CHAIN_LIB")
		component_merge.merge_components(second, [third])
		component_merge.merge_components(first, [second])
		document = frappe.get_doc("SG Component", first)
		self.assertEqual({row.alias_name for row in document.aliases}, {"Chain Lib", "CHAIN_LIB"})

	def test_target_without_purl_takes_the_purl_of_the_source(self):
		target = self.component("Promote Lib")
		source = self.component("promote-lib", "pkg:npm/promote-lib")
		component_merge.merge_components(target, [source])
		self.assertEqual(frappe.db.get_value("SG Component", target, "purl_base"), "pkg:npm/promote-lib")

	def test_invalid_requests_are_refused(self):
		target = self.component("refuse-lib")
		with self.assertRaises(frappe.ValidationError):
			component_merge.merge_components(target, [target])
		with self.assertRaises(frappe.ValidationError):
			component_merge.merge_components(target, ["SGC-MISSING"])

	def test_user_without_permission_cannot_merge(self):
		target, source = self.component("perm-lib"), self.component("Perm Lib")
		frappe.set_user("Guest")
		try:
			with self.assertRaises(frappe.PermissionError):
				component_merge.merge_components(target, [source])
		finally:
			frappe.set_user("Administrator")
		self.assertTrue(frappe.db.exists("SG Component", source))

	def sbom(self, serial: str, component: dict) -> bytes:
		return json.dumps(
			{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"serialNumber": serial,
				"version": 1,
				"metadata": {"timestamp": "2026-11-01T00:00:00Z", "authors": [{"name": "x"}]},
				"components": [component],
			}
		).encode()

	def test_import_marks_candidates_and_reimport_uses_the_merge(self):
		purl = "pkg:npm/import-lib@1.0"
		importer.import_content(
			self.sbom(
				"urn:uuid:c0000000-0000-4000-8000-000000000001",
				{"type": "library", "name": "import-lib", "version": "1.0", "purl": purl},
			),
			"a.json",
		)
		named = {"type": "library", "name": "Import Lib", "version": "1.0"}
		importer.import_content(self.sbom("urn:uuid:c0000000-0000-4000-8000-000000000002", named), "b.json")
		target = frappe.db.get_value("SG Component", {"purl_base": "pkg:npm/import-lib"})
		source = frappe.db.get_value("SG Component", {"component_name": "Import Lib"})
		self.assertEqual(frappe.db.get_value("SG Component", source, "review_status"), "Needs Review")

		component_merge.merge_components(target, [source])
		document = importer.import_content(
			self.sbom("urn:uuid:c0000000-0000-4000-8000-000000000003", named), "c.json"
		)
		self.assertFalse(frappe.db.exists("SG Component", {"component_name": "Import Lib"}))
		version = frappe.db.get_value("SG BOM Entry", {"bom_document": document}, "component_version")
		self.assertEqual(frappe.db.get_value("SG Component Version", version, "component"), target)
