# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe
from frappe.tests import IntegrationTestCase

from supplygraph.sg_bom import flatten


class IntegrationTestFlatten(IntegrationTestCase):
	def tearDown(self):
		frappe.db.rollback()

	def version(self, name: str) -> str:
		component = frappe.get_doc(
			{"doctype": "SG Component", "component_name": name, "component_type": "library"}
		).insert()
		return (
			frappe.get_doc({"doctype": "SG Component Version", "component": component.name, "version": "1"})
			.insert()
			.name
		)

	def release(self, code: str = "REL-1", **values) -> str:
		document = frappe.get_doc(
			{
				"doctype": "SG Release",
				"release_code": code,
				"version": "1",
				"release_type": "Software",
				"release_status": "Released",
				**values,
			}
		)
		return document.insert().name

	def bom(self, entries: list[tuple], subject_release: str | None = None, primary=None, submit=True):
		document = frappe.get_doc(
			{
				"doctype": "SG BOM Document",
				"bom_type": "SBOM",
				"format": "CycloneDX",
				"lifecycle_phase": "Build",
				"author_name": "x",
				"bom_timestamp": "2026-11-01 00:00:00",
				"subject_release": subject_release,
				"primary_component": primary,
			}
		).insert()
		for version, is_direct, external in entries:
			frappe.get_doc(
				{
					"doctype": "SG BOM Entry",
					"bom_document": document.name,
					"component_version": version,
					"is_direct": is_direct,
					"external_bom": external,
				}
			).insert()
		if submit:
			document.submit()
		return document

	def rows(self, release: str) -> dict[tuple[str, str], int]:
		rows = frappe.get_all(
			"SG Release Component", {"release": release}, ["component_version", "via_bom_document", "depth"]
		)
		return {(row.component_version, row.via_bom_document): row.depth for row in rows}

	def test_direct_and_transitive_depth(self):
		direct, transitive = self.version("direct"), self.version("transitive")
		release = self.release()
		bom = self.bom([(direct, 1, None), (transitive, 0, None)], release).name
		flatten.rebuild_release(release)
		self.assertEqual(self.rows(release), {(direct, bom): 0, (transitive, bom): 1})

	def test_nested_sbom_is_expanded(self):
		parent_part, nested_part = self.version("parent-part"), self.version("nested-part")
		release = self.release()
		child = self.bom([(nested_part, 1, None)]).name
		parent = self.bom([(parent_part, 1, child)], release).name
		flatten.rebuild_release(release)
		self.assertEqual(self.rows(release), {(parent_part, parent): 0, (nested_part, child): 1})

	def test_cycle_ends(self):
		first_part, second_part = self.version("first-part"), self.version("second-part")
		release = self.release()
		first = self.bom([(first_part, 1, None)], release, submit=False)
		second = self.bom([(second_part, 1, first.name)])
		frappe.db.set_value("SG BOM Entry", {"bom_document": first.name}, "external_bom", second.name)
		first.submit()
		self.assertEqual(flatten.rebuild_release(release), 2)
		self.assertEqual(set(flatten.affected_releases(second.name)), {release})

	def test_only_submitted_sboms_count(self):
		part, nested_part = self.version("part"), self.version("draft-nested")
		release = self.release()
		draft = self.bom([(nested_part, 1, None)], submit=False).name
		bom = self.bom([(part, 1, draft)], release).name
		self.assertEqual(self.rows(release), {(part, bom): 0})

	def test_submit_fills_primary_bom_and_the_index(self):
		part = self.version("submit-part")
		release = self.release()
		bom = self.bom([(part, 1, None)], release).name
		self.assertEqual(frappe.db.get_value("SG Release", release, "primary_bom"), bom)
		self.assertEqual(self.rows(release), {(part, bom): 0})

	def test_cancel_empties_the_index(self):
		part = self.version("cancel-part")
		release = self.release()
		bom = self.bom([(part, 1, None)], release)
		bom.cancel()
		self.assertEqual(self.rows(release), {})

	def test_nested_sbom_submitted_later_updates_the_parents(self):
		part, nested_part = self.version("late-part"), self.version("late-nested")
		release = self.release()
		child = self.bom([(nested_part, 1, None)], submit=False)
		parent = self.bom([(part, 1, child.name)], release).name
		self.assertEqual(self.rows(release), {(part, parent): 0})
		child.submit()
		self.assertEqual(self.rows(release), {(part, parent): 0, (nested_part, child.name): 1})

	def test_rebuild_twice_and_keeps_rows_without_sbom(self):
		part, manual = self.version("twice-part"), self.version("manual-part")
		release = self.release()
		frappe.get_doc(
			{"doctype": "SG Release Component", "release": release, "component_version": manual, "depth": 0}
		).insert()
		bom = self.bom([(part, 1, None), (part, 0, None)], release).name
		flatten.rebuild_release(release)
		flatten.rebuild_release(release)
		self.assertEqual(self.rows(release), {(manual, None): 0, (part, bom): 0})

	def test_changing_the_primary_bom_rebuilds(self):
		old_part, new_part = self.version("old-part"), self.version("new-part")
		release = self.release()
		self.bom([(old_part, 1, None)], release)
		new_bom = self.bom([(new_part, 1, None)]).name
		document = frappe.get_doc("SG Release", release)
		document.primary_bom = new_bom
		document.save()
		self.assertEqual(self.rows(release), {(new_part, new_bom): 0})
