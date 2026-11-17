# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Components used only for development: marked by the SBOM or by hand, and shown apart."""

import json

import frappe
from frappe.desk.doctype.number_card.number_card import get_result
from frappe.tests import IntegrationTestCase

from supplygraph.sg_bom import flatten, importer
from supplygraph.sg_catalog.component_merge import merge_components
from supplygraph.sg_vulnerability.report.sg_vulnerability_impact import sg_vulnerability_impact as report

EXCLUDED = "excluded"


def spdx_document(relationships: list[tuple[str, str, str]]) -> bytes:
	packages = [
		{
			"SPDXID": f"SPDXRef-{name}",
			"name": name,
			"versionInfo": "1.0",
			"downloadLocation": "NOASSERTION",
		}
		for name in ("App", "Runtime", "Tool", "Both")
	]
	data = {
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "dev-only",
		"documentNamespace": "https://example.com/spdx/dev-only",
		"creationInfo": {"created": "2026-11-18T00:00:00Z", "creators": ["Organization: Example"]},
		"packages": packages,
		"relationships": [
			{
				"spdxElementId": "SPDXRef-DOCUMENT",
				"relationshipType": "DESCRIBES",
				"relatedSpdxElement": "SPDXRef-App",
			},
			*(
				{
					"spdxElementId": f"SPDXRef-{a}",
					"relationshipType": kind,
					"relatedSpdxElement": f"SPDXRef-{b}",
				}
				for a, kind, b in relationships
			),
		],
	}
	return json.dumps(data).encode()


class IntegrationTestDevelopmentOnly(IntegrationTestCase):
	def tearDown(self):
		frappe.db.rollback()

	def version(self, name: str, component: str | None = None) -> str:
		if not component:
			component = (
				frappe.get_doc(
					{"doctype": "SG Component", "component_name": name, "component_type": "library"}
				)
				.insert()
				.name
			)
		return (
			frappe.get_doc({"doctype": "SG Component Version", "component": component, "version": "1"})
			.insert()
			.name
		)

	def release(self, code: str) -> str:
		return (
			frappe.get_doc(
				{
					"doctype": "SG Release",
					"release_code": code,
					"version": "1",
					"release_type": "Software",
					"release_status": "Released",
				}
			)
			.insert()
			.name
		)

	def bom(self, release: str, entries: list[tuple[str, str | None]]) -> str:
		document = frappe.get_doc(
			{
				"doctype": "SG BOM Document",
				"bom_type": "SBOM",
				"format": "CycloneDX",
				"lifecycle_phase": "Build",
				"author_name": "x",
				"bom_timestamp": "2026-11-01 00:00:00",
				"subject_release": release,
			}
		).insert()
		for version, scope in entries:
			frappe.get_doc(
				{
					"doctype": "SG BOM Entry",
					"bom_document": document.name,
					"component_version": version,
					"is_direct": 1,
					"scope": scope,
				}
			).insert()
		document.submit()
		return document.name

	def vulnerability(self, vuln_id: str) -> str:
		return (
			frappe.get_doc(
				{"doctype": "SG Vulnerability", "vuln_id": vuln_id, "source": "Manual", "severity": "High"}
			)
			.insert()
			.name
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

	def flag(self, match: str) -> int:
		return frappe.db.get_value("SG Vulnerability Match", match, "development_only")

	def entry(self, bom: str, version: str) -> str:
		return frappe.db.get_value("SG BOM Entry", {"bom_document": bom, "component_version": version})

	def test_spdx_development_relationships_give_scope_excluded(self):
		bom = importer.parse_content(
			spdx_document(
				[
					("App", "DEPENDS_ON", "Runtime"),
					("Tool", "DEV_DEPENDENCY_OF", "App"),
					("Both", "BUILD_DEPENDENCY_OF", "App"),
					("App", "DEPENDS_ON", "Both"),
				]
			),
			"dev-only.spdx.json",
		)
		scopes = {component.ref: component.scope for component in bom.components}
		self.assertEqual(scopes["SPDXRef-Tool"], EXCLUDED)
		# Also a runtime dependency, so it runs
		self.assertIsNone(scopes["SPDXRef-Both"])
		self.assertIsNone(scopes["SPDXRef-Runtime"])
		self.assertIn(("SPDXRef-App", "SPDXRef-Both", "dev-dependency"), bom.relations)

	def test_index_and_match_carry_the_flag(self):
		tool, library = self.version("dev-tool"), self.version("runtime-lib")
		release = self.release("DEV-REL-1")
		self.bom(release, [(tool, EXCLUDED), (library, "required")])
		rows = dict(
			frappe.get_all(
				"SG Release Component",
				{"release": release},
				["component_version", "development_only"],
				as_list=True,
			)
		)
		self.assertEqual(rows, {tool: 1, library: 0})
		vulnerability = self.vulnerability("CVE-2099-5901")
		self.assertEqual(self.flag(self.match(vulnerability, tool)), 1)
		self.assertEqual(self.flag(self.match(vulnerability, library)), 0)

	def test_a_version_that_runs_in_any_release_is_not_development_only(self):
		shared = self.version("shared-lib")
		self.bom(self.release("DEV-REL-2"), [(shared, EXCLUDED)])
		match = self.match(self.vulnerability("CVE-2099-5902"), shared)
		self.assertEqual(self.flag(match), 1)
		self.bom(self.release("RUN-REL-2"), [(shared, None)])
		self.assertEqual(self.flag(match), 0)

	def test_marking_by_hand_rebuilds_the_index(self):
		part = self.version("hand-marked")
		bom = self.bom(self.release("HAND-REL"), [(part, "optional")])
		match = self.match(self.vulnerability("CVE-2099-5903"), part)
		self.assertEqual(self.flag(match), 0)
		self.assertEqual(flatten.set_development_only([self.entry(bom, part)], 1), 1)
		self.assertEqual(self.flag(match), 1)
		self.assertEqual(flatten.set_development_only(json.dumps([self.entry(bom, part)]), "0"), 1)
		self.assertEqual(self.flag(match), 0)
		self.assertIsNone(frappe.db.get_value("SG BOM Entry", self.entry(bom, part), "scope"))
		# Clearing keeps a scope that does not mean development
		frappe.db.set_value("SG BOM Entry", self.entry(bom, part), "scope", "optional")
		self.assertEqual(flatten.set_development_only([self.entry(bom, part)], 0), 0)

	def test_editing_the_scope_in_the_form_rebuilds_the_index(self):
		part = self.version("form-edited")
		bom = self.bom(self.release("FORM-REL"), [(part, None)])
		match = self.match(self.vulnerability("CVE-2099-5904"), part)
		entry = frappe.get_doc("SG BOM Entry", self.entry(bom, part))
		entry.scope = EXCLUDED
		entry.save()
		self.assertEqual(self.flag(match), 1)

	def test_open_matches_card_leaves_out_development_only(self):
		tool, library = self.version("card-tool"), self.version("card-lib")
		self.bom(self.release("CARD-REL"), [(tool, EXCLUDED), (library, None)])
		vulnerability = self.vulnerability("CVE-2099-5905")
		self.match(vulnerability, tool)
		self.match(vulnerability, library)
		cards = {}
		for name in ("Open Vulnerability Matches", "Open Development Only Matches"):
			card = frappe.get_doc("Number Card", name)
			filters = [
				*json.loads(card.filters_json),
				["SG Vulnerability Match", "vulnerability", "=", vulnerability],
			]
			cards[name] = get_result(card, json.dumps(filters))
		self.assertEqual(cards, {"Open Vulnerability Matches": 1, "Open Development Only Matches": 1})

	def test_impact_report_lists_development_components_apart(self):
		tool, library = self.version("impact-tool"), self.version("impact-lib")
		vulnerability = self.vulnerability("CVE-2099-5906")
		self.match(vulnerability, tool)
		self.match(vulnerability, library)
		development_release = self.release("IMPACT-DEV")
		self.bom(development_release, [(tool, EXCLUDED)])
		runtime_release = self.release("IMPACT-RUN")
		self.bom(runtime_release, [(tool, EXCLUDED), (library, None)])
		rows = report.get_impact(vulnerability)
		self.assertEqual([row["release"] for row in rows], [runtime_release, development_release])
		self.assertEqual(rows[0]["development_only"], 0)
		self.assertEqual(rows[0]["development_components"], tool)
		self.assertEqual(rows[0]["component_versions"], library)
		self.assertEqual(rows[1]["development_only"], 1)
		self.assertEqual(rows[1]["component_versions"], "")

	def test_merging_components_updates_the_flag(self):
		tool = self.version("merge-tool")
		self.bom(self.release("MERGE-DEV"), [(tool, EXCLUDED)])
		match = self.match(self.vulnerability("CVE-2099-5907"), tool)
		self.assertEqual(self.flag(match), 1)
		runtime = self.version("merge-runtime")
		self.bom(self.release("MERGE-RUN"), [(runtime, None)])
		target = frappe.db.get_value("SG Component Version", runtime, "component")
		source = frappe.db.get_value("SG Component Version", tool, "component")
		merge_components(target, [source])
		self.assertEqual(self.flag(match), 0)
