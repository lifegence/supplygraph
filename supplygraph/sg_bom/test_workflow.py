# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import json
from pathlib import Path

import frappe
from frappe.model.workflow import WorkflowPermissionError, apply_workflow, get_transitions
from frappe.tests import IntegrationTestCase

from supplygraph.sg_bom.importer import import_content
from supplygraph.sg_catalog.component_merge import merge_components
from supplygraph.sg_vulnerability.matching import create_exact_matches, reject_matches
from supplygraph.sg_vulnerability.report.sg_vulnerability_impact import sg_vulnerability_impact as report

PURL = "pkg:npm/role-lib@1"


def sbom(name: str = "role-root") -> bytes:
	return json.dumps(
		{
			"bomFormat": "CycloneDX",
			"specVersion": "1.6",
			"metadata": {
				"timestamp": "2026-11-01T00:00:00Z",
				"authors": [{"name": "Role Supplier"}],
				"lifecycles": [{"phase": "build"}],
				"component": {"type": "firmware", "bom-ref": "root", "name": name, "version": "1"},
			},
			"components": [
				{"type": "library", "bom-ref": "lib", "name": "role-lib", "version": "1", "purl": PURL}
			],
			"dependencies": [{"ref": "root", "dependsOn": ["lib"]}],
		}
	).encode()


class RoleCase(IntegrationTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		self.release = (
			frappe.get_doc(
				{
					"doctype": "SG Release",
					"release_code": "ROLE-FW",
					"version": "1",
					"release_type": "Firmware",
					"release_status": "Released",
				}
			)
			.insert()
			.name
		)

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.rollback()

	def login(self, role: str) -> str:
		email = f"{role.lower().replace(' ', '-')}@example.com"
		frappe.set_user("Administrator")
		if not frappe.db.exists("User", email):
			frappe.get_doc(
				{
					"doctype": "User",
					"email": email,
					"first_name": role,
					"send_welcome_email": 0,
					"roles": [{"role": role}],
				}
			).insert()
		frappe.set_user(email)
		return email

	def imported(self, name: str = "role-root") -> str:
		frappe.set_user("Administrator")
		return import_content(sbom(name), f"{name}.cdx.json", subject_release=self.release)

	def set_rule_set(self, value: str | None) -> None:
		frappe.set_user("Administrator")
		frappe.db.set_value("SG BOM Type", "SBOM", "validation_rule_set", value)

	def status(self, name: str) -> tuple:
		return frappe.db.get_value("SG BOM Document", name, ["import_status", "docstatus"])


class IntegrationTestBomWorkflow(RoleCase):
	def test_fixtures_are_installed(self):
		workflow = frappe.get_doc("Workflow", "SG BOM Document")
		self.assertTrue(workflow.is_active)
		self.assertEqual(workflow.workflow_state_field, "import_status")
		for name, doc_status in (("Parsed", "0"), ("Accepted", "1"), ("Cancelled", "2")):
			self.assertIn((name, doc_status), [(row.state, row.doc_status) for row in workflow.states])
		fixture = json.loads(
			(Path(frappe.get_app_path("supplygraph")) / "fixtures/workflow.json").read_text()
		)
		self.assertEqual(len(workflow.transitions), len(fixture[0]["transitions"]))

	def test_import_starts_at_parsed(self):
		self.assertEqual(self.status(self.imported()), ("Parsed", 0))

	def test_validated_document_is_accepted_and_indexed(self):
		name = self.imported()
		frappe.db.set_value("SG BOM Document", name, "import_status", "Validated")
		self.login("SG Configuration Manager")
		apply_workflow(frappe.get_doc("SG BOM Document", name), "Accept")
		self.assertEqual(self.status(name), ("Accepted", 1))
		self.assertTrue(frappe.db.exists("SG Release Component", {"release": self.release}))

	def test_parsed_needs_validation_when_the_type_has_rules(self):
		self.set_rule_set("SBOM Syntax")
		name = self.imported()
		self.login("SG Configuration Manager")
		document = frappe.get_doc("SG BOM Document", name)
		self.assertEqual([row.action for row in get_transitions(document)], ["Reject"])
		self.assertRaises(frappe.ValidationError, apply_workflow, document, "Accept")

	def test_parsed_can_be_accepted_when_the_type_has_no_rules(self):
		self.set_rule_set(None)
		name = self.imported()
		self.login("SG Configuration Manager")
		apply_workflow(frappe.get_doc("SG BOM Document", name), "Accept")
		self.assertEqual(self.status(name), ("Accepted", 1))

	def test_rejected_document_cannot_be_submitted_directly(self):
		name = self.imported()
		self.login("SG Configuration Manager")
		apply_workflow(frappe.get_doc("SG BOM Document", name), "Reject")
		self.assertEqual(self.status(name), ("Rejected", 0))
		document = frappe.get_doc("SG BOM Document", name)
		self.assertRaises(frappe.ValidationError, document.submit)
		self.assertEqual(self.status(name), ("Rejected", 0))

	def test_direct_submit_and_cancel_keep_the_state_right(self):
		self.set_rule_set(None)
		name = self.imported()
		frappe.get_doc("SG BOM Document", name).submit()
		self.assertEqual(self.status(name), ("Accepted", 1))
		frappe.get_doc("SG BOM Document", name).cancel()
		self.assertEqual(self.status(name), ("Cancelled", 2))
		self.assertFalse(frappe.db.exists("SG Release Component", {"release": self.release}))

	def test_cancel_through_the_workflow(self):
		self.set_rule_set(None)
		name = self.imported()
		self.login("SG Configuration Manager")
		apply_workflow(frappe.get_doc("SG BOM Document", name), "Accept")
		apply_workflow(frappe.get_doc("SG BOM Document", name), "Cancel")
		self.assertEqual(self.status(name), ("Cancelled", 2))

	def test_other_roles_have_no_actions(self):
		self.set_rule_set(None)
		name = self.imported()
		for role in ("SG Security Analyst", "SG PSIRT Manager", "SG Viewer"):
			self.login(role)
			document = frappe.get_doc("SG BOM Document", name)
			self.assertEqual(get_transitions(document), [], role)
			self.assertRaises(frappe.ValidationError, apply_workflow, document, "Accept")
		self.assertEqual(self.status(name), ("Parsed", 0))

	def test_state_cannot_be_written_past_the_workflow(self):
		name = self.imported()
		self.login("SG Configuration Manager")
		document = frappe.get_doc("SG BOM Document", name)
		document.import_status = "Cancelled"
		self.assertRaises(WorkflowPermissionError, document.save)


class IntegrationTestRolePaths(RoleCase):
	"""The main path with the role of each step, as the permission table in the design document gives it."""

	def setUp(self):
		super().setUp()
		self.set_rule_set(None)
		self.login("SG Configuration Manager")
		self.document = import_content(sbom(), "role.cdx.json", subject_release=self.release)
		apply_workflow(frappe.get_doc("SG BOM Document", self.document), "Accept")
		frappe.set_user("Administrator")
		self.vulnerability = (
			frappe.get_doc({"doctype": "SG Vulnerability", "vuln_id": "CVE-2099-5001", "source": "Manual"})
			.insert()
			.name
		)
		create_exact_matches({PURL: [{"id": "CVE-2099-5001"}]})
		self.match = frappe.db.get_value("SG Vulnerability Match", {"vulnerability": self.vulnerability})

	def assessment(self) -> "frappe.model.document.Document":
		return frappe.get_doc(
			{
				"doctype": "SG Impact Assessment",
				"vulnerability": self.vulnerability,
				"release": self.release,
				"vex_status": "Affected",
			}
		)

	def test_read_only_roles_cannot_import(self):
		for role in ("SG Security Analyst", "SG PSIRT Manager", "SG Viewer"):
			self.login(role)
			self.assertFalse(frappe.has_permission("SG BOM Document", "create"), role)

	def test_every_desk_role_reads_the_report_and_the_units(self):
		for role in (
			"SG Configuration Manager",
			"SG Security Analyst",
			"SG PSIRT Manager",
			"SG Compliance Officer",
			"SG Release Manager",
			"SG Viewer",
		):
			self.login(role)
			rows = report.execute({"vulnerability": self.vulnerability})[1]
			self.assertEqual([row["release"] for row in rows], [self.release], role)
			self.assertEqual(report.get_units(self.release)["total"], 0, role)

	def test_supplier_reads_nothing(self):
		self.login("SG Supplier")
		for doctype in ("SG BOM Document", "SG Product Unit", "SG Vulnerability", "SG Impact Assessment"):
			self.assertFalse(frappe.has_permission(doctype, "read"), doctype)
		self.assertRaises(frappe.PermissionError, report.get_units, self.release)

	def test_analyst_rejects_a_match_and_viewer_cannot(self):
		self.login("SG Viewer")
		self.assertRaises(frappe.PermissionError, reject_matches, [self.match])
		self.login("SG Security Analyst")
		self.assertEqual(reject_matches([self.match]), 1)

	def test_analyst_drafts_and_psirt_approves(self):
		self.login("SG Security Analyst")
		document = self.assessment().insert()
		self.assertRaises(frappe.PermissionError, document.submit)
		self.login("SG PSIRT Manager")
		frappe.get_doc("SG Impact Assessment", document.name).submit()
		self.assertEqual(frappe.db.get_value("SG Impact Assessment", document.name, "docstatus"), 1)

	def test_viewer_cannot_assess(self):
		self.login("SG Viewer")
		self.assertRaises(frappe.PermissionError, self.assessment().insert)

	def test_only_the_administrator_merges_components(self):
		frappe.set_user("Administrator")
		names = [
			frappe.get_doc({"doctype": "SG Component", "component_name": name, "component_type": "library"})
			.insert()
			.name
			for name in ("merge-me", "Merge_Me")
		]
		for role in ("SG Configuration Manager", "SG Security Analyst", "SG Viewer"):
			self.login(role)
			self.assertRaises(frappe.PermissionError, merge_components, names[0], [names[1]])
		self.login("SG Administrator")
		self.assertEqual(merge_components(names[0], [names[1]]), names[0])
