# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe

ROLES = [
	"SG Administrator",
	"SG Configuration Manager",
	"SG Security Analyst",
	"SG PSIRT Manager",
	"SG Compliance Officer",
	"SG Release Manager",
	"SG Supplier",
	"SG Viewer",
]

DEFAULT_BOM_TYPES = [
	{"bom_type_name": "SBOM", "provided_by_app": "supplygraph", "validation_rule_set": "SBOM Syntax"},
]


def after_install():
	create_roles()
	create_default_bom_types()


def after_migrate():
	create_roles()


def create_roles():
	for role in ROLES:
		if not frappe.db.exists("Role", role):
			frappe.get_doc(
				{"doctype": "Role", "role_name": role, "desk_access": 0 if role == "SG Supplier" else 1}
			).insert(ignore_permissions=True)


def create_default_bom_types():
	for row in DEFAULT_BOM_TYPES:
		if not frappe.db.exists("SG BOM Type", row["bom_type_name"]):
			frappe.get_doc({"doctype": "SG BOM Type", **row}).insert(ignore_permissions=True)
