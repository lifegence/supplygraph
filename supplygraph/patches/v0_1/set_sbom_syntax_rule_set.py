# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe


def execute():
	"""Sites installed before rule sets were added have the SBOM type without a rule set. Leave a value set by hand."""
	if frappe.db.exists("SG BOM Type", "SBOM") and not frappe.db.get_value(
		"SG BOM Type", "SBOM", "validation_rule_set"
	):
		frappe.db.set_value("SG BOM Type", "SBOM", "validation_rule_set", "SBOM Syntax")
