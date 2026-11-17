# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe


def execute():
	"""The workflow needs every document in a state of its docstatus; Uploaded is gone from the options."""
	frappe.db.set_value(
		"SG BOM Document", {"docstatus": 1}, "import_status", "Accepted", update_modified=False
	)
	frappe.db.set_value(
		"SG BOM Document", {"docstatus": 2}, "import_status", "Cancelled", update_modified=False
	)
	frappe.db.set_value(
		"SG BOM Document",
		{"docstatus": 0, "import_status": ("in", ("Uploaded", "", None))},
		"import_status",
		"Parsed",
		update_modified=False,
	)
