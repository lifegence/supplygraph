# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe
from frappe.model.document import Document


class SGComponentVersion(Document):
	pass


def on_doctype_update():
	frappe.db.add_unique(
		"SG Component Version", ["`component`", "`version`"], constraint_name="unique_component_version"
	)
