# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe
from frappe.model.document import Document


class SGRelease(Document):
	pass


def on_doctype_update():
	frappe.db.add_unique(
		"SG Release", ["`release_code`", "`version`"], constraint_name="unique_release_code_version"
	)
