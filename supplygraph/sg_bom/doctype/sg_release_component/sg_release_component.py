# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe
from frappe.model.document import Document


class SGReleaseComponent(Document):
	pass


def on_doctype_update():
	frappe.db.add_unique(
		"SG Release Component",
		["`release`", "`component_version`", "`via_bom_document`"],
		constraint_name="unique_release_component_version_via_bom_document",
	)
