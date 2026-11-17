# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe
from frappe.model.document import Document


class SGBOMEntry(Document):
	pass


def on_doctype_update():
	frappe.db.add_index(
		"SG BOM Entry",
		["`bom_document`", "`component_version`"],
		index_name="bom_document_component_version_index",
	)
