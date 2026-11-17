# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe
from frappe.model.document import Document

from supplygraph.sg_bom import flatten


class SGBOMEntry(Document):
	def on_update(self):
		# Scope "excluded" marks a component used only for development; the release index keeps that flag
		if self.has_value_changed("scope"):
			flatten.reindex_bom_documents([self.bom_document])


def on_doctype_update():
	frappe.db.add_index(
		"SG BOM Entry",
		["`bom_document`", "`component_version`"],
		index_name="bom_document_component_version_index",
	)
