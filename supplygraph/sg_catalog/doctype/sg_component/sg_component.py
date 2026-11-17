# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe
from frappe.model.document import Document


class SGComponent(Document):
	pass


def on_doctype_update():
	frappe.db.add_index(
		"SG Component", ["`cpe_vendor`", "`cpe_product`"], index_name="cpe_vendor_cpe_product_index"
	)
