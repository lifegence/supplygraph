# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe
from frappe.model.document import Document


class SGUpdateRecord(Document):
	pass


def on_doctype_update():
	frappe.db.add_unique(
		"SG Update Record",
		["`update_campaign`", "`product_unit`"],
		constraint_name="unique_update_campaign_product_unit",
	)
