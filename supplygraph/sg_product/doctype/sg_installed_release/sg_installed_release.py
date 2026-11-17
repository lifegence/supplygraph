# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe
from frappe.model.document import Document


class SGInstalledRelease(Document):
	pass


def on_doctype_update():
	frappe.db.add_index("SG Installed Release", ["`release`", "`parent`"], index_name="release_parent_index")
