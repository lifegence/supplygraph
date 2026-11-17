# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import frappe


def execute():
	# on_doctype_update runs only when the DocType changes, so existing sites need this patch
	frappe.db.add_index("SG Installed Release", ["`release`", "`parent`"], index_name="release_parent_index")
