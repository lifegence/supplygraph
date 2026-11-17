# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Checks for SG Product Unit, registered in hooks.py (doc_events).

They are not in the controller, because tools/gen_doctypes.py writes the controller again on every run.
Records written with bulk_insert, such as the synthetic data, are not checked.
"""

import re

import frappe
from frappe import _


def validate(doc, method=None):
	# Only when the serial number or the model is set: a unit saved under an older or no rule can still
	# be changed in other ways, such as its status or its installed releases.
	if doc.is_new() or doc.has_value_changed("serial_no") or doc.has_value_changed("product_model"):
		validate_serial_no(doc)


def validate_serial_no(doc) -> None:
	"""The serial number must match the serial_pattern of the product category, if there is one."""
	# A missing product model or category is reported by the mandatory and link checks
	if not doc.product_model:
		return
	category = frappe.get_cached_value("SG Product Model", doc.product_model, "product_category")
	if not category:
		return
	values = frappe.get_cached_value("SG Product Category", category, ["unit_label", "serial_pattern"])
	if not values or not values[1]:
		return
	label, pattern = values
	try:
		matched = re.fullmatch(pattern, doc.serial_no or "")
	except re.error as error:
		frappe.throw(
			_("The serial number rule of product category {0} is not a valid regular expression: {1}").format(
				category, str(error)
			),
			title=_("Invalid Serial Number Rule"),
		)
	if not matched:
		frappe.throw(
			_("{0} {1} does not match the rule of product category {2}: {3}").format(
				label or _("Serial No"), doc.serial_no, category, pattern
			),
			title=_("Invalid Serial Number"),
		)
