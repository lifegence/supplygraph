# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

# import frappe
from frappe.tests import IntegrationTestCase

# On IntegrationTestCase, the doctype test records and all
# link-field test record dependencies are recursively loaded
# Use these module variables to add/remove to/from that list
EXTRA_TEST_RECORD_DEPENDENCIES = []  # eg. ["User"]
IGNORE_TEST_RECORD_DEPENDENCIES = []  # eg. ["User"]


class IntegrationTestSGBOMEntry(IntegrationTestCase):
	"""Integration tests for SG BOM Entry."""

	pass
