# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Rules of the SG BOM Document workflow that hold for every path, not only for the Desk buttons.

The states and transitions are in fixtures/workflow.json. Frappe checks the transition only when the
state field changes, and doc.submit() sets the state itself, so a direct submit would skip them. A direct
cancel does not run the workflow at all, so the state is set here.
"""

import frappe
from frappe import _, _lt

# The extractor does not read fixtures, so name the workflow actions here to translate them.
WORKFLOW_ACTIONS = (_lt("Accept"), _lt("Reject"), _lt("Cancel"))


def before_submit(doc, _method=None) -> None:
	before = doc.get_doc_before_save()
	if before and before.import_status == "Rejected":
		frappe.throw(_("SG BOM Document {0} is rejected and cannot be submitted").format(doc.name))


def before_cancel(doc, _method=None) -> None:
	doc.import_status = "Cancelled"
