app_name = "supplygraph"
app_title = "SupplyGraph"
app_publisher = "Lifegence"
app_description = "Product & software supply chain graph: SBOM, vulnerability impact and fleet traceability"
app_email = "info@lifegence.co.jp"
app_license = "Apache-2.0"

required_apps = ["frappe"]

app_logo_url = "/assets/supplygraph/images/logo.svg"
app_home = "/desk/supplygraph"

add_to_apps_screen = [
	{
		"name": app_name,
		"logo": app_logo_url,
		"title": app_title,
		"route": app_home,
		"has_permission": "frappe.permissions.check_app_permission",
	}
]

export_python_type_annotations = True

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------
after_install = "supplygraph.install.after_install"
after_migrate = "supplygraph.install.after_migrate"

# ---------------------------------------------------------------------------
# Document events
# ---------------------------------------------------------------------------
doc_events = {
	"SG BOM Document": {
		"before_submit": "supplygraph.sg_bom.workflow.before_submit",
		"on_submit": "supplygraph.sg_bom.flatten.on_bom_change",
		"before_cancel": "supplygraph.sg_bom.workflow.before_cancel",
		"on_cancel": "supplygraph.sg_bom.flatten.on_bom_change",
	},
	"SG Impact Assessment": {
		"on_submit": "supplygraph.sg_vulnerability.vex.on_assessment_change",
		"on_cancel": "supplygraph.sg_vulnerability.vex.on_assessment_change",
	},
	"SG Release": {
		"on_update": "supplygraph.sg_bom.flatten.on_release_update",
	},
	"SG Product Unit": {
		"validate": "supplygraph.sg_product.product_unit.validate",
	},
}

# ---------------------------------------------------------------------------
# Fixtures: bench export-fixtures --app supplygraph
# ---------------------------------------------------------------------------
fixtures = [
	{
		"dt": "Workflow State",
		"filters": [["name", "in", ["Parsed", "Validated", "Rejected", "Accepted", "Cancelled"]]],
	},
	{"dt": "Workflow Action Master", "filters": [["name", "in", ["Accept", "Reject", "Cancel"]]]},
	{"dt": "Workflow", "filters": [["name", "=", "SG BOM Document"]]},
]

# ---------------------------------------------------------------------------
# Scheduled jobs
# ---------------------------------------------------------------------------
scheduler_events = {
	"hourly": [
		"supplygraph.sg_vulnerability.osv.scheduled_hourly",
	],
	"daily": [
		"supplygraph.sg_vulnerability.osv.scheduled_daily",
	],
}

# ---------------------------------------------------------------------------
# BOM validation rule sets: name -> function run(bom_document) -> RuleSetResult.
# SG BOM Type.validation_rule_set picks one by name. Industry apps add their own here.
# ---------------------------------------------------------------------------
sg_bom_rule_sets = {
	"SBOM Syntax": "supplygraph.sg_bom.validation.syntax.run",
}
