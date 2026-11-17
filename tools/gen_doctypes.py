"""Generate SupplyGraph DocType files from tools/doctype_spec.json.

Usage: python3 tools/gen_doctypes.py [APP_ROOT]  (default: repository root)
"""

import json
import re
import sys
from pathlib import Path

SPEC = json.loads(Path(__file__).with_name("doctype_spec.json").read_text(encoding="utf-8"))
ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
APP = "supplygraph"
PKG = ROOT / APP
TS = "2026-10-15 00:00:00.000000"
HEADER = "# Copyright (c) 2026, Lifegence and contributors\n# License: Apache-2.0. See LICENSE\n"

SECTION_MODULE = {"5.1": "SG Catalog", "5.2": "SG BOM", "5.3": "SG Product", "5.4": "SG Vulnerability"}
MODULE_OVERRIDE = {"SG Exchange Request": "SG Exchange", "SG Settings": "SG Catalog"}
MODULES = ["SG Catalog", "SG BOM", "SG Product", "SG Vulnerability", "SG Compliance", "SG Exchange"]

# DocTypes referenced by the spec but only summarised in the design doc
EXTRA = [
	(
		"SG Catalog",
		{
			"name": "SG Component Alias",
			"kind": "子テーブル",
			"naming": "",
			"fields": [
				["alias_name", "Data", "", "必須", "統合前の部品名"],
				["alias_purl_base", "Data", "", "", "統合前の版なしPURL"],
			],
		},
	),
	(
		"SG Product",
		{
			"name": "SG Market",
			"naming": "field:market_code",
			"fields": [
				["market_code", "Data", "", "必須・一意", "例：JP、EU、US、CN"],
				["market_name", "Data", "", "必須", ""],
			],
		},
	),
	(
		"SG Product",
		{
			"name": "SG Market Row",
			"kind": "子テーブル",
			"naming": "",
			"fields": [["market", "Link", "SG Market", "必須", ""]],
		},
	),
	(
		"SG Product",
		{
			"name": "SG Campaign Model",
			"kind": "子テーブル",
			"naming": "",
			"fields": [["product_model", "Link", "SG Product Model", "必須", ""]],
		},
	),
	(
		"SG Product",
		{
			"name": "SG Campaign Release",
			"kind": "子テーブル",
			"naming": "",
			"fields": [
				["unit_type", "Link", "SG Unit Type", "必須", ""],
				["from_release", "Link", "SG Release", "", "適用前提のリリース（空なら全て）"],
				["to_release", "Link", "SG Release", "必須", "適用するリリース"],
			],
		},
	),
	(
		"SG Vulnerability",
		{
			"name": "SG Vulnerability Alias",
			"kind": "子テーブル",
			"naming": "",
			"fields": [["alias_id", "Data", "", "必須", ""], ["alias_source", "Data", "", "", ""]],
		},
	),
	(
		"SG Vulnerability",
		{
			"name": "SG Reference",
			"kind": "子テーブル",
			"naming": "",
			"fields": [
				["url", "Data (URL)", "", "必須", ""],
				["reference_type", "Select", "Advisory / Fix / Report / Article / Other", "", ""],
			],
		},
	),
	(
		"SG Vulnerability",
		{
			"name": "SG Case Vulnerability",
			"kind": "子テーブル",
			"naming": "",
			"fields": [["vulnerability", "Link", "SG Vulnerability", "必須", ""]],
		},
	),
	(
		"SG Compliance",
		{
			"name": "SG Advisory Revision",
			"kind": "子テーブル",
			"naming": "",
			"fields": [
				["revision_number", "Data", "", "必須", ""],
				["revision_date", "Date", "", "", ""],
				["summary", "Small Text", "", "", ""],
			],
		},
	),
]

# Composite indexes / unique constraints (design doc §5 notes)
INDEXES = {
	"SG Component": [("index", ["cpe_vendor", "cpe_product"])],
	"SG Component Version": [("unique", ["component", "version"])],
	"SG BOM Entry": [("index", ["bom_document", "component_version"])],
	"SG Release Component": [("unique", ["release", "component_version", "via_bom_document"])],
	"SG Release": [("unique", ["release_code", "version"])],
	"SG Installed Release": [("index", ["release", "parent"])],
	"SG Vulnerability Match": [("unique", ["vulnerability", "component_version"])],
	"SG Update Record": [("unique", ["update_campaign", "product_unit"])],
	"SG Impact Assessment": [("index", ["vulnerability", "release"])],
}
SEARCH_INDEX = {
	"component",
	"component_version",
	"vulnerability",
	"release",
	"bom_document",
	"product_unit",
	"product_model",
	"match_status",
	"end_of_support_date",
	"update_campaign",
	"vulnerability_case",
}
TITLE_FIELDS = {
	"SG Component": "component_name",
	"SG Release": "release_code",
	"SG Vulnerability": "title",
	"SG Vulnerability Case": "case_title",
	"SG Update Campaign": "campaign_title",
	"SG Advisory": "title",
	"SG Product Model": "model_name",
	"SG Unit Type": "unit_name",
	"SG License": "license_name",
	"SG Market": "market_name",
}
# DocTypes that Data Import may write to. The roles that can create records also get the import permission.
ALLOW_IMPORT = {"SG Product Unit"}
MANDATORY_DEPENDS = {("SG Impact Assessment", "justification"): "eval:doc.vex_status=='Not Affected'"}

# Role permissions (design doc §8). R=read W=write C=create D=delete S=submit
ADMIN, CONF, ANA, PSIRT, COMP, REL, VIEW = (
	"SG Administrator",
	"SG Configuration Manager",
	"SG Security Analyst",
	"SG PSIRT Manager",
	"SG Compliance Officer",
	"SG Release Manager",
	"SG Viewer",
)
ROLES = [ADMIN, CONF, ANA, PSIRT, COMP, REL, "SG Supplier", VIEW]
ALL_READ = {ANA: "R", PSIRT: "R", COMP: "R", REL: "R", VIEW: "R"}
P_CATALOG = {CONF: "RWC", **ALL_READ, ANA: "RW"}
P_CONFIG = {CONF: "RWC", **ALL_READ}
PERMS = {
	**dict.fromkeys(
		[
			"SG Organization",
			"SG Component",
			"SG Component Version",
			"SG License",
			"SG BOM Type",
			"SG Product Category",
			"SG Market",
		],
		P_CATALOG,
	),
	"SG BOM Document": {CONF: "RWCS", **ALL_READ},
	**dict.fromkeys(
		[
			"SG BOM Entry",
			"SG Dependency",
			"SG Release Component",
			"SG Product Model",
			"SG Unit Type",
			"SG Release",
		],
		P_CONFIG,
	),
	"SG Product Unit": {CONF: "RWC", **ALL_READ, REL: "RW"},
	"SG Configuration Change": {CONF: "RWCS", **ALL_READ, REL: "RWCS"},
	"SG Update Record": {CONF: "R", **ALL_READ, REL: "RWC"},
	"SG Update Campaign": {CONF: "R", **ALL_READ, PSIRT: "RW", REL: "RWC"},
	"SG Vulnerability": {CONF: "R", **ALL_READ, ANA: "RW", PSIRT: "RW"},
	"SG Vulnerability Match": {CONF: "R", **ALL_READ, ANA: "RWC", PSIRT: "RW"},
	"SG Impact Assessment": {CONF: "R", **ALL_READ, ANA: "RWC", PSIRT: "RWCS"},
	"SG Vulnerability Case": {CONF: "R", **ALL_READ, ANA: "RW", PSIRT: "RWC", COMP: "RW"},
	"SG Compensating Control": {CONF: "R", **ALL_READ, ANA: "RWC", PSIRT: "RWCS"},
	"SG Report Type": {**ALL_READ, COMP: "RWC"},
	"SG Regulatory Report": {ANA: "R", PSIRT: "RWC", COMP: "RWCS", VIEW: "R"},
	"SG Advisory": {ANA: "RW", PSIRT: "RWCS", COMP: "R", VIEW: "R"},
	"SG Exchange Request": {CONF: "RWC", ANA: "R", PSIRT: "R", VIEW: "R"},
	"SG Settings": {},
}


def scrub(name):
	return name.lower().replace(" ", "_").replace("-", "_")


def label(fieldname):
	special = {
		"purl": "PURL",
		"cpe": "CPE",
		"url": "URL",
		"id": "ID",
		"cvss": "CVSS",
		"epss": "EPSS",
		"cwe": "CWE",
		"bom": "BOM",
		"vex": "VEX",
		"psirt": "PSIRT",
		"tlp": "TLP",
		"csaf": "CSAF",
		"sha256": "SHA-256",
		"ids": "IDs",
		"nvd": "NVD",
		"osv": "OSV",
		"ai": "AI",
		"sl": "SL",
		"v3": "v3",
		"v4": "v4",
		"spdx": "SPDX",
		"osi": "OSI",
	}
	return " ".join(special.get(w, w.capitalize()) for w in fieldname.split("_"))


def convert_field(dt, row, kind):
	fieldname, ftype, options, constraint, desc = row
	f = {"fieldname": fieldname, "label": label(fieldname)}
	m = re.match(r"Data \((URL|Email)\)", ftype)
	if m:
		f["fieldtype"], f["options"] = "Data", m.group(1)
	else:
		f["fieldtype"] = ftype
		if options:
			f["options"] = (
				"\n".join(o.strip() for o in options.split(" / ")) if ftype == "Select" else options
			)
	if "必須" in constraint and "条件付き" not in constraint:
		f["reqd"] = 1
	if "一意" in constraint:
		f["unique"] = 1
	if "読取専用" in constraint:
		f["read_only"] = 1
	if (dt, fieldname) in MANDATORY_DEPENDS:
		f["mandatory_depends_on"] = MANDATORY_DEPENDS[(dt, fieldname)]
	desc = re.sub(r"（D\d）", "", desc)
	if desc:
		f["description"] = desc
	if ftype == "Link" and fieldname in SEARCH_INDEX and kind not in ("子テーブル", "Single"):
		f["search_index"] = 1
	if fieldname == "naming_series":
		f.update({"hidden": 1, "default": options, "label": "Naming Series"})
	return f


def perm_rows(dt, submittable):
	rows = []
	full = "RWCDS" if submittable else "RWCD"
	for role, flags in [("System Manager", full), (ADMIN, full), *PERMS.get(dt, {}).items()]:
		r = {"role": role, "read": 1, "report": 1, "export": 1, "print": 1, "email": 1, "share": 1}
		r["write"] = int("W" in flags)
		r["create"] = int("C" in flags)
		r["delete"] = int("D" in flags)
		if dt in ALLOW_IMPORT:
			r["import"] = int("C" in flags)
		if submittable:
			r["submit"] = int("S" in flags)
			r["cancel"] = int("S" in flags)
			r["amend"] = int("S" in flags)
		rows.append(r)
	return rows


def build_doctype(d, module):
	kind = d.get("kind", "通常")
	dt = d["name"]
	naming = d.get("naming", "")
	fields = [convert_field(dt, r, kind) for r in d["fields"]]
	doc = {
		"actions": [],
		"creation": TS,
		"doctype": "DocType",
		"engine": "InnoDB",
		"links": [],
		"modified": TS,
		"modified_by": "Administrator",
		"module": module,
		"name": dt,
		"owner": "Administrator",
		"sort_field": "creation",
		"sort_order": "DESC",
		"states": [],
		"track_changes": 0 if d.get("track") is False else 1,
	}
	if kind == "子テーブル":
		doc.update({"istable": 1, "editable_grid": 1, "track_changes": 0})
	elif kind == "Single":
		doc.update({"issingle": 1})
	if kind == "提出可能":
		doc["is_submittable"] = 1
		fields.append(
			{
				"fieldname": "amended_from",
				"fieldtype": "Link",
				"label": "Amended From",
				"no_copy": 1,
				"options": dt,
				"print_hide": 1,
				"read_only": 1,
				"search_index": 1,
			}
		)
	if naming.startswith("naming_series:"):
		series = naming.split(":", 1)[1].strip()
		doc.update({"autoname": "naming_series:", "naming_rule": 'By "Naming Series" field'})
		if not any(f["fieldname"] == "naming_series" for f in fields):
			fields.insert(
				0,
				{
					"fieldname": "naming_series",
					"fieldtype": "Select",
					"label": "Naming Series",
					"options": series,
					"default": series,
					"reqd": 1,
					"hidden": 1,
				},
			)
	elif naming.startswith("field:"):
		doc.update({"autoname": naming, "naming_rule": "By fieldname"})
	elif naming == "hash":
		doc.update({"autoname": "hash", "naming_rule": "Random"})
	# list view: first three plain required fields
	shown = 0
	for f in fields:
		if (
			shown < 3
			and f.get("reqd")
			and not f.get("hidden")
			and f["fieldtype"] not in ("Table", "Table MultiSelect", "Text Editor")
		):
			f["in_list_view"] = 1
			shown += 1
	if dt in ALLOW_IMPORT:
		doc["allow_import"] = 1
	if dt in TITLE_FIELDS:
		doc["title_field"] = TITLE_FIELDS[dt]
		doc["show_title_field_in_link"] = 1
	doc["field_order"] = [f["fieldname"] for f in fields]
	doc["fields"] = fields
	doc["permissions"] = [] if kind == "子テーブル" else perm_rows(dt, kind == "提出可能")
	return dict(sorted(doc.items()))


def write(path, text):
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(text, encoding="utf-8")


def controller(dt):
	cls = dt.replace(" ", "")
	out = HEADER + "\nimport frappe\nfrom frappe.model.document import Document\n\n\n"
	out += f"class {cls}(Document):\n\tpass\n"
	if dt in INDEXES:
		out += "\n\ndef on_doctype_update():\n"
		for kind, cols in INDEXES[dt]:
			# frappe.db.add_unique / add_index put the column names into the SQL as they are, so quote them:
			# some field names (e.g. "release") are reserved words in MariaDB. Name the constraint or index
			# explicitly, because the default name would include the backquotes.
			quoted = [f"`{col}`" for col in cols]
			if kind == "unique":
				out += f'\tfrappe.db.add_unique("{dt}", {quoted!r}, constraint_name="unique_{"_".join(cols)}")\n'.replace(
					"'", '"'
				)
			else:
				out += f'\tfrappe.db.add_index("{dt}", {quoted!r}, index_name="{"_".join(cols)}_index")\n'.replace(
					"'", '"'
				)
	return out


def test_file(dt):
	cls = dt.replace(" ", "")
	return (
		HEADER
		+ "\n# import frappe\nfrom frappe.tests import IntegrationTestCase\n\n"
		+ "# On IntegrationTestCase, the doctype test records and all\n"
		+ "# link-field test record dependencies are recursively loaded\n"
		+ "# Use these module variables to add/remove to/from that list\n"
		+ 'EXTRA_TEST_RECORD_DEPENDENCIES = []  # eg. ["User"]\n'
		+ 'IGNORE_TEST_RECORD_DEPENDENCIES = []  # eg. ["User"]\n\n\n'
		+ f'class IntegrationTest{cls}(IntegrationTestCase):\n\t"""Integration tests for {dt}."""\n\n\tpass\n'
	)


def js_file(dt):
	return (
		"// Copyright (c) 2026, Lifegence and contributors\n// License: Apache-2.0. See LICENSE\n\n"
		f'// frappe.ui.form.on("{dt}", {{\n// \trefresh(frm) {{\n// \t}},\n// }});\n'
	)


# ---------------------------------------------------------------- generate
entries = []
for section, docs in SPEC.items():
	key = section.split(" ")[0]
	for d in docs:
		module = MODULE_OVERRIDE.get(d["name"], SECTION_MODULE.get(key, "SG Compliance"))
		entries.append((module, d))
entries += EXTRA

names = {d["name"] for _, d in entries}
for module in MODULES:
	write(PKG / scrub(module) / "__init__.py", "")
	write(PKG / scrub(module) / "doctype" / "__init__.py", "")

for module, d in entries:
	dt = d["name"]
	folder = PKG / scrub(module) / "doctype" / scrub(dt)
	doc = build_doctype(d, module)
	for f in doc["fields"]:
		if f["fieldtype"] in ("Link", "Table", "Table MultiSelect") and f["options"] not in names | {
			"User",
			"Country",
			"DocType",
		}:
			raise SystemExit(f"{dt}.{f['fieldname']}: unknown target {f['options']}")
	write(folder / "__init__.py", "")
	write(folder / f"{scrub(dt)}.json", json.dumps(doc, indent=1, ensure_ascii=False))
	write(folder / f"{scrub(dt)}.py", controller(dt))
	if d.get("kind") != "子テーブル":
		write(folder / f"{scrub(dt)}.js", js_file(dt))
		write(folder / f"test_{scrub(dt)}.py", test_file(dt))

write(PKG / "modules.txt", "\n".join(MODULES) + "\n")
roles_py = ",\n".join(f'\t"{r}"' for r in ROLES)
write(
	PKG / "install.py",
	HEADER
	+ f"""
import frappe

ROLES = [
{roles_py},
]

DEFAULT_BOM_TYPES = [
	{{"bom_type_name": "SBOM", "provided_by_app": "supplygraph", "validation_rule_set": "SBOM Syntax"}},
]


def after_install():
	create_roles()
	create_default_bom_types()


def after_migrate():
	create_roles()


def create_roles():
	for role in ROLES:
		if not frappe.db.exists("Role", role):
			frappe.get_doc(
				{{"doctype": "Role", "role_name": role, "desk_access": 0 if role == "SG Supplier" else 1}}
			).insert(ignore_permissions=True)


def create_default_bom_types():
	for row in DEFAULT_BOM_TYPES:
		if not frappe.db.exists("SG BOM Type", row["bom_type_name"]):
			frappe.get_doc({{"doctype": "SG BOM Type", **row}}).insert(ignore_permissions=True)
""",
)
print(f"generated {len(entries)} doctypes")
