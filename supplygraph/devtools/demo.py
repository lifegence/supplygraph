# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

"""Demo data for the MVP main path, with no network access: a fictional maker, its vehicles and SBOMs.

	bench --site supplygraph.localhost execute supplygraph.devtools.demo.load
	bench --site supplygraph.localhost execute supplygraph.devtools.demo.purge

The story and the expected results are in docs/demo/DemoScenario.md. SBOM files go through the real
importer, and the vulnerabilities through the same functions as the OSV sync. The vulnerability records
are public OSV records cut down by hand; the next real sync updates them.

Records are found by the DEMO prefix. Components, versions and vulnerabilities carry real names, so
purge() keeps those that other data still uses.

Both run only on a site with ``developer_mode`` or ``allow_tests`` enabled, never on production.
"""

import json

import frappe
from frappe import _

from supplygraph.sg_bom.flatten import rebuild_release
from supplygraph.sg_bom.importer import import_file
from supplygraph.sg_bom.validation import validate_bom
from supplygraph.sg_vulnerability.matching import create_exact_matches, create_range_matches, find_names
from supplygraph.sg_vulnerability.osv import store_vulnerability

PREFIX = "DEMO"
MAKER = "DEMO Motors"
TIER1 = "DEMO Tier1 Electronics"
CATEGORY = "DEMO Vehicle"
SEDAN = "DEMO-SEDAN"
SUV = "DEMO-SUV"
IVI = "DEMO-IVI-100"
TCU = "DEMO-TCU-200"
BCM = "DEMO-BCM-300"
LOG4J_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core"
VULNERABLE_LOG4J = f"{LOG4J_PURL}@2.14.1"
CVSS_LOG4SHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS_INCOMPLETE_FIX = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
LOG4SHELL = "CVE-2021-44228"
INCOMPLETE_FIX = "CVE-2021-45046"


def _log4j_affected(*ranges: tuple[str, str]) -> list[dict]:
	events = [event for lower, fixed in ranges for event in ({"introduced": lower}, {"fixed": fixed})]
	return [
		{
			"package": {
				"name": "org.apache.logging.log4j:log4j-core",
				"ecosystem": "Maven",
				"purl": LOG4J_PURL,
			},
			"ranges": [{"type": "ECOSYSTEM", "events": events}],
		}
	]


OSV_RECORDS = [
	{
		"id": "GHSA-jfh8-c2jp-5v3q",
		"aliases": [LOG4SHELL],
		"summary": "Remote code injection in Log4j",
		"modified": "2026-01-01T00:00:00Z",
		"published": "2021-12-10T00:40:56Z",
		"database_specific": {"severity": "CRITICAL"},
		"severity": [{"type": "CVSS_V3", "score": CVSS_LOG4SHELL}],
		"affected": _log4j_affected(("2.13.0", "2.15.0"), ("2.4", "2.12.2"), ("2.0-beta9", "2.3.1")),
	},
	{
		"id": "GHSA-7rjr-3q55-vv33",
		"aliases": [INCOMPLETE_FIX],
		"summary": "Incomplete fix for Apache Log4j vulnerability",
		"modified": "2026-01-01T00:00:00Z",
		"published": "2021-12-14T18:01:28Z",
		"database_specific": {"severity": "CRITICAL"},
		"severity": [{"type": "CVSS_V3", "score": CVSS_INCOMPLETE_FIX}],
		"affected": _log4j_affected(("2.13.0", "2.16.0"), ("2.0-beta9", "2.12.2")),
	},
]

# (release code, version, unit type, SBOM format, components as (name, version, purl))
RELEASES = [
	(
		"DEMO-IVI-FW",
		"1.0",
		IVI,
		"CycloneDX",
		[
			("log4j-core", "2.14.1", VULNERABLE_LOG4J),
			("zlib", "1.3.1", "pkg:generic/zlib@1.3.1"),
			("demo-media-player", "4.2.0", "pkg:generic/demo-media-player@4.2.0"),
		],
	),
	(
		"DEMO-IVI-FW",
		"1.1",
		IVI,
		"CycloneDX",
		[
			("log4j-core", "2.17.1", f"{LOG4J_PURL}@2.17.1"),
			("zlib", "1.3.1", "pkg:generic/zlib@1.3.1"),
			("demo-media-player", "4.3.0", "pkg:generic/demo-media-player@4.3.0"),
		],
	),
	# Delivered by the Tier 1 supplier, not installed in any vehicle yet
	(
		"DEMO-IVI-NEXT",
		"2.0-rc1",
		IVI,
		"CycloneDX",
		[("log4j-core", "2.14.1", VULNERABLE_LOG4J), ("zlib", "1.3.1", "pkg:generic/zlib@1.3.1")],
	),
	# Has the vulnerable library, but assessed as Not Affected
	("DEMO-TCU-FW", "3.2", TCU, "SPDX", [("log4j-core", "2.14.1", VULNERABLE_LOG4J)]),
	# The same library under another name and without a PURL: goes to the merge review queue
	("DEMO-BCM-FW", "1.0", BCM, "CycloneDX", [("ZLIB", "1.3.1", None)]),
]

# Serial numbers keep the VIN alphabet (no I, O or Q), so they start with DEM and not DEMO
# (model, count of units on IVI 1.0, count of units on IVI 1.1)
FLEET = [(SEDAN, 12, 8), (SUV, 10, 0)]


def load() -> dict:
	"""Create the demo data. Purge first to load it again."""
	_check_site()
	if exists():
		frappe.throw(_("Demo data is already loaded. Run supplygraph.devtools.demo.purge first."))
	_create_masters()
	releases = {
		(code, version): _create_release(code, version, unit) for code, version, unit, _f, _c in RELEASES
	}
	for code, version, _unit, sbom_format, components in RELEASES:
		_import_sbom(releases[code, version], code, version, sbom_format, components)
	# flatten.py enqueues the rebuild; do it here too, so the data is ready without a worker
	for release in releases.values():
		rebuild_release(release)
	matches = _store_vulnerabilities()
	_assess(releases["DEMO-TCU-FW", "3.2"])
	units = _create_units(releases)
	return {"status": "loaded", "releases": len(releases), "units": units, **matches}


def purge() -> dict:
	"""Remove the demo data and keep whatever other data still uses."""
	_check_site()
	releases = frappe.get_all("SG Release", {"release_code": ["like", f"{PREFIX}-%"]}, pluck="name")
	# "in" with an empty list would also match the documents without a release
	documents = (
		frappe.get_all("SG BOM Document", {"subject_release": ["in", releases]}, ["name", "source_file"])
		if releases
		else []
	)
	names = [row.name for row in documents]
	versions = set(frappe.get_all("SG BOM Entry", {"bom_document": ["in", names]}, pluck="component_version"))
	models = frappe.get_all("SG Product Model", {"model_code": ["like", f"{PREFIX}-%"]}, pluck="name")
	units = frappe.get_all("SG Product Unit", {"product_model": ["in", models]}, pluck="name")

	frappe.db.delete("SG Impact Assessment", {"release": ["in", releases]})
	frappe.db.delete("SG Release Component", {"release": ["in", releases]})
	frappe.db.delete("SG Installed Release", {"parent": ["in", units]})
	frappe.db.delete("SG Product Unit", {"name": ["in", units]})
	frappe.db.delete("SG Dependency", {"bom_document": ["in", names]})
	frappe.db.delete("SG BOM Entry", {"bom_document": ["in", names]})
	frappe.db.delete("SG BOM Validation Result", {"parent": ["in", names], "parenttype": "SG BOM Document"})
	frappe.db.delete("SG BOM Document", {"name": ["in", names]})
	for row in documents:
		for file_name in frappe.get_all("File", {"file_url": row.source_file}, pluck="name"):
			frappe.delete_doc("File", file_name, force=True, ignore_permissions=True)

	_delete_unused_catalog(versions)
	_delete_unused_vulnerabilities()
	for release in releases:
		_delete("SG Release", release)
	for model in models:
		_delete("SG Product Model", model)
	for doctype, field in (
		("SG Unit Type", "unit_part_number"),
		("SG Product Category", "category_name"),
		("SG Organization", "organization_name"),
	):
		for name in frappe.get_all(doctype, {field: ["like", f"{PREFIX}%"]}, pluck="name"):
			_delete(doctype, name)
	return {"status": "purged", "releases": len(releases), "units": len(units)}


def exists() -> bool:
	return bool(frappe.db.exists("SG Product Model", SEDAN))


def _check_site() -> None:
	if not (frappe.conf.developer_mode or frappe.conf.allow_tests):
		frappe.throw(
			_("Demo data can be loaded or removed only on a site with developer_mode or allow_tests")
		)


def _delete(doctype: str, name: str) -> None:
	frappe.delete_doc(doctype, name, force=True, ignore_permissions=True)


def _create_masters() -> None:
	frappe.get_doc(
		{"doctype": "SG Organization", "organization_name": MAKER, "organization_type": "Manufacturer"}
	).insert()
	frappe.get_doc(
		{
			"doctype": "SG Organization",
			"organization_name": TIER1,
			"organization_type": "Supplier",
			"tier": "Tier 1",
		}
	).insert()
	frappe.get_doc(
		{
			"doctype": "SG Product Category",
			"category_name": CATEGORY,
			"unit_label": "VIN",
			"serial_pattern": "^[0-9A-HJ-NPR-Z]{17}$",
		}
	).insert()
	for code, name in ((SEDAN, "Demo Sedan"), (SUV, "Demo SUV")):
		frappe.get_doc(
			{
				"doctype": "SG Product Model",
				"model_code": code,
				"model_name": name,
				"product_category": CATEGORY,
				"manufacturer": MAKER,
				"lifecycle_status": "In Production",
			}
		).insert()
	for number, name, connectivity in (
		(IVI, "In-vehicle infotainment", "Cellular or Internet"),
		(TCU, "Telematics control unit", "Cellular or Internet"),
		(BCM, "Body control module", "Internal Bus"),
	):
		frappe.get_doc(
			{
				"doctype": "SG Unit Type",
				"unit_part_number": number,
				"unit_name": name,
				"supplier": TIER1,
				"external_connectivity": connectivity,
			}
		).insert()


def _create_release(code: str, version: str, unit_type: str) -> str:
	return (
		frappe.get_doc(
			{
				"doctype": "SG Release",
				"release_code": code,
				"version": version,
				"release_type": "Firmware",
				"unit_type": unit_type,
				"release_status": "Released",
			}
		)
		.insert()
		.name
	)


def _import_sbom(release: str, code: str, version: str, sbom_format: str, components: list[tuple]) -> None:
	if sbom_format == "SPDX":
		file_name, content = f"{code}-{version}.spdx.json", _spdx(code, version, components)
	else:
		file_name, content = f"{code}-{version}.cdx.json", _cyclonedx(code, version, components)
	file_doc = frappe.get_doc(
		{"doctype": "File", "file_name": file_name, "content": content, "is_private": 1}
	).insert(ignore_permissions=True)
	name = import_file(file_doc.file_url, "SBOM", release)
	validate_bom(name)
	frappe.get_doc("SG BOM Document", name).submit()


def _cyclonedx(code: str, version: str, components: list[tuple]) -> bytes:
	root = code.lower()
	refs = [f"{name}@{component_version}" for name, component_version, _purl in components]
	return json.dumps(
		{
			"bomFormat": "CycloneDX",
			"specVersion": "1.6",
			"version": 1,
			"metadata": {
				"timestamp": "2026-11-01T00:00:00Z",
				"lifecycles": [{"phase": "build"}],
				"authors": [{"name": TIER1}],
				"supplier": {"name": TIER1},
				"component": {"type": "firmware", "bom-ref": root, "name": root, "version": version},
			},
			"components": [
				{
					"type": "library",
					"bom-ref": ref,
					"name": name,
					"version": component_version,
					**({"purl": purl} if purl else {}),
				}
				for ref, (name, component_version, purl) in zip(refs, components, strict=True)
			],
			"dependencies": [{"ref": root, "dependsOn": refs}],
		},
		indent=1,
	).encode()


def _spdx(code: str, version: str, components: list[tuple]) -> bytes:
	root = {
		"name": code.lower(),
		"SPDXID": "SPDXRef-Root",
		"versionInfo": version,
		"downloadLocation": "NOASSERTION",
		"primaryPackagePurpose": "FIRMWARE",
	}
	packages = [
		{
			"name": name,
			"SPDXID": f"SPDXRef-Package-{index}",
			"versionInfo": component_version,
			"downloadLocation": "NOASSERTION",
			"externalRefs": [
				{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}
			],
		}
		for index, (name, component_version, purl) in enumerate(components)
	]
	return json.dumps(
		{
			"spdxVersion": "SPDX-2.3",
			"dataLicense": "CC0-1.0",
			"SPDXID": "SPDXRef-DOCUMENT",
			"name": code.lower(),
			"documentNamespace": f"https://example.com/sbom/{code.lower()}-{version}",
			"creationInfo": {
				"created": "2026-11-01T00:00:00Z",
				"creators": [f"Organization: {TIER1}", "Tool: demo-1.0"],
			},
			"packages": [root, *packages],
			"relationships": [
				{
					"spdxElementId": "SPDXRef-DOCUMENT",
					"relationshipType": "DESCRIBES",
					"relatedSpdxElement": "SPDXRef-Root",
				},
				*(
					{
						"spdxElementId": "SPDXRef-Root",
						"relationshipType": "DEPENDS_ON",
						"relatedSpdxElement": package["SPDXID"],
					}
					for package in packages
				),
			],
		},
		indent=1,
	).encode()


def _store_vulnerabilities() -> dict:
	# The same steps as osv.sync_osv, with the answer of OSV for the vulnerable PURL written down
	for record in OSV_RECORDS:
		store_vulnerability(record)
	found = {VULNERABLE_LOG4J: [{"id": record["id"]} for record in OSV_RECORDS]}
	exact = create_exact_matches(found)
	ranges = create_range_matches(find_names([record["id"] for record in OSV_RECORDS]))
	return {"vulnerabilities": len(OSV_RECORDS), "exact_matches": exact, "range_matches": ranges["created"]}


def _assess(release: str) -> None:
	for cve in (LOG4SHELL, INCOMPLETE_FIX):
		document = frappe.get_doc(
			{
				"doctype": "SG Impact Assessment",
				"vulnerability": cve,
				"release": release,
				"vex_status": "Not Affected",
				"justification": "vulnerable_code_not_in_execute_path",
				"impact_statement": "The firmware does not log data received from outside.",
			}
		)
		document.insert()
		document.submit()


def _create_units(releases: dict) -> int:
	old, new = releases["DEMO-IVI-FW", "1.0"], releases["DEMO-IVI-FW", "1.1"]
	number = 0
	for model, on_old, on_new in FLEET:
		for ivi_release in [old] * on_old + [new] * on_new:
			number += 1
			frappe.get_doc(
				{
					"doctype": "SG Product Unit",
					"serial_no": f"DEM{number:014d}",
					"product_model": model,
					"unit_status": "In Service",
					"installed_releases": [
						{"unit_type": IVI, "slot_name": "IVI", "release": ivi_release},
						{"unit_type": TCU, "slot_name": "TCU", "release": releases["DEMO-TCU-FW", "3.2"]},
						{"unit_type": BCM, "slot_name": "BCM", "release": releases["DEMO-BCM-FW", "1.0"]},
					],
				}
			).insert()
	return number


def _delete_unused_catalog(versions: set[str]) -> None:
	components = set()
	for version in versions:
		if frappe.db.exists("SG BOM Entry", {"component_version": version}) or frappe.db.exists(
			"SG Release Component", {"component_version": version}
		):
			continue
		components.add(frappe.db.get_value("SG Component Version", version, "component"))
		frappe.db.delete("SG Vulnerability Match", {"component_version": version})
		_delete("SG Component Version", version)
	for component in components:
		if not frappe.db.exists("SG Component Version", {"component": component}):
			_delete("SG Component", component)


def _delete_unused_vulnerabilities() -> None:
	for cve in (LOG4SHELL, INCOMPLETE_FIX):
		if frappe.db.exists("SG Vulnerability", cve) and not frappe.db.exists(
			"SG Vulnerability Match", {"vulnerability": cve}
		):
			_delete("SG Vulnerability", cve)
