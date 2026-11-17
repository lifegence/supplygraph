# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Import public SBOMs, export them in both formats and import the export again.

What stays and what is lost on the way is fixed here. The values are compared as the importer reads each
file, not as SupplyGraph keeps them: SG Component and SG Component Version are shared by every document,
so the second import would always read back the values of the first one.
"""

import copy
import json
import os
import re
from collections import Counter

import frappe
from frappe.tests import IntegrationTestCase, UnitTestCase

from supplygraph.sg_bom import importer
from supplygraph.sg_bom.export import export_bom
from supplygraph.sg_bom.export.test_export import cyclonedx_errors, spdx_errors
from supplygraph.sg_bom.importer.model import NOASSERTION, Issue, ParsedBom, is_version_constraint

DATA = os.path.join(os.path.dirname(__file__), "test_data")
# File -> format and version in the file. Sources and licenses are in test_data/README.md.
SAMPLES = {
	"cyclonedx-1.4_laravel-7.12.0.cdx.json": ("CycloneDX", "1.4"),
	"cyclonedx-1.5_npm-dev-dependencies.cdx.json": ("CycloneDX", "1.5"),
	"cyclonedx-1.6_npm-bundled-dependencies.cdx.json": ("CycloneDX", "1.6"),
	"spdx-2.3_tools-python-example.spdx.json": ("SPDX", "2.3"),
	"spdx-2.3_tools-python-example.spdx": ("SPDX", "2.3"),
	"spdx-2.3_github-cyclonedx-javascript-library.spdx.json": ("SPDX", "2.3"),
}
MAX_SIZE = 1024 * 1024
# The values of a component that are compared. hashes are the ones the importer keeps (SHA-1 and stronger).
FIELDS = (
	"component_type",
	"cpe",
	"supplier",
	"file_name",
	"download_location",
	"license_declared",
	"license_concluded",
	"copyright_text",
	"scope",
	"external_bom_ref",
	"hashes",
)
LICENSE_FIELDS = ("license_declared", "license_concluded")
# Relationship types written as dependsOn in CycloneDX, which the importer reads back as depends-on
CYCLONEDX_RELATIONSHIPS = {
	"dev-dependency": "depends-on",
	"optional-dependency": "depends-on",
	"provided-by": "depends-on",
}
# Written as pedigree in CycloneDX, which the importer does not read
CYCLONEDX_DROPPED_RELATIONSHIPS = {"generated-from", "variant-of"}
# What the first import does not keep of the samples: (rule_code, message) of its issues
DROPPED_ON_IMPORT = {
	("IMP-HASH", "Skipped unsupported hash MD5"),
	("IMP-HASH", "Skipped unsupported hash BLAKE2B_384"),
}

# What may differ between the first and the second import. Any other difference fails the test.
ALLOWED = """
- Both formats: a missing value and NOASSERTION are the same. SPDX writes NOASSERTION for a missing value;
  CycloneDX leaves NOASSERTION out.
- Both formats: a license expression may lose the parentheses around the whole of it.
- SPDX: a license that is not an SPDX expression becomes a LicenseRef- id. Its text is in
  hasExtractedLicensingInfos, which the importer does not read back.
- SPDX: the scope of a component (required, optional, excluded) is not written; SPDX has no such field.
- CycloneDX: dev-dependency, optional-dependency and provided-by are written as dependsOn and come back as
  depends-on.
- CycloneDX: generated-from and variant-of are written as pedigree, which the importer does not read.
- CycloneDX: contains is written as nesting only where it forms a tree. contains from the primary
  component, and contains of a component that more than one component contains, come back as depends-on.

What the first import already drops is not seen by the comparison. It is listed in DROPPED_ON_IMPORT, and
an import issue that is not listed fails the test.
"""


def no_value(value):
	return None if value == NOASSERTION else value


def without_outer_parentheses(value: str | None) -> str | None:
	"""(MIT AND CC-BY-3.0) -> MIT AND CC-BY-3.0, but not (MIT) AND (BSD-3-Clause)."""
	if not value or not (value.startswith("(") and value.endswith(")")):
		return value
	depth = 0
	for index, character in enumerate(value):
		depth += {"(": 1, ")": -1}.get(character, 0)
		if depth == 0 and index < len(value) - 1:
			return value
	return value[1:-1].strip()


def component_values(component, format: str, licenses: dict[str, str]) -> tuple:
	"""The compared values of a component, with the allowed differences of the format taken out.

	licenses is {LicenseRef- id: text} of the exported SPDX file. A LicenseRef- that SPDX made for a value
	is replaced by the text it was made for, so a LicenseRef- with another text still differs.
	"""
	values = []
	for field in FIELDS:
		value = getattr(component, field)
		if field == "hashes":
			value = tuple(sorted(value))
		else:
			value = no_value(value)
		if field in LICENSE_FIELDS:
			value = without_outer_parentheses(licenses.get(value, value))
		if field == "scope" and format == "SPDX":
			value = None
		values.append(value)
	return tuple(values)


def snapshot(parsed: ParsedBom, format: str, licenses: dict[str, str] | None = None) -> dict:
	"""Components, relationships and values of a parsed SBOM, as the format can carry them."""
	licenses = licenses or {}
	keys = {}
	for component in parsed.components:
		keys.setdefault(component.ref, (component.name, component.version, component.purl))
	containers = Counter(
		to_ref for _from_ref, to_ref, relationship in parsed.relations if relationship == "contains"
	)
	relations = Counter()
	for from_ref, to_ref, relationship in parsed.relations:
		if format == "CycloneDX":
			if relationship in CYCLONEDX_DROPPED_RELATIONSHIPS:
				continue
			relationship = CYCLONEDX_RELATIONSHIPS.get(relationship, relationship)
			if relationship == "contains" and (from_ref == parsed.primary_ref or containers[to_ref] > 1):
				relationship = "depends-on"
		# A ref that no component has is compared as the ref
		relations[(keys.get(from_ref, from_ref), keys.get(to_ref, to_ref), relationship)] += 1
	return {
		"components": Counter(keys[component.ref] for component in parsed.components),
		"relations": relations,
		"values": Counter(
			(keys[component.ref], component_values(component, format, licenses))
			for component in parsed.components
		),
	}


def differences(first: ParsedBom, second: ParsedBom, format: str, licenses: dict[str, str]) -> list[str]:
	"""What the second import lost or changed, other than what ALLOWED lists."""
	expected = snapshot(first, format)
	actual = snapshot(second, format, licenses)
	result = []
	for part in ("components", "relations", "values"):
		lost = expected[part] - actual[part]
		added = actual[part] - expected[part]
		if lost or added:
			result.append(f"{part}: lost {sorted(lost.elements())[:5]}, added {sorted(added.elements())[:5]}")
	return result


def extracted_licenses(content: str, format: str) -> dict[str, str]:
	if format != "SPDX":
		return {}
	return {
		item["licenseId"]: item["extractedText"]
		for item in json.loads(content).get("hasExtractedLicensingInfos", [])
	}


def issues(parsed: ParsedBom) -> set[tuple[str, str]]:
	return {(issue.rule_code, issue.message) for issue in parsed.issues}


def read_sample(name: str) -> bytes:
	with open(os.path.join(DATA, name), "rb") as file:
		return file.read()


class UnitTestRoundTripSamples(UnitTestCase):
	def test_samples_cover_the_issue(self):
		"""CycloneDX 1.4, 1.5 and 1.6, SPDX JSON and tag-value, nested components and version ranges."""
		files = {name for name in os.listdir(DATA) if name != "README.md"}
		self.assertEqual(files, set(SAMPLES))
		with open(os.path.join(DATA, "README.md"), encoding="utf-8") as file:
			readme = file.read()
		versions, nested, ranges = set(), False, False
		for name, (format, version) in SAMPLES.items():
			with self.subTest(name=name):
				content = read_sample(name)
				self.assertLessEqual(len(content), MAX_SIZE)
				self.assertIn(name, readme)
				if format == "CycloneDX":
					data = json.loads(content)
					self.assertEqual(data["specVersion"], version)
					nested = nested or any(c.get("components") for c in data.get("components", []))
				else:
					self.assertIn(f"SPDX-{version}".encode(), content)
				versions.add((format, version, name.endswith(".json")))
				parsed = importer.parse_content(content, name)
				ranges = ranges or any(is_version_constraint(c.version) for c in parsed.components)
		self.assertTrue(
			{
				("CycloneDX", "1.4", True),
				("CycloneDX", "1.5", True),
				("CycloneDX", "1.6", True),
				("SPDX", "2.3", True),
				("SPDX", "2.3", False),
			}
			<= versions
		)
		self.assertTrue(nested)
		self.assertTrue(ranges)


class UnitTestDifferences(UnitTestCase):
	"""A difference that ALLOWED does not list is found."""

	def setUp(self):
		name = "spdx-2.3_tools-python-example.spdx.json"
		self.parsed = importer.parse_content(read_sample(name), name)

	def changed(self, change) -> ParsedBom:
		parsed = copy.deepcopy(self.parsed)
		change(parsed)
		return parsed

	def test_the_same_sbom_has_no_differences(self):
		for format in ("CycloneDX", "SPDX"):
			self.assertEqual(differences(self.parsed, copy.deepcopy(self.parsed), format, {}), [])

	def test_changed_values_are_found(self):
		changes = {
			"supplier": "Another Organization",
			"license_declared": "GPL-3.0-only",
			"license_concluded": None,
			"copyright_text": "(C) Someone Else",
			"file_name": "other.tar.gz",
			"download_location": "https://example.com/other",
			"cpe": "cpe:2.3:a:other:other:1:*:*:*:*:*:*:*",
			"component_type": "firmware",
			"hashes": [],
		}
		for field, value in changes.items():
			with self.subTest(field=field):
				second = self.changed(lambda parsed: setattr(parsed.components[0], field, value))
				self.assertNotEqual(getattr(self.parsed.components[0], field), value)
				for format in ("CycloneDX", "SPDX"):
					self.assertTrue(differences(self.parsed, second, format, {}), format)

	def test_lost_and_changed_components_and_relationships_are_found(self):
		changes = {
			"lost component": lambda parsed: parsed.components.pop(),
			"changed name": lambda parsed: setattr(parsed.components[0], "name", "other"),
			"changed version": lambda parsed: setattr(parsed.components[0], "version", "0.0.0"),
			"lost relationship": lambda parsed: parsed.relations.pop(),
			"changed type": lambda parsed: parsed.relations.append(
				(*parsed.relations.pop()[:2], "generated-from")
			),
		}
		self.assertEqual(len(self.parsed.relations), 1)
		self.assertNotEqual(self.parsed.relations[0][2], "generated-from")
		for label, change in changes.items():
			with self.subTest(change=label):
				second = self.changed(change)
				for format in ("CycloneDX", "SPDX"):
					self.assertTrue(differences(self.parsed, second, format, {}), format)

	def test_allowed_differences(self):
		component = self.parsed.components[0]
		component.license_declared, component.copyright_text = "MIT AND CC-BY-3.0", None
		component.scope = "optional"
		component.license_concluded = "MPLv2.0"
		second = self.changed(lambda parsed: None)
		second.components[0].license_declared = "(MIT AND CC-BY-3.0)"
		second.components[0].copyright_text = NOASSERTION
		second.components[0].scope = None
		second.components[0].license_concluded = "LicenseRef-MPLv2.0"
		self.assertEqual(differences(self.parsed, second, "SPDX", {"LicenseRef-MPLv2.0": "MPLv2.0"}), [])
		# The scope is kept by CycloneDX, and a LicenseRef- is the license only with its text
		self.assertTrue(differences(self.parsed, second, "CycloneDX", {}))
		self.assertTrue(differences(self.parsed, second, "SPDX", {"LicenseRef-MPLv2.0": "MPL-2.0"}))
		second.components[0].scope = "optional"
		second.components[0].license_concluded = "MPLv2.0"
		self.assertEqual(differences(self.parsed, second, "CycloneDX", {}), [])

	def test_relationship_types_that_cyclonedx_cannot_carry(self):
		first = copy.deepcopy(self.parsed)
		from_ref, to_ref, _relationship = first.relations[0]
		second = copy.deepcopy(first)
		first.relations[:] = [(from_ref, to_ref, "dev-dependency"), (from_ref, to_ref, "variant-of")]
		second.relations[:] = [(from_ref, to_ref, "depends-on")]
		self.assertEqual(differences(first, second, "CycloneDX", {}), [])
		self.assertTrue(differences(first, second, "SPDX", {}))

	def test_what_the_first_import_drops_is_listed(self):
		self.assertEqual(issues(self.parsed), DROPPED_ON_IMPORT)
		parsed = self.changed(lambda parsed: None)
		parsed.issues.append(Issue("IMP-HASH", "Skipped unsupported hash SHA-999"))
		self.assertFalse(issues(parsed) <= DROPPED_ON_IMPORT)

	def test_parentheses_are_taken_only_around_the_whole_expression(self):
		self.assertEqual(without_outer_parentheses("(MIT AND CC-BY-3.0)"), "MIT AND CC-BY-3.0")
		self.assertEqual(without_outer_parentheses("(MIT) AND (BSD-3-Clause)"), "(MIT) AND (BSD-3-Clause)")
		self.assertEqual(without_outer_parentheses("MIT"), "MIT")
		self.assertIsNone(without_outer_parentheses(None))


class IntegrationTestRoundTrip(IntegrationTestCase):
	def setUp(self):
		self.files = []

	def tearDown(self):
		# Files are written to disk, which a rollback does not undo
		for file_name in self.files:
			frappe.delete_doc("File", file_name, force=True, ignore_permissions=True, delete_permanently=True)
		frappe.db.rollback()

	def import_file(self, content: bytes, file_name: str) -> str:
		file_doc = frappe.get_doc(
			{"doctype": "File", "file_name": file_name, "is_private": 1, "content": content}
		).insert(ignore_permissions=True)
		self.files.append(file_doc.name)
		return importer.import_content(content, file_name, "SBOM", None, file_doc.file_url)

	def round_trip(self, name: str) -> None:
		self.round_trip_content(read_sample(name), name)

	def round_trip_content(self, content: bytes, name: str) -> None:
		first = importer.parse_content(content, name)
		self.assertLessEqual(issues(first), DROPPED_ON_IMPORT)
		document = self.import_file(content, name)
		entries = frappe.db.count("SG BOM Entry", {"bom_document": document})
		self.assertEqual(entries, len(first.components))
		self.assertGreater(entries, 0)
		for format in ("CycloneDX", "SPDX"):
			with self.subTest(format=format):
				# force: a public SBOM need not pass the validation; this checks the export, not the SBOM
				result = export_bom(document, format, force=True)
				data = json.loads(result["content"])
				if format == "CycloneDX":
					self.assertEqual(data["specVersion"], "1.6")
					self.assertEqual(cyclonedx_errors(data), [])
				else:
					self.assertEqual(data["spdxVersion"], "SPDX-2.3")
					self.assertEqual(spdx_errors(data), [])
				exported = result["content"].encode()
				second = importer.parse_content(exported, result["filename"])
				self.assertEqual(
					differences(first, second, format, extracted_licenses(result["content"], format)),
					[],
					ALLOWED,
				)
				self.assertLessEqual(issues(second), DROPPED_ON_IMPORT)
				again = self.import_file(exported, result["filename"])
				self.assertEqual(frappe.db.count("SG BOM Entry", {"bom_document": again}), entries)

	def test_cyclonedx_1_4(self):
		self.round_trip("cyclonedx-1.4_laravel-7.12.0.cdx.json")

	def test_cyclonedx_1_5_with_optional_components(self):
		self.round_trip("cyclonedx-1.5_npm-dev-dependencies.cdx.json")

	def test_cyclonedx_1_6_with_nested_components(self):
		self.round_trip("cyclonedx-1.6_npm-bundled-dependencies.cdx.json")

	def test_spdx_json(self):
		self.round_trip("spdx-2.3_tools-python-example.spdx.json")

	def test_spdx_tag_value(self):
		self.round_trip("spdx-2.3_tools-python-example.spdx")

	def test_spdx_from_github_with_version_ranges(self):
		self.round_trip("spdx-2.3_github-cyclonedx-javascript-library.spdx.json")

	def test_relationship_types_and_their_direction(self):
		"""None of the public SBOMs has these, so a small SPDX file is made for them."""

		def package(name: str) -> dict:
			return {
				"SPDXID": f"SPDXRef-{name}",
				"name": f"rel-{name}",
				"versionInfo": "1.0.0",
				"downloadLocation": "NOASSERTION",
				"filesAnalyzed": False,
			}

		def relationship(element: str, kind: str, related: str) -> dict:
			return {
				"spdxElementId": f"SPDXRef-{element}",
				"relationshipType": kind,
				"relatedSpdxElement": f"SPDXRef-{related}",
			}

		data = {
			"spdxVersion": "SPDX-2.3",
			"dataLicense": "CC0-1.0",
			"SPDXID": "SPDXRef-DOCUMENT",
			"name": "relationships",
			"documentNamespace": f"https://example.com/spdx/relationships-{frappe.generate_hash(length=8)}",
			"creationInfo": {"created": "2026-11-01T00:00:00Z", "creators": ["Tool: test"]},
			"packages": [
				package(name) for name in ("app", "dev", "opt", "prov", "src", "var", "lib", "sub", "shared")
			],
			"relationships": [
				relationship("DOCUMENT", "DESCRIBES", "app"),
				relationship("dev", "DEV_DEPENDENCY_OF", "app"),
				relationship("opt", "OPTIONAL_DEPENDENCY_OF", "app"),
				relationship("prov", "PROVIDED_DEPENDENCY_OF", "app"),
				relationship("app", "GENERATED_FROM", "src"),
				relationship("var", "VARIANT_OF", "app"),
				# The primary component's part, a part of a part (a tree), and a part of two components
				relationship("app", "CONTAINS", "lib"),
				relationship("lib", "CONTAINS", "sub"),
				relationship("lib", "CONTAINS", "shared"),
				relationship("sub", "CONTAINS", "shared"),
			],
		}
		content = json.dumps(data).encode()
		first = importer.parse_content(content, "relationships.spdx.json")
		# The direction: "dev DEV_DEPENDENCY_OF app" is app -> dev
		self.assertIn(("SPDXRef-app", "SPDXRef-dev", "dev-dependency"), first.relations)
		self.assertIn(("SPDXRef-app", "SPDXRef-src", "generated-from"), first.relations)
		self.round_trip_content(content, "relationships.spdx.json")
		document = frappe.get_all(
			"SG BOM Document", filters={"serial_number": data["documentNamespace"]}, pluck="name"
		)[0]
		exported = json.loads(export_bom(document, "CycloneDX", force=True)["content"])
		depends_on = {item["ref"]: set(item.get("dependsOn", [])) for item in exported["dependencies"]}
		app, dev = (
			next(c["bom-ref"] for c in walk_components(exported) if c["name"] == f"rel-{name}")
			for name in ("app", "dev")
		)
		self.assertIn(dev, depends_on[app])
		# The importer does not read pedigree, so the round trip cannot see it; the export writes it
		primary = exported["metadata"]["component"]
		self.assertEqual([item["name"] for item in primary["pedigree"]["ancestors"]], ["rel-src"])
		# "var VARIANT_OF app": var -> app, written on var
		variant = next(c for c in walk_components(exported) if c["name"] == "rel-var")
		self.assertEqual([item["name"] for item in variant["pedigree"]["variants"]], ["rel-app"])


def walk_components(data: dict):
	stack = [data["metadata"]["component"], *data.get("components", [])]
	while stack:
		component = stack.pop()
		yield component
		stack.extend(component.get("components", []))
