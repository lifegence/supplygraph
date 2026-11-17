# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import copy
import hashlib
import json
import os
import random
from datetime import datetime

import frappe
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from frappe.tests import IntegrationTestCase, UnitTestCase
from jsonschema import Draft7Validator
from spdx_tools.spdx.model import RelationshipType
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from supplygraph.sg_bom import importer
from supplygraph.sg_bom.export import SbomHasErrorsError, _primary_ref, export_bom, load_bom, write_bom
from supplygraph.sg_bom.export.cyclonedx import LIFECYCLES, build_cyclonedx, is_iri_reference
from supplygraph.sg_bom.export.model import (
	ExportBom,
	ExportComponent,
	ExternalBom,
	cyclonedx_serial,
	spdx_namespace,
)
from supplygraph.sg_bom.export.spdx import build_spdx
from supplygraph.sg_bom.importer.cyclonedx import parse_cyclonedx
from supplygraph.sg_bom.importer.spdx import spdx_temp_file

APP = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DATA = os.path.join(APP, "sg_bom", "importer", "test_data")
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
CHILD_SERIAL = "urn:uuid:11111111-2222-3333-4444-555555555555"


def read_bytes(name: str) -> bytes:
	with open(os.path.join(DATA, name), "rb") as file:
		return file.read()


def cyclonedx_errors(data: dict) -> list[str]:
	errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(data), all_errors=True)
	return [str(error) for error in errors or []]


def parse_spdx(data: dict):
	with spdx_temp_file(json.dumps(data).encode(), ".spdx.json") as path:
		return parse_file(path)


def spdx_errors(data: dict) -> list[str]:
	return [
		message.validation_message for message in validate_full_spdx_document(parse_spdx(data), "SPDX-2.3")
	]


def full_bom() -> ExportBom:
	"""Every one of the 16 Framework fields has a value."""
	return ExportBom(
		name="SGB-2026-00001",
		format="CycloneDX",
		serial_number="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		bom_version=2,
		lifecycle_phase="Build",
		author_name="T Company, Ltd.",
		author_org=None,
		supplier="T Company",
		timestamp=datetime(2026, 11, 1, 5, 55, 55),
		primary_ref="app",
		components=[
			ExportComponent(
				ref="app",
				name="T-Sample",
				version="1.0.0",
				component_type="application",
				purl="pkg:generic/t-sample@1.0.0",
				supplier="T Company",
				file_name="T-Sample.exe",
				download_location="https://example.com/t.exe",
				license_declared="LicenseRef-T-Proprietary",
				license_concluded="NOASSERTION",
				copyright_text="(C) 2026 T Company",
				hashes=[("SHA-256", SHA256)],
			),
			ExportComponent(
				ref="lib-a",
				name="a-lib",
				version="1.2.3",
				purl="pkg:pypi/a-lib@1.2.3",
				cpe="cpe:2.3:a:a_project:a-lib:1.2.3:*:*:*:*:*:*:*",
				supplier="A Project",
				file_name="a_lib.whl",
				download_location="https://example.com/a.whl",
				license_declared="MIT",
				license_concluded="Apache-2.0",
				copyright_text="(C) A Project",
				hashes=[("SHA-256", SHA256), ("SHA-1", SHA1)],
				scope="required",
			),
			ExportComponent(
				ref="fw-b",
				name="b-firmware",
				version="3.0",
				component_type="firmware",
				purl="pkg:generic/b-firmware@3.0",
				supplier="B Company",
				file_name="b.iso",
				download_location="NONE",
				license_declared="MIT OR GPL-2.0-only",
				license_concluded="MIT",
				copyright_text="NOASSERTION",
				external_bom=ExternalBom(
					uri=f"urn:cdx:{CHILD_SERIAL.removeprefix('urn:uuid:')}/1", checksum=("SHA-256", SHA256)
				),
			),
		],
		relations=[("app", "lib-a", "depends-on"), ("app", "fw-b", "contains")],
		tool_version="0.0.1",
		site_url="https://sbom.example.com",
	)


def component(data: dict, ref: str) -> dict:
	"""A CycloneDX component by bom-ref, in metadata, the top level or nested."""
	stack = [data["metadata"]["component"], *data.get("components", [])]
	while stack:
		item = stack.pop()
		if item.get("bom-ref") == ref:
			return item
		stack.extend(item.get("components", []))
	raise KeyError(ref)


def package(data: dict, spdx_id: str) -> dict:
	return next(item for item in data["packages"] if item["SPDXID"] == spdx_id)


def relationships(data: dict) -> set[tuple[str, str, str]]:
	return {
		(item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"])
		for item in data["relationships"]
	}


class UnitTestCycloneDX(UnitTestCase):
	def test_output_passes_the_strict_schema(self):
		data, warnings = build_cyclonedx(full_bom())
		self.assertEqual(cyclonedx_errors(data), [])
		self.assertEqual(warnings, [])
		self.assertEqual(data["specVersion"], "1.6")

	def test_every_framework_field_is_written(self):
		data, _warnings = build_cyclonedx(full_bom())
		metadata = data["metadata"]
		self.assertEqual(metadata["authors"], [{"name": "T Company, Ltd."}])  # Author Name
		self.assertEqual(metadata["timestamp"], "2026-11-01T05:55:55Z")  # Timestamp
		self.assertEqual(metadata["lifecycles"], [{"phase": "build"}])  # SBOM Type
		self.assertEqual(metadata["component"]["bom-ref"], "app")  # Primary Component
		self.assertEqual(metadata["supplier"], {"name": "T Company"})
		lib = component(data, "lib-a")
		self.assertEqual(lib["name"], "a-lib")  # Name
		self.assertEqual(lib["version"], "1.2.3")  # Version
		self.assertEqual(lib["supplier"], {"name": "A Project"})  # Supplier
		self.assertIn({"ref": "app", "dependsOn": ["lib-a", "fw-b"]}, data["dependencies"])  # Relationship
		self.assertEqual(lib["purl"], "pkg:pypi/a-lib@1.2.3")  # Unique Identifier
		self.assertEqual(lib["cpe"], "cpe:2.3:a:a_project:a-lib:1.2.3:*:*:*:*:*:*:*")
		self.assertEqual(data["serialNumber"], "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79")
		self.assertEqual(  # File Name
			lib["evidence"]["identity"][0]["methods"][0],
			{"technique": "filename", "confidence": 1, "value": "a_lib.whl"},
		)
		self.assertIn({"type": "distribution", "url": "https://example.com/a.whl"}, lib["externalReferences"])
		self.assertEqual(  # Declared and Concluded License
			lib["licenses"],
			[
				{"license": {"id": "MIT", "acknowledgement": "declared"}},
				{"license": {"id": "Apache-2.0", "acknowledgement": "concluded"}},
			],
		)
		self.assertEqual(lib["hashes"][0], {"alg": "SHA-256", "content": SHA256})  # Hash
		self.assertEqual(lib["copyright"], "(C) A Project")  # Copyright
		self.assertIn(  # External Document References
			{
				"type": "bom",
				"url": "urn:cdx:11111111-2222-3333-4444-555555555555/1",
				"hashes": [{"alg": "SHA-256", "content": SHA256}],
			},
			component(data, "fw-b")["externalReferences"],
		)

	def test_output_is_read_back_by_the_importer(self):
		data, _warnings = build_cyclonedx(full_bom())
		parsed = parse_cyclonedx(data)
		self.assertEqual(parsed.lifecycle_phase, "Build")
		self.assertEqual(parsed.author_name, "T Company, Ltd.")
		self.assertEqual(parsed.primary_ref, "app")
		self.assertEqual(len(parsed.components), 3)
		lib = next(c for c in parsed.components if c.ref == "lib-a")
		self.assertEqual((lib.license_declared, lib.license_concluded), ("MIT", "Apache-2.0"))
		self.assertEqual((lib.file_name, lib.download_location), ("a_lib.whl", "https://example.com/a.whl"))
		firmware = next(c for c in parsed.components if c.ref == "fw-b")
		self.assertEqual(firmware.external_bom_ref, "urn:cdx:11111111-2222-3333-4444-555555555555/1")
		self.assertEqual(
			set(parsed.relations), {("app", "lib-a", "depends-on"), ("app", "fw-b", "depends-on")}
		)

	def test_missing_values_are_left_out(self):
		bom = full_bom()
		bom.components.append(ExportComponent(ref="bare", name="bare", version="NOASSERTION"))
		bom.relations.append(("app", "bare", "depends-on"))
		data, _warnings = build_cyclonedx(bom)
		self.assertEqual(component(data, "bare"), {"type": "library", "bom-ref": "bare", "name": "bare"})
		firmware = component(data, "fw-b")
		# A copyright stated as NOASSERTION stays stated; a missing one is left out (bare above)
		self.assertEqual(firmware["copyright"], "NOASSERTION")
		self.assertEqual([ref["type"] for ref in firmware["externalReferences"]], ["bom"])
		self.assertEqual(cyclonedx_errors(data), [])

	def test_copyright_stated_as_unknown_or_none_is_kept(self):
		"""An SPDX copyright of NOASSERTION or NONE is still stated after a CycloneDX export."""
		for stored, written in (("NOASSERTION", "NOASSERTION"), ("NONE", "NONE"), (" (C) X ", "(C) X")):
			with self.subTest(stored=stored):
				bom = full_bom()
				bom.components.append(ExportComponent(ref="c", name="c", version="1", copyright_text=stored))
				bom.relations.append(("app", "c", "depends-on"))
				data, _warnings = build_cyclonedx(bom)
				self.assertEqual(component(data, "c")["copyright"], written)
				self.assertEqual(cyclonedx_errors(data), [])
				# The importer reads it back as it was stated
				parsed = parse_cyclonedx(data)
				self.assertEqual(next(c for c in parsed.components if c.ref == "c").copyright_text, written)
		for stored in (None, "", "  "):
			with self.subTest(stored=stored):
				bom = full_bom()
				bom.components.append(ExportComponent(ref="c", name="c", version="1", copyright_text=stored))
				bom.relations.append(("app", "c", "depends-on"))
				self.assertNotIn("copyright", component(build_cyclonedx(bom)[0], "c"))

	def test_relationships(self):
		bom = full_bom()
		for ref in ("c", "d", "e", "f", "g", "h"):
			bom.components.append(ExportComponent(ref=ref, name=ref, version="1"))
		bom.relations = [
			("app", "lib-a", "depends-on"),
			("lib-a", "c", "contains"),
			("lib-a", "d", "dev-dependency"),
			("lib-a", "e", "optional-dependency"),
			("lib-a", "f", "provided-by"),
			("fw-b", "g", "generated-from"),
			("fw-b", "h", "variant-of"),
		]
		data, _warnings = build_cyclonedx(bom)
		self.assertEqual(cyclonedx_errors(data), [])
		# contains in a tree is a nested component, and is not repeated in dependencies
		lib = component(data, "lib-a")
		self.assertEqual([item["bom-ref"] for item in lib["components"]], ["c"])
		self.assertNotIn("c", [item["bom-ref"] for item in data["components"]])
		dependencies = {item["ref"]: item.get("dependsOn", []) for item in data["dependencies"]}
		self.assertEqual(dependencies["lib-a"], ["d", "e", "f"])
		self.assertEqual(dependencies["app"], ["lib-a"])
		firmware = component(data, "fw-b")
		self.assertEqual([item["name"] for item in firmware["pedigree"]["ancestors"]], ["g"])
		self.assertEqual([item["name"] for item in firmware["pedigree"]["variants"]], ["h"])
		# bom-ref stays unique: the copies in pedigree have none
		self.assertNotIn("bom-ref", firmware["pedigree"]["ancestors"][0])
		self.assertEqual(dependencies["fw-b"], [])

	def test_contains_that_is_not_a_tree_stays_in_dependencies(self):
		bom = full_bom()
		bom.components += [ExportComponent(ref=ref, name=ref, version="1") for ref in ("x", "y", "z")]
		bom.relations = [
			# z has two parents; x and y contain each other
			("lib-a", "z", "contains"),
			("fw-b", "z", "contains"),
			("x", "y", "contains"),
			("y", "x", "contains"),
			# the primary component keeps its parts at the top level
			("app", "lib-a", "contains"),
		]
		data, _warnings = build_cyclonedx(bom)
		self.assertEqual(cyclonedx_errors(data), [])
		self.assertEqual({item["bom-ref"] for item in data["components"]}, {"lib-a", "fw-b", "x", "y", "z"})
		dependencies = {item["ref"]: item.get("dependsOn", []) for item in data["dependencies"]}
		self.assertEqual(
			(dependencies["lib-a"], dependencies["fw-b"], dependencies["x"], dependencies["y"]),
			(["z"], ["z"], ["y"], ["x"]),
		)
		self.assertEqual(dependencies["app"], ["lib-a"])

	def test_licenses(self):
		cases = [
			# (declared, concluded, licenses)
			("MIT", None, [{"license": {"id": "MIT", "acknowledgement": "declared"}}]),
			("mit", None, [{"license": {"id": "MIT", "acknowledgement": "declared"}}]),
			("MIT OR Apache-2.0", None, [{"expression": "MIT OR Apache-2.0", "acknowledgement": "declared"}]),
			# Expressions are normalized, as in the SPDX export
			("mit or apache-2.0", None, [{"expression": "MIT OR Apache-2.0", "acknowledgement": "declared"}]),
			(
				"mit or apache-2.0",
				"mit",
				[
					{"license": {"name": "MIT OR Apache-2.0", "acknowledgement": "declared"}},
					{"license": {"id": "MIT", "acknowledgement": "concluded"}},
				],
			),
			(
				None,
				"GPL-2.0-only WITH Classpath-exception-2.0",
				[{"expression": "GPL-2.0-only WITH Classpath-exception-2.0", "acknowledgement": "concluded"}],
			),
			(
				"GPL-2.0-only or commercial license",
				None,
				[{"license": {"name": "GPL-2.0-only or commercial license", "acknowledgement": "declared"}}],
			),
			# CycloneDX takes one expression or a list of licenses: with two, the expression is a name
			(
				"MIT OR Apache-2.0",
				"MIT",
				[
					{"license": {"name": "MIT OR Apache-2.0", "acknowledgement": "declared"}},
					{"license": {"id": "MIT", "acknowledgement": "concluded"}},
				],
			),
			("NONE", "NOASSERTION", None),
			(
				"MIT OR LicenseRef-foo",
				None,
				[{"expression": "MIT OR LicenseRef-foo", "acknowledgement": "declared"}],
			),
			(
				"LicenseRef-foo",
				None,
				[{"license": {"name": "LicenseRef-foo", "acknowledgement": "declared"}}],
			),
			("MIT AND", None, [{"license": {"name": "MIT AND", "acknowledgement": "declared"}}]),
		]
		for declared, concluded, expected in cases:
			with self.subTest(declared=declared, concluded=concluded):
				bom = full_bom()
				lib = bom.components[1]
				lib.license_declared, lib.license_concluded = declared, concluded
				data, _warnings = build_cyclonedx(bom)
				self.assertEqual(component(data, "lib-a").get("licenses"), expected)
				self.assertEqual(cyclonedx_errors(data), [])

	def test_download_location_that_is_not_a_url_is_left_out_with_a_warning(self):
		bom = full_bom()
		bom.components[1].download_location = "from the supplier portal"
		data, warnings = build_cyclonedx(bom)
		self.assertEqual(cyclonedx_errors(data), [])
		self.assertNotIn("externalReferences", component(data, "lib-a"))
		self.assertEqual(len(warnings), 1)
		self.assertIn("from the supplier portal", warnings[0])

	def test_url_check_accepts_only_what_the_schema_accepts(self):
		checker = Draft7Validator.FORMAT_CHECKER
		accepted = [
			"https://example.com/a.whl",
			"https://example.com/a%20b.tgz?x=1&y=2#top",
			"http://example.com:8080/パッケージ.zip",
			"git+https://github.com/example/repo.git@v1.0",
			"urn:cdx:11111111-2222-3333-4444-555555555555/1",
			"urn:uuid:11111111-2222-3333-4444-555555555555",
			"ftp://example.com/a",
			"files/a.tgz",
		]
		refused = [
			"from the supplier portal",
			"https://example.com/a b",
			"https://example.com/%zz",
			"https://example.com/a#b#c",
			"1http://example.com",
			"a:b:c d",
			"<https://example.com>",
			'https://example.com/"a"',
			"https://example.com/{a}",
			"https://example.com/a\\b",
			"https://[::1/a",
			"https://example.com/\x01",
		]
		for value in accepted:
			with self.subTest(value=value):
				self.assertTrue(is_iri_reference(value))
				self.assertTrue(checker.conforms(value, "iri-reference"))
		for value in refused:
			with self.subTest(value=value):
				self.assertFalse(is_iri_reference(value))
		# Never more lenient than the schema: whatever passes the quick check passes the schema
		alphabet = "ab09AF:/?#%[]@!$&'()*+,;=-._~ <>\"{}|\\^`あ\x01"
		generator = random.Random(16)
		samples = ["".join(generator.choices(alphabet, k=generator.randint(1, 12))) for _index in range(300)]
		for value in accepted + refused + samples:
			if is_iri_reference(value):
				self.assertTrue(checker.conforms(value, "iri-reference"), value)

	def test_external_sbom_that_is_not_a_uri_is_left_out_with_a_warning(self):
		bom = full_bom()
		bom.components[2].external_bom = ExternalBom(uri="the SBOM of B")
		data, warnings = build_cyclonedx(bom)
		self.assertEqual(cyclonedx_errors(data), [])
		self.assertNotIn("externalReferences", component(data, "fw-b"))
		self.assertEqual(len(warnings), 1)

	def test_hardware_is_a_device(self):
		bom = full_bom()
		bom.components[2].component_type = "hardware"
		data, _warnings = build_cyclonedx(bom)
		self.assertEqual(cyclonedx_errors(data), [])
		self.assertEqual(component(data, "fw-b")["type"], "device")

	def test_every_component_type_passes_the_schema(self):
		path = os.path.join(APP, "sg_catalog", "doctype", "sg_component", "sg_component.json")
		with open(path) as file:
			fields = json.load(file)["fields"]
		types = next(f for f in fields if f["fieldname"] == "component_type")["options"].split("\n")
		self.assertIn("hardware", types)
		bom = full_bom()
		bom.components += [ExportComponent(ref=t, name=t, version="1", component_type=t) for t in types]
		data, _warnings = build_cyclonedx(bom)
		self.assertEqual(cyclonedx_errors(data), [])
		data, _warnings = build_spdx(bom)
		self.assertEqual(spdx_errors(data), [])

	def test_every_sbom_type_has_a_lifecycle(self):
		for phase in ("Design", "Source", "Build", "Analyzed", "Deployed", "Runtime"):
			bom = full_bom()
			bom.lifecycle_phase = phase
			data, _warnings = build_cyclonedx(bom)
			self.assertEqual(data["metadata"]["lifecycles"], [{"phase": LIFECYCLES[phase]}])
			self.assertEqual(cyclonedx_errors(data), [])

	def test_serial_number(self):
		bom = full_bom()
		self.assertEqual(cyclonedx_serial(bom), bom.serial_number)
		bom.serial_number = "https://example.com/spdx/T-Sample"
		serial = cyclonedx_serial(bom)
		self.assertRegex(serial, r"^urn:uuid:[0-9a-f-]{36}$")
		# The same document always gets the same serial number
		self.assertEqual(cyclonedx_serial(bom), serial)
		bom.name = "SGB-2026-00002"
		self.assertNotEqual(cyclonedx_serial(bom), serial)

	def test_primary_component_without_parts(self):
		bom = full_bom()
		bom.components, bom.relations = bom.components[:1], []
		data, _warnings = build_cyclonedx(bom)
		self.assertNotIn("components", data)
		self.assertEqual(data["dependencies"], [{"ref": "app"}])
		self.assertEqual(cyclonedx_errors(data), [])


class UnitTestPrimaryComponent(UnitTestCase):
	def test_the_primary_component_that_nothing_contains_is_chosen(self):
		entries = [
			frappe._dict(name="e-copy", component_version="SGCV-1"),
			frappe._dict(name="e-app", component_version="SGCV-1"),
			frappe._dict(name="e-lib", component_version="SGCV-2"),
		]
		refs = {"e-copy": "copy", "e-app": "app", "e-lib": "lib"}
		relations = [("app", "lib", "contains"), ("lib", "copy", "contains")]
		for ordered in (entries, entries[::-1]):
			with self.subTest(first=ordered[0].name):
				self.assertEqual(_primary_ref("SGCV-1", ordered, refs, relations), "app")
		self.assertIsNone(_primary_ref("SGCV-9", entries, refs, relations))
		self.assertIsNone(_primary_ref(None, entries, refs, relations))


class UnitTestSpdx(UnitTestCase):
	def test_output_has_no_validation_errors(self):
		data, warnings = build_spdx(full_bom())
		self.assertEqual(spdx_errors(data), [])
		self.assertEqual(warnings, [])
		self.assertEqual(data["spdxVersion"], "SPDX-2.3")

	def test_document_without_components_is_written_with_a_warning(self):
		bom = full_bom()
		bom.components, bom.relations, bom.primary_ref = [], [], None
		data, warnings = build_spdx(bom)
		self.assertEqual(data["packages"], [])
		self.assertEqual(len(warnings), 1)
		self.assertIn("no components", warnings[0])
		# SPDX 2.3 does not allow it, which the warning tells
		self.assertNotEqual(spdx_errors(data), [])
		# CycloneDX allows it
		data, warnings = build_cyclonedx(bom)
		self.assertEqual(warnings, [])
		self.assertEqual(cyclonedx_errors(data), [])

	def test_every_framework_field_is_written(self):
		data, _warnings = build_spdx(full_bom())
		info = data["creationInfo"]
		self.assertIn("Organization: T Company, Ltd.", info["creators"])  # Author Name
		self.assertEqual(info["created"], "2026-11-01T05:55:55Z")  # Timestamp
		self.assertEqual(info["comment"], "SBOM Type : Build")  # SBOM Type
		rels = relationships(data)
		self.assertIn(("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-app"), rels)  # Primary Component
		lib = package(data, "SPDXRef-lib-a")
		self.assertEqual(lib["name"], "a-lib")  # Name
		self.assertEqual(lib["versionInfo"], "1.2.3")  # Version
		self.assertEqual(lib["supplier"], "Organization: A Project")  # Supplier
		self.assertIn(("SPDXRef-app", "DEPENDS_ON", "SPDXRef-lib-a"), rels)  # Relationship
		self.assertIn(("SPDXRef-app", "CONTAINS", "SPDXRef-fw-b"), rels)
		self.assertIn(  # Unique Identifier
			{
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceType": "purl",
				"referenceLocator": "pkg:pypi/a-lib@1.2.3",
			},
			lib["externalRefs"],
		)
		self.assertIn(
			{
				"referenceCategory": "SECURITY",
				"referenceType": "cpe23Type",
				"referenceLocator": "cpe:2.3:a:a_project:a-lib:1.2.3:*:*:*:*:*:*:*",
			},
			lib["externalRefs"],
		)
		self.assertTrue(data["documentNamespace"].startswith("https://sbom.example.com/spdx/SGB-2026-00001-"))
		self.assertEqual(lib["packageFileName"], "a_lib.whl")  # File Name
		self.assertEqual(lib["downloadLocation"], "https://example.com/a.whl")  # Download Location
		self.assertEqual(lib["licenseDeclared"], "MIT")  # Declared License
		self.assertEqual(lib["licenseConcluded"], "Apache-2.0")  # Concluded License
		self.assertEqual(package(data, "SPDXRef-app")["licenseDeclared"], "LicenseRef-T-Proprietary")
		self.assertEqual(
			data["hasExtractedLicensingInfos"],
			[
				{
					"licenseId": "LicenseRef-T-Proprietary",
					"extractedText": "NOASSERTION",
					"name": "LicenseRef-T-Proprietary",
				}
			],
		)
		self.assertEqual(  # Hash
			lib["checksums"],
			[{"algorithm": "SHA256", "checksumValue": SHA256}, {"algorithm": "SHA1", "checksumValue": SHA1}],
		)
		self.assertEqual(lib["copyrightText"], "(C) A Project")  # Copyright
		self.assertEqual(  # External Document References
			data["externalDocumentRefs"],
			[
				{
					"externalDocumentId": "DocumentRef-1",
					"spdxDocument": "urn:cdx:11111111-2222-3333-4444-555555555555/1",
					"checksum": {"algorithm": "SHA256", "checksumValue": SHA256},
				}
			],
		)
		self.assertIn(("SPDXRef-fw-b", "DESCRIBED_BY", "DocumentRef-1:SPDXRef-DOCUMENT"), rels)

	def test_output_is_read_back_by_the_importer(self):
		data, _warnings = build_spdx(full_bom())
		parsed = importer.parse_content(json.dumps(data).encode(), "out.spdx.json")
		self.assertEqual(parsed.lifecycle_phase, "Build")
		self.assertEqual(parsed.author_name, "T Company, Ltd.")
		self.assertEqual(parsed.primary_ref, "SPDXRef-app")
		self.assertEqual(len(parsed.components), 3)
		self.assertEqual(
			set(parsed.relations),
			{("SPDXRef-app", "SPDXRef-lib-a", "depends-on"), ("SPDXRef-app", "SPDXRef-fw-b", "contains")},
		)
		firmware = next(c for c in parsed.components if c.ref == "SPDXRef-fw-b")
		self.assertEqual(firmware.external_bom_ref, "urn:cdx:11111111-2222-3333-4444-555555555555/1")

	def test_missing_values_are_noassertion(self):
		bom = full_bom()
		bom.components.append(ExportComponent(ref="bare", name="bare", version="1"))
		bom.relations.append(("app", "bare", "depends-on"))
		data, _warnings = build_spdx(bom)
		bare = package(data, "SPDXRef-bare")
		for key in ("supplier", "downloadLocation", "licenseConcluded", "licenseDeclared", "copyrightText"):
			self.assertEqual(bare[key], "NOASSERTION", key)
		self.assertNotIn("packageFileName", bare)
		self.assertNotIn("checksums", bare)
		# NONE stays NONE
		self.assertEqual(package(data, "SPDXRef-fw-b")["downloadLocation"], "NONE")
		self.assertEqual(spdx_errors(data), [])

	def test_relationships(self):
		bom = full_bom()
		bom.relations = [
			("app", "lib-a", "depends-on"),
			("app", "fw-b", "contains"),
			("app", "lib-a", "dev-dependency"),
			("app", "lib-a", "optional-dependency"),
			("app", "lib-a", "provided-by"),
			("fw-b", "lib-a", "generated-from"),
			("fw-b", "lib-a", "variant-of"),
		]
		data, _warnings = build_spdx(bom)
		self.assertEqual(spdx_errors(data), [])
		self.assertTrue(
			{
				("SPDXRef-app", "DEPENDS_ON", "SPDXRef-lib-a"),
				("SPDXRef-app", "CONTAINS", "SPDXRef-fw-b"),
				# *_OF relationships point the other way
				("SPDXRef-lib-a", "DEV_DEPENDENCY_OF", "SPDXRef-app"),
				("SPDXRef-lib-a", "OPTIONAL_DEPENDENCY_OF", "SPDXRef-app"),
				("SPDXRef-lib-a", "PROVIDED_DEPENDENCY_OF", "SPDXRef-app"),
				("SPDXRef-fw-b", "GENERATED_FROM", "SPDXRef-lib-a"),
				("SPDXRef-fw-b", "VARIANT_OF", "SPDXRef-lib-a"),
			}
			<= relationships(data)
		)
		# The importer reads each of them back as the same relationship
		parsed = importer.parse_content(json.dumps(data).encode(), "out.spdx.json")
		self.assertEqual(
			set(parsed.relations),
			{(f"SPDXRef-{a}", f"SPDXRef-{b}", kind) for a, b, kind in bom.relations},
		)

	def test_license_that_is_not_an_spdx_expression_keeps_its_text(self):
		bom = full_bom()
		bom.components[1].license_declared = "GPL-2.0-only or commercial license"
		bom.components[2].license_declared = "GPL-2.0-only or commercial license"
		data, _warnings = build_spdx(bom)
		self.assertEqual(spdx_errors(data), [])
		license_id = package(data, "SPDXRef-lib-a")["licenseDeclared"]
		self.assertEqual(license_id, "LicenseRef-GPL-2.0-only-or-commercial-license")
		self.assertEqual(package(data, "SPDXRef-fw-b")["licenseDeclared"], license_id)
		extracted = {item["licenseId"]: item for item in data["hasExtractedLicensingInfos"]}
		self.assertEqual(extracted[license_id]["extractedText"], "GPL-2.0-only or commercial license")

	def test_license_refs_from_the_original_file_are_kept(self):
		app_ref = {"LicenseRef-T-Proprietary": "NOASSERTION"}
		cases = [
			# (value, written, {LicenseRef- id: extracted text}); the text of a LicenseRef- of the original
			# file is not kept in SupplyGraph
			("LicenseRef-T-Proprietary", "LicenseRef-T-Proprietary", {}),
			("MIT OR LicenseRef-foo", "MIT OR LicenseRef-foo", {"LicenseRef-foo": "NOASSERTION"}),
			("mit and LicenseRef-foo", "MIT AND LicenseRef-foo", {"LicenseRef-foo": "NOASSERTION"}),
			# A reference to another document's license cannot be defined here, so it is wrapped
			(
				"DocumentRef-x:LicenseRef-y",
				"LicenseRef-DocumentRef-x-LicenseRef-y",
				{"LicenseRef-DocumentRef-x-LicenseRef-y": "DocumentRef-x:LicenseRef-y"},
			),
			# Broken text that license-expression fails on with errors of its own
			("MIT AND", "LicenseRef-MIT-AND", {"LicenseRef-MIT-AND": "MIT AND"}),
			("(MIT", "LicenseRef-MIT", {"LicenseRef-MIT": "(MIT"}),
			(
				"Unknown-License OR MIT",
				"LicenseRef-Unknown-License-OR-MIT",
				{"LicenseRef-Unknown-License-OR-MIT": "Unknown-License OR MIT"},
			),
		]
		for value, written, texts in cases:
			with self.subTest(value=value):
				bom = full_bom()
				bom.components[1].license_declared = value
				data, _warnings = build_spdx(bom)
				self.assertEqual(spdx_errors(data), [])
				self.assertEqual(package(data, "SPDXRef-lib-a")["licenseDeclared"], written)
				extracted = {
					item["licenseId"]: item["extractedText"] for item in data["hasExtractedLicensingInfos"]
				}
				self.assertEqual(extracted, {**app_ref, **texts})

	def test_made_license_ref_does_not_take_the_id_of_one_from_the_file(self):
		bom = full_bom()
		bom.components[1].license_declared = "LicenseRef-a-b"
		bom.components[1].license_concluded = "a b"
		data, _warnings = build_spdx(bom)
		self.assertEqual(spdx_errors(data), [])
		lib = package(data, "SPDXRef-lib-a")
		self.assertEqual(
			(lib["licenseDeclared"], lib["licenseConcluded"]), ("LicenseRef-a-b", "LicenseRef-a-b-2")
		)

	def test_hashes(self):
		bom = full_bom()
		bom.components[1].hashes = [
			("SHA-256", SHA256.upper()),
			("BLAKE3", SHA256),
			("SHA-1", "not hex"),
		]
		data, warnings = build_spdx(bom)
		self.assertEqual(spdx_errors(data), [])
		lib = package(data, "SPDXRef-lib-a")
		# SPDX wants lower case
		self.assertEqual(lib["checksums"], [{"algorithm": "SHA256", "checksumValue": SHA256}])
		self.assertEqual(lib["comment"], f"BLAKE3 hash: {SHA256}\nSHA-1 hash: not hex")
		self.assertEqual(len(warnings), 2)
		data, warnings = build_cyclonedx(bom)
		self.assertEqual(cyclonedx_errors(data), [])
		self.assertEqual(
			component(data, "lib-a")["hashes"],
			[{"alg": "SHA-256", "content": SHA256.upper()}, {"alg": "BLAKE3", "content": SHA256}],
		)
		self.assertEqual(len(warnings), 1)

	def test_checksum_of_an_external_sbom_that_spdx_does_not_accept(self):
		bom = full_bom()
		bom.components[2].external_bom.checksum = ("BLAKE3", SHA256)
		data, warnings = build_spdx(bom)
		self.assertEqual(spdx_errors(data), [])
		self.assertNotIn("externalDocumentRefs", data)
		self.assertIn("External SBOM: urn:cdx:", package(data, "SPDXRef-fw-b")["comment"])
		self.assertEqual(len(warnings), 1)
		bom.components[2].external_bom.checksum = ("SHA-256", SHA256.upper())
		data, _warnings = build_spdx(bom)
		self.assertEqual(data["externalDocumentRefs"][0]["checksum"]["checksumValue"], SHA256)

	def test_values_that_spdx_does_not_accept_go_to_the_comment(self):
		bom = full_bom()
		lib = bom.components[1]
		lib.download_location = "from the supplier portal"
		lib.cpe = "not a cpe"
		data, warnings = build_spdx(bom)
		self.assertEqual(spdx_errors(data), [])
		written = package(data, "SPDXRef-lib-a")
		self.assertEqual(written["downloadLocation"], "NOASSERTION")
		self.assertEqual(written["comment"], "Download location: from the supplier portal\nCPE: not a cpe")
		self.assertEqual(len(warnings), 2)

	def test_external_sbom_without_checksum_goes_to_the_comment(self):
		bom = full_bom()
		bom.components[2].external_bom = ExternalBom(uri="https://example.com/spdx/B")
		data, warnings = build_spdx(bom)
		self.assertEqual(spdx_errors(data), [])
		self.assertNotIn("externalDocumentRefs", data)
		self.assertEqual(
			package(data, "SPDXRef-fw-b")["comment"], "External SBOM: https://example.com/spdx/B"
		)
		self.assertEqual(len(warnings), 1)

	def test_two_packages_with_one_external_sbom_share_the_reference(self):
		bom = full_bom()
		bom.components[1].external_bom = copy.deepcopy(bom.components[2].external_bom)
		data, _warnings = build_spdx(bom)
		self.assertEqual(spdx_errors(data), [])
		self.assertEqual(len(data["externalDocumentRefs"]), 1)
		self.assertIn(
			("SPDXRef-lib-a", "DESCRIBED_BY", "DocumentRef-1:SPDXRef-DOCUMENT"), relationships(data)
		)

	def test_spdx_ids_are_made_from_refs(self):
		bom = full_bom()
		bom.components += [
			ExportComponent(ref="pkg:npm/x@1", name="x", version="1"),
			ExportComponent(ref="pkg-npm-x-1", name="y", version="1"),
			ExportComponent(ref="SPDXRef-Z", name="z", version="1"),
		]
		bom.relations += [("app", c.ref, "depends-on") for c in bom.components[3:]]
		data, _warnings = build_spdx(bom)
		self.assertEqual(spdx_errors(data), [])
		self.assertEqual(
			[item["SPDXID"] for item in data["packages"][3:]],
			["SPDXRef-pkg-npm-x-1", "SPDXRef-pkg-npm-x-1-2", "SPDXRef-Z"],
		)

	def test_supplier_whose_name_ends_with_a_parenthesis(self):
		bom = full_bom()
		bom.components[1].supplier = "A Company (Japan)"
		data, _warnings = build_spdx(bom)
		parsed = parse_spdx(data)
		supplier = next(p.supplier for p in parsed.packages if p.spdx_id == "SPDXRef-lib-a")
		self.assertEqual((supplier.name, supplier.email), ("A Company (Japan)", None))

	def test_every_sbom_type_is_read_back(self):
		for phase in ("Design", "Source", "Build", "Analyzed", "Deployed", "Runtime"):
			bom = full_bom()
			bom.lifecycle_phase = phase
			data, _warnings = build_spdx(bom)
			parsed = importer.parse_content(json.dumps(data).encode(), "out.spdx.json")
			self.assertEqual(parsed.lifecycle_phase, phase)

	def test_without_a_primary_component_the_top_components_are_described(self):
		bom = full_bom()
		bom.primary_ref = None
		data, _warnings = build_spdx(bom)
		self.assertEqual(spdx_errors(data), [])
		described = {item[2] for item in relationships(data) if item[1] == "DESCRIBES"}
		self.assertEqual(described, {"SPDXRef-app"})
		self.assertEqual(data["name"], "SGB-2026-00001")

	def test_namespace(self):
		bom = full_bom()
		bom.format = "SPDX"
		bom.serial_number = "https://example.com/spdx/T-Sample"
		self.assertEqual(spdx_namespace(bom), "https://example.com/spdx/T-Sample")
		# A CycloneDX serial number belongs to the CycloneDX document; SPDX gets a namespace of its own
		bom.format = "CycloneDX"
		self.assertEqual(spdx_namespace(bom), spdx_namespace(bom))
		self.assertTrue(spdx_namespace(bom).startswith("https://sbom.example.com/spdx/SGB-2026-00001-"))


class UnitTestTranslations(UnitTestCase):
	def test_messages_of_a_cancelled_document_are_translated(self):
		from babel.messages.pofile import read_po

		with open(os.path.join(APP, "locale", "ja.po"), "rb") as po_file:
			catalog = read_po(po_file)
		for message in ("SG BOM Document {0} is cancelled and is not exported", "Cancelled SBOM"):
			with self.subTest(message=message):
				self.assertTrue(catalog.get(message) and catalog[message].string)


class IntegrationTestExport(IntegrationTestCase):
	def setUp(self):
		self.files = []

	def tearDown(self):
		# Files are written to disk, which a rollback does not undo
		for file_name in self.files:
			frappe.delete_doc("File", file_name, force=True, ignore_permissions=True, delete_permanently=True)
		frappe.set_user("Administrator")
		frappe.db.rollback()

	def upload(self, content: bytes, file_name: str) -> str:
		file_doc = frappe.get_doc(
			{"doctype": "File", "file_name": file_name, "is_private": 1, "content": content}
		).insert(ignore_permissions=True)
		self.files.append(file_doc.name)
		return file_doc.file_url

	def import_file(self, content: bytes, file_name: str) -> str:
		return importer.import_content(content, file_name, "SBOM", None, self.upload(content, file_name))

	def import_cyclonedx(self, data: dict | None = None) -> str:
		data = data or json.loads(read_bytes("cyclonedx_sample.json"))
		return self.import_file(json.dumps(data).encode(), "sample.cdx.json")

	def import_spdx(self, data: dict | None = None) -> str:
		content = json.dumps(data).encode() if data else read_bytes("spdx_sample.spdx.json")
		return self.import_file(content, "sample.spdx.json")

	def export(self, bom_document: str, format: str, **kwargs) -> dict:
		result = export_bom(bom_document, format, **kwargs)
		self.assertEqual(set(result), {"filename", "content", "warnings"})
		return json.loads(result["content"])

	def test_unknown_format_is_refused(self):
		document = self.import_cyclonedx()
		for value in ("XML", "cyclonedx", ""):
			with self.subTest(format=value), self.assertRaises(frappe.ValidationError):
				export_bom(document, value)

	def test_unknown_document_is_refused(self):
		with self.assertRaises(frappe.DoesNotExistError):
			export_bom("SGB-2026-99999", "SPDX")

	def test_imported_documents_are_exported_in_both_formats(self):
		for document in (self.import_cyclonedx(), self.import_spdx()):
			with self.subTest(document=document):
				result = export_bom(document, "CycloneDX")
				self.assertEqual(result["filename"], f"{document}.cdx.json")
				self.assertEqual(cyclonedx_errors(json.loads(result["content"])), [])
				result = export_bom(document, "SPDX")
				self.assertEqual(result["filename"], f"{document}.spdx.json")
				self.assertEqual(spdx_errors(json.loads(result["content"])), [])

	def test_spdx_read_back_has_the_same_components_and_relationships(self):
		for document in (self.import_cyclonedx(), self.import_spdx()):
			with self.subTest(document=document):
				parsed = parse_spdx(self.export(document, "SPDX"))
				dependencies = [
					r
					for r in parsed.relationships
					if r.relationship_type not in (RelationshipType.DESCRIBES, RelationshipType.DESCRIBED_BY)
				]
				self.assertEqual(
					len(parsed.packages), frappe.db.count("SG BOM Entry", {"bom_document": document})
				)
				self.assertEqual(
					len(dependencies), frappe.db.count("SG Dependency", {"bom_document": document})
				)

	def test_fields_of_the_records_are_written(self):
		document = self.import_cyclonedx()
		data = self.export(document, "SPDX")
		lib = package(data, "SPDXRef-lib-a")
		self.assertEqual(lib["versionInfo"], "1.2.3")
		self.assertEqual(lib["packageFileName"], "a_lib.whl")
		self.assertEqual(lib["licenseConcluded"], "Apache-2.0")
		self.assertEqual(lib["checksums"], [{"algorithm": "SHA256", "checksumValue": SHA256}])
		self.assertEqual(data["creationInfo"]["comment"], "SBOM Type : Build")
		self.assertEqual(data["packages"][0]["SPDXID"], "SPDXRef-app")
		data = self.export(document, "CycloneDX")
		self.assertEqual(data["serialNumber"], "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79")
		self.assertEqual(data["metadata"]["component"]["name"], "T-Sample")
		self.assertEqual(component(data, "lib-a-child")["name"], "a-child")
		# The child of lib-a is nested again, as in the original file
		self.assertEqual([c["bom-ref"] for c in component(data, "lib-a")["components"]], ["lib-a-child"])

	def test_supplier_and_concluded_license_of_the_entry_come_first(self):
		document = self.import_cyclonedx()
		frappe.get_doc(
			{
				"doctype": "SG Organization",
				"organization_name": "Entry Supplier",
				"organization_type": "Supplier",
			}
		).insert()
		if not frappe.db.exists("SG License", "BSD-3-Clause"):
			frappe.get_doc(
				{
					"doctype": "SG License",
					"spdx_id": "BSD-3-Clause",
					"license_name": "BSD 3-Clause",
					"category": "Permissive",
					"policy": "Allowed",
				}
			).insert()
		entry = frappe.db.get_value("SG BOM Entry", {"bom_document": document, "bom_ref": "lib-a"})
		frappe.db.set_value(
			"SG BOM Entry", entry, {"supplier": "Entry Supplier", "license_concluded": "BSD-3-Clause"}
		)
		lib = package(self.export(document, "SPDX"), "SPDXRef-lib-a")
		self.assertEqual(
			(lib["supplier"], lib["licenseConcluded"]), ("Organization: Entry Supplier", "BSD-3-Clause")
		)

	def test_primary_component_that_is_not_an_entry_is_written(self):
		document = self.import_cyclonedx()
		version = frappe.db.get_value("SG BOM Document", document, "primary_component")
		frappe.db.delete("SG Dependency", {"bom_document": document})
		frappe.db.delete("SG BOM Entry", {"bom_document": document, "component_version": version})
		data = self.export(document, "CycloneDX", force=True)
		self.assertEqual(data["metadata"]["component"]["name"], "T-Sample")
		self.assertEqual(data["metadata"]["component"]["bom-ref"], "primary")
		data = self.export(document, "SPDX", force=True)
		self.assertIn(("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-primary"), relationships(data))
		self.assertEqual(spdx_errors(data), [])

	def test_external_sbom_that_is_imported(self):
		child = json.loads(read_bytes("cyclonedx_sample.json"))
		child["serialNumber"] = CHILD_SERIAL
		child_content = json.dumps(child).encode()
		child_document = self.import_file(child_content, "child.cdx.json")
		parent = self.import_cyclonedx()
		self.assertEqual(
			frappe.db.get_value("SG BOM Entry", {"bom_document": parent, "bom_ref": "fw-b"}, "external_bom"),
			child_document,
		)
		checksum = hashlib.sha256(child_content).hexdigest()
		data = self.export(parent, "CycloneDX")
		self.assertIn(
			{
				"type": "bom",
				"url": "urn:cdx:11111111-2222-3333-4444-555555555555/1",
				"hashes": [{"alg": "SHA-256", "content": checksum}],
			},
			component(data, "fw-b")["externalReferences"],
		)
		data = self.export(parent, "SPDX")
		self.assertEqual(spdx_errors(data), [])
		self.assertEqual(
			data["externalDocumentRefs"],
			[
				{
					"externalDocumentId": "DocumentRef-1",
					"spdxDocument": "urn:cdx:11111111-2222-3333-4444-555555555555/1",
					"checksum": {"algorithm": "SHA256", "checksumValue": checksum},
				}
			],
		)
		self.assertIn(("SPDXRef-fw-b", "DESCRIBED_BY", "DocumentRef-1:SPDXRef-DOCUMENT"), relationships(data))

	def test_external_sbom_link_set_by_hand_uses_the_serial_number(self):
		child = json.loads(read_bytes("cyclonedx_sample.json"))
		child["serialNumber"] = CHILD_SERIAL
		child["version"] = 3
		child_document = self.import_file(json.dumps(child).encode(), "child.cdx.json")
		parent = self.import_spdx()
		entry = frappe.db.get_value("SG BOM Entry", {"bom_document": parent, "bom_ref": "SPDXRef-A"})
		frappe.db.set_value("SG BOM Entry", entry, {"external_bom": child_document, "external_bom_ref": None})
		data = self.export(parent, "CycloneDX")
		references = component(data, "SPDXRef-A")["externalReferences"]
		self.assertEqual(references[-1]["url"], "urn:cdx:11111111-2222-3333-4444-555555555555/3")

	def test_checksum_of_an_external_sbom_comes_from_the_original_spdx_file(self):
		# The B-Component SBOM is not imported; the original file holds its checksum
		data = self.export(self.import_spdx(), "SPDX")
		self.assertEqual(spdx_errors(data), [])
		original = json.loads(read_bytes("spdx_sample.spdx.json"))["externalDocumentRefs"][0]
		self.assertEqual(data["externalDocumentRefs"][0]["spdxDocument"], original["spdxDocument"])
		self.assertEqual(data["externalDocumentRefs"][0]["checksum"], original["checksum"])
		self.assertIn(("SPDXRef-B", "DESCRIBED_BY", "DocumentRef-1:SPDXRef-DOCUMENT"), relationships(data))
		self.assertEqual(data["documentNamespace"], "https://example.com/spdx/T-Sample")

	def test_document_with_errors_is_exported_only_with_force(self):
		data = json.loads(read_bytes("cyclonedx_sample.json"))
		data["components"][0]["hashes"][0]["alg"] = "SHA-999"
		document = self.import_cyclonedx(data)
		# The form catches this type to offer exporting anyway
		with self.assertRaises(SbomHasErrorsError) as context:
			export_bom(document, "CycloneDX")
		self.assertIn("SYN-CDX", str(context.exception))
		self.assertEqual(frappe.db.get_value("SG BOM Document", document, "import_status"), "Rejected")
		for force in (True, "1", "true"):
			with self.subTest(force=force):
				self.assertEqual(cyclonedx_errors(self.export(document, "CycloneDX", force=force)), [])
		with self.assertRaises(frappe.ValidationError):
			export_bom(document, "SPDX", force="0")

	def test_cancelled_document_is_not_exported_even_with_force(self):
		document = self.import_cyclonedx()
		# A submitted document is still exported
		self.export(document, "CycloneDX")
		frappe.get_doc("SG BOM Document", document).submit()
		self.assertEqual(cyclonedx_errors(self.export(document, "CycloneDX")), [])
		frappe.get_doc("SG BOM Document", document).cancel()
		self.assertEqual(frappe.db.get_value("SG BOM Document", document, "docstatus"), 2)
		for format in ("CycloneDX", "SPDX"):
			for force in (False, True, "1"):
				with self.subTest(format=format, force=force):
					with self.assertRaises(frappe.ValidationError) as context:
						export_bom(document, format, force=force)
					# Not "cancelled and cannot be validated" of validate_bom, which force=False alone would give
					self.assertIn(
						f"SG BOM Document {document} is cancelled and is not exported", str(context.exception)
					)
					# Not the errors of the validation: the cancelled document is refused before it
					self.assertNotIsInstance(context.exception, SbomHasErrorsError)

	def test_message_lists_the_errors(self):
		document = self.import_cyclonedx()
		frappe.db.set_value("SG BOM Document", document, "source_file", None)
		with self.assertRaises(frappe.ValidationError) as context:
			export_bom(document, "SPDX")
		self.assertIn("SYN-NO-FILE", str(context.exception))

	def test_document_without_errors_is_validated_before_the_export(self):
		document = self.import_cyclonedx()
		self.assertEqual(frappe.db.get_value("SG BOM Document", document, "import_status"), "Parsed")
		self.export(document, "SPDX")
		self.assertEqual(frappe.db.get_value("SG BOM Document", document, "import_status"), "Validated")

	def test_user_without_read_permission_cannot_export(self):
		document = self.import_cyclonedx()
		user = self.make_user("sg-export-none@example.com", [])
		frappe.set_user(user)
		with self.assertRaises(frappe.PermissionError):
			export_bom(document, "SPDX")
		with self.assertRaises(frappe.PermissionError):
			export_bom(document, "CycloneDX", force=True)

	def test_user_without_read_permission_does_not_learn_which_documents_exist(self):
		frappe.set_user(self.make_user("sg-export-none@example.com", []))
		with self.assertRaises(frappe.PermissionError):
			export_bom("SGB-2026-99999", "SPDX")

	def test_linked_sbom_that_the_user_cannot_read_is_not_written(self):
		child = json.loads(read_bytes("cyclonedx_sample.json"))
		child["serialNumber"] = CHILD_SERIAL
		child_document = self.import_file(json.dumps(child).encode(), "child.cdx.json")
		parent = self.import_spdx()
		entry = frappe.db.get_value("SG BOM Entry", {"bom_document": parent, "bom_ref": "SPDXRef-A"})
		frappe.db.set_value("SG BOM Entry", entry, {"external_bom": child_document, "external_bom_ref": None})
		user = self.make_user("sg-export-limited@example.com", ["SG Viewer"])
		frappe.get_doc(
			{"doctype": "User Permission", "user": user, "allow": "SG BOM Document", "for_value": parent}
		).insert(ignore_permissions=True)
		frappe.set_user(user)
		self.assertFalse(frappe.has_permission("SG BOM Document", "read", doc=child_document))
		data = self.export(parent, "CycloneDX")
		references = component(data, "SPDXRef-A")["externalReferences"]
		self.assertEqual([reference["type"] for reference in references], ["distribution"])
		frappe.set_user("Administrator")
		data = self.export(parent, "CycloneDX")
		self.assertEqual(component(data, "SPDXRef-A")["externalReferences"][-1]["type"], "bom")

	def test_linked_sbom_without_a_serial_number_gets_the_one_of_its_export(self):
		child = json.loads(read_bytes("cyclonedx_sample.json"))
		del child["serialNumber"]
		child_document = self.import_file(json.dumps(child).encode(), "child.cdx.json")
		parent = self.import_spdx()
		entry = frappe.db.get_value("SG BOM Entry", {"bom_document": parent, "bom_ref": "SPDXRef-A"})
		frappe.db.set_value("SG BOM Entry", entry, {"external_bom": child_document, "external_bom_ref": None})
		serial = self.export(child_document, "CycloneDX")["serialNumber"]
		data = self.export(parent, "CycloneDX")
		reference = component(data, "SPDXRef-A")["externalReferences"][-1]
		# The checksum of the original file is not the checksum of the export
		self.assertEqual(reference, {"type": "bom", "url": f"urn:cdx:{serial.removeprefix('urn:uuid:')}/1"})
		result = export_bom(parent, "SPDX")
		self.assertEqual(spdx_errors(json.loads(result["content"])), [])
		self.assertTrue(any("SPDXRef-A: external SBOM urn:cdx:" in warning for warning in result["warnings"]))

	def test_dependency_on_another_document_is_left_out_with_a_warning(self):
		document = self.import_cyclonedx()
		other = self.import_spdx()
		frappe.get_doc(
			{
				"doctype": "SG Dependency",
				"bom_document": document,
				"from_entry": frappe.db.get_value(
					"SG BOM Entry", {"bom_document": document, "bom_ref": "app"}
				),
				"to_entry": frappe.db.get_value(
					"SG BOM Entry", {"bom_document": other, "bom_ref": "SPDXRef-A"}
				),
				"relationship": "depends-on",
			}
		).db_insert()
		result = export_bom(document, "SPDX")
		self.assertEqual(spdx_errors(json.loads(result["content"])), [])
		self.assertIn("1 dependencies on entries of other documents are left out", result["warnings"])

	def test_user_limited_to_other_documents_cannot_export(self):
		allowed, document = self.import_spdx(), self.import_cyclonedx()
		user = self.make_user("sg-export-limited@example.com", ["SG Viewer"])
		frappe.get_doc(
			{"doctype": "User Permission", "user": user, "allow": "SG BOM Document", "for_value": allowed}
		).insert(ignore_permissions=True)
		frappe.set_user(user)
		self.assertEqual(spdx_errors(self.export(allowed, "SPDX")), [])
		for force in (False, True):
			with self.subTest(force=force), self.assertRaises(frappe.PermissionError):
				export_bom(document, "SPDX", force=force)

	def test_user_with_read_permission_can_export(self):
		document = self.import_cyclonedx()
		frappe.set_user(self.make_user("sg-export-viewer@example.com", ["SG Viewer"]))
		self.assertEqual(spdx_errors(self.export(document, "SPDX")), [])

	def make_user(self, email: str, roles: list[str]) -> str:
		if not frappe.db.exists("User", email):
			frappe.get_doc(
				{"doctype": "User", "email": email, "first_name": "Export Test", "send_welcome_email": 0}
			).insert(ignore_permissions=True)
		user = frappe.get_doc("User", email)
		user.add_roles(*roles)
		return email

	def test_write_bom_is_the_same_as_the_export(self):
		document = self.import_cyclonedx()
		exported = export_bom(document, "SPDX")
		self.assertEqual(write_bom(load_bom(document), "SPDX").content, exported["content"])

	def test_serial_number_does_not_follow_the_host_of_the_request(self):
		document = self.import_cyclonedx()
		frappe.db.set_value("SG BOM Document", document, "serial_number", None)
		urls, serials, namespaces = set(), set(), set()
		saved = getattr(frappe.local, "request", None)
		try:
			for host in (None, "supplygraph.internal:8080", "attacker.example"):
				frappe.local.request = (
					Request(EnvironBuilder(headers={"Host": host}).get_environ()) if host else None
				)
				bom = load_bom(document)
				urls.add(bom.site_url)
				serials.add(json.loads(write_bom(bom, "CycloneDX").content)["serialNumber"])
				namespaces.add(json.loads(write_bom(bom, "SPDX").content)["documentNamespace"])
				if host:
					# The request is the one get_url would read the host from
					self.assertIn(host, frappe.utils.get_url())
		finally:
			frappe.local.request = saved
		self.assertEqual(len(urls), 1)
		self.assertNotIn("supplygraph.internal", next(iter(urls)))
		self.assertEqual(len(serials), 1)
		self.assertEqual(len(namespaces), 1)
