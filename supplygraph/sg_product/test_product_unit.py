# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Tests for supplygraph.sg_product.product_unit and the sample CSV of docs/guides/ProductUnitImport.md.

They are not in the DocType folder, because tools/gen_doctypes.py writes test_sg_product_unit.py again.
"""

import ast
import csv
import io
import json
from pathlib import Path
from unittest.mock import patch

import frappe
from frappe.core.doctype.data_import.exporter import Exporter
from frappe.tests import IntegrationTestCase, UnitTestCase

import supplygraph
from supplygraph.sg_bom.importer import import_content
from supplygraph.sg_vulnerability import osv
from supplygraph.sg_vulnerability.report.sg_vulnerability_impact import sg_vulnerability_impact as report
from supplygraph.sg_vulnerability.test_main_path import CVE, cyclonedx, osv_api

SAMPLE = Path(supplygraph.__file__).parent.parent / "docs" / "guides" / "samples" / "product_unit_import.csv"
VIN_PATTERN = "^[0-9A-HJ-NPR-Z]{17}$"
PREFIX = "TEST-PU"
# The releases that the sample CSV refers to, as docs/guides/ProductUnitImport.md lists them
SAMPLE_RELEASES = {
	"SGR-0000001": ("DEMO-IVI-FW", "1.0"),
	"SGR-0000002": ("DEMO-IVI-FW", "1.1"),
	"SGR-0000004": ("DEMO-TCU-FW", "3.2"),
}
# Serial numbers of this test in place of those of the sample, which a developer may have imported
SERIALS = {"SAMPLE00000000001": "TESTPU00000000001", "SAMPLE00000000002": "TESTPU00000000002"}


def create_category(name: str, pattern: str | None, label: str | None = "VIN") -> str:
	frappe.get_doc(
		{
			"doctype": "SG Product Category",
			"category_name": name,
			"unit_label": label,
			"serial_pattern": pattern,
		}
	).insert()
	return name


def create_model(code: str, category: str) -> str:
	frappe.get_doc(
		{"doctype": "SG Product Model", "model_code": code, "model_name": code, "product_category": category}
	).insert()
	return code


def read_sample() -> list[list[str]]:
	return list(csv.reader(io.StringIO(SAMPLE.read_text(encoding="utf-8"))))


class UnitTestSampleCsv(UnitTestCase):
	def test_columns_are_those_of_the_import_template(self):
		template = Exporter(
			"SG Product Unit",
			export_fields={
				"SG Product Unit": [df.fieldname for df in frappe.get_meta("SG Product Unit").fields],
				"installed_releases": [df.fieldname for df in frappe.get_meta("SG Installed Release").fields],
			},
			export_data=False,
			file_type="CSV",
		).get_csv_array_for_export()[0]
		header = read_sample()[0]
		self.assertEqual([column for column in header if column not in template], [])

	def test_two_units_with_two_installed_releases_each(self):
		header, *rows = read_sample()
		serials = [row[header.index("Serial No")] for row in rows]
		self.assertEqual(len(rows), 4)
		self.assertEqual([serial for serial in serials if serial], ["SAMPLE00000000001", "SAMPLE00000000002"])
		# A unit spans several rows: the rows after it leave the unit columns empty
		self.assertEqual(serials[1], "")
		self.assertEqual(serials[3], "")


class UnitTestSampleReleases(UnitTestCase):
	def test_release_ids_of_the_sample_are_those_of_the_demo_data(self):
		from supplygraph.devtools import demo

		# demo.load creates the releases in this order, so a new site numbers them SGR-0000001 and up
		releases = [(code, version) for code, version, *_rest in demo.RELEASES]
		self.assertEqual(
			{sample_id: releases[int(sample_id[4:]) - 1] for sample_id in SAMPLE_RELEASES},
			SAMPLE_RELEASES,
		)
		header, *rows = read_sample()
		used = {row[header.index("Release (Installed Releases)")] for row in rows}
		self.assertEqual(used, set(SAMPLE_RELEASES))


class UnitTestTranslations(UnitTestCase):
	def test_every_message_has_a_japanese_translation(self):
		from babel.messages.pofile import read_po

		from supplygraph.sg_product import product_unit

		source = Path(product_unit.__file__).read_text(encoding="utf-8")
		messages = {
			node.args[0].value
			for node in ast.walk(ast.parse(source))
			if isinstance(node, ast.Call)
			and getattr(node.func, "id", None) == "_"
			and node.args
			and isinstance(node.args[0], ast.Constant)
		}
		self.assertEqual(len(messages), 5)
		with (Path(supplygraph.__file__).parent / "locale" / "ja.po").open("rb") as po_file:
			catalog = read_po(po_file)
		untranslated = [
			message for message in messages if not (catalog.get(message) and catalog[message].string)
		]
		self.assertEqual(untranslated, [])


class IntegrationTestSerialNo(IntegrationTestCase):
	def setUp(self):
		self.vehicle = create_model(f"{PREFIX}-CAR", create_category(f"{PREFIX} Vehicle", VIN_PATTERN))
		self.free = create_model(f"{PREFIX}-FREE", create_category(f"{PREFIX} Free", None))

	def tearDown(self):
		frappe.db.rollback()

	def insert_unit(self, serial_no: str, product_model: str):
		return frappe.get_doc(
			{"doctype": "SG Product Unit", "serial_no": serial_no, "product_model": product_model}
		).insert()

	def assertRefused(self, serial_no: str, product_model: str) -> str:
		with self.assertRaises(frappe.ValidationError) as context:
			self.insert_unit(serial_no, product_model)
		self.assertFalse(frappe.db.exists("SG Product Unit", serial_no))
		return str(context.exception)

	def test_serial_no_that_matches_the_rule_is_saved(self):
		self.insert_unit("JH4KA7650MC000000", self.vehicle)
		self.assertTrue(frappe.db.exists("SG Product Unit", "JH4KA7650MC000000"))

	def test_serial_no_that_does_not_match_shows_the_category_and_the_rule(self):
		message = self.assertRefused("ABC123", self.vehicle)
		self.assertIn(f"{PREFIX} Vehicle", message)
		self.assertIn(VIN_PATTERN, message)
		self.assertIn("VIN ABC123", message)

	def test_serial_no_with_a_letter_that_vins_do_not_use_is_refused(self):
		self.assertRefused("JH4KA7650MC00000I", self.vehicle)

	def test_any_serial_no_is_saved_without_a_rule(self):
		for serial_no in ("ABC123", "JH4KA7650MC00000I", "unit 1-a"):
			self.insert_unit(serial_no, self.free)
			self.assertTrue(frappe.db.exists("SG Product Unit", serial_no), serial_no)

	def test_the_whole_serial_no_must_match(self):
		# Without ^ and $, re.search would find 17 valid characters inside a longer value
		model = create_model(f"{PREFIX}-LOOSE", create_category(f"{PREFIX} Loose", "[0-9A-HJ-NPR-Z]{17}"))
		self.assertRefused("JH4KA7650MC000000X", model)
		self.assertRefused("XJH4KA7650MC000000", model)
		self.insert_unit("JH4KA7650MC000000", model)

	def test_the_label_defaults_to_serial_no(self):
		model = create_model(f"{PREFIX}-NOLABEL", create_category(f"{PREFIX} No Label", "^[0-9]+$", None))
		self.assertIn("Serial No ABC", self.assertRefused("ABC", model))

	def test_invalid_rule_gives_the_reason(self):
		model = create_model(f"{PREFIX}-BROKEN", create_category(f"{PREFIX} Broken", "^[A-Z"))
		message = self.assertRefused("ABC", model)
		self.assertIn(f"{PREFIX} Broken", message)
		self.assertIn("not a valid regular expression", message)
		# The reason from the re module
		self.assertIn("unterminated character set", message)

	def test_rule_is_checked_when_the_model_changes(self):
		unit = self.insert_unit("ABC123", self.free)
		unit.product_model = self.vehicle
		with self.assertRaises(frappe.ValidationError):
			unit.save()

	def test_a_unit_saved_under_an_older_rule_can_still_be_changed(self):
		unit = self.insert_unit("ABC123", self.free)
		category = frappe.get_doc("SG Product Category", f"{PREFIX} Free")
		category.serial_pattern = VIN_PATTERN
		category.save()
		unit.reload()
		unit.unit_status = "Decommissioned"
		unit.save()
		self.assertEqual(frappe.db.get_value("SG Product Unit", "ABC123", "unit_status"), "Decommissioned")

	def test_a_changed_rule_is_used_at_once(self):
		self.insert_unit("ABC123", self.free)
		category = frappe.get_doc("SG Product Category", f"{PREFIX} Free")
		category.serial_pattern = VIN_PATTERN
		category.save()
		self.assertRefused("XYZ789", self.free)


class ProductUnitImportTestCase(IntegrationTestCase):
	"""Data Import commits after every row, so the records are committed here and deleted afterwards."""

	def setUp(self):
		self.addCleanup(self.delete_records)
		self.category = create_category(f"{PREFIX} Import Vehicle", VIN_PATTERN)
		self.models = {
			"DEMO-SEDAN": create_model(f"{PREFIX}-SEDAN", self.category),
			"DEMO-SUV": create_model(f"{PREFIX}-SUV", self.category),
		}
		self.unit_types = {}
		for demo_name, name in (("DEMO-IVI-100", f"{PREFIX}-IVI"), ("DEMO-TCU-200", f"{PREFIX}-TCU")):
			frappe.get_doc({"doctype": "SG Unit Type", "unit_part_number": name, "unit_name": name}).insert()
			self.unit_types[demo_name] = name
		# The release IDs of the sample are those of the demo data on a new site
		unit_type_of = {"DEMO-IVI-FW": "DEMO-IVI-100", "DEMO-TCU-FW": "DEMO-TCU-200"}
		self.releases = {
			sample_id: self.create_release(code, version, self.unit_types[unit_type_of[code]])
			for sample_id, (code, version) in SAMPLE_RELEASES.items()
		}
		for serial_no in SERIALS.values():
			self.assertFalse(frappe.db.exists("SG Product Unit", serial_no), serial_no)
		frappe.db.commit()  # nosemgrep

	def create_release(self, code: str, version: str, unit_type: str) -> str:
		return (
			frappe.get_doc(
				{
					"doctype": "SG Release",
					"release_code": code.replace("DEMO", PREFIX),
					"version": version,
					"release_type": "Firmware",
					"release_status": "Released",
					"unit_type": unit_type,
				}
			)
			.insert()
			.name
		)

	def delete_records(self):
		frappe.db.rollback()
		for data_import in frappe.get_all(
			"Data Import", {"import_file": ["like", f"%/{PREFIX}-%"]}, pluck="name"
		):
			import_file = frappe.db.get_value("Data Import", data_import, "import_file")
			frappe.db.delete("Data Import Log", {"data_import": data_import})
			frappe.delete_doc("Data Import", data_import, force=True, delete_permanently=True)
			for file_name in frappe.get_all("File", {"file_url": import_file}, pluck="name"):
				# Through on_trash, so that the file on disk goes too
				frappe.delete_doc(
					"File", file_name, force=True, ignore_permissions=True, delete_permanently=True
				)
		for serial_no in frappe.get_all(
			"SG Product Unit", {"product_model": ["like", f"{PREFIX}-%"]}, pluck="name"
		):
			frappe.delete_doc("SG Product Unit", serial_no, force=True, delete_permanently=True)
		for release in frappe.get_all("SG Release", {"release_code": ["like", f"{PREFIX}-%"]}, pluck="name"):
			frappe.delete_doc("SG Release", release, force=True, delete_permanently=True)
		for doctype, field in (
			("SG Unit Type", "unit_part_number"),
			("SG Product Model", "model_code"),
			("SG Product Category", "category_name"),
		):
			for name in frappe.get_all(doctype, {field: ["like", f"{PREFIX}%"]}, pluck="name"):
				frappe.delete_doc(doctype, name, force=True, delete_permanently=True)
		frappe.db.commit()  # nosemgrep

	def sample_for_this_site(self, change=None) -> str:
		"""The sample CSV, with the demo names and the serial numbers replaced by those of this test."""
		header, *rows = read_sample()
		replace = {
			"Serial No": SERIALS,
			"Product Model": self.models,
			"Unit Type (Installed Releases)": self.unit_types,
			"Release (Installed Releases)": self.releases,
		}
		for row in rows:
			for column, names in replace.items():
				index = header.index(column)
				row[index] = names.get(row[index], row[index])
			if change:
				change(header, row)
		out = io.StringIO()
		csv.writer(out, lineterminator="\n").writerows([header, *rows])
		return out.getvalue()

	def run_import(self, content: str):
		import_file = frappe.get_doc(
			{
				"doctype": "File",
				"file_name": f"{PREFIX}-{frappe.generate_hash(length=8)}.csv",
				"is_private": 1,
				"content": content,
			}
		).insert(ignore_permissions=True)
		data_import = frappe.get_doc(
			{
				"doctype": "Data Import",
				"reference_doctype": "SG Product Unit",
				"import_type": "Insert New Records",
				"import_file": import_file.file_url,
			}
		).insert()
		frappe.db.commit()  # nosemgrep
		data_import.start_import()
		return data_import.reload()

	def failed_rows(self, data_import) -> list[tuple]:
		"""(row numbers, messages) of the units that were not imported, by row."""
		rows = frappe.get_all(
			"Data Import Log",
			{"data_import": data_import.name, "success": 0},
			["messages", "row_indexes"],
		)
		return sorted((frappe.parse_json(row.row_indexes), row.messages) for row in rows)

	def installed(self, serial_no: str) -> list[tuple]:
		unit = frappe.get_doc("SG Product Unit", serial_no)
		return [(row.slot_name, row.unit_type, row.release, row.source) for row in unit.installed_releases]


class IntegrationTestProductUnitImport(ProductUnitImportTestCase):
	def test_sample_imports_two_units_with_two_units_installed_each(self):
		data_import = self.run_import(self.sample_for_this_site())
		self.assertEqual(data_import.status, "Success")
		ivi, tcu = self.unit_types["DEMO-IVI-100"], self.unit_types["DEMO-TCU-200"]
		self.assertEqual(
			self.installed("TESTPU00000000001"),
			[
				("IVI", ivi, self.releases["SGR-0000002"], "As-Built"),
				("TCU", tcu, self.releases["SGR-0000004"], "As-Built"),
			],
		)
		self.assertEqual(
			self.installed("TESTPU00000000002"),
			[
				("IVI", ivi, self.releases["SGR-0000001"], "As-Built"),
				("TCU", tcu, self.releases["SGR-0000004"], "As-Built"),
			],
		)
		first = frappe.get_doc("SG Product Unit", "TESTPU00000000001")
		self.assertEqual(
			(first.product_model, str(first.manufactured_on), first.plant, first.unit_status),
			(self.models["DEMO-SEDAN"], "2026-04-01", "Demo Plant 1", "In Service"),
		)
		self.assertEqual(str(first.installed_releases[0].installed_on), "2026-04-01 09:00:00")

	def test_a_unit_with_a_wrong_serial_no_is_left_out_with_the_reason(self):
		def break_second_unit(header, row):
			if row[header.index("Serial No")] == "TESTPU00000000002":
				row[header.index("Serial No")] = "TESTPU0000000000I"

		data_import = self.run_import(self.sample_for_this_site(break_second_unit))
		self.assertEqual(data_import.status, "Partial Success")
		self.assertTrue(frappe.db.exists("SG Product Unit", "TESTPU00000000001"))
		self.assertFalse(frappe.db.exists("SG Product Unit", "TESTPU0000000000I"))
		failed = frappe.get_all(
			"Data Import Log",
			{"data_import": data_import.name, "success": 0},
			["messages", "row_indexes"],
		)
		self.assertEqual(len(failed), 1)
		self.assertEqual(frappe.parse_json(failed[0].row_indexes), [4, 5])
		self.assertIn("does not match the rule of product category", failed[0].messages)


class IntegrationTestImportToImpact(ProductUnitImportTestCase):
	"""Units imported with Data Import, through the OSV sync, to the impact report.

	test_main_path makes its units with insert. The SBOMs and the vulnerability are made after the import
	and are not committed (the OSV commit is replaced), so the rollback of delete_records takes them away.
	"""

	def import_sbom(self, release: str, logger_version: str) -> None:
		content = cyclonedx(f"{PREFIX}-{release}", logger_version)
		name = import_content(content, f"{PREFIX}-{release}.cdx.json", subject_release=release)
		frappe.get_doc("SG BOM Document", name).submit()

	def sync(self) -> dict:
		with (
			patch.object(osv, "_request", osv_api),
			patch("supplygraph.sg_vulnerability.osv.frappe.db.commit"),
		):
			return osv.sync_osv(force=True)

	def test_imported_units_reach_the_impact_report(self):
		data_import = self.run_import(self.sample_for_this_site())
		self.assertEqual(data_import.status, "Success")
		# IVI 1.1 has the affected version; IVI 1.0 and TCU 3.2 have the fixed one
		affected = self.releases["SGR-0000002"]
		self.import_sbom(affected, "2.14.1")
		self.import_sbom(self.releases["SGR-0000001"], "2.15.0")
		self.import_sbom(self.releases["SGR-0000004"], "2.15.0")

		result = self.sync()
		self.assertEqual((result["created"], result["exact_matches"]), (1, 1))

		rows = report.execute({"vulnerability": CVE})[1]
		self.assertEqual(
			[(row["release"], row["product_model"], row["units"]) for row in rows],
			[(affected, self.models["DEMO-SEDAN"], 1)],
		)
		units = report.get_units(affected, self.models["DEMO-SEDAN"])
		self.assertEqual([row["serial_no"] for row in units["units"]], ["TESTPU00000000001"])
		self.assertEqual(report.get_units(affected, self.models["DEMO-SUV"]), {"total": 0, "units": []})
		# The SUV was imported with releases that are not affected, and is in no row of the report
		self.assertEqual(self.installed("TESTPU00000000002")[0][2], self.releases["SGR-0000001"])
		self.assertNotIn(self.models["DEMO-SUV"], {row["product_model"] for row in rows})

	def test_rows_that_fail_give_the_reason_and_the_others_are_imported(self):
		frappe.get_doc(
			{
				"doctype": "SG Product Unit",
				"serial_no": "TESTPU00000000003",
				"product_model": self.models["DEMO-SEDAN"],
				"installed_releases": [
					{"unit_type": self.unit_types["DEMO-IVI-100"], "release": self.releases["SGR-0000002"]}
				],
			}
		).insert()
		frappe.db.commit()  # nosemgrep
		header = read_sample()[0]
		ivi, release = self.unit_types["DEMO-IVI-100"], self.releases["SGR-0000002"]
		sedan = self.models["DEMO-SEDAN"]

		def unit(serial_no, model=sedan, unit_type=ivi, release=release):
			values = {
				"Serial No": serial_no,
				"Product Model": model,
				"Unit Type (Installed Releases)": unit_type,
				"Slot Name (Installed Releases)": "IVI",
				"Release (Installed Releases)": release,
			}
			return [values.get(column, "") for column in header]

		rows = [
			unit("TESTPU00000000001"),
			# The same serial number again in the file
			unit("TESTPU00000000001"),
			# Already registered
			unit("TESTPU00000000003"),
			unit("TESTPU00000000004", release="SGR-9999999"),
			unit("TESTPU00000000005", model=f"{PREFIX}-NO-MODEL"),
			unit("TESTPU00000000006", unit_type=""),
			unit("TESTPU00000000007"),
		]
		out = io.StringIO()
		csv.writer(out, lineterminator="\n").writerows([header, *rows])
		data_import = self.run_import(out.getvalue())

		# A product model or a release that does not exist stops the whole import at "Fix issues", with
		# the value and the row. Nothing is imported until those rows are skipped (or the values mapped).
		self.assertEqual(data_import.status, "Pending")
		warnings = sorted(
			(warning["col"], warning["message"])
			for warning in frappe.parse_json(data_import.template_warnings)
		)
		self.assertEqual(len(warnings), 2)
		self.assertIn(
			f'{PREFIX}-NO-MODEL</strong>" is not a valid <strong>Product Model</strong> — row 6',
			warnings[0][1],
		)
		self.assertIn('SGR-9999999</strong>" is not a valid <strong>Release</strong> — row 5', warnings[1][1])
		self.assertFalse(frappe.db.exists("SG Product Unit", "TESTPU00000000001"))

		for row_number in (5, 6):
			# As the form does; the importer reads the row from the file
			data_import.append(
				"skipped_rows", {"row_number": row_number, "row_data": json.dumps(rows[row_number - 2])}
			)
		data_import.save()
		frappe.db.commit()  # nosemgrep
		data_import.start_import()
		data_import.reload()

		self.assertEqual(data_import.status, "Partial Success")
		for serial_no in ("TESTPU00000000001", "TESTPU00000000007"):
			self.assertEqual(self.installed(serial_no), [("IVI", ivi, release, "As-Built")])
		for serial_no in ("TESTPU00000000004", "TESTPU00000000005", "TESTPU00000000006"):
			self.assertFalse(frappe.db.exists("SG Product Unit", serial_no), serial_no)
		# The unit that was there is not changed
		self.assertEqual(self.installed("TESTPU00000000003"), [(None, ivi, release, "As-Built")])
		# The rows of the file: 1 is the header, so the units are rows 2 to 8. Skipped rows have no log.
		failed = self.failed_rows(data_import)
		self.assertEqual([row_indexes for row_indexes, _messages in failed], [[3], [4], [7]])
		reasons = {
			3: "SG Product Unit <strong>TESTPU00000000001</strong> already exists",
			4: "SG Product Unit <strong>TESTPU00000000003</strong> already exists",
			7: "Value missing for: Unit Type",
		}
		for row_indexes, messages in failed:
			self.assertIn(reasons[row_indexes[0]], messages)
