# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

import re
import time
import unittest
from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase, UnitTestCase

from supplygraph.devtools import synthetic
from supplygraph.sg_vulnerability.matching import create_range_matches, version_in_range

SKIP_MESSAGE = (
	"このサイトには合成データがあるため、消さないように合成データのテストを飛ばしました。"
	"テストするには、合成データの無いサイトで実行するか、先に purge() を実行してください"
)

# Expected counts for scale="small"
SMALL_COUNTS = {
	"SG Organization": 5,
	"SG Component": 200,
	"SG Component Version": 1_000,
	"SG Unit Type": 5,
	"SG Release": 20,
	"SG Release Component": 20 * 50,
	"SG Product Category": 1,
	"SG Product Model": 2,
	"SG Model Unit": 3 + 5,
	"SG Product Unit": 1_000,
	"SG Installed Release": 500 * 3 + 500 * 5,
	"SG Vulnerability": 50,
	"SG Affected Range": None,  # depends on the seed; checked in test_small_counts_and_time
	"SG Vulnerability Match": 100,
}

# Reverse lookup from the DocType design document (10.2)
REVERSE_LOOKUP = """
	SELECT pu.product_model, COUNT(DISTINCT pu.name) AS units
	FROM `tabSG Vulnerability Match` vm
	JOIN `tabSG Release Component` rc ON rc.component_version = vm.component_version
	JOIN `tabSG Installed Release` ir ON ir.release = rc.release
	JOIN `tabSG Product Unit` pu ON pu.name = ir.parent
	LEFT JOIN `tabSG Impact Assessment` ia
		ON ia.vulnerability = vm.vulnerability AND ia.release = rc.release AND ia.docstatus = 1
	WHERE vm.vulnerability = %(vuln_id)s
		AND vm.match_status != 'False Positive'
		AND COALESCE(ia.vex_status, 'Under Investigation') IN ('Affected', 'Under Investigation')
	GROUP BY pu.product_model
"""


def synthetic_names(doctype: str) -> list[str]:
	"""Names of the synthetic records of one DocType, matched case-sensitively like purge()."""
	return [
		name
		for d, prefix, condition in synthetic.PURGE_ORDER
		if d == doctype
		for name in synthetic._names(d, prefix, condition, limit=10**8)
	]


def synthetic_counts() -> dict[str, int]:
	return {
		doctype: len(synthetic._names(doctype, prefix, condition, limit=10**8))
		for doctype, prefix, condition in synthetic.PURGE_ORDER
	}


def snapshot() -> dict[str, list]:
	"""Names of every synthetic record, plus the links that decide the reverse lookup."""
	data = {
		doctype: sorted(synthetic._names(doctype, prefix, condition, limit=10**8))
		for doctype, prefix, condition in synthetic.PURGE_ORDER
	}
	data["installed"] = frappe.db.sql(
		"select parent, `release` from `tabSG Installed Release` where name like 'SYN-IR-%%' order by name"
	)
	data["release_components"] = frappe.db.sql(
		"select `release`, component_version from `tabSG Release Component`"
		" where name like 'SGRC-SYN-%%' order by name"
	)
	data["matches"] = frappe.db.sql(
		"select vulnerability, component_version, match_status from `tabSG Vulnerability Match`"
		" where name like 'SGVM-SYN-%%' order by name"
	)
	return data


class UnitTestSyntheticVin(UnitTestCase):
	def test_vin_format(self):
		for index in (1, 2, 33, 999_999, 1_000_000):
			vin = synthetic.make_vin(index)
			self.assertEqual(len(vin), 17)
			self.assertTrue(vin.startswith("SYN"))
			self.assertNotRegex(vin, "[IOQ]")

	def test_vin_is_unique(self):
		vins = {synthetic.make_vin(i) for i in range(1, 5_001)}
		self.assertEqual(len(vins), 5_000)


class IntegrationTestSynthetic(IntegrationTestCase):
	@classmethod
	def setUpClass(cls):
		# purge() commits, so the tests would delete synthetic data made for other work (for example
		# the performance data, which takes about 12 minutes to make again). Leave it alone.
		if synthetic.exists():
			raise unittest.SkipTest(SKIP_MESSAGE)
		super().setUpClass()
		# Registered first, so that rows committed by a failing generate() are removed too
		cls.addClassCleanup(synthetic.purge)
		started = time.monotonic()
		cls.result = synthetic.generate(scale="small", seed=42)
		cls.seconds = time.monotonic() - started

	def ensure_generated(self):
		if not synthetic.exists():
			synthetic.generate(scale="small", seed=42)

	def test_small_counts_and_time(self):
		self.ensure_generated()
		self.assertEqual(self.result["status"], "created")
		self.assertLess(self.seconds, 60)
		counts = synthetic_counts()
		# At least one range per vulnerability; how many more depends on the seed
		self.assertGreaterEqual(counts.pop("SG Affected Range"), SMALL_COUNTS["SG Vulnerability"])
		self.assertEqual(counts, {k: v for k, v in SMALL_COUNTS.items() if k != "SG Affected Range"})

	def test_identifiers(self):
		self.ensure_generated()
		for doctype, field in (
			("SG Organization", "organization_name"),
			("SG Component", "component_name"),
			("SG Unit Type", "unit_part_number"),
			("SG Product Model", "model_code"),
			("SG Release", "release_code"),
			("SG Product Unit", "serial_no"),
		):
			values = frappe.get_all(doctype, filters={"name": ["in", synthetic_names(doctype)]}, pluck=field)
			self.assertTrue(values, doctype)
			self.assertTrue(all(value.startswith("SYN") for value in values), doctype)

		vins = frappe.get_all(
			"SG Product Unit", filters={"name": ["in", synthetic_names("SG Product Unit")]}, pluck="serial_no"
		)
		self.assertEqual(len(vins), SMALL_COUNTS["SG Product Unit"])
		self.assertTrue(all(len(vin) == 17 and not re.search("[IOQ]", vin) for vin in vins))

		components = frappe.get_all(
			"SG Component",
			filters={"name": ["in", synthetic_names("SG Component")]},
			fields=["name", "purl_base"],
		)
		self.assertTrue(all(re.fullmatch(r"pkg:generic/syn-\d+", c.purl_base) for c in components))
		versions = frappe.get_all(
			"SG Component Version",
			filters={"name": ["in", synthetic_names("SG Component Version")]},
			fields=["purl", "version", "component"],
		)
		bases = {c.name: c.purl_base for c in components}
		self.assertTrue(all(v.purl == f"{bases[v.component]}@{v.version}" for v in versions))

	def test_same_seed_gives_same_data(self):
		self.ensure_generated()
		first = snapshot()
		synthetic.purge()
		synthetic.generate(scale="small", seed=42)
		self.assertEqual(snapshot(), first)

	def test_every_unit_installs_old_and_new_releases(self):
		self.ensure_generated()
		# Units of the same ECU have different releases installed
		rows = frappe.db.sql(
			"""select unit_type, count(distinct `release`) from `tabSG Installed Release`
			where name like 'SYN-IR-%%' group by unit_type"""
		)
		self.assertTrue(rows)
		self.assertTrue(all(releases > 1 for _unit_type, releases in rows))

	def test_popular_versions_are_in_half_of_the_releases(self):
		self.ensure_generated()
		releases = SMALL_COUNTS["SG Release"]
		top = frappe.db.sql(
			"""select component_version, count(*) as used from `tabSG Release Component`
			where name like 'SGRC-SYN-%%' group by component_version order by used desc limit %(top)s""",
			{"top": SMALL_COUNTS["SG Component Version"] // 100},
		)
		self.assertTrue(all(used > releases / 2 for _cv, used in top))

	def test_match_status_mix(self):
		self.ensure_generated()
		rows = dict(
			frappe.db.sql(
				"""select match_status, count(*) from `tabSG Vulnerability Match`
				where name like 'SGVM-SYN-%%' group by match_status"""
			)
		)
		self.assertEqual(rows, {"Open": 70, "Confirmed": 20, "False Positive": 10})

	def test_reverse_lookup_finds_units_for_hot_cve(self):
		self.ensure_generated()
		rows = frappe.db.sql(REVERSE_LOOKUP, {"vuln_id": synthetic.HOT_VULN}, as_dict=True)
		units = sum(row.units for row in rows)
		self.assertGreaterEqual(units, 1)
		# About 10% of the units are affected
		self.assertGreater(units, SMALL_COUNTS["SG Product Unit"] * 0.05)
		self.assertLess(units, SMALL_COUNTS["SG Product Unit"] * 0.15)

	def test_generate_twice_asks_for_purge(self):
		self.ensure_generated()
		before = synthetic_counts()
		result = synthetic.generate(scale="small", seed=42)
		self.assertEqual(result["status"], "exists")
		self.assertIn("purge()", result["message"])
		self.assertEqual(synthetic_counts(), before)

	def test_purge_keeps_other_records(self):
		self.ensure_generated()
		# Both match the synthetic prefixes when compared case-insensitively, or by name alone,
		# so purge() must use the case-sensitive match and the product model condition.
		organization = frappe.get_doc(
			{
				"doctype": "SG Organization",
				"organization_name": "syn-org-keep",
				"organization_type": "Supplier",
			}
		).insert()
		category = frappe.get_doc(
			{"doctype": "SG Product Category", "category_name": "Keep Category"}
		).insert()
		model = frappe.get_doc(
			{
				"doctype": "SG Product Model",
				"model_code": "KEEP-MODEL",
				"model_name": "Keep Model",
				"product_category": category.name,
			}
		).insert()
		unit = frappe.get_doc(
			{"doctype": "SG Product Unit", "serial_no": "SYNKEEP0000000001", "product_model": model.name}
		).insert()
		try:
			synthetic.purge()
			self.assertEqual(set(synthetic_counts().values()), {0})
			self.assertFalse(synthetic.exists())
			for doc in (organization, category, model, unit):
				self.assertTrue(frappe.db.exists(doc.doctype, doc.name), doc.name)
		finally:
			for doc in (unit, model, category, organization):
				if frappe.db.exists(doc.doctype, doc.name):
					frappe.delete_doc(doc.doctype, doc.name, force=True)
			# purge() commits, which also committed the records above, so remove them for good.
			frappe.db.commit()  # nosemgrep

	def test_different_seed_gives_different_data(self):
		self.ensure_generated()
		first = snapshot()
		synthetic.purge()
		try:
			synthetic.generate(scale="small", seed=43)
			second = snapshot()
		finally:
			synthetic.purge()
			synthetic.generate(scale="small", seed=42)
		self.assertNotEqual(second["installed"], first["installed"])
		self.assertNotEqual(second["release_components"], first["release_components"])

	def test_units_change_only_the_units(self):
		self.ensure_generated()
		first = snapshot()
		synthetic.purge()
		try:
			synthetic.generate(scale="small", seed=42, units=10)
			second = snapshot()
			self.assertEqual(len(second["SG Product Unit"]), 10)
		finally:
			synthetic.purge()
			synthetic.generate(scale="small", seed=42)
		for key in (
			"release_components",
			"matches",
			"SG Release",
			"SG Component Version",
			"SG Vulnerability",
		):
			self.assertEqual(second[key], first[key], key)

	def test_each_release_has_50_component_versions(self):
		self.ensure_generated()
		per_release = frappe.db.sql(
			"""select count(*) from `tabSG Release Component`
			where name like 'SGRC-SYN-%%' group by `release`"""
		)
		self.assertEqual(len(per_release), SMALL_COUNTS["SG Release"])
		self.assertEqual({count for (count,) in per_release}, {50})

	def test_category_describes_the_vins(self):
		self.ensure_generated()
		category = frappe.db.get_value(
			"SG Product Category", "SYN-CATEGORY", ["unit_label", "serial_pattern"], as_dict=True
		)
		self.assertEqual(category.unit_label, "VIN")
		vins = frappe.get_all(
			"SG Product Unit", filters={"name": ["in", synthetic_names("SG Product Unit")]}, pluck="serial_no"
		)
		self.assertTrue(vins)
		self.assertTrue(all(re.fullmatch(category.serial_pattern, vin) for vin in vins))

	def test_runs_only_on_development_or_test_sites(self):
		self.ensure_generated()
		before = synthetic_counts()
		with patch.dict(frappe.local.conf, {"developer_mode": 0, "allow_tests": 0}):
			with self.assertRaises(frappe.ValidationError):
				synthetic.purge()
			with self.assertRaises(frappe.ValidationError):
				synthetic.generate(scale="small", seed=7)
		self.assertEqual(synthetic_counts(), before)

	def test_negative_units_are_rejected(self):
		with self.assertRaises(frappe.ValidationError):
			synthetic.generate(scale="small", units=-1)

	def test_unknown_scale_is_rejected(self):
		with self.assertRaises(frappe.ValidationError):
			synthetic.generate(scale="huge")

	def test_matches_are_the_versions_in_the_affected_ranges(self):
		self.ensure_generated()
		ranges = frappe.db.sql(
			"""select parent, purl_base, version_range from `tabSG Affected Range`
			where name like 'SYN-AR-%%'"""
		)
		versions = frappe.db.sql(
			"""select cv.name, c.purl_base, cv.version from `tabSG Component Version` cv
			join `tabSG Component` c on c.name = cv.component where cv.name like 'SGCV-SYN-%%'"""
		)
		by_base = {}
		for name, base, version in versions:
			by_base.setdefault(base, []).append((name, version))
		expected = {
			(vulnerability, name)
			for vulnerability, base, version_range in ranges
			for name, version in by_base.get(base, [])
			if version_in_range(version, version_range)
		}
		stored = set(
			frappe.db.sql(
				"""select vulnerability, component_version from `tabSG Vulnerability Match`
				where name like 'SGVM-SYN-%%'"""
			)
		)
		self.assertEqual(len(stored), SMALL_COUNTS["SG Vulnerability Match"])
		self.assertEqual(stored, expected)
		# The matching itself finds nothing that is not stored already
		result = create_range_matches(synthetic_names("SG Vulnerability"))
		self.assertEqual(result, {"created": 0, "unreadable": 0})
		# SYN-CVE-HOT is the only vulnerability of its component version
		hot = frappe.get_all(
			"SG Vulnerability Match", {"vulnerability": synthetic.HOT_VULN}, pluck="component_version"
		)
		self.assertEqual(len(hot), 1)
		self.assertEqual(frappe.db.count("SG Vulnerability Match", {"component_version": hot[0]}), 1)

	def test_severity_follows_the_score(self):
		self.ensure_generated()
		rows = frappe.get_all(
			"SG Vulnerability",
			{"name": ["in", synthetic_names("SG Vulnerability")]},
			["cvss_v3_score", "severity"],
		)
		self.assertEqual(len(rows), SMALL_COUNTS["SG Vulnerability"])
		for row in rows:
			score = row.cvss_v3_score
			expected = (
				"Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"
			)
			self.assertEqual(row.severity, expected, score)

	def test_units_are_built_after_their_releases(self):
		self.ensure_generated()
		late = frappe.db.sql(
			"""select count(*) from `tabSG Installed Release` ir
			join `tabSG Product Unit` pu on pu.name = ir.parent
			join `tabSG Release` r on r.name = ir.`release`
			where ir.name like 'SYN-IR-%%' and ir.source = 'As-Built' and r.released_on > pu.manufactured_on"""
		)[0][0]
		self.assertEqual(late, 0)
		# The dates still spread over the period instead of all moving to the newest release
		days = frappe.db.sql(
			"""select count(distinct manufactured_on) from `tabSG Product Unit`
			where name like binary 'SYN%%' and product_model like binary 'SYN-MODEL-%%'"""
		)[0][0]
		self.assertGreater(days, 300)

	def test_purge_removes_derived_and_added_rows(self):
		self.ensure_generated()
		release, version = frappe.db.get_value(
			"SG Release Component", {"name": ["like", "SGRC-SYN-%"]}, ["release", "component_version"]
		)
		other = frappe.get_all(
			"SG Vulnerability Match",
			{"name": ["like", "SGVM-SYN-%"], "vulnerability": ["!=", synthetic.HOT_VULN]},
			pluck="vulnerability",
			limit=1,
		)[0]
		# Rows with random names, as a sync, an SBOM or a person would add them
		index_row = frappe.get_doc(
			{"doctype": "SG Release Component", "release": release, "component_version": version, "depth": 2}
		).insert(ignore_permissions=True)
		match = frappe.get_doc(
			{
				"doctype": "SG Vulnerability Match",
				"vulnerability": synthetic.HOT_VULN,
				"component_version": version,
				"match_method": "PURL Exact",
				"confidence": "High",
				"match_status": "Open",
			}
		).insert(ignore_permissions=True)
		vulnerability = frappe.get_doc("SG Vulnerability", other)
		vulnerability.append(
			"affected_ranges", {"purl_base": "pkg:generic/added", "version_range": "vers:generic/<9"}
		)
		vulnerability.save(ignore_permissions=True)
		added_range = vulnerability.affected_ranges[-1].name
		self.assertFalse(added_range.startswith("SYN-AR-"))
		frappe.db.commit()  # nosemgrep

		synthetic.purge()
		self.assertFalse(synthetic.exists())
		for doctype, name in (
			("SG Release Component", index_row.name),
			("SG Vulnerability Match", match.name),
			("SG Affected Range", added_range),
		):
			self.assertFalse(frappe.db.exists(doctype, name), doctype)

		# Generating again gives the same data, because nothing of the first run was left behind
		synthetic.generate(scale="small", seed=42)
		self.assertEqual(synthetic_counts()["SG Vulnerability Match"], SMALL_COUNTS["SG Vulnerability Match"])

	def test_purge_stops_when_other_records_point_to_the_data(self):
		self.ensure_generated()
		release = frappe.get_all("SG Release", {"name": ["like", "SGR-SYN-%"]}, pluck="name", limit=1)[0]
		assessment = frappe.get_doc(
			{
				"doctype": "SG Impact Assessment",
				"vulnerability": synthetic.HOT_VULN,
				"release": release,
				"vex_status": "Under Investigation",
			}
		).insert(ignore_permissions=True)
		frappe.db.commit()  # nosemgrep
		try:
			before = synthetic_counts()
			self.assertIn(f"SG Impact Assessment {assessment.name}", synthetic.find_references())
			with self.assertRaises(frappe.ValidationError) as context:
				synthetic.purge()
			self.assertIn(assessment.name, str(context.exception))
			self.assertEqual(synthetic_counts(), before)
		finally:
			frappe.delete_doc("SG Impact Assessment", assessment.name, force=True, ignore_permissions=True)
			frappe.db.commit()  # nosemgrep
		self.assertEqual(synthetic.find_references(), [])


class UnitTestSyntheticSeverity(UnitTestCase):
	def test_bands(self):
		for score, severity in (
			(9.8, "Critical"),
			(9.0, "Critical"),
			(8.9, "High"),
			(7.0, "High"),
			(6.9, "Medium"),
			(4.0, "Medium"),
			(3.9, "Low"),
			(0.1, "Low"),
			(0.0, "None"),
		):
			with self.subTest(score=score):
				self.assertEqual(synthetic.severity_for(score), severity)
