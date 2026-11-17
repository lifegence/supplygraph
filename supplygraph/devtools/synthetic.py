# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

"""Synthetic data for performance checks and automated tests.

Creates organizations, components, releases, product units and vulnerabilities that can be
generated again with the same content from the same seed, and removed with ``purge()``.

	bench --site supplygraph.localhost execute supplygraph.devtools.synthetic.generate --kwargs "{'scale': 'small'}"
	bench --site supplygraph.localhost execute supplygraph.devtools.synthetic.purge

Every identifying string starts with ``SYN`` (names, codes, VINs). Documents named by a naming
series get names such as ``SGC-SYN-0000001``. ``purge()`` finds the records by these prefixes
with a case-sensitive match, so records such as "Synopsys" are never touched. Rows that the app
derives from synthetic records (matches from a sync, the index rebuilt from an SBOM) and child rows
added to synthetic records are removed with them. Records that are not synthetic but point to
synthetic ones (for example an Impact Assessment made by hand for SYN-CVE-HOT) stop ``purge()``
before anything is deleted, so remove those yourself first.

Each vulnerability has affected ranges, and the matches are exactly the component versions in those
ranges, so the stored matches equal what ``create_range_matches`` finds. The severity follows the
CVSS v3 score. A product unit is made on or after the release date of every release it was built with.

Both run only on a site with ``developer_mode`` or ``allow_tests`` enabled, never on production.
"""

import random
import time
from datetime import date, datetime, timedelta
from itertools import accumulate

import frappe
from frappe import _
from frappe.utils import now

COMMIT_EVERY = 10_000
INSERT_CHUNK = 2_000
DELETE_CHUNK = 20_000

HOT_VULN = "SYN-CVE-HOT"
EXISTS_MESSAGE = "合成データが既にあります。先に purge() を実行してください"

# VIN characters: digits and capital letters without I, O and Q
VIN_CHARS = "0123456789ABCDEFGHJKLMNPRSTUVWXYZ"
# Stored in SG Product Category.serial_pattern, which holds a regular expression for the serial numbers
VIN_PATTERN = "^[0-9A-HJ-NPR-Z]{17}$"

SCALES = {
	"small": {
		"organizations": 5,
		"components": 200,
		"component_versions": 1_000,
		"unit_types": 5,
		"releases": 20,
		"components_per_release": 50,
		"product_models": 2,
		"slots_per_model": (3, 5),
		"units": 1_000,
		"vulnerabilities": 50,
		"matches": 100,
	},
	"perf": {
		"organizations": 50,
		"components": 20_000,
		"component_versions": 100_000,
		"unit_types": 30,
		"releases": 300,
		"components_per_release": 2_000,
		"product_models": 10,
		"slots_per_model": (10,),
		"units": 1_000_000,
		"vulnerabilities": 2_000,
		"matches": 10_000,
	},
}

# Share of component versions treated as "popular" and how often each of them is used
HOT_SHARE = 0.01
HOT_RELEASE_SHARE = 7  # out of 10 releases
# Share of product units that install the release containing the SYN-CVE-HOT component
HOT_UNIT_SHARE = 0.1
MATCH_STATUS_SHARES = (("Open", 7), ("Confirmed", 2), ("False Positive", 1))

BASE_DATE = date(2025, 1, 1)

# (doctype, name prefix, extra condition). Children first so that parents are removed last.
PURGE_ORDER = (
	("SG Installed Release", "SYN-IR-", None),
	("SG Product Unit", "SYN", "product_model like binary 'SYN-MODEL-%%'"),
	("SG Model Unit", "SYN-MU-", None),
	("SG Product Model", "SYN-MODEL-", None),
	("SG Release Component", "SGRC-SYN-", None),
	("SG Vulnerability Match", "SGVM-SYN-", None),
	("SG Affected Range", "SYN-AR-", None),
	("SG Vulnerability", "SYN-CVE-", None),
	("SG Release", "SGR-SYN-", None),
	("SG Component Version", "SGCV-SYN-", None),
	("SG Component", "SGC-SYN-", None),
	("SG Unit Type", "SYN-ECU-", None),
	("SG Product Category", "SYN-CATEGORY", None),
	("SG Organization", "SYN-ORG-", None),
)
SYNTHETIC = {doctype: (prefix, condition) for doctype, prefix, condition in PURGE_ORDER}
# Rows that the app derives from synthetic records, such as matches found by a sync or the index rebuilt
# from an SBOM. Their names are random, so they are found by the synthetic records they point to.
DERIVED_LINKS = {
	"SG Release Component": (("release", "SG Release"), ("component_version", "SG Component Version")),
	"SG Vulnerability Match": (
		("vulnerability", "SG Vulnerability"),
		("component_version", "SG Component Version"),
	),
}
REFERENCE_LIMIT = 5
# CVSS v3.1 qualitative rating: (lowest score, severity)
SEVERITY_BANDS = ((9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"))


def generate(scale: str = "small", seed: int = 42, units: int | None = None) -> dict:
	"""Create synthetic data. The same scale, seed and units always give the same data."""
	_check_site()
	if scale not in SCALES:
		frappe.throw(f"Unknown scale: {scale}. Use one of {', '.join(SCALES)}")

	config = dict(SCALES[scale])
	if units is not None:
		if int(units) < 0:
			frappe.throw(f"units must be 0 or more: {units}")
		config["units"] = int(units)

	if exists():
		print(EXISTS_MESSAGE)
		return {"status": "exists", "message": EXISTS_MESSAGE}

	generator = _Generator(config, random.Random(seed))
	generator.run()
	return {"status": "created", "counts": generator.writer.counts, "seconds": generator.writer.elapsed()}


def purge() -> dict:
	"""Delete every record created by generate(), with the rows derived from them. Other records are kept.

	Stops before deleting anything when records outside the synthetic data point to it."""
	_check_site()
	references = find_references()
	if references:
		frappe.throw(
			_(
				"Records outside the synthetic data point to it, so nothing was deleted. Remove them first: {0}"
			).format(", ".join(references))
		)
	started = time.monotonic()
	counts = {}
	for doctype, prefix, condition in PURGE_ORDER:
		# Child rows go before their parent, which the query needs to find them
		counts[doctype] = _delete_children(doctype)
		counts[doctype] += _delete(doctype, prefix, condition)
		counts[doctype] += _delete_derived(doctype)
		_log(f"purged {doctype}: {counts[doctype]} rows", started)
	# Rows were deleted with SQL, so drop cached documents that may still hold them
	frappe.clear_cache()
	return {"status": "purged", "counts": counts}


def find_references(limit: int = REFERENCE_LIMIT) -> list[str]:
	"""Records outside the synthetic data that link to it, as "DocType name"."""
	skip = set(SYNTHETIC) | set(DERIVED_LINKS)
	found = []
	for parent, fieldname, target in _link_fields():
		if parent in skip:
			continue
		subquery, params = _subquery(target)
		found += [
			f"{parent} {name}"
			for name in frappe.db.sql_list(
				f"select name from `tab{parent}` where `{fieldname}` in ({subquery}) limit {int(limit)}",
				params,
			)
		]
	for parent, fieldname, doctype_field in _dynamic_link_fields():
		if parent in skip:
			continue
		for target in SYNTHETIC:
			subquery, params = _subquery(target)
			query = (
				f"select name from `tab{parent}` where `{doctype_field}` = %(target_doctype)s"
				f" and `{fieldname}` in ({subquery}) limit {int(limit)}"
			)
			names = frappe.db.sql_list(query, {**params, "target_doctype": target})
			found += [f"{parent} {name}" for name in names]
	return found


def severity_for(score: float) -> str:
	return next((severity for lowest, severity in SEVERITY_BANDS if score >= lowest), "None")


def exists() -> bool:
	"""True when synthetic data from an earlier generate() is still in the database."""
	return any(_names(doctype, prefix, condition, limit=1) for doctype, prefix, condition in PURGE_ORDER)


def make_vin(index: int) -> str:
	"""A 17 character VIN that starts with SYN and has no I, O or Q."""
	digits = []
	for _position in range(14):
		index, remainder = divmod(index, len(VIN_CHARS))
		digits.append(VIN_CHARS[remainder])
	if index:
		raise ValueError("Index is too large for a 17 character VIN")
	return "SYN" + "".join(reversed(digits))


def _check_site() -> None:
	# generate() and purge() add or delete millions of rows, so a production site must never run them.
	# Development sites have developer_mode; CI and test sites have allow_tests (needed by run-tests).
	if not (frappe.conf.developer_mode or frappe.conf.allow_tests):
		frappe.throw(
			_("Synthetic data can be created or deleted only on a site with developer_mode or allow_tests")
		)


def _names(doctype: str, prefix: str, condition: str | None, limit: int) -> list[str]:
	# doctype and condition come only from PURGE_ORDER above, never from user input.
	# The first LIKE uses the primary key index; LIKE BINARY keeps the match case-sensitive.
	extra = f" and {condition}" if condition else ""
	return frappe.db.sql_list(
		f"select name from `tab{doctype}` where name like %(prefix)s and name like binary %(prefix)s"
		f"{extra} limit {int(limit)}",
		{"prefix": prefix + "%"},
	)


def _subquery(doctype: str, key: str = "prefix") -> tuple[str, dict]:
	"""SQL that selects the names of the synthetic records of a DocType, with its parameters."""
	prefix, condition = SYNTHETIC[doctype]
	extra = f" and {condition}" if condition else ""
	return (
		f"select name from `tab{doctype}` where name like %({key})s and name like binary %({key})s{extra}",
		{key: prefix + "%"},
	)


def _link_fields() -> list[tuple[str, str, str]]:
	"""(DocType, field, linked DocType) of every Link field that points to a synthetic DocType."""
	filters = {"fieldtype": "Link", "options": ["in", list(SYNTHETIC)], "is_virtual": 0}
	fields = frappe.get_all("DocField", filters, ["parent", "fieldname", "options"], as_list=True)
	fields += frappe.get_all("Custom Field", filters, ["dt", "fieldname", "options"], as_list=True)
	return [field for field in fields if _has_table(field[0])]


def _dynamic_link_fields() -> list[tuple[str, str, str]]:
	"""(DocType, field, field holding the DocType) of the Dynamic Link fields of this app's DocTypes."""
	filters = {"fieldtype": "Dynamic Link", "parent": ["like", "SG %"], "is_virtual": 0}
	fields = frappe.get_all("DocField", filters, ["parent", "fieldname", "options"], as_list=True)
	return [field for field in fields if _has_table(field[0])]


def _has_table(doctype: str) -> bool:
	meta = frappe.get_meta(doctype)
	return not (meta.issingle or meta.is_virtual)


def _delete_children(doctype: str) -> int:
	"""Child rows of the synthetic records whose names do not show they are synthetic."""
	total = 0
	for table in frappe.get_meta(doctype).get_table_fields():
		subquery, params = _subquery(doctype)
		total += _delete_where(
			table.options,
			f"parenttype = %(parenttype)s and parent in ({subquery})",
			{**params, "parenttype": doctype},
		)
	return total


def _delete_derived(doctype: str) -> int:
	if doctype not in DERIVED_LINKS:
		return 0
	conditions, params = [], {}
	for i, (fieldname, target) in enumerate(DERIVED_LINKS[doctype]):
		subquery, values = _subquery(target, key=f"prefix{i}")
		conditions.append(f"`{fieldname}` in ({subquery})")
		params.update(values)
	return _delete_where(doctype, " or ".join(conditions), params)


def _delete_where(doctype: str, where: str, params: dict) -> int:
	# where comes only from the functions above, which build it from PURGE_ORDER and DocType metadata
	total = 0
	while names := frappe.db.sql_list(
		f"select name from `tab{doctype}` where {where} limit {DELETE_CHUNK}", params
	):
		frappe.db.delete(doctype, {"name": ("in", names)})
		frappe.db.commit()  # nosemgrep
		total += len(names)
	return total


def _delete(doctype: str, prefix: str, condition: str | None) -> int:
	# Searching from the start each time took the same time as continuing after the last name
	# (126 s for the perf data either way), so the simpler query is kept.
	total = 0
	while names := _names(doctype, prefix, condition, limit=DELETE_CHUNK):
		frappe.db.delete(doctype, {"name": ("in", names)})
		# Commit each chunk: a single transaction for 10 million rows exhausts the undo log.
		frappe.db.commit()  # nosemgrep
		total += len(names)
	return total


def _log(message: str, started: float) -> None:
	print(f"[synthetic] {message} ({time.monotonic() - started:.1f}s)")


class _Writer:
	"""Buffers rows per DocType, inserts them with bulk_insert and commits every 10,000 rows."""

	def __init__(self):
		self.started = time.monotonic()
		self.now = now()
		self.user = frappe.session.user
		self.fields: dict[str, list[str]] = {}
		self.buffers: dict[str, list[tuple]] = {}
		self.counts: dict[str, int] = {}

	def add(self, doctype: str, values: dict) -> None:
		if doctype not in self.fields:
			self.fields[doctype] = [*values, "creation", "modified", "owner", "modified_by"]
			self.buffers[doctype] = []
			self.counts[doctype] = 0
		self.buffers[doctype].append((*values.values(), self.now, self.now, self.user, self.user))
		if len(self.buffers[doctype]) >= COMMIT_EVERY:
			self.flush(doctype)

	def flush(self, doctype: str) -> None:
		rows = self.buffers[doctype]
		if not rows:
			return
		frappe.db.bulk_insert(doctype, self.fields[doctype], rows, chunk_size=INSERT_CHUNK)
		# Commit every 10,000 rows, so that a long perf run keeps its progress.
		frappe.db.commit()  # nosemgrep
		self.counts[doctype] += len(rows)
		self.buffers[doctype] = []
		_log(f"{doctype}: {self.counts[doctype]} rows", self.started)

	def flush_all(self) -> None:
		for doctype in self.buffers:
			self.flush(doctype)

	def elapsed(self) -> float:
		return round(time.monotonic() - self.started, 1)


class _Generator:
	def __init__(self, config: dict, rng: random.Random):
		self.config = config
		self.rng = rng
		self.writer = _Writer()

	def run(self) -> None:
		self.organizations()
		self.components()
		self.unit_types()
		self.releases()
		self.product_models()
		self.release_components()
		self.vulnerabilities()
		self.matches()
		# Last, so that changing the number of units changes nothing else
		self.product_units()
		self.writer.flush_all()
		_log("done", self.writer.started)

	def organizations(self) -> None:
		self.org_names = [f"SYN-ORG-{i:03d}" for i in range(1, self.config["organizations"] + 1)]
		for i, name in enumerate(self.org_names):
			self.writer.add(
				"SG Organization",
				{
					"name": name,
					"organization_name": name,
					"organization_type": "Manufacturer" if i == 0 else "Supplier",
					"tier": "N/A" if i == 0 else ("Tier 1" if i % 2 else "Tier 2"),
					"is_active": 1,
				},
			)
		self.suppliers = self.org_names[1:] or self.org_names

	def components(self) -> None:
		count = self.config["components"]
		versions_per_component = self.config["component_versions"] // count
		self.versions_per_component = versions_per_component
		self.cv_names: list[str] = []
		self.cv_component: list[int] = []
		self.cv_versions: list[str] = []
		self.purl_bases: list[str] = []
		for c in range(1, count + 1):
			name = f"SGC-SYN-{c:07d}"
			purl_base = f"pkg:generic/syn-{c}"
			supplier = self.rng.choice(self.suppliers)
			self.purl_bases.append(purl_base)
			self.writer.add(
				"SG Component",
				{
					"name": name,
					"naming_series": "SGC-.#######",
					"component_name": f"SYN-COMP-{c:06d}",
					"component_type": "library",
					"purl_base": purl_base,
					"supplier": supplier,
				},
			)
			for v in range(versions_per_component):
				cv_name = f"SGCV-SYN-{len(self.cv_names) + 1:09d}"
				version = f"1.{v}.0"
				self.cv_names.append(cv_name)
				self.cv_component.append(c - 1)
				self.cv_versions.append(version)
				self.writer.add(
					"SG Component Version",
					{
						"name": cv_name,
						"naming_series": "SGCV-.#########",
						"component": name,
						"version": version,
						"purl": f"{purl_base}@{version}",
						"supplier": supplier,
						"support_status": "Active",
					},
				)

	def unit_types(self) -> None:
		self.unit_type_names = [f"SYN-ECU-{i:02d}" for i in range(1, self.config["unit_types"] + 1)]
		for name in self.unit_type_names:
			self.writer.add(
				"SG Unit Type",
				{
					"name": name,
					"unit_part_number": name,
					"unit_name": name.replace("-", " "),
					"supplier": self.rng.choice(self.suppliers),
				},
			)

	def releases(self) -> None:
		per_type = self.config["releases"] // len(self.unit_type_names)
		self.release_names: list[str] = []
		self.releases_by_type: list[list[str]] = []
		self.release_dates: dict[str, date] = {}
		for t, unit_type in enumerate(self.unit_type_names):
			names = []
			for v in range(per_type):
				name = f"SGR-SYN-{len(self.release_names) + 1:07d}"
				released_on = BASE_DATE + timedelta(days=60 * v)
				self.release_dates[name] = released_on
				self.writer.add(
					"SG Release",
					{
						"name": name,
						"naming_series": "SGR-.#######",
						"release_code": f"SYN-REL-{t + 1:02d}",
						"version": f"{v + 1}.0.0",
						"release_type": "Software",
						"unit_type": unit_type,
						"release_status": "Released",
						"released_on": released_on,
						"previous_release": names[-1] if names else None,
					},
				)
				names.append(name)
				self.release_names.append(name)
			self.releases_by_type.append(names)

		# Units choose between old and new releases of the same ECU. The oldest release of the first
		# unit type goes to HOT_UNIT_SHARE of the units and carries the SYN-CVE-HOT component.
		self.release_weights = []
		for t, names in enumerate(self.releases_by_type):
			if t == 0:
				rest = (1 - HOT_UNIT_SHARE) / max(len(names) - 1, 1)
				weights = [HOT_UNIT_SHARE] + [rest] * (len(names) - 1)
			else:
				weights = [v + 1 for v in range(len(names))]
			self.release_weights.append(weights)
		self.hot_release = self.releases_by_type[0][0]

	def product_models(self) -> None:
		category = "SYN-CATEGORY"
		self.writer.add(
			"SG Product Category",
			{
				"name": category,
				"category_name": category,
				"unit_label": "VIN",
				"serial_pattern": VIN_PATTERN,
			},
		)
		slot_counts = self.config["slots_per_model"]
		self.model_names: list[str] = []
		self.model_slots: list[list[int]] = []
		slot_row = 0
		for m in range(self.config["product_models"]):
			name = f"SYN-MODEL-{m + 1:02d}"
			slots = slot_counts[m % len(slot_counts)]
			# Every model has the first unit type, so that SYN-CVE-HOT can reach units of every model
			types = [0, *self.rng.sample(range(1, len(self.unit_type_names)), slots - 1)]
			self.model_names.append(name)
			self.model_slots.append(types)
			self.writer.add(
				"SG Product Model",
				{
					"name": name,
					"model_code": name,
					"model_name": name.replace("-", " "),
					"product_category": category,
					"manufacturer": self.org_names[0],
					"lifecycle_status": "In Production",
				},
			)
			for idx, t in enumerate(types, start=1):
				slot_row += 1
				self.writer.add(
					"SG Model Unit",
					{
						"name": f"SYN-MU-{slot_row:06d}",
						"parent": name,
						"parenttype": "SG Product Model",
						"parentfield": "unit_slots",
						"idx": idx,
						"unit_type": self.unit_type_names[t],
						"slot_name": f"SLOT-{idx:02d}",
						"default_release": self.releases_by_type[t][-1],
					},
				)

	def product_units(self) -> None:
		installed_row = 0
		cumulative = [_cumulative(weights) for weights in self.release_weights]
		for u in range(self.config["units"]):
			m = u % len(self.model_names)
			vin = make_vin(u + 1)
			slots = self.model_slots[m]
			releases = [
				self.rng.choices(self.releases_by_type[t], cum_weights=cumulative[t])[0] for t in slots
			]
			# As-Built: a unit cannot be built with a release that came out later
			newest = max(self.release_dates[release] for release in releases)
			self.writer.add(
				"SG Product Unit",
				{
					"name": vin,
					"serial_no": vin,
					"product_model": self.model_names[m],
					"manufactured_on": max(BASE_DATE + timedelta(days=u % 600), newest),
					"unit_status": "In Service",
				},
			)
			for idx, (t, release) in enumerate(zip(slots, releases, strict=True), start=1):
				installed_row += 1
				self.writer.add(
					"SG Installed Release",
					{
						"name": f"SYN-IR-{installed_row:09d}",
						"parent": vin,
						"parenttype": "SG Product Unit",
						"parentfield": "installed_releases",
						"idx": idx,
						"unit_type": self.unit_type_names[t],
						"slot_name": f"SLOT-{idx:02d}",
						"release": release,
						"source": "As-Built",
					},
				)

	def release_components(self) -> None:
		total = len(self.cv_names)
		hot_count = max(1, round(total * HOT_SHARE))
		picked = self.rng.sample(range(total), hot_count + 1)
		self.hot_versions, self.hot_target = picked[:hot_count], picked[hot_count]
		excluded = set(picked)
		pool = [i for i in range(total) if i not in excluded]
		per_release = self.config["components_per_release"]

		row = 0
		for r, release in enumerate(self.release_names):
			# Each popular version is in 7 of every 10 releases: the worst case for the reverse lookup
			chosen = [h for k, h in enumerate(self.hot_versions) if (r + k) % 10 < HOT_RELEASE_SHARE]
			if release == self.hot_release:
				chosen.append(self.hot_target)
			chosen += self.rng.sample(pool, per_release - len(chosen))
			for i in chosen:
				row += 1
				self.writer.add(
					"SG Release Component",
					{
						"name": f"SGRC-SYN-{row:09d}",
						"release": release,
						"component_version": self.cv_names[i],
						"depth": 1,
					},
				)

	def vulnerabilities(self) -> None:
		self.vuln_names = [HOT_VULN] + [
			f"SYN-CVE-2026-{i:05d}" for i in range(1, self.config["vulnerabilities"])
		]
		ranges = self.affected_ranges()
		row = 0
		for i, name in enumerate(self.vuln_names, start=1):
			score = 9.8 if name == HOT_VULN else round(self.rng.uniform(2.0, 9.9), 1)
			self.writer.add(
				"SG Vulnerability",
				{
					"name": name,
					"vuln_id": name,
					"source": "Manual",
					"title": f"Synthetic vulnerability {name}",
					"published_on": datetime(2026, 1, 1) + timedelta(hours=i),
					"cvss_v3_score": score,
					"severity": severity_for(score),
				},
			)
			for idx, (component, version_range) in enumerate(ranges[name], start=1):
				row += 1
				self.writer.add(
					"SG Affected Range",
					{
						"name": f"SYN-AR-{row:06d}",
						"parent": name,
						"parenttype": "SG Vulnerability",
						"parentfield": "affected_ranges",
						"idx": idx,
						"purl_base": self.purl_bases[component],
						"version_range": version_range,
					},
				)

	def affected_ranges(self) -> dict[str, list[tuple[int, str]]]:
		"""Give each vulnerability ranges so that exactly `matches` component versions fall in them.

		Versions of a component are 1.0.0, 1.1.0, ... so "<1.k.0" holds the first k of them. The component
		of the SYN-CVE-HOT version is left to SYN-CVE-HOT alone. Vulnerabilities left over when the
		count is reached get a range below every version in the catalog, so they match nothing."""
		per_component = self.versions_per_component
		hot_component = self.cv_component[self.hot_target]
		ranges = {HOT_VULN: [(hot_component, f"vers:generic/={self.cv_versions[self.hot_target]}")]}
		self.match_pairs = [(HOT_VULN, self.hot_target)]
		others = self.vuln_names[1:]
		components = [c for c in range(len(self.purl_bases)) if c != hot_component]
		remaining = self.config["matches"] - 1
		if remaining > 0 and not (others and components):
			raise ValueError("matches needs at least two vulnerabilities and two components")
		for name in others:
			ranges[name] = []
		while remaining > 0:
			for name in others:
				if remaining <= 0:
					break
				used = {component for component, _range in ranges[name]}
				if len(used) == len(components):
					continue
				component = self.rng.choice(components)
				while component in used:
					component = self.rng.choice(components)
				upper = min(self.rng.randint(1, max(per_component - 1, 1)), remaining)
				ranges[name].append((component, f"vers:generic/<1.{upper}.0"))
				self.match_pairs += [(name, component * per_component + v) for v in range(upper)]
				remaining -= upper
		for name in others:
			if not ranges[name]:
				ranges[name].append((self.rng.choice(components), "vers:generic/<1.0.0"))
		return ranges

	def matches(self) -> None:
		total = len(self.match_pairs)
		statuses = [status for status, share in MATCH_STATUS_SHARES for _ in range(total * share // 10)]
		statuses += ["Open"] * (total - len(statuses))
		statuses.remove("Open")  # the SYN-CVE-HOT match
		self.rng.shuffle(statuses)

		for row, ((vulnerability, cv), status) in enumerate(
			zip(self.match_pairs, ["Open", *statuses], strict=True), 1
		):
			self.writer.add(
				"SG Vulnerability Match",
				{
					"name": f"SGVM-SYN-{row:07d}",
					"vulnerability": vulnerability,
					"component_version": self.cv_names[cv],
					# What create_range_matches stores for a generic range
					"match_method": "PURL Range",
					"confidence": "Medium",
					"match_status": status,
				},
			)


def _cumulative(weights: list[float]) -> list[float]:
	return list(accumulate(weights))
