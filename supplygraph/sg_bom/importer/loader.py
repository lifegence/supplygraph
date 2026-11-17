# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Store a ParsedBom. Rows are bulk inserted, because an SBOM can hold tens of thousands of components."""

from collections import Counter

import frappe
from frappe import _
from frappe.model.naming import make_autoname
from frappe.utils import cint, now

from supplygraph.sg_bom.importer.model import (
	NOASSERTION,
	Issue,
	ParsedBom,
	ParsedComponent,
	is_version_constraint,
)
from supplygraph.sg_catalog.component_merge import mark_duplicates

DATA_LENGTH = 140  # varchar size of a Data field
DEFAULT_LIFECYCLE = "Analyzed"
FIND_CHUNK = 1000
COMPONENT_SERIES = "SGC-.#######"
VERSION_SERIES = "SGCV-.#########"
# SG Component Version fields filled from the SBOM when they are empty
VERSION_FIELDS = (
	"cpe",
	"file_name",
	"download_location",
	"license_declared",
	"license_expression",
	"license_concluded",
	"copyright_text",
	"supplier",
)


def load_bom(
	parsed: ParsedBom,
	bom_type: str,
	sha256: str | None = None,
	subject_release: str | None = None,
	source_file: str | None = None,
) -> str:
	loader = _Loader(parsed)
	return loader.run(bom_type, sha256, subject_release, source_file)


class _Loader:
	def __init__(self, parsed: ParsedBom):
		self.parsed = parsed
		self.issues: list[Issue] = list(parsed.issues)
		self.base_row = {
			"creation": now(),
			"modified": now(),
			"owner": frappe.session.user,
			"modified_by": frappe.session.user,
			"docstatus": 0,
			"idx": 0,
		}

	def run(self, bom_type, sha256, subject_release, source_file) -> str:
		parsed = self.parsed
		self._drop_long_purls()
		self._check_lengths()
		self._record_version_constraints()
		organizations = self._organizations()
		components = self._components(organizations)
		versions = self._versions(components, organizations)
		self._apply_defaults()

		primary = versions.get(parsed.primary_ref)
		document = frappe.get_doc(
			{
				"doctype": "SG BOM Document",
				"bom_type": bom_type,
				"format": parsed.format,
				"spec_version": parsed.spec_version,
				"serial_number": parsed.serial_number,
				"bom_version": cint(parsed.bom_version) or None,
				"lifecycle_phase": parsed.lifecycle_phase,
				"author_name": parsed.author_name,
				"supplier_org": organizations.get(parsed.supplier),
				"bom_timestamp": parsed.timestamp,
				"primary_component": primary,
				"subject_release": subject_release,
				"source_file": source_file,
				"source_sha256": sha256,
				"import_status": "Parsed",
				"entry_count": len(parsed.components),
			}
		)
		document.insert()

		entries = self._entries(document.name, versions, organizations)
		self._dependencies(document.name, entries)
		self._link_external_boms(document.name, entries)
		self._link_waiting_entries(document)
		self._record_issues(document.name)
		mark_duplicates()
		return document.name

	def _drop_long_purls(self) -> None:
		for component in self.parsed.components:
			if component.purl and len(component.purl) > DATA_LENGTH:
				self.issues.append(
					Issue("IMP-LONG-PURL", f"PURL is too long to store: {component.purl}", component.ref)
				)
				component.purl = component.purl_base = None

	def _record_version_constraints(self) -> None:
		for component in self.parsed.components:
			if is_version_constraint(component.version):
				self.issues.append(
					Issue(
						"IMP-VERSION-RANGE",
						"Version is a range, not the installed version, so it is not checked against OSV",
					)
				)

	def _check_lengths(self) -> None:
		for component in self.parsed.components:
			for label, value in (("name", component.name), ("version", component.version)):
				if len(value) > DATA_LENGTH:
					frappe.throw(
						_("Component {0} has a {1} over {2} characters").format(
							component.ref, label, DATA_LENGTH
						)
					)
			for attribute in ("cpe", "file_name", "license_declared"):
				value = getattr(component, attribute)
				if value and len(value) > DATA_LENGTH:
					self.issues.append(
						Issue("IMP-LONG-VALUE", f"{attribute} is too long to store", component.ref)
					)
					setattr(component, attribute, None)

	def _apply_defaults(self) -> None:
		parsed = self.parsed
		if not parsed.lifecycle_phase:
			parsed.lifecycle_phase = DEFAULT_LIFECYCLE
			self.issues.append(
				Issue("IMP-LIFECYCLE", f"No SBOM type in the file; set to {DEFAULT_LIFECYCLE}")
			)
		if not parsed.author_name:
			parsed.author_name = NOASSERTION
			self.issues.append(Issue("IMP-AUTHOR", "No SBOM author in the file"))
		if not parsed.timestamp:
			parsed.timestamp = frappe.utils.now_datetime()
			self.issues.append(
				Issue("IMP-TIMESTAMP", "No readable timestamp in the file; set to the import time")
			)

	def _organizations(self) -> dict[str, str]:
		names = {component.supplier for component in self.parsed.components if component.supplier}
		if self.parsed.supplier:
			names.add(self.parsed.supplier)
		names = {name for name in names if len(name) <= DATA_LENGTH}
		found = set(_find("SG Organization", "name", names))
		rows = [
			{"name": name, "organization_name": name, "organization_type": "Supplier", "is_active": 1}
			for name in sorted(names - found)
		]
		self._insert("SG Organization", rows)
		return {name: name for name in names}

	def _components(self, organizations: dict[str, str]) -> dict[str, str]:
		"""Return the SG Component name for each component ref, creating the missing ones."""
		parsed = self.parsed
		purls = {c.purl_base for c in parsed.components if c.purl_base}
		names = {c.name for c in parsed.components if not c.purl_base}
		# Components merged earlier come back to the record they were merged into
		by_purl = _find("SG Component Alias", "alias_purl_base", purls, "parent")
		by_purl.update(_find("SG Component", "purl_base", purls))
		by_name = _find("SG Component Alias", "alias_name", names, "parent")
		by_name.update(_find_without_purl(names))
		rows, result = [], {}
		for component in parsed.components:
			lookup = by_purl if component.purl_base else by_name
			key = component.purl_base or component.name
			if key not in lookup:
				lookup[key] = make_autoname(COMPONENT_SERIES, "SG Component")
				rows.append(
					{
						"name": lookup[key],
						"naming_series": COMPONENT_SERIES,
						"component_name": component.name,
						"component_type": component.component_type,
						"purl_base": component.purl_base,
						"supplier": organizations.get(component.supplier),
					}
				)
			result[component.ref] = lookup[key]
		self._insert("SG Component", rows)
		return result

	def _versions(self, components: dict[str, str], organizations: dict[str, str]) -> dict[str, str]:
		"""Return the SG Component Version name for each component ref, creating the missing ones."""
		parsed = self.parsed
		existing = _existing_versions(set(components.values()), {c.purl for c in parsed.components if c.purl})
		by_key = {(row.component, row.version): row for row in existing}
		by_purl = {row.purl: row for row in existing if row.purl}
		rows, hash_rows, result, seen_new = [], [], {}, set()
		for component in parsed.components:
			key = (components[component.ref], component.version)
			row = by_key.get(key) or by_purl.get(component.purl)
			if row:
				result[component.ref] = row.name
				if row.name not in seen_new:
					self._fill_empty_fields(row, component, organizations)
				continue
			name = make_autoname(VERSION_SERIES, "SG Component Version")
			values = self._version_values(component, organizations)
			rows.append(
				{
					"name": name,
					"naming_series": VERSION_SERIES,
					"component": key[0],
					"version": component.version,
					"purl": component.purl,
					**values,
				}
			)
			for index, (algorithm, value) in enumerate(component.hashes, 1):
				hash_rows.append(
					{
						"name": frappe.generate_hash(length=10),
						"parent": name,
						"parenttype": "SG Component Version",
						"parentfield": "hashes",
						"idx": index,
						"algorithm": algorithm,
						"hash_value": value,
					}
				)
			new_row = frappe._dict(
				name=name, component=key[0], version=component.version, purl=component.purl, **values
			)
			by_key[key] = new_row
			if component.purl:
				by_purl[component.purl] = new_row
			seen_new.add(name)
			result[component.ref] = name
		self._insert("SG Component Version", rows)
		self._insert("SG Hash", hash_rows)
		return result

	def _version_values(self, component: ParsedComponent, organizations: dict[str, str]) -> dict:
		concluded, expression = self._concluded_license(component.license_concluded)
		return {
			"cpe": component.cpe,
			"file_name": component.file_name,
			"download_location": component.download_location,
			"license_declared": component.license_declared,
			"license_concluded": concluded,
			"license_expression": expression,
			"copyright_text": component.copyright_text,
			"supplier": organizations.get(component.supplier),
		}

	def _concluded_license(self, value: str | None) -> tuple[str | None, str | None]:
		"""Link a known single license; anything else stays as an expression."""
		if not value:
			return None, None
		if frappe.db.exists("SG License", value):
			return value, None
		if len(value) > DATA_LENGTH:
			self.issues.append(
				Issue("IMP-LONG-VALUE", f"Concluded license is too long to store: {value[:60]}")
			)
			return None, None
		return None, value

	def _fill_empty_fields(self, row, component: ParsedComponent, organizations: dict[str, str]) -> None:
		values = self._version_values(component, organizations)
		updates = {
			field: values[field] for field in VERSION_FIELDS if values.get(field) and not row.get(field)
		}
		if updates:
			frappe.db.set_value("SG Component Version", row.name, updates, update_modified=True)
			row.update(updates)

	def _entries(
		self, document: str, versions: dict[str, str], organizations: dict[str, str]
	) -> dict[str, str]:
		parsed = self.parsed
		direct = {to_ref for from_ref, to_ref, _kind in parsed.relations if from_ref == parsed.primary_ref}
		rows, result = [], {}
		for component in parsed.components:
			name = frappe.generate_hash(length=10)
			result[component.ref] = name
			rows.append(
				{
					"name": name,
					"bom_document": document,
					"component_version": versions[component.ref],
					"bom_ref": component.ref if len(component.ref) <= DATA_LENGTH else None,
					"scope": component.scope,
					"is_direct": 1 if component.ref in direct else 0,
					"supplier": organizations.get(component.supplier),
					"external_bom_ref": component.external_bom_ref,
				}
			)
		self._insert("SG BOM Entry", rows)
		return result

	def _dependencies(self, document: str, entries: dict[str, str]) -> None:
		seen = set()
		rows = []
		for from_ref, to_ref, relationship in self.parsed.relations:
			key = (from_ref, to_ref, relationship)
			if key in seen:
				continue
			seen.add(key)
			rows.append(
				{
					"name": frappe.generate_hash(length=10),
					"bom_document": document,
					"from_entry": entries[from_ref],
					"to_entry": entries[to_ref],
					"relationship": relationship,
				}
			)
		self._insert("SG Dependency", rows)

	def _link_external_boms(self, document: str, entries: dict[str, str]) -> None:
		"""Point entries to the external SBOMs that are already imported."""
		references = {c.external_bom_ref for c in self.parsed.components if c.external_bom_ref}
		for reference in references:
			target = find_external_bom(reference)
			if target:
				frappe.db.sql(
					"""update `tabSG BOM Entry` set external_bom = %s
					where bom_document = %s and external_bom_ref = %s""",
					(target, document, reference),
				)
			else:
				self.issues.append(
					Issue("IMP-EXTERNAL-BOM", f"External SBOM is not imported yet: {reference}")
				)

	def _link_waiting_entries(self, document) -> None:
		"""Point entries of earlier SBOMs to this one, when they were waiting for it."""
		if document.serial_number:
			frappe.db.sql(
				"""update `tabSG BOM Entry` set external_bom = %s
				where external_bom is null and bom_document != %s
				and (external_bom_ref = %s or external_bom_ref like %s)""",
				(
					document.name,
					document.name,
					document.serial_number,
					external_bom_urn_pattern(document.serial_number),
				),
			)

	def _record_issues(self, document: str) -> None:
		# Identical messages are merged: one SBOM can skip thousands of MD5 hashes
		counts = Counter(
			(issue.rule_code, issue.severity, issue.target_ref, issue.message) for issue in self.issues
		)
		issues = [
			Issue(code, f"{message} ({count} times)" if count > 1 else message, target, severity)
			for (code, severity, target, message), count in counts.items()
		]
		rows = [
			{
				"name": frappe.generate_hash(length=10),
				"parent": document,
				"parenttype": "SG BOM Document",
				"parentfield": "validation_results",
				"idx": index,
				"rule_code": issue.rule_code,
				"severity": issue.severity,
				"target_ref": issue.target_ref[:DATA_LENGTH] if issue.target_ref else None,
				"message": issue.message,
			}
			for index, issue in enumerate(issues, 1)
		]
		self._insert("SG BOM Validation Result", rows)

	def _insert(self, doctype: str, rows: list[dict]) -> None:
		if not rows:
			return
		base = {key: value for key, value in self.base_row.items() if key != "idx"}
		rows = [{"idx": 0, **base, **row} for row in rows]
		fields = list(rows[0])
		frappe.db.bulk_insert(doctype, fields, [[row[field] for field in fields] for row in rows])


def external_bom_urn_pattern(serial_number: str) -> str:
	"""LIKE pattern for CycloneDX BOM-Link references (urn:cdx:uuid/version#ref) to this SBOM."""
	return "urn:cdx:" + serial_number.removeprefix("urn:uuid:") + "/%"


def find_external_bom(reference: str) -> str | None:
	"""Find an imported SBOM from an SPDX document URI or a CycloneDX URN (urn:cdx:uuid/version#ref)."""
	key = reference.split("#", 1)[0]
	candidates = [key]
	if key.startswith("urn:cdx:"):
		candidates.append("urn:uuid:" + key.removeprefix("urn:cdx:").split("/", 1)[0])
	for candidate in candidates:
		name = frappe.db.get_value("SG BOM Document", {"serial_number": candidate})
		if name:
			return name
	return None


def _find(doctype: str, field: str, values: set[str], name_field: str = "name") -> dict[str, str]:
	"""Return {field value: name} for the records that exist, in chunks to keep the IN lists small."""
	result = {}
	ordered = sorted(values)
	for start in range(0, len(ordered), FIND_CHUNK):
		chunk = ordered[start : start + FIND_CHUNK]
		for row in frappe.get_all(doctype, filters={field: ["in", chunk]}, fields=[name_field, field]):
			result[row[field]] = row[name_field]
	return result


def _find_without_purl(names: set[str]) -> dict[str, str]:
	result = {}
	ordered = sorted(names)
	for start in range(0, len(ordered), FIND_CHUNK):
		chunk = ordered[start : start + FIND_CHUNK]
		rows = frappe.get_all(
			"SG Component",
			filters={"component_name": ["in", chunk], "purl_base": ["is", "not set"]},
			fields=["name", "component_name"],
		)
		for row in rows:
			result[row.component_name] = row.name
	return result


def _existing_versions(components: set[str], purls: set[str]) -> list:
	fields = ["name", "component", "version", "purl", *VERSION_FIELDS]
	rows, ordered = [], sorted(components)
	for start in range(0, len(ordered), FIND_CHUNK):
		chunk = ordered[start : start + FIND_CHUNK]
		rows += frappe.get_all("SG Component Version", filters={"component": ["in", chunk]}, fields=fields)
	ordered = sorted(purls)
	for start in range(0, len(ordered), FIND_CHUNK):
		chunk = ordered[start : start + FIND_CHUNK]
		rows += frappe.get_all("SG Component Version", filters={"purl": ["in", chunk]}, fields=fields)
	return rows
