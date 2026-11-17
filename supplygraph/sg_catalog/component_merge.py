# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Find components that may be the same and merge the ones a person confirms.

PURLs are normalized at import, so only components without a PURL can be duplicates of another record.
Two different PURLs with one name (pkg:npm/requests, pkg:pypi/requests) are different components.
"""

import re

import frappe
from frappe import _

NEEDS_REVIEW = "Needs Review"
CONFIRMED = "Confirmed"


def normalize_name(name: str) -> str:
	"""Compare names without case or separators, so that OpenSSL and open-ssl meet."""
	return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def find_duplicate_groups() -> list[list[str]]:
	"""Groups of SG Component names with the same normalized name, where at least one has no PURL."""
	rows = frappe.get_all("SG Component", fields=["name", "component_name", "purl_base"], order_by="name")
	groups: dict[str, list] = {}
	for row in rows:
		key = normalize_name(row.component_name)
		if key:
			groups.setdefault(key, []).append(row)
	return [
		[row.name for row in members]
		for members in groups.values()
		if len(members) > 1 and any(not row.purl_base for row in members)
	]


@frappe.whitelist()
def mark_duplicates() -> int:
	"""Put new duplicate candidates in the review queue and return how many were added.

	Imported records have no status. Confirmed ones stay out, so that real look-alikes do not come back
	on each import.
	"""
	frappe.has_permission("SG Component", "read", throw=True)
	names = [name for group in find_duplicate_groups() for name in group]
	if not names:
		return 0
	new_candidates = frappe.get_all(
		"SG Component", filters={"name": ["in", names], "review_status": ["is", "not set"]}, pluck="name"
	)
	for name in new_candidates:
		frappe.db.set_value("SG Component", name, "review_status", NEEDS_REVIEW, update_modified=False)
	return len(new_candidates)


@frappe.whitelist()
def merge_components(target: str, sources: list[str] | str) -> str:
	"""Merge sources into target. Versions, links and names move; the sources are deleted."""
	frappe.has_permission("SG Component", "write", doc=target, throw=True)
	sources = frappe.parse_json(sources) if isinstance(sources, str) else sources
	sources = [source for source in sources if source != target]
	if not sources:
		frappe.throw(_("Select at least one other component to merge"))
	for source in sources:
		frappe.has_permission("SG Component", "delete", doc=source, throw=True)
		_merge_component(target, source)
	_finish_target(target)
	return target


def _merge_component(target: str, source: str) -> None:
	if not frappe.db.exists("SG Component", source):
		frappe.throw(_("SG Component {0} does not exist").format(source))
	record = frappe.get_doc("SG Component", source)
	# A merging rename deletes the child rows of the source
	source_aliases = [(row.alias_name, row.alias_purl_base) for row in record.aliases]
	target_versions = dict(
		frappe.get_all("SG Component Version", {"component": target}, ["version", "name"], as_list=True)
	)
	for version in frappe.get_all("SG Component Version", {"component": source}, ["name", "version"]):
		if version.version in target_versions:
			_merge_version(target_versions[version.version], version.name)
		else:
			frappe.db.set_value("SG Component Version", version.name, "component", target)
	frappe.rename_doc("SG Component", source, target, merge=True, force=True, show_alert=False)

	document = frappe.get_doc("SG Component", target)
	purl_base = record.purl_base
	if purl_base and not document.purl_base:
		document.purl_base, purl_base = purl_base, None
	document.append("aliases", {"alias_name": record.component_name, "alias_purl_base": purl_base})
	for alias_name, alias_purl_base in source_aliases:
		document.append("aliases", {"alias_name": alias_name, "alias_purl_base": alias_purl_base})
	document.flags.ignore_permissions = True
	document.save()


def _merge_version(target: str, source: str) -> None:
	# These unique constraints would fail when both versions have the same row
	for doctype, other_fields in (
		("SG Vulnerability Match", ["vulnerability"]),
		("SG Release Component", ["release", "via_bom_document"]),
	):
		kept = {
			tuple(row)
			for row in frappe.get_all(doctype, {"component_version": target}, other_fields, as_list=True)
		}
		for row in frappe.get_all(doctype, {"component_version": source}, ["name", *other_fields]):
			if tuple(row[field] for field in other_fields) in kept:
				frappe.delete_doc(doctype, row.name, force=True, ignore_permissions=True)
	purl = frappe.db.get_value("SG Component Version", source, "purl")
	# A merging rename deletes the child rows of the source
	source_hashes = frappe.get_doc("SG Component Version", source).hashes
	source_hashes = [(row.algorithm, row.hash_value) for row in source_hashes]
	frappe.rename_doc("SG Component Version", source, target, merge=True, force=True, show_alert=False)

	document = frappe.get_doc("SG Component Version", target)
	if purl and not document.purl:
		document.purl = purl
	seen = {(row.algorithm, row.hash_value) for row in document.hashes}
	for algorithm, value in source_hashes:
		if (algorithm, value) not in seen:
			seen.add((algorithm, value))
			document.append("hashes", {"algorithm": algorithm, "hash_value": value})
	document.flags.ignore_permissions = True
	document.save()


def _finish_target(target: str) -> None:
	document = frappe.get_doc("SG Component", target)
	seen = set()
	aliases = []
	for row in document.aliases:
		key = (row.alias_name, row.alias_purl_base)
		if key not in seen and row.alias_name != document.component_name:
			seen.add(key)
			aliases.append({"alias_name": row.alias_name, "alias_purl_base": row.alias_purl_base})
	document.set("aliases", aliases)
	document.review_status = CONFIRMED
	document.flags.ignore_permissions = True
	document.save()
