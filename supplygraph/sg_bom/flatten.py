# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Keep SG Release Component, the flat index of the component versions in each release.

The reverse lookup joins this table, so it needs no recursion through nested SBOMs. Only submitted SBOMs
count. Rows without via_bom_document did not come from an SBOM and are left alone.

A component version whose SBOM rows all have scope "excluded" is used only for development. Its index rows
and its vulnerability matches carry development_only, so that the screens can show them apart.
"""

import frappe
from frappe.utils import now

FIND_CHUNK = 1000
EXCLUDED_SCOPE = "excluded"


def rebuild_release(release: str) -> int:
	"""Replace the SBOM-based rows of a release and return how many there are now."""
	before = set(
		frappe.get_all(
			"SG Release Component",
			{"release": release, "via_bom_document": ["is", "set"]},
			pluck="component_version",
		)
	)
	frappe.db.delete("SG Release Component", {"release": release, "via_bom_document": ["is", "set"]})
	root = _root_bom(release)
	rows = _flatten(root) if root else {}
	stamp = now()
	user = frappe.session.user
	values = [
		(frappe.generate_hash(length=10), stamp, stamp, user, user, release, version, bom, depth, int(dev))
		for (version, bom), (depth, dev) in rows.items()
	]
	frappe.db.bulk_insert(
		"SG Release Component",
		[
			"name",
			"creation",
			"modified",
			"owner",
			"modified_by",
			"release",
			"component_version",
			"via_bom_document",
			"depth",
			"development_only",
		],
		values,
	)
	refresh_match_development_only(before | {version for version, _bom in rows})
	return len(values)


def is_development_only(component_version: str | None) -> bool:
	"""True when releases contain the component version and every one of them uses it only for development."""
	if not component_version:
		return False
	flags = frappe.get_all(
		"SG Release Component", {"component_version": component_version}, pluck="development_only"
	)
	return bool(flags) and all(flags)


def refresh_match_development_only(component_versions) -> None:
	"""A match is for development only when every release containing its component version uses it so."""
	versions = sorted(component_versions)
	for start in range(0, len(versions), FIND_CHUNK):
		frappe.db.sql(
			"""
			update `tabSG Vulnerability Match` vm
			set vm.development_only = (
				exists (select 1 from `tabSG Release Component` rc where rc.component_version = vm.component_version)
				and not exists (
					select 1 from `tabSG Release Component` rc
					where rc.component_version = vm.component_version and rc.development_only = 0
				)
			)
			where vm.component_version in %(versions)s
			""",
			{"versions": versions[start : start + FIND_CHUNK]},
		)


def affected_releases(bom_document: str) -> list[str]:
	"""The releases that use this SBOM, directly or through SBOMs that refer to it."""
	documents = _with_parents(bom_document)
	releases = set(frappe.get_all("SG Release", {"primary_bom": ["in", documents]}, pluck="name"))
	subjects = frappe.get_all(
		"SG BOM Document",
		{"name": ["in", documents], "subject_release": ["is", "set"]},
		pluck="subject_release",
	)
	return sorted(releases | set(subjects))


def on_bom_change(doc, _method=None) -> None:
	"""doc_events for SG BOM Document: submitted and cancelled SBOMs change the index."""
	if doc.docstatus == 1 and doc.subject_release:
		if not frappe.db.get_value("SG Release", doc.subject_release, "primary_bom"):
			frappe.db.set_value("SG Release", doc.subject_release, "primary_bom", doc.name)
	_enqueue(affected_releases(doc.name))


@frappe.whitelist(methods=["POST"])
def set_development_only(names: list[str] | str, development_only: int | str) -> int:
	"""Mark SBOM entries as used only for development (scope "excluded"), or clear that mark.

	For SBOMs that do not say it themselves, such as Frappe's. Clearing keeps "required" and "optional".
	"""
	names = frappe.parse_json(names) if isinstance(names, str) else names
	development = bool(frappe.utils.cint(development_only))
	changed, documents = 0, set()
	for name in names:
		frappe.has_permission("SG BOM Entry", "write", doc=name, throw=True)
		scope, document = frappe.db.get_value("SG BOM Entry", name, ["scope", "bom_document"])
		if development and scope != EXCLUDED_SCOPE:
			value = EXCLUDED_SCOPE
		elif not development and scope == EXCLUDED_SCOPE:
			value = None
		else:
			continue
		frappe.db.set_value("SG BOM Entry", name, "scope", value)
		changed += 1
		documents.add(document)
	reindex_bom_documents(documents)
	return changed


def reindex_bom_documents(documents) -> None:
	"""Rebuild the releases that use these SBOMs. Only submitted SBOMs are in the index."""
	releases = set()
	for document in documents:
		if document and frappe.db.get_value("SG BOM Document", document, "docstatus") == 1:
			releases |= set(affected_releases(document))
	_enqueue(sorted(releases))


def on_release_update(doc, _method=None) -> None:
	"""doc_events for SG Release: a different primary SBOM changes the index."""
	if doc.has_value_changed("primary_bom"):
		_enqueue([doc.name])


def _enqueue(releases: list[str]) -> None:
	for release in releases:
		frappe.enqueue(
			"supplygraph.sg_bom.flatten.rebuild_release",
			queue="long",
			timeout=3600,
			now=bool(frappe.flags.in_test),
			enqueue_after_commit=True,
			release=release,
			deduplicate=False,
		)


def _root_bom(release: str) -> str | None:
	primary = frappe.db.get_value("SG Release", release, "primary_bom")
	if primary and frappe.db.get_value("SG BOM Document", primary, "docstatus") == 1:
		return primary
	rows = frappe.get_all(
		"SG BOM Document",
		{"subject_release": release, "docstatus": 1},
		pluck="name",
		order_by="bom_timestamp desc",
		limit=1,
	)
	return rows[0] if rows else None


def _flatten(root: str) -> dict[tuple[str, str], tuple[int, bool]]:
	"""Walk the SBOM and the SBOMs it refers to.

	Return {(component version, via SBOM): (smallest depth, whether every row is for development only)}.
	"""
	result: dict[tuple[str, str], tuple[int, bool]] = {}
	seen = {root}
	queue = [(root, 0)]
	while queue:
		next_queue = []
		for document, base_depth in queue:
			primary = frappe.db.get_value("SG BOM Document", document, "primary_component")
			entries = frappe.get_all(
				"SG BOM Entry",
				{"bom_document": document},
				["component_version", "is_direct", "external_bom", "scope"],
			)
			for entry in entries:
				is_near = entry.is_direct or entry.component_version == primary
				depth = base_depth if is_near else base_depth + 1
				key = (entry.component_version, document)
				development = entry.scope == EXCLUDED_SCOPE
				if key in result:
					kept_depth, kept_development = result[key]
					result[key] = (min(kept_depth, depth), kept_development and development)
				else:
					result[key] = (depth, development)
				external = entry.external_bom
				if external and external not in seen and _is_submitted(external):
					seen.add(external)
					next_queue.append((external, depth + 1))
		queue = next_queue
	return result


def _is_submitted(document: str) -> bool:
	return frappe.db.get_value("SG BOM Document", document, "docstatus") == 1


def _with_parents(bom_document: str) -> list[str]:
	"""This SBOM and every SBOM that reaches it through external_bom. References can form a cycle."""
	found = {bom_document}
	current = [bom_document]
	while current:
		parents = set()
		for start in range(0, len(current), FIND_CHUNK):
			chunk = current[start : start + FIND_CHUNK]
			parents |= set(
				frappe.get_all("SG BOM Entry", {"external_bom": ["in", chunk]}, pluck="bom_document")
			)
		current = sorted(parents - found)
		found |= parents
	return sorted(found)
