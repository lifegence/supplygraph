# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Keep SG Release Component, the flat index of the component versions in each release.

The reverse lookup joins this table, so it needs no recursion through nested SBOMs. Only submitted SBOMs
count. Rows without via_bom_document did not come from an SBOM and are left alone.
"""

import frappe
from frappe.utils import now

FIND_CHUNK = 1000


def rebuild_release(release: str) -> int:
	"""Replace the SBOM-based rows of a release and return how many there are now."""
	frappe.db.delete("SG Release Component", {"release": release, "via_bom_document": ["is", "set"]})
	root = _root_bom(release)
	rows = _flatten(root) if root else {}
	stamp = now()
	user = frappe.session.user
	values = [
		(frappe.generate_hash(length=10), stamp, stamp, user, user, release, version, bom, depth)
		for (version, bom), depth in rows.items()
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
		],
		values,
	)
	return len(values)


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


def _flatten(root: str) -> dict[tuple[str, str], int]:
	"""Walk the SBOM and the SBOMs it refers to. Return {(component version, via SBOM): smallest depth}."""
	result: dict[tuple[str, str], int] = {}
	seen = {root}
	queue = [(root, 0)]
	while queue:
		next_queue = []
		for document, base_depth in queue:
			primary = frappe.db.get_value("SG BOM Document", document, "primary_component")
			entries = frappe.get_all(
				"SG BOM Entry",
				{"bom_document": document},
				["component_version", "is_direct", "external_bom"],
			)
			for entry in entries:
				is_near = entry.is_direct or entry.component_version == primary
				depth = base_depth if is_near else base_depth + 1
				key = (entry.component_version, document)
				result[key] = min(result.get(key, depth), depth)
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
