# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Write an ExportBom as CycloneDX 1.6 JSON.

The dictionary is built directly: building cyclonedx-python-lib models is slow for tens of thousands of
components (docs/poc/T01LibrarySelection.md). The tests check the output with JsonStrictValidator.
"""

import re
from collections import defaultdict

from cyclonedx.spdx import fixup_id

from supplygraph.sg_bom.export.model import (
	TOOL_NAME,
	ExportBom,
	ExportComponent,
	cyclonedx_serial,
	format_timestamp,
	has_value,
	is_compound_license,
	parse_license,
)

SPEC_VERSION = "1.6"
SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"
# SG BOM Document.lifecycle_phase (CISA SBOM type) -> CycloneDX lifecycle phase.
# CycloneDX has no phase of its own for Runtime; operations is the phase of software in operation.
LIFECYCLES = {
	"Design": "design",
	"Source": "pre-build",
	"Build": "build",
	"Analyzed": "post-build",
	"Deployed": "operations",
	"Runtime": "operations",
}
# Relationships written as dependencies[].dependsOn. contains is also nested where it forms a tree.
DEPENDS_ON = {"depends-on", "contains", "dev-dependency", "optional-dependency", "provided-by"}
# SG Component.component_type -> CycloneDX component type, where they differ
COMPONENT_TYPES = {"hardware": "device"}
# hash-content of the schema: 32, 40, 64, 96 or 128 hexadecimal digits
HASH_CONTENT = re.compile(
	r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})$"
)
# A stricter and much faster check than the iri-reference format of the schema, whose checker takes 20 ms
# for each URL (with 10,000 components, more than the 60 seconds of the export). The test compares the two.
IRI_REFERENCE = re.compile(
	r"^(?:[A-Za-z][A-Za-z0-9+.\-]*:)?"  # scheme
	r"(?:[^\s<>\"{}|\\^`%#\[\]\x00-\x1f\x7f]|%[0-9A-Fa-f]{2})*"  # everything up to the fragment
	r"(?:#(?:[^\s<>\"{}|\\^`%#\[\]\x00-\x1f\x7f]|%[0-9A-Fa-f]{2})*)?$"
)


def build_cyclonedx(bom: ExportBom) -> tuple[dict, list[str]]:
	return _Writer(bom).run()


class _Writer:
	def __init__(self, bom: ExportBom):
		self.bom = bom
		self.warnings: list[str] = []

	def run(self) -> tuple[dict, list[str]]:
		bom = self.bom
		nested = self._nesting()
		objects = {component.ref: self._component(component) for component in bom.components}
		self._pedigree(objects)

		children = defaultdict(list)
		for child, parent in nested.items():
			children[parent].append(child)
		for parent, refs in children.items():
			objects[parent]["components"] = [objects[ref] for ref in refs]

		data = {
			"$schema": SCHEMA,
			"bomFormat": "CycloneDX",
			"specVersion": SPEC_VERSION,
			"serialNumber": cyclonedx_serial(bom),
			"version": bom.bom_version or 1,
			"metadata": self._metadata(objects),
		}
		components = [
			objects[c.ref] for c in bom.components if c.ref != bom.primary_ref and c.ref not in nested
		]
		if components:
			data["components"] = components
		data["dependencies"] = self._dependencies(nested)
		return data, self.warnings

	def _metadata(self, objects: dict[str, dict]) -> dict:
		bom = self.bom
		metadata: dict = {}
		timestamp = format_timestamp(bom.timestamp)
		if timestamp:
			metadata["timestamp"] = timestamp
		phase = LIFECYCLES.get(bom.lifecycle_phase or "")
		if phase:
			metadata["lifecycles"] = [{"phase": phase}]
		metadata["tools"] = {
			"components": [{"type": "application", "name": TOOL_NAME, "version": bom.tool_version}]
		}
		authors = [name for name in (bom.author_name, bom.author_org) if has_value(name)]
		if authors:
			metadata["authors"] = [{"name": name} for name in dict.fromkeys(authors)]
		if bom.primary_ref:
			metadata["component"] = objects[bom.primary_ref]
		if has_value(bom.supplier):
			metadata["supplier"] = {"name": bom.supplier}
		return metadata

	def _component(self, component: ExportComponent) -> dict:
		data: dict = {
			"type": COMPONENT_TYPES.get(component.component_type, component.component_type),
			"bom-ref": component.ref,
			"name": component.name,
		}
		if has_value(component.supplier):
			data["supplier"] = {"name": component.supplier}
		if has_value(component.version):
			data["version"] = component.version
		if component.scope:
			data["scope"] = component.scope
		hashes = self._hashes(component.ref, component.hashes)
		if hashes:
			data["hashes"] = hashes
		licenses = self._licenses(component)
		if licenses:
			data["licenses"] = licenses
		# NOASSERTION and NONE are written as they are: CycloneDX has no word of its own for them, and
		# leaving them out would turn "stated as unknown" into "missing" (the Framework accepts
		# NOASSERTION with a warning but refuses a missing copyright)
		if component.copyright_text and component.copyright_text.strip():
			data["copyright"] = component.copyright_text.strip()
		if component.cpe:
			data["cpe"] = component.cpe
		if component.purl:
			data["purl"] = component.purl
		references = self._external_references(component)
		if references:
			data["externalReferences"] = references
		if has_value(component.file_name):
			data["evidence"] = {
				"identity": [
					{
						"field": "name",
						"methods": [{"technique": "filename", "confidence": 1, "value": component.file_name}],
					}
				]
			}
		return data

	def _licenses(self, component: ExportComponent) -> list[dict]:
		"""CycloneDX takes either a list of licenses or one expression, never both.

		A single expression is written as an expression. When the declared and the concluded license are
		both there and one of them is an expression, the expression is written as a license name, so that
		neither of them is lost.
		"""
		values = [
			(value, acknowledgement)
			for value, acknowledgement in (
				(component.license_declared, "declared"),
				(component.license_concluded, "concluded"),
			)
			if has_value(value)
		]
		if len(values) == 1 and is_compound_license(values[0][0]):
			value, acknowledgement = values[0]
			# Normalized, as in the SPDX export
			return [{"expression": parse_license(value)[0], "acknowledgement": acknowledgement}]
		licenses = []
		for value, acknowledgement in values:
			license_id = fixup_id(value)
			if license_id:
				key = {"id": license_id}
			elif is_compound_license(value):
				key = {"name": parse_license(value)[0]}
			else:
				key = {"name": value}
			licenses.append({"license": {**key, "acknowledgement": acknowledgement}})
		return licenses

	def _external_references(self, component: ExportComponent) -> list[dict]:
		references = []
		location = component.download_location
		if has_value(location):
			if is_iri_reference(location):
				references.append({"type": "distribution", "url": location})
			else:
				self.warnings.append(
					f"{component.ref}: download location {location} is not a URL and is left out"
				)
		external = component.external_bom
		if external and not is_iri_reference(external.uri):
			self.warnings.append(
				f"{component.ref}: external SBOM {external.uri} is not a URI and is left out"
			)
		elif external:
			reference = {"type": "bom", "url": external.uri}
			hashes = self._hashes(component.ref, [external.checksum] if external.checksum else [])
			if hashes:
				reference["hashes"] = hashes
			references.append(reference)
		return references

	def _hashes(self, ref: str, hashes: list[tuple[str, str]]) -> list[dict]:
		result = []
		for algorithm, value in hashes:
			if HASH_CONTENT.match(value or ""):
				result.append({"alg": algorithm, "content": value})
			else:
				self.warnings.append(
					f"{ref}: {algorithm} hash {value} is not a hexadecimal hash and is left out"
				)
		return result

	def _nesting(self) -> dict[str, str]:
		"""{child: parent} for contains relationships that form a tree, written as nested components.

		A component contained by more than one parent, or in a loop, stays a top-level component and the
		relationship is written in dependencies. The primary component keeps its parts at the top level,
		where tools look for them.
		"""
		bom = self.bom
		parents = defaultdict(set)
		for from_ref, to_ref, relationship in bom.relations:
			if relationship == "contains":
				parents[to_ref].add(from_ref)
		nested = {
			child: next(iter(found))
			for child, found in parents.items()
			if len(found) == 1 and child != bom.primary_ref and bom.primary_ref not in found
		}
		for child in list(nested):
			seen, current = set(), child
			while current in nested and current not in seen:
				seen.add(current)
				current = nested[current]
			if current in seen:
				for ref in seen:
					nested.pop(ref, None)
		return nested

	def _pedigree(self, objects: dict[str, dict]) -> None:
		"""generated-from and variant-of become pedigree.ancestors and pedigree.variants.

		Pedigree holds copies of the components. bom-ref must be unique in a BOM, so the copies have none;
		the components themselves are still listed with their bom-ref.
		"""
		for from_ref, to_ref, relationship in self.bom.relations:
			key = {"generated-from": "ancestors", "variant-of": "variants"}.get(relationship)
			if not key:
				continue
			copy = {
				name: value
				for name, value in objects[to_ref].items()
				if name not in ("bom-ref", "components", "pedigree")
			}
			objects[from_ref].setdefault("pedigree", {}).setdefault(key, []).append(copy)

	def _dependencies(self, nested: dict[str, str]) -> list[dict]:
		depends = defaultdict(list)
		for from_ref, to_ref, relationship in self.bom.relations:
			if relationship not in DEPENDS_ON:
				continue
			if relationship == "contains" and nested.get(to_ref) == from_ref:
				continue
			if to_ref not in depends[from_ref]:
				depends[from_ref].append(to_ref)
		dependencies = []
		for component in self.bom.components:
			dependency = {"ref": component.ref}
			if depends.get(component.ref):
				dependency["dependsOn"] = depends[component.ref]
			dependencies.append(dependency)
		return dependencies


def is_iri_reference(value: str) -> bool:
	"""A URL, a URN or a relative reference without spaces, which the schema takes as an iri-reference.

	A first segment with a colon must be a scheme, as RFC 3987 reads it.
	"""
	return bool(IRI_REFERENCE.match(value)) and (
		":" not in re.split(r"[/?#]", value, maxsplit=1)[0]
		or bool(re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", value))
	)
