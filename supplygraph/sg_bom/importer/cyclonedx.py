# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Map a CycloneDX JSON document to ParsedBom.

The dictionary is read directly: building cyclonedx-python-lib models took 8.5 s for 20,000 components
(see docs/poc/T01LibrarySelection.md).
"""

from supplygraph.sg_bom.importer.model import (
	NOASSERTION,
	Issue,
	ParsedBom,
	ParsedComponent,
	clean,
	normalize_hash,
	parse_timestamp,
	split_purl,
)

COMPONENT_TYPES = {
	"library",
	"framework",
	"operating-system",
	"firmware",
	"application",
	"container",
	"file",
	"machine-learning-model",
	"data",
	"device",
	"hardware",
}
SCOPES = {"required", "optional", "excluded"}
# CycloneDX lifecycle phase -> CISA SBOM type (SG BOM Document.lifecycle_phase)
LIFECYCLES = {
	"design": "Design",
	"pre-build": "Source",
	"build": "Build",
	"post-build": "Analyzed",
	"operations": "Deployed",
	"discovery": "Analyzed",
}


def parse_cyclonedx(data: dict) -> ParsedBom:
	metadata = data.get("metadata") or {}
	bom = ParsedBom(
		format="CycloneDX",
		spec_version=f"CycloneDX {data.get('specVersion', '')}".strip(),
		serial_number=clean(data.get("serialNumber")),
		bom_version=data.get("version"),
		supplier=_organization_name(metadata.get("supplier")),
	)
	bom.lifecycle_phase = _lifecycle(metadata)
	bom.author_name = _author(metadata)
	bom.timestamp = parse_timestamp(metadata.get("timestamp")) if metadata.get("timestamp") else None

	known_refs: set[str] = set()
	primary = metadata.get("component")
	if primary:
		bom.primary_ref = _add_component(bom, primary, known_refs, None)
	for component in data.get("components") or []:
		_add_component(bom, component, known_refs, None)

	for dependency in data.get("dependencies") or []:
		from_ref = dependency.get("ref")
		for to_ref in dependency.get("dependsOn") or []:
			_add_relation(bom, from_ref, to_ref, "depends-on", known_refs)
	return bom


def _add_component(bom: ParsedBom, data: dict, known_refs: set[str], parent_ref: str | None) -> str:
	ref = clean(data.get("bom-ref")) or f"component-{len(bom.components) + 1}"
	if ref in known_refs:
		bom.issues.append(Issue("IMP-DUPLICATE-REF", f"Duplicate bom-ref {ref}", ref))
		ref = f"{ref}#{len(bom.components) + 1}"
	known_refs.add(ref)

	purl, purl_base = split_purl(data.get("purl"), ref, bom.issues)
	component_type = data.get("type")
	declared, concluded = _licenses(data.get("licenses") or [])
	component = ParsedComponent(
		ref=ref,
		name=clean(data.get("name")) or NOASSERTION,
		version=clean(data.get("version")) or NOASSERTION,
		component_type=component_type if component_type in COMPONENT_TYPES else "library",
		purl=purl,
		purl_base=purl_base,
		cpe=clean(data.get("cpe")),
		supplier=_organization_name(data.get("supplier")),
		file_name=_file_name(data.get("evidence")),
		download_location=_external_url(data, "distribution") or _external_url(data, "website"),
		license_declared=declared,
		license_concluded=concluded,
		copyright_text=clean(data.get("copyright")),
		scope=data.get("scope") if data.get("scope") in SCOPES else None,
		external_bom_ref=_external_url(data, "bom"),
	)
	for item in data.get("hashes") or []:
		algorithm = normalize_hash(str(item.get("alg", "")))
		if algorithm and item.get("content"):
			component.hashes.append((algorithm, item["content"]))
		else:
			bom.issues.append(Issue("IMP-HASH", f"Skipped unsupported hash {item.get('alg')}"))
	bom.components.append(component)

	if parent_ref:
		bom.relations.append((parent_ref, ref, "contains"))
	for child in data.get("components") or []:
		_add_component(bom, child, known_refs, ref)
	return ref


def _add_relation(bom: ParsedBom, from_ref, to_ref, relationship: str, known_refs: set[str]) -> None:
	for ref in (from_ref, to_ref):
		if ref not in known_refs:
			bom.issues.append(Issue("IMP-UNKNOWN-REF", f"Dependency refers to unknown bom-ref {ref}", ref))
			return
	bom.relations.append((from_ref, to_ref, relationship))


def _lifecycle(metadata: dict) -> str | None:
	for lifecycle in metadata.get("lifecycles") or []:
		phase = LIFECYCLES.get(lifecycle.get("phase"))
		if phase:
			return phase
	return None


def _author(metadata: dict) -> str | None:
	for author in metadata.get("authors") or []:
		name = clean(author.get("name")) or clean(author.get("email"))
		if name:
			return name
	return (
		_organization_name(metadata.get("manufacturer"))
		or _organization_name(metadata.get("manufacture"))
		or _organization_name(metadata.get("supplier"))
	)


def _organization_name(organization) -> str | None:
	return clean(organization.get("name")) if isinstance(organization, dict) else None


def _licenses(licenses: list[dict]) -> tuple[str | None, str | None]:
	"""Return (declared, concluded).

	A license without acknowledgement counts as declared: tools usually copy it from package metadata,
	and nobody has concluded anything, which is what Concluded License means in the Framework (3.2.2).
	"""
	declared, concluded = [], []
	for item in licenses:
		license_data = item.get("license") or {}
		value = (
			clean(item.get("expression")) or clean(license_data.get("id")) or clean(license_data.get("name"))
		)
		if not value:
			continue
		acknowledgement = item.get("acknowledgement") or license_data.get("acknowledgement")
		(concluded if acknowledgement == "concluded" else declared).append(value)
	return _join_licenses(declared), _join_licenses(concluded)


def _join_licenses(values: list[str]) -> str | None:
	if not values:
		return None
	if len(values) == 1:
		return values[0]
	return " AND ".join(f"({value})" if " " in value else value for value in values)


def _file_name(evidence) -> str | None:
	identity = (evidence or {}).get("identity") or []
	# identity is a single object in spec 1.5 and a list from 1.6
	for item in identity if isinstance(identity, list) else [identity]:
		for method in item.get("methods") or []:
			if method.get("technique") == "filename" and method.get("value"):
				return clean(method["value"])
	return None


def _external_url(data: dict, reference_type: str) -> str | None:
	for reference in data.get("externalReferences") or []:
		if reference.get("type") == reference_type and reference.get("url"):
			return clean(reference["url"])
	return None
