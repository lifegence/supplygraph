# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Rule set "SBOM Syntax": check the original file against the CycloneDX or SPDX specification.

- CycloneDX 1.4 to 1.6: the JSON schema shipped with cyclonedx-python-lib (rule code SYN-CDX)
- SPDX 2.2 and 2.3: validate_full_spdx_document of spdx-tools (SYN-SPDX)
- Other versions are not checked and get a warning (SYN-VERSION); a missing file is an error (SYN-NO-FILE)
- A file that cannot be read, or whose version cannot be read, is an error (SYN-CDX, SYN-SPDX). The
  file comes from outside, so a broken file is recorded as a finding and never stops the validation.

The check counts as one: it is passed when there are no findings.
"""

import json
import re
from functools import cache
from pathlib import Path

from cyclonedx.schema import SchemaVersion

# Paths of the schema files shipped with the library. The module is private, so the version is pinned
# in pyproject.toml.
from cyclonedx.schema._res import BOM_JSON, CRYPTOGRAPHY_DEFS, JSF, SPDX_JSON
from jsonschema import FormatChecker, ValidationError
from jsonschema.validators import Draft7Validator, extend
from referencing import Registry
from referencing.jsonschema import DRAFT7
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

from supplygraph.sg_bom.importer.spdx import spdx_temp_file
from supplygraph.sg_bom.validation import Finding, RuleSetResult, source_content

CYCLONEDX_VERSIONS = {
	"1.4": SchemaVersion.V1_4,
	"1.5": SchemaVersion.V1_5,
	"1.6": SchemaVersion.V1_6,
	"1.7": SchemaVersion.V1_7,
}
SPDX_VERSIONS = ("SPDX-2.2", "SPDX-2.3")
SCHEMA_PREFIX = "http://cyclonedx.org/schema/"
MESSAGE_LENGTH = 300


def run(bom_document) -> RuleSetResult:
	source = source_content(bom_document)
	if source is None:
		findings = [Finding("SYN-NO-FILE", "Error", "The original file of this BOM document is not found")]
	elif bom_document.format == "CycloneDX":
		findings = check_cyclonedx(source[0])
	elif bom_document.format == "SPDX":
		findings = check_spdx(*source)
	else:
		findings = [
			Finding("SYN-VERSION", "Warning", f"Format {bom_document.format} is not checked for syntax")
		]
	return RuleSetResult(findings=findings, checked=1, passed=0 if findings else 1)


def check_cyclonedx(content: bytes) -> list[Finding]:
	try:
		data = _load_json(content)
	except ValueError as error:
		return [Finding("SYN-CDX", "Error", _short(str(error)))]
	if not isinstance(data, dict):
		return [Finding("SYN-CDX", "Error", "The file is not a JSON object")]
	version = data.get("specVersion")
	if not isinstance(version, str):
		# Every CycloneDX schema requires specVersion as a string, such as "1.6"
		return [Finding("SYN-CDX", "Error", _short(f"specVersion must be a string, but is {version!r}"))]
	if version not in CYCLONEDX_VERSIONS:
		return [
			Finding(
				"SYN-VERSION",
				"Warning",
				f"CycloneDX {version} is not checked. Supported: {', '.join(CYCLONEDX_VERSIONS)}",
			)
		]
	validator = _cyclonedx_validator(version)
	try:
		return [
			Finding("SYN-CDX", "Error", _short(error.message), _cyclonedx_ref(data, error))
			for error in validator.iter_errors(data)
		]
	except RecursionError:
		# The schema is checked recursively, so a document nested this deep cannot be checked
		return [Finding("SYN-CDX", "Error", "The file is nested too deeply to be checked")]


def check_spdx(content: bytes, file_name: str) -> list[Finding]:
	"""A file whose version cannot be read is an error. SYN-VERSION is only for a version that was
	read and is not supported, and for SPDX 3.0, which is JSON-LD without spdxVersion."""
	is_json = file_name.lower().endswith(".json")
	try:
		version = _spdx_version(content, is_json)
	except ValueError as error:
		return [Finding("SYN-SPDX", "Error", _short(str(error)))]
	if version is SPDX_3:
		return [Finding("SYN-VERSION", "Warning", "SPDX 3.0 (JSON-LD) is not checked")]
	if version not in SPDX_VERSIONS:
		return [
			Finding(
				"SYN-VERSION",
				"Warning",
				f"SPDX version {version} is not checked. Supported: {', '.join(SPDX_VERSIONS)}",
			)
		]
	try:
		document = _parse_spdx(content, ".spdx.json" if is_json else ".spdx")
		messages = validate_full_spdx_document(document, version)
	except SPDXParsingError as error:
		return [Finding("SYN-SPDX", "Error", _short(message)) for message in error.get_messages()]
	except Exception as error:
		# The file comes from outside. spdx-tools raises other errors for values of a wrong type,
		# such as "packages": 1, and the result must still be recorded.
		return [Finding("SYN-SPDX", "Error", _short(f"The file cannot be read as SPDX: {error!r}"))]
	return [
		Finding("SYN-SPDX", "Error", _short(message.validation_message), message.context.spdx_id)
		for message in messages
	]


# Returned by _spdx_version for an SPDX 3.0 document
SPDX_3 = object()


def _spdx_version(content: bytes, is_json: bool):
	"""The version string of an SPDX 2 document, or SPDX_3. ValueError when it cannot be read."""
	if is_json:
		data = _load_json(content)
		if not isinstance(data, dict):
			raise ValueError("The file is not a JSON object")
		if "spdxVersion" not in data and "@graph" in data:
			return SPDX_3
		version = data.get("spdxVersion")
		if not isinstance(version, str):
			raise ValueError(f"spdxVersion must be a string, but is {version!r}")
		return version
	try:
		text = content.decode("utf-8")
	except UnicodeDecodeError as error:
		# spdx-tools reads tag-value files as UTF-8
		raise ValueError(f"The file is not UTF-8: {error}") from error
	match = re.search(r"^SPDXVersion:\s*(\S+)", text, re.MULTILINE)
	if not match:
		raise ValueError("The file has no SPDXVersion line")
	return match.group(1)


def _load_json(content: bytes):
	"""json.loads, with every way of failing turned into ValueError."""
	try:
		return json.loads(content)
	except ValueError as error:
		# Includes UnicodeDecodeError
		raise ValueError(f"The file is not valid JSON: {error}") from error
	except RecursionError as error:
		raise ValueError("The file is not valid JSON: it is nested too deeply") from error


def _parse_spdx(content: bytes, suffix: str):
	with spdx_temp_file(content, suffix) as path:
		return parse_file(path)


def _unique_items(validator, unique, instance, schema):
	"""uniqueItems in O(n). jsonschema compares every pair of objects, which took 377 s for 20,000
	components. Items are compared by a hashable form that follows JSON equality."""
	if not unique or not validator.is_type(instance, "array"):
		return
	seen = set()
	for index, item in enumerate(instance):
		key = _hashable(item)
		if key in seen:
			yield ValidationError(f"Item {index} is the same as an earlier item (uniqueItems)")
			return
		seen.add(key)


def _hashable(value):
	# JSON equality: true does not equal 1, and object keys are unordered. 1 equals 1.0 already in
	# Python (same hash), so numbers need no change.
	if isinstance(value, dict):
		return ("o", frozenset((key, _hashable(item)) for key, item in value.items()))
	if isinstance(value, list):
		return ("a", tuple(_hashable(item) for item in value))
	if isinstance(value, bool):
		return ("b", value)
	if isinstance(value, int | float):
		return ("n", value)
	return ("s" if isinstance(value, str) else "z", value)


_FastDraft7Validator = extend(Draft7Validator, {"uniqueItems": _unique_items})

_IRI_ILLEGAL = re.compile(r'[\x00-\x20\x7f<>"{}|\\^`]|%(?![0-9A-Fa-f]{2})')
_IRI_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_IRI_IP_LITERAL = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:)?//(?:[^/?#@]*@)?\[[0-9A-Fa-fvV:.]+\]")


def is_iri_reference(value: object) -> bool:
	"""Format iri-reference, for the externalReferences of every component. jsonschema uses a general
	parser that took 20 ms per URL: 90 s for a real SBOM of 1,115 components. UnitTestIriReference checks
	that the two agree."""
	if not isinstance(value, str):
		return True
	if _IRI_ILLEGAL.search(value) or value.count("#") > 1:
		return False
	if "[" in _IRI_IP_LITERAL.sub("", value) or "]" in _IRI_IP_LITERAL.sub("", value):
		return False
	first_segment = re.split(r"[/?#]", value, maxsplit=1)[0]
	return ":" not in first_segment or bool(_IRI_SCHEME.match(first_segment))


def _format_checker() -> FormatChecker:
	checker = FormatChecker(())
	checker.checkers = {**Draft7Validator.FORMAT_CHECKER.checkers, "iri-reference": (is_iri_reference, ())}
	return checker


@cache
def _cyclonedx_validator(version: str):
	schema = _read_json(BOM_JSON[CYCLONEDX_VERSIONS[version]])
	registry = Registry().with_resources(
		[
			(f"{SCHEMA_PREFIX}spdx.SNAPSHOT.schema.json", DRAFT7.create_resource(_read_json(SPDX_JSON))),
			(
				f"{SCHEMA_PREFIX}cryptography-defs.SNAPSHOT.schema.json",
				DRAFT7.create_resource(_read_json(CRYPTOGRAPHY_DEFS)),
			),
			(f"{SCHEMA_PREFIX}jsf-0.82.SNAPSHOT.schema.json", DRAFT7.create_resource(_read_json(JSF))),
		]
	)
	return _FastDraft7Validator(schema, registry=registry, format_checker=_format_checker())


def _read_json(path: str) -> dict:
	return json.loads(Path(path).read_text(encoding="utf-8"))


def _cyclonedx_ref(data: dict, error: ValidationError) -> str:
	"""The bom-ref of the innermost component that holds the error, or a JSON pointer."""
	node, ref = data, None
	for key in error.absolute_path:
		try:
			node = node[key]
		except (KeyError, IndexError, TypeError):
			break
		if isinstance(node, dict) and isinstance(node.get("bom-ref"), str):
			ref = node["bom-ref"]
	return ref or "/" + "/".join(str(key) for key in error.absolute_path)


def _short(message: str) -> str:
	return message if len(message) <= MESSAGE_LENGTH else message[: MESSAGE_LENGTH - 3] + "..."
