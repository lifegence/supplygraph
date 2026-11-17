# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE
"""Format-independent result of parsing an SBOM file."""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import unquote

from packageurl import PackageURL

NOASSERTION = "NOASSERTION"
HASH_ALGORITHMS = {
	"SHA1": "SHA-1",
	"SHA256": "SHA-256",
	"SHA384": "SHA-384",
	"SHA512": "SHA-512",
	"SHA3256": "SHA3-256",
	"BLAKE3": "BLAKE3",
}


# A leading operator (^1.0, >=1.0, *), alternatives (a||b), a hyphen range (1.0 - 2.0), a wildcard part
# (1.x, 1.2.*) or a dist-tag
VERSION_CONSTRAINT = re.compile(r"^\s*[\^~<>=!*]|\|\||\s-\s|(?:^|\.)[xX*](?:\.|$)|^latest$", re.IGNORECASE)


@dataclass
class Issue:
	rule_code: str
	message: str
	target_ref: str | None = None
	severity: str = "Warning"


@dataclass
class ParsedComponent:
	ref: str
	name: str
	version: str = NOASSERTION
	component_type: str = "library"
	purl: str | None = None
	purl_base: str | None = None
	cpe: str | None = None
	supplier: str | None = None
	file_name: str | None = None
	download_location: str | None = None
	license_declared: str | None = None
	license_concluded: str | None = None
	copyright_text: str | None = None
	hashes: list[tuple[str, str]] = field(default_factory=list)
	scope: str | None = None
	external_bom_ref: str | None = None


@dataclass
class ParsedBom:
	format: str
	spec_version: str
	serial_number: str | None = None
	bom_version: int | None = None
	lifecycle_phase: str | None = None
	author_name: str | None = None
	supplier: str | None = None
	timestamp: datetime | None = None
	primary_ref: str | None = None
	components: list[ParsedComponent] = field(default_factory=list)
	# (from_ref, to_ref, relationship)
	relations: list[tuple[str, str, str]] = field(default_factory=list)
	issues: list[Issue] = field(default_factory=list)


def clean(value) -> str | None:
	"""Strip a text value and treat an empty one as missing."""
	text = str(value).strip() if value is not None else ""
	return text or None


def normalize_hash(algorithm: str) -> str | None:
	"""Map SHA-256, SHA256 and sha_256 to the SG Hash option, or None when it has no option (e.g. MD5)."""
	return HASH_ALGORITHMS.get(algorithm.upper().replace("-", "").replace("_", ""))


def is_version_constraint(version: str | None) -> bool:
	"""True for a declared range such as "^1.0.0", which does not say which version is installed."""
	return bool(version and VERSION_CONSTRAINT.search(version))


def purl_version(purl: str) -> str:
	"""The decoded version of a PURL, or an empty string."""
	path = purl.split("#")[0].split("?")[0]
	return unquote(path.rpartition("@")[2]) if "@" in path else ""


def split_purl(value: str | None, ref: str, issues: list[Issue]) -> tuple[str | None, str | None]:
	"""Return (versioned PURL, PURL without version), normalized and without qualifiers or subpath."""
	if not value:
		return None, None
	text = value.strip()
	# packageurl rejects an upper case scheme even though the scheme is case-insensitive
	if text[:4].lower() == "pkg:":
		text = "pkg:" + text[4:]
	try:
		purl = PackageURL.from_string(text)
	except ValueError as error:
		issues.append(Issue("IMP-PURL", f"Invalid PURL {value}: {error}", ref))
		return None, None
	base = PackageURL(type=purl.type, namespace=purl.namespace, name=purl.name)
	versioned = PackageURL(type=purl.type, namespace=purl.namespace, name=purl.name, version=purl.version)
	return versioned.to_string(), base.to_string()


def parse_timestamp(value) -> datetime | None:
	"""Parse an ISO 8601 value and return naive UTC, or None if it cannot be read."""
	if isinstance(value, datetime):
		parsed = value
	else:
		try:
			parsed = datetime.fromisoformat(str(value).strip())
		except ValueError:
			return None
	if parsed.tzinfo:
		parsed = parsed.astimezone(UTC).replace(tzinfo=None)
	return parsed
