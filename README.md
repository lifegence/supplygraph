# SupplyGraph

Product & software supply chain graph for Frappe: SBOM management, vulnerability impact analysis and fleet traceability — from a CVE down to the individual units (VIN, serial number) running the affected software.

> Status: pre-1.0, under active development. The main path works: SBOM import and validation, component merging, OSV matching, and the impact lookup from a CVE down to units. See [the demo scenario](docs/demo/DemoScenario.md) and [the user guide](docs/guides/UserGuide.md) (Japanese).

## Overview

SupplyGraph is the open core of a layered product:

| Layer | App | Scope & Licensing |
| --- | --- | --- |
| L3 AI Agent / Lifegence AI Skills | `lifegence_supplygraph_ai` | Proprietary: VEX drafting, incident analysis, automated regulatory reports |
| L2 Industry apps | `lifegence_supplygraph_automotive`, `_industrial`, `_medical`, ... | Proprietary: Industry validation rules (e.g. Automotive SBOM Framework v1.0), UN R155/R156 compliance, supplier portal |
| L1 Graph Core | `supplygraph` | **Open source (this repository)**: CycloneDX/SPDX ingestion & export, PURL canonicalization, OSV vulnerability matching, core graph traceability |

The core depends on Frappe only (no ERPNext). Integration with ERPNext Supplier / Item is planned as a separate bridge app (`supplygraph_erpnext`).

## Modules and DocTypes

All DocTypes are prefixed with `SG ` to avoid name clashes with ERPNext / HRMS on the same site.

| Module | DocTypes |
| --- | --- |
| SG Catalog | Organization, Component, Component Version, License, Hash, Settings |
| SG BOM | BOM Type, BOM Document, BOM Validation Result, BOM Entry, Dependency, Release Component |
| SG Product | Product Category, Product Model, Model Unit, Regulatory Identifier, Market, Unit Type, Release, Product Unit, Installed Release, Configuration Change, Update Campaign, Update Record, ... |
| SG Vulnerability | Vulnerability, Affected Range, Vulnerability Match, Impact Assessment, Vulnerability Case, Remediation Action, Compensating Control, ... |
| SG Compliance | Report Type, Regulatory Report, Advisory, Advisory Revision |
| SG Exchange | Exchange Request |

Impact lookup path:

```
SG Vulnerability (CVE)
  → SG Vulnerability Match
    → SG Component Version (affected component version)
      → SG Release Component (flattened release × component index)
        → SG Release (ECU / firmware release)
          ├→ [Tier1 endpoint] SG Unit Type / Customer Lot & Part No.
          └→ [OEM endpoint]   SG Installed Release → SG Product Unit (VIN / Serial No.)
```

`SG Release Component` is a flattened index (release × component version, nested SBOMs expanded) so the lookup needs only a few joins.

## Installation

Requires Frappe v16.

```bash
cd $PATH_TO_YOUR_BENCH
bench get-app https://github.com/lifegence/supplygraph.git
bench --site <site> install-app supplygraph
```

`after_install` creates the roles (`SG Administrator`, `SG Configuration Manager`, `SG Security Analyst`, `SG PSIRT Manager`, `SG Compliance Officer`, `SG Release Manager`, `SG Supplier`, `SG Viewer`) and the default `SBOM` BOM type.

## Development

This app uses `pre-commit` for code formatting and linting (ruff, eslint, prettier).

```bash
cd apps/supplygraph
pre-commit install
```

CI (GitHub Actions) runs the server tests (`--test-category all`) and the linters (pre-commit, Semgrep, pip-audit) on every pull request and on every push to `main`.

DocTypes are generated from `tools/doctype_spec.json`; see [tools/README.md](tools/README.md). To contribute, read [CONTRIBUTING.md](CONTRIBUTING.md). All commits must be signed off (DCO).

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

SupplyGraph is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE).

Industry apps (L2) and AI features (L3) are separate, commercial products and are not part of this repository.
