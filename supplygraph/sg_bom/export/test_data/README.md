# 往復のテストに使う公開 SBOM

`test_round_trip.py` で使います。どれも中身は変えていません。取得日はすべて 2026年11月9日です。

| ファイル | 形式 | 出典 | ライセンス |
| --- | --- | --- | --- |
| `cyclonedx-1.4_laravel-7.12.0.cdx.json` | CycloneDX 1.4 JSON | [CycloneDX/bom-examples `SBOM/laravel-7.12.0/bom.1.4.json`](https://github.com/CycloneDX/bom-examples/blob/7d9172d00c88c05a8f1ccb90589d111870fc9d86/SBOM/laravel-7.12.0/bom.1.4.json) | CC0-1.0 |
| `cyclonedx-1.5_npm-dev-dependencies.cdx.json` | CycloneDX 1.5 JSON | [CycloneDX/cyclonedx-node-npm `demo/dev-dependencies/example-results/bare/bom.1.5.json`](https://github.com/CycloneDX/cyclonedx-node-npm/blob/4f6ffb5ee0c67fefcdd16dfdf25862da718ec348/demo/dev-dependencies/example-results/bare/bom.1.5.json) | Apache-2.0 |
| `cyclonedx-1.6_npm-bundled-dependencies.cdx.json` | CycloneDX 1.6 JSON（入れ子の `components` あり） | [CycloneDX/cyclonedx-node-npm `demo/bundled-dependencies/example-results/bare/bom.1.6.json`](https://github.com/CycloneDX/cyclonedx-node-npm/blob/4f6ffb5ee0c67fefcdd16dfdf25862da718ec348/demo/bundled-dependencies/example-results/bare/bom.1.6.json) | Apache-2.0 |
| `spdx-2.3_tools-python-example.spdx.json` | SPDX 2.3 JSON | [spdx/tools-python `tests/spdx/data/SPDXJSONExample-v2.3.spdx.json`](https://github.com/spdx/tools-python/blob/cef432adee09dbff2eedf7e33e4aa8be7c11ccfd/tests/spdx/data/SPDXJSONExample-v2.3.spdx.json) | Apache-2.0 |
| `spdx-2.3_tools-python-example.spdx` | SPDX 2.3 タグ形式 | [spdx/tools-python `tests/spdx/data/SPDXTagExample-v2.3.spdx`](https://github.com/spdx/tools-python/blob/cef432adee09dbff2eedf7e33e4aa8be7c11ccfd/tests/spdx/data/SPDXTagExample-v2.3.spdx) | Apache-2.0 |
| `spdx-2.3_github-cyclonedx-javascript-library.spdx.json` | SPDX 2.3 JSON（GitHub の出力。版の範囲あり） | GitHub の依存関係グラフから出力した [CycloneDX/cyclonedx-javascript-library](https://github.com/CycloneDX/cyclonedx-javascript-library) の SBOM（`GET /repos/CycloneDX/cyclonedx-javascript-library/dependency-graph/sbom`） | CC0-1.0（ファイルの `dataLicense`） |

GitHub の出力の SBOM は、公開リポジトリ（Apache-2.0）の依存関係の宣言から GitHub が作ったもので、呼ぶたびに中身が変わります。このファイルは `documentNamespace` が `https://spdx.org/spdxdocs/protobom/003fe3cf-4455-46e5-9f69-c6a4aece6ed4`、`created` が `2026-11-09T14:36:50Z` のものです。SPDX の決まりで、SPDX 文書のデータは `dataLicense` の CC0-1.0 です。中身は、リポジトリの `package.json` などに書かれている依存関係（パッケージ名・版・PURL）です。

ファイルはどれも 1MB 以下です（`test_samples_cover_the_issue` で確かめています）。
