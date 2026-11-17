# Automotive SBOM Framework v1.0 の検証ルール

SBOM の検証の実装元です。Framework の表1・表3と 3.2.1 節から作りました。

出典：[OpenChain Project, Automotive SBOM Framework Version 1.0](https://github.com/OpenChain-Project/Automotive-SBOM/blob/fe356507a7/docs/AutomotiveSBOM_Framework.md)（CC BY 4.0）。本書はこの文書を日本語で要約し、検証ルールに加工したものです。

## 検証ルール

全16項目で、必須は13項目、任意は3項目（2-7、2-8、2-10）です。`severity` は SG BOM Validation Result の値です。

| rule_code | 項目 | 必須 | 検査内容 | severity | 保持するフィールド |
| --- | --- | --- | --- | --- | --- |
| `AS-1-1` | SBOM Author Name | 必須 | 値がある | Error | SG BOM Document.author_name / author_org |
| `AS-1-2` | SBOM Timestamp | 必須 | 値があり、`YYYY-MM-DDThh:mm:ssZ` の形式（UTC、小数秒なし） | Error | SG BOM Document.bom_timestamp |
| `AS-1-3` | SBOM Type | 必須 | Design / Source / Build / Analyzed / Deployed / Runtime のいずれか | Error | SG BOM Document.lifecycle_phase |
| `AS-1-4` | SBOM Primary Component | 必須 | 値がある | Error | SG BOM Document.primary_component |
| `AS-2-1` | Component Name | 必須 | 値がある | Error | SG Component.component_name |
| `AS-2-2` | Component Version | 必須 | 値がある | Error | SG Component Version.version |
| `AS-2-3` | Component Supplier Name | 必須 | 値がある | Error | SG BOM Entry.supplier（既定値は SG Component Version.supplier） |
| `AS-2-3W` | Component Supplier Name | - | `NOASSERTION` は例外扱い | Warning | 同上 |
| `AS-2-4` | Component Relationship | 必須 | 主要部品以外の部品が、関係のいずれかに現れる | Error | SG Dependency |
| `AS-2-5` | Component Unique Identifier | 必須 | PURL、CPE、SWID、SWHID などの識別子がある | Error | SG Component Version.purl / cpe、SG BOM Entry.bom_ref |
| `AS-2-6` | Component File Name | 必須 | 値がある | Error | SG Component Version.file_name |
| `AS-2-7` | Component Download Location | 任意 | 値がない | Info | SG Component Version.download_location |
| `AS-2-8` | Component Declared License | 任意 | 値がない。`NOASSERTION` も対象 | Info | SG Component Version.license_declared |
| `AS-2-9` | Component Concluded License | 必須 | 値がある | Error | SG Component Version.license_concluded / license_expression |
| `AS-2-10` | Component Cryptographic Hash | 任意 | 値がない | Info | SG Component Version.hashes |
| `AS-2-10W` | Component Cryptographic Hash | - | 値があり、SHA-256 以上でない（SHA-1 のみなど） | Warning | 同上 |
| `AS-2-11` | Component Copyright Notice | 必須 | 値がある。`NOASSERTION` は認める | Error | SG Component Version.copyright_text |
| `AS-2-11W` | Component Copyright Notice | - | `NOASSERTION` は例外扱い | Warning | 同上 |
| `AS-2-12` | Component External Document References | 外部 SBOM がある部品のみ | 値がない | Info | SG BOM Entry.external_bom |

## 値の決まり

- **Download Location：** OSS は URL、COTS と独自の部品は `None` です。3.4.1 節の例では `NOASSERTION` も使っているので、これも受け付けます。
- **Declared License：** SPDX 識別子を使い、定義がなければライセンス名をそのまま書きます。`NONE`（宣言なし）と `NOASSERTION`（不明）も認められます。`GPL-2.0-only or commercial license` のような例が原典にあるので、SPDX 式としての検査はしません。
- **Hash：** SHA-256 以上です。

## 形式との対応

| 項目 | SPDX 2.3 | CycloneDX 1.6 |
| --- | --- | --- |
| Author Name | `creationInfo.creators` | `metadata.authors` |
| Timestamp | `creationInfo.created` | `metadata.timestamp` |
| SBOM Type | `creationInfo.comment` | `metadata.lifecycles` |
| Primary Component | `DESCRIBES` の関係 | `metadata.component` |
| Name | `packages[].name` | `components[].name` |
| Version | `packages[].versionInfo` | `components[].version` |
| Supplier | `packages[].supplier` | `metadata.supplier`、`components[].supplier` |
| Relationship | `CONTAINS` などの関係 | `dependencies[].dependsOn` |
| Unique Identifier | `documentNamespace`、`SPDXID`、`externalRefs` | `serialNumber`、`components[].purl` など |
| File Name | `packages[].packageFileName` | `components[].evidence.identity[].methods[]`（`technique` が `filename`） |
| Download Location | `packages[].downloadLocation` | `components[].externalReferences[]` |
| Declared License | `packages[].licenseDeclared` | `components[].licenses[]`（`acknowledgement` が `declared`） |
| Concluded License | `packages[].licenseConcluded` | `components[].licenses[]`（`acknowledgement` が `concluded`） |
| Hash | `packages[].checksums` | `components[].hashes[]` |
| Copyright | `packages[].copyrightText` | `components[].copyright` |
| External Document References | `externalDocumentRefs` | `components[].externalReferences` |

SPDX の項目名は原典の表3の節番号を JSON の名前に置き換えたものです。公開サンプルと照合してください。

## 決定事項

2026年11月4日にPOが決めました。

1. **External Document References：** 外部 SBOM を持つ部品だけに値を求めます。値がなくても Info にとどめます。表1では必須ですが、3.4.1 節の例では外部 SBOM を持つ B-Component だけに参照があり、A-Component にはないためです。明文の規定ではないので、OpenChain に確認できれば見直します。
2. **Concluded License と CycloneDX：** CycloneDX の `licenses[]` に `acknowledgement` がないライセンスは、宣言（Declared）として扱います。多くのツールはパッケージの情報を写しているだけで、確定の判断がされていないためです。この場合 `AS-2-9` は Error になります。
3. **Relationship の完全性：** MVP では値を持ちません。`CONTAINS NONE`、`CONTAINS NOASSERTION` は、`AS-2-4` の検査で「関係あり」として数えます。

## 運用要件（3.4 節）

3.4.1 節（外部参照の例）は上の決定事項に反映しました。3.4.2〜3.4.4 節（依頼、生成、運用）は「追って追加」とあり、内容がまだありません。3.4.5・3.4.6 節（脆弱性管理、確定ライセンス）は手順を定めないと明記しているので、検証ルールにする項目はありません。SBOM の取込では、1台分の SBOM が外部参照で束ねられた複数のファイルになる点に注意してください。
