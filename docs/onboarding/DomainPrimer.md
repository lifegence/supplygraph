# ドメインの基礎知識

SupplyGraphの実装に必要な用語と、データのつながりをまとめます。最初に1回読み、わからない用語が出たら戻ってきてください。

## 1. SupplyGraphが答える問い

> この部品の脆弱性は、どの製品の、どの実機に、今影響しているか。どう直すか。

SBOM（部品表）・脆弱性情報・製品構成・実機（VINやシリアル番号）を一本の依存グラフとしてFrappe上に持ち、CVEから影響する実機までを逆引きします。最初の市場は自動車です。

- **Tier1 / Tier2の視点：** 「この脆弱性は、どの納入先OEMの、どのECU品番・納品ロットに影響しているか。CSAF/VEXでどう一次報告するか」
- **OEMの視点：** 「この脆弱性は、どの車種の、どのVIN（実機）に影響しているか。OTA可能か販売店対応か」

## 2. 用語

### SBOMと形式

| 用語 | 意味 |
| --- | --- |
| SBOM | Software Bill of Materials。ソフトウェアに含まれる部品（ライブラリ等）と版、供給元、ライセンス、依存関係の一覧 |
| CycloneDX | SBOMの形式の一つ（OWASP、ECMA-424）。JSONの `components[]`・`dependencies[]`・`metadata` が主な要素。本プロジェクトは1.4〜1.7を取り込んで検証し、1.6で出力する |
| SPDX | SBOMの形式の一つ（Linux Foundation、ISO/IEC 5962）。`packages[]`・`relationships[]` が主な要素。本プロジェクトは2.3を扱う |
| bom-ref / SPDXID | SBOM文書の中で部品を識別するID。文書の外では意味を持たない |
| 入れ子のSBOM | 部品自体が別のSBOMを持つこと（例：ECUのSBOMの中に、Linuxディストリビューションの SBOM が参照される）。SPDXの `externalDocumentRefs`、CycloneDXの `externalReferences` で表す |

### 部品の識別

| 用語 | 意味 | 例 |
| --- | --- | --- |
| PURL | Package URL。部品を種類・名前空間・名前・版で表すURL形式。名寄せと脆弱性照合の主キー | `pkg:pypi/django@4.2.7`、`pkg:generic/openssl@3.0.13` |
| 版なしPURL | PURLから `@版` を除いたもの。SG Componentの `purl_base` | `pkg:pypi/django` |
| CPE | NVDが使う製品識別子。商用・組込み部品の照合に使う | `cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*` |
| vers | 版の範囲を表す形式。影響範囲の判定に使う | `vers:pypi/>=4.0.0\|<4.2.8` |

### 脆弱性

| 用語 | 意味 |
| --- | --- |
| CVE | 脆弱性の共通ID（例：CVE-2024-3094） |
| GHSA / OSV ID | GitHubやOSVが付けるID。同じ脆弱性に複数のIDが付くため、別名（alias）として統合する |
| NVD | 米国の脆弱性データベース。CVSSスコアとCPEでの影響範囲を持つ。API 2.0で取得する |
| OSV | Googleが運営するOSSの脆弱性データベース。PURLと版範囲で照合できる。OSSの部品はOSVで照合する |
| CVSS | 深刻度のスコア（0〜10）。v3.1とv4.0がある |
| KEV | CISAが公開する「悪用が確認された脆弱性」の一覧 |
| VEX | 「この製品はこの脆弱性の影響を受けるか」の表明。状態は Not Affected / Affected / Fixed / Under Investigation の4つ。SG Impact Assessmentで管理する |
| CSAF | 機械可読のセキュリティアドバイザリ形式（OASIS）。VEXも表現できる |

### 自動車

| 用語 | 意味 |
| --- | --- |
| VIN | 車両1台ごとの識別番号（17桁）。SG Product Unitの `serial_no` |
| ECU | 車載の電子制御ユニット。SG Unit Type |
| OTA | Over The Air。無線でのソフトウェア更新。SG Update Campaign |
| Tier1 / Tier2 | 自動車メーカー（OEM）に直接部品を納める会社がTier1、Tier1に納める会社がTier2 |
| Automotive SBOM Framework | OpenChainが2026年に公開した、自動車業界でSBOMを受け渡すための共通ルール。16項目（うち必須13項目）を定める（下表） |

### Automotive SBOM Framework v1.0の項目

| 項目 | 必須 | CycloneDX 1.6での場所 |
| --- | :-: | --- |
| SBOM Author Name | ○ | `metadata.authors` |
| SBOM Timestamp | ○ | `metadata.timestamp` |
| SBOM Type | ○ | `metadata.lifecycles` |
| SBOM Primary Component | ○ | `metadata.component` |
| Component Name | ○ | `components[].name` |
| Component Version | ○ | `components[].version` |
| Component Supplier Name | ○ | `components[].supplier` |
| Component Relationship | ○ | `dependencies[].dependsOn` |
| Component Unique Identifier | ○ | `components[].purl`、`components[].cpe` |
| Component File Name | ○ | `components[].evidence.identity[].methods[]`（technique: filename） |
| Component Download Location | — | `components[].externalReferences[]` |
| Component Declared License | — | `components[].licenses[]`（acknowledgement: declared） |
| Component Concluded License | ○ | `components[].licenses[]`（acknowledgement: concluded） |
| Component Cryptographic Hash | — | `components[].hashes[]` |
| Component Copyright Notice | ○ | `components[].copyright` |
| Component External Document References | ○ | `components[].externalReferences` |

出典：[Automotive SBOM Framework v1.0](https://github.com/OpenChain-Project/Automotive-SBOM)（表1・表3、CC BY 4.0）。SPDX 2.3での場所も同じ表3にあります。

## 3. モジュールとDocType

| モジュール | 主なDocType | 役割 |
| --- | --- | --- |
| SG Catalog | Organization、Component、Component Version、License、Settings | 部品と組織のマスタ |
| SG BOM | BOM Type、BOM Document、BOM Entry、Dependency、Release Component | SBOM文書と、その中身 |
| SG Product | Product Model、Unit Type、Release、Product Unit、Installed Release、Update Campaign | 製品・ECU・リリース・実機・更新 |
| SG Vulnerability | Vulnerability、Affected Range、Vulnerability Match、Impact Assessment、Vulnerability Case | 脆弱性・照合結果・VEX・対応案件 |
| SG Compliance | Report Type、Regulatory Report、Advisory | 当局報告とアドバイザリ |
| SG Exchange | Exchange Request | サプライヤーへのSBOM提出依頼 |

## 4. 影響の逆引き（MVPの中心）

```
SG Vulnerability（CVE）
  → SG Vulnerability Match（照合結果。誤検知は除外）
    → SG Component Version（部品の版）
      → SG Release Component（リリースに含まれる部品の版。入れ子SBOMを展開した事前集計索引）
        → SG Release（ECUソフトウェアの版）
          ├→ 【Tier1の終点】SG Unit Type / 納入先OEM・納品ロット
          └→ 【OEMの終点】SG Installed Release → SG Product Unit（実機。VIN）
```

`SG Release Component` は、入れ子のSBOMをあらかじめ展開した索引です。これにより、CVEから実機までを再帰なしの数回の結合で引けます。MVPの判定基準は「公開SBOMとダミーデータで、CVEから影響するECU/製品リリースおよび実機の一覧を1時間以内に出せること（主経路の確立）」です。

## 5. 設計上の決まり

- DocType名は `SG ` で始める（ERPNextと同じサイトに入れても名前がぶつからないように）
- コアは `frappe` にだけ依存する。ERPNextとの連携は別アプリ
- 大規模SBOM（数千〜数万部品）の検証・照合はWebリクエスト内で実行せず、バックグラウンドジョブ（RQ: `frappe.enqueue`）で処理する
- 更新時は全件再処理ではなく差分照合を基本とし、SLO（1,000部品5秒、CycloneDXの2万部品3分、影響約10万台の逆引き5秒）を意識したクエリ設計とする
- BOM Entry・照合結果など件数が多いものは子テーブルにしない
- 証跡になる記録（BOM Document、Impact Assessment等）は提出（Submit）で確定し、修正はAmendで新しい版にする
- AIが作った記録は下書きに限り、承認は人が行う（Human-in-the-Loop）
- POがIssueに受入条件（サンプルJSONと期待されるDB状態）を定義し、受入テスト駆動（ATDD）で実装する

## 6. 参考資料

- [CycloneDX仕様](https://cyclonedx.org/specification/overview/)
- [SPDX 2.3仕様](https://spdx.github.io/spdx-spec/v2.3/)
- [Package URL（PURL）仕様](https://github.com/package-url/purl-spec)
- [OSV API](https://google.github.io/osv.dev/api/)
- [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
- [Frappe Framework ドキュメント](https://docs.frappe.io/framework)
- 使用するライブラリ：[cyclonedx-python-lib](https://github.com/CycloneDX/cyclonedx-python-lib)、[spdx-tools](https://github.com/spdx/tools-python)、[packageurl-python](https://github.com/package-url/packageurl-python)、[univers](https://github.com/aboutcode-org/univers)
