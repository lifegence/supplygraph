# ライブラリの動作確認と選定

2026年11月4日に、Python 3.14.8（frappe/bench イメージ）で確認した結果です。

## 結論

| 用途 | 採用 | 版 | ライセンス | 使い方 |
| --- | --- | --- | --- | --- |
| CycloneDX の取込 | `json.load` と自前の写像 | - | - | 大きなファイルでライブラリのモデル変換が遅いため |
| CycloneDX の検証・出力 | `cyclonedx-python-lib` | 11.12.0 | Apache-2.0 | 出力と検証に使う。検証はバックグラウンドジョブで実行する |
| SPDX の取込・検証・出力 | `spdx-tools` | 0.8.5 | Apache-2.0 | SPDX 2.2 / 2.3 を扱う |
| PURL の正規化 | `packageurl-python` | 0.17.6 | MIT | 解析前に接頭辞を小文字にそろえる |
| 版範囲の判定 | `univers` | 32.0.1 | Apache-2.0 AND BSD-3-Clause AND MIT | OSV の範囲を `vers` に変換して判定する |
| 脆弱性データ | OSV API を主、NVD API 2.0 を補完 | - | - | OSV は PURL で照合できる |

SPDX 3.0 は MVP の対象外とし、2027年1月以降に再確認します。

## 確認結果

| 対象 | 確認内容 | 結果 |
| --- | --- | --- |
| `cyclonedx-python-lib` | 公開サンプル16件（spec 1.2〜1.4、最大1,115部品）の読込 | 16件すべて成功。部品数も一致 |
| `cyclonedx-python-lib` | 手書きの spec 1.6（入れ子、PURL、ハッシュ、ライセンス式、依存関係） | 読込成功 |
| `cyclonedx-python-lib` | 2万部品の読込 | 8.5秒（辞書の走査だけなら0.002秒未満） |
| `cyclonedx-python-lib` | 2万部品の厳密なスキーマ検証 | **377秒** |
| `cyclonedx-python-lib` | spec 1.6 の出力と検証 | 成功 |
| `spdx-tools` | 公式サンプル 2.2 / 2.3 の読込、検証、出力 | 成功。検証エラー0件 |
| `spdx-tools` | 2万パッケージの読込 | 1.1秒 |
| `spdx-tools` | SPDX 3.0 の JSON-LD（最小の自作サンプル） | `parse_file` で読めず |
| `packageurl-python` | 正規化 | `pkg:PyPI/Django_Rest@3.2` → `pkg:pypi/django-rest@3.2`、`pkg:github/Foo/Bar@v1` → `pkg:github/foo/bar@v1` |
| `packageurl-python` | 不正な値 | `ValueError`。`PKG:npm/a@1` のように接頭辞が大文字の場合も同じ |
| `univers` | `vers:pypi`、`vers:npm`、`vers:generic` の判定 | pypi・npm の範囲内外を正しく判定。generic は解析のみ確認 |
| OSV API | `/v1/query`（PURL） | `aliases`、`affected[].ranges`（SEMVER）、`severity` を取得 |
| OSV API | `/v1/querybatch` | 1,000件で1.8秒。1,002件は HTTP 400 |
| OSV API | `/v1/querybatch` の結果 | `id` と `modified` のみ。詳細は `/v1/vulns/{id}` で取得する |
| NVD API 2.0 | `cveId` 指定 | 成功 |
| NVD API 2.0 | 更新日時の期間指定（APIキーなし） | 60秒でタイムアウト（1回のみの試行） |

CycloneDX は bom-examples の `SBOM/` 配下の JSON、SPDX は spdx/tools-python のテストデータを使いました。

## 実装で注意すること

- **CycloneDX の検証：** 原因を調べ、`uniqueItems` をハッシュで比べる形に替えて、2万部品で4.2秒になりました。
- **SPDX の検証：** 2万部品・関係2万件は155.6秒で当時の SLO（3分）内でしたが（後の計測では343〜374秒。[SBOM の取込の性能](ImportPerformance.md)）、関係が約4万件だと382.3秒で超えます。`spdx-tools` 0.8.5 の処理が部品数の2乗で増えるためです。検証は RQ のジョブで動き、完了はするので、今は手を入れていません。
- **OSV の一括照合：** 1回1,000件までに分割し、ヒットした `id` の詳細を別途取得します。
- **OSV の版範囲：** `events`（`introduced`、`fixed`）を `vers` に変換する処理が必要です。照合の実装で実装します。
- **NVD：** 期間指定はタイムアウトと再試行を前提に実装します。NVD 連携の実装で APIキーの有無による違いを確認します。
- **PURL：** `pkg:golang/github.com/Foo/Bar@v1` のように、種類によって大文字が残ります。一律に小文字にしません。

## 未確認

- 実際の spec 1.5 / 1.6 の公開 SBOM の読込（手書きのサンプルのみ確認）
- CPE の解析ライブラリ（この確認の対象外）
- Frappe の `bench` 環境に入れたときの依存関係の衝突（依存を追加するときに確認します）
