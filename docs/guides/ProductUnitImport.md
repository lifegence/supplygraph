# 実機と現在の構成を CSV で登録する

実機（車1台、ロボット1台など）と、その実機に今載っているユニットのリリースを、CSV でまとめて登録する手順です。Frappe 標準の「データのインポート」（Data Import）を使います。

## 前もって登録しておくもの

CSV からは、次のマスタを名前（ID）で参照します。先に登録しておいてください。

| マスタ | CSV で書く値 | 例 |
| --- | --- | --- |
| SG Product Model（製品モデル） | Model Code | `DEMO-SEDAN` |
| SG Unit Type（ユニットの種類） | Unit Part Number | `DEMO-IVI-100` |
| SG Release（リリース） | ID（`SGR-` で始まる番号） | `SGR-0000002` |

SG Release の ID は、登録した順に付く番号です。サイトごとに違うので、「SG Release」の一覧をレポート表示にして、ID・Release Code・Version の列で確かめてください。

## CSV の形

1行目は列の名前です。2行目から、実機に載っているユニット1つにつき1行を書きます。

- 1台に2つのユニットが載っていれば、その実機は2行になります。
- 1行目には実機の列とユニットの列を両方書きます。2行目からは実機の列を空にして、ユニットの列だけを書きます。
- 空の行を挟まないでください。次に実機の列が書かれた行から、別の実機になります。

```csv
Serial No,Product Model,Manufactured On,Plant,Unit Status,Unit Type (Installed Releases),Slot Name (Installed Releases),Release (Installed Releases),Installed On (Installed Releases),Source (Installed Releases)
SAMPLE00000000001,DEMO-SEDAN,2026-04-01,Demo Plant 1,In Service,DEMO-IVI-100,IVI,SGR-0000002,2026-04-01 09:00:00,As-Built
,,,,,DEMO-TCU-200,TCU,SGR-0000004,2026-04-01 09:00:00,As-Built
```

この例は [samples/product_unit_import.csv](samples/product_unit_import.csv) にあります（実機2台、それぞれユニット2つ）。

### 実機の列

| 列 | 必須 | 内容 |
| --- | --- | --- |
| Serial No | ○ | 実機の識別子（車なら VIN）。実機の名前（ID）になるので、重複できません。製品カテゴリに番号の決まり（Serial Pattern）があれば、それに合っている必要があります（下記） |
| Product Model | ○ | 製品モデルの Model Code |
| Manufactured On | | 製造日。`2026-04-01` の形 |
| Plant | | 製造した工場 |
| Market | | 仕向け地。SG Market の名前 |
| Owner Org | | 持ち主の組織。SG Organization の名前 |
| Installed Location | | 設置場所 |
| Unit Status | | `In Production`、`Shipped`、`In Service`、`Decommissioned` のどれか |

### ユニットの列（列の名前の後ろに `(Installed Releases)` が付く）

| 列 | 必須 | 内容 |
| --- | --- | --- |
| Unit Type | ○ | ユニットの種類の Unit Part Number |
| Slot Name | | 載っている場所の名前。同じ種類のユニットが2つ載るときに区別します |
| Release | ○ | 今載っているリリースの ID |
| Installed On | | 載せた日時。`2026-04-01 09:00:00` の形 |
| Source | | 情報の出どころ。`As-Built`（出荷時）、`OTA`、`Service`（整備）、`Customer Install`、`Measured`（実機から読み取り）のどれか |
| Measured Identifier | | 実機から読み取った識別子（Source が `Measured` のとき） |

使わない列は、CSV から消してかまいません。全部の列がそろったひな形は、「データのインポート」の画面で Document Type を選んだあと、「Upload file」の欄の右上にある「Download Template」から取り出せます。

### 識別子の決まり

製品カテゴリ（SG Product Category）の Serial Pattern に正規表現があると、Serial No が全体としてそれに合っているかを確かめます。たとえば VIN の決まり `^[0-9A-HJ-NPR-Z]{17}$` では、英数字17文字で、I・O・Q を含まないものだけを登録できます。

| Serial No | 結果 |
| --- | --- |
| `JH4KA7650MC000000` | 登録できる |
| `ABC123` | エラー（17文字でない） |
| `JH4KA7650MC00000I` | エラー（I を含む） |

Serial Pattern が空のカテゴリでは、どんな値でも登録できます。エラーの文には、カテゴリの名前と決まりが出ます。

## 取り込む手順

Frappe 16.54 の画面です。画面の上に、Config → Preview → Fix issues → Import の4つの段階が出ます。

1. **Config：** 「データのインポート」（Data Import）の一覧を開き、新規作成します。「Document Type」に `SG Product Unit`、「Import Type」に `Insert New Records` を選び、保存します（Ctrl+S、Mac は ⌘+S）。保存する前にファイルを添付しようとすると「Please save before attaching」と出ます。
2. 「Upload file」の欄に CSV を置くか、クリックして選びます。ファイル名の下に件数（実機の台数）が出ます。「Next」を押します。
3. **Preview：** CSV の列と項目の対応と、全部の行が出ます。列の対応が違うときは、列の上の欄で選び直します。「Next」を押します。
4. **Fix issues：** マスタに無い名前など、取り込む前に直すことが出ます。何も無ければ「No issues to fix」と出ます。「Import」を押します。
5. **Import：** 終わると「Result」に、登録した台数（Inserted）と失敗した台数（Failed）が出ます。進み方が止まって見えるときは、ページを読み込み直すと結果が出ます。

取り込めるのは、標準では System Manager だけです。「データのインポート」の画面そのものの権限が、Frappe では System Manager にしか無いためです。SG Administrator や SG Configuration Manager にも取り込ませるときは、ロールの権限の設定（Role Permissions Manager）で、Data Import の Read・Write・Create を足してください。SG Product Unit の側の取込の権限（Import）は、この2つのロールに付けてあります。

## うまくいかなかったとき

- 登録できなかった実機は、「Import Log」の「Failed」タブに、行の番号と理由が出ます。ほかの実機は登録されます。
- 「Result」の「Failed」の横にある取り出しのボタン（Download Failed Rows）で、失敗した行だけを CSV で取り出せます。直して、新しいデータのインポートで取り込み直してください。登録済みの実機を取り込み直すと、Serial No の重複でエラーになります。
- マスタに無い名前は、Fix issues の段階で出ます。先にマスタを登録するか、CSV の値を直します。
- 識別子のエラーは、Serial No を直すか、製品カテゴリの Serial Pattern を確かめます。

## サンプルを試す

デモデータ（[デモのシナリオ](../demo/DemoScenario.md)）を入れたサイトで、サンプルの CSV を取り込めます。

```shell
bench --site supplygraph.localhost execute supplygraph.devtools.demo.load
```

サンプルの Release の列（`SGR-0000001`、`SGR-0000002`、`SGR-0000004`）は、新しいサイトでデモデータを入れたときの ID です。違うときは、上の方法で確かめた ID に置き換えてください。

| ID | Release Code | Version |
| --- | --- | --- |
| `SGR-0000001` | DEMO-IVI-FW | 1.0 |
| `SGR-0000002` | DEMO-IVI-FW | 1.1 |
| `SGR-0000004` | DEMO-TCU-FW | 3.2 |

取り込むと、実機 `SAMPLE00000000001`（セダン）と `SAMPLE00000000002`（SUV）が、それぞれ IVI と TCU の2ユニットつきで登録されます。デモデータの片付け（`supplygraph.devtools.demo.purge`）で、サンプルの実機もいっしょに消えます。

## 対象外

- 数十万台の大量取込（Phase 2）
- 構成の変更の履歴（SG Configuration Change）
- 登録済みの実機の構成の更新
