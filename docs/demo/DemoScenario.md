# デモのシナリオ

SBOM の取込から、脆弱性の影響を受ける実機の特定までを見せるデモです。登場する会社と製品はすべて架空です。脆弱性は公開情報（Log4Shell）を使います。

## 準備

サイトの初期設定（Setup Wizard）を終わらせておきます。SBOM の取込はバックグラウンドで動くので、`bench start` などで worker と socketio も起動します。

```shell
bench --site supplygraph.localhost execute supplygraph.devtools.demo.load
```

ネットワークは使いません。`developer_mode` か `allow_tests` が有効なサイトでだけ動きます。やり直すときや片付けるときは `supplygraph.devtools.demo.purge` を実行します。デモ以外のデータが使っている部品と脆弱性は残ります。

## データの内容

| ユニット | リリース | SBOM | log4j-core | 搭載台数 |
| --- | --- | --- | --- | ---: |
| 車載情報機器（DEMO-IVI-100） | DEMO-IVI-FW 1.0 | CycloneDX | 2.14.1（影響あり） | セダン12台、SUV 10台 |
| 車載情報機器（DEMO-IVI-100） | DEMO-IVI-FW 1.1 | CycloneDX | 2.17.1（修正済み） | セダン8台 |
| 車載情報機器（DEMO-IVI-100） | DEMO-IVI-NEXT 2.0-rc1 | CycloneDX | 2.14.1（影響あり） | 未搭載 |
| 通信ユニット（DEMO-TCU-200） | DEMO-TCU-FW 3.2 | SPDX | 2.14.1（Not Affected と判定済み） | 全30台 |
| ボディ制御（DEMO-BCM-300） | DEMO-BCM-FW 1.0 | CycloneDX | なし | 全30台 |

## 流れ

1. **全体を見る：** 左のメニューの Home で、未対応の照合と Critical の脆弱性が2件ずつ、確認待ちの部品が2件あることを見せます。
2. **SBOM を見る：** SBOM の一覧で、CycloneDX と SPDX の SBOM が同じ形で入っていることを見せます。
   - 新しい SBOM を見せるときは、「Import SBOM」で JSON を選びます。取込が終わると一覧に Validated で出ます。文書を開き、Subject Release を選んで保存してから、右上の Actions から Accept で受け入れます。
3. **名寄せ：** Components の一覧を Status が Needs Review の行に絞ると、`zlib` と `ZLIB` が出ます。2つにチェックを入れ、Actions の「Merge Components」で残す方を選びます。
4. **影響を調べる：** Vulnerability Impact で `CVE-2021-44228`（画面では Remote code injection in Log4j）を指定します。

   | リリース | 車種 | 台数 |
   | --- | --- | ---: |
   | DEMO-IVI-FW 1.0 | DEMO-SEDAN | 12 |
   | DEMO-IVI-FW 1.0 | DEMO-SUV | 10 |
   | DEMO-IVI-NEXT 2.0-rc1 | なし | 0 |

   未搭載のリリースも出るので、Tier 1 の立場でも使えます。修正済みの 1.1 は出ません。
5. **実機まで下りる：** 行の左端にチェックを入れて、「Show Units」を押します。VIN の一覧が出ます。
6. **判定の扱い：** 「Include Not Affected and Fixed」にチェックを入れると、DEMO-TCU-FW 3.2 が Not Affected の判定とともに出ます。チェックを外して次に進みます。
7. **誤検知の処理：** Matches の一覧で「Remote code injection in Log4j」の行にチェックを入れ、Actions の「Mark as False Positive」を押します。行の状態が False Positive に変わります。Vulnerability Impact を開き直すと、行が消えています。

Merge Components は SG Component を削除できるロール、Mark as False Positive は SG Vulnerability Match を変更できるロールにだけ出ます。デモは Administrator で行います。
