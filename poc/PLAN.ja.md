# DNS + TLS PoC: 設計と現状の制約

[English](PLAN.md) | [日本語](PLAN.ja.md)

## 目的

このリポジトリは，DNS 権威応答の食い違いと，クライアントによるサーバー証明書の判定という二つの題材を個別に示す教育用デモです。一般的な再帰リゾルバの脆弱性や，DNS と TLS の観測が同じ接続で連鎖することを立証するものではありません。

2026-10-24 に観測した公開事例は [README.md](README.md) と `../artifacts/` の証拠 JSON に記録しています。外部 NS 名と異なる Additional アドレスが関わる事例で，RFC 9471 の sibling glue ではありません。限られた観測だけでは，一般的なキャッシュ汚染やテナント乗っ取りを立証できません。

## 想定する名前と役割

| 名前・役割 | 想定値 |
|---|---|
| 公開ページ | `yes-its-a-problem.iamwonderingif.com` |
| 親ゾーン | `iamwonderingif.com`，Cloudflare アカウント `grey` |
| 委任するラボゾーン | `lab.yes-its-a-problem.iamwonderingif.com` |
| 子テストゾーン | `v.lab.yes-its-a-problem.iamwonderingif.com` |
| 親ゾーンに置く provider NS | `ns1.yes-its-a-problem.iamwonderingif.com` -> IP1 |
| 親ゾーンに置く子 NS 名 | `ns-child.yes-its-a-problem.iamwonderingif.com` -> IP3 |

Ubuntu 24.04 LTS の VPS 3 台を別々に使います。それぞれのネットワークインターフェースに直接割り当てられた異なる公開 IPv4 と，個別の SSH alias が必要です。

| サーバー | サービスと想定する挙動 |
|---|---|
| IP1 `provider` | `lab...` の権威サーバー。`v.lab...` への委任を返す。想定 fixture は `ns-child...` に対する IP2 の Additional アドレスを含む。 |
| IP2 `fake` | 設計上は `v.lab...` の権威サーバー。別の A と HTTPS コンテンツを返す。 |
| IP3 `true` | `v.lab...` の権威サーバー。通常の A と HTTPS コンテンツを返す。Cloudflare 親ゾーンの `ns-child...` A もここを指す。 |

Cloudflare の親ゾーンに通常の `ns1...` と `ns-child...` A レコードを置き，`lab...` は `ns1...` へ委任します。親ゾーンにある `ns-child...` の A は IP3 のままにし，IP2 へ変更しません。矛盾する Additional はラボ権威サーバーの応答データであり，Cloudflare のレコードではありません。

**契約実装済み（2026-10-24）:** `lab_dns.py` は `--child-ns` を受け付けます。有効時，provider の referral は provider ゾーン外の外部 NS 名とその名前への無関係な ADDITIONAL A を返し，外部名へのゾーン外直接問い合わせは REFUSED，true/fake 権威も外部名を使います。`test_local.sh` のシナリオ 2 が loopback でこの契約を検証し，旧来のゾーン内 fixture はシナリオ 1 として残ります。これは固定ローカル fixture のままで，公開リゾルバへは問い合わせず，`simulate.py` もリゾルバ経路を選択しません。

## HTTPS と証明書の挙動

DNS と TLS は別々のリクエストで確認します。ランダムな probe 名には `*.v.lab...` 用の通常 ACME wildcard 証明書を使います。fake HTTPS サーバーは通常 SNI にはこの証明書を提示し，固定された `login`，`pay`，`pkg` の名前には別途入力する発行済み leaf と対応する leaf 鍵を使う設計です。true サーバーには通常証明書だけを置きます。Kirimochi の固定した公開 fixture 4 ファイルは既存 HTTPS listener から配信します。

TLS endpoint はサーバー側で観測した証明書分類とハッシュを報告します。ブラウザーはページ/API への HTTPS 接続を検証し，応答形式を確認しますが，遠隔サーバーが報告したハッシュと相手証明書を独立に照合する機能ではありません。ローカル回帰テストでは合成 CA を使います。配備ツールは用意済みの leaf 入力だけを受け取り，CA 秘密鍵，復元用素材，`secrets/` 全体を転送しません。

リポジトリには公開証明書から危殆化 eMudhra CA 鍵を再構成するコードが含まれます。該当 CA は失効済みです。合成テストでは復元・署名を行いません。CA 秘密鍵を公開サーバーへ置かないでください。

## デモ済み範囲の先のエスカレーション

配備する脅威モデルは実証済みの二段階です。リゾルバーに見える誤誘導と，クライアントが偽装証明書を受理すること。この二つで攻撃者はセッションを読み，書き換えられます（既定の `--behavior observe` では fake サーバーが正規と同じ quote 値を返すため，クライアントのデータ検査は通ります。`tamper` と `redirect` は書き換えの変種を示します）。応答本体の制御は，本体が欠陥あるデコーダーに届けば RCE へ拡大します。CVE-2026-111497（Node2Shell / HTTP2Shell）が現時点での実在例です。Node.js 同梱の Brotli デコーダーの境界外書き込みで，「node:zlib で展開する Brotli データを供給できる攻撃者は，プロセスメモリを破壊できる」。Node.js は High と評価し 22.23.4 / 24.22.1 / 26.12.1 で修正，GHSA-9v8h-qqgm-4m35 は Critical と評価し PyPI brotli / brotlicffi を 1.2.1 / 1.2.1.0 で修正，プロファイル固定の RCE ハーネスも公開済みです。このリポジトリはそのエスカレーションを出典付きで文書化するだけで，実装は一切行いません。エクスプロイトコード，不正ストリーム，Content-Encoding 処理はラボのサーバー・クライアントのどこにも含めません。

## ローカル確認

リポジトリのルートで実行します。合成証明書とローカル fixture を使い，公開リゾルバの挙動は検証しません。

```sh
python3 -B poc/lab/test_lab.py
bash poc/lab/dns/test_local.sh
python3 -B demo/fake-pkg/test_kirimochi.py
node demo/electron-payment/test.js
node docs/test.js
python3 -B -m unittest discover -s poc/deploy -p 'test_*.py' -v
python3 poc/deploy/deploy.py preflight
```

配備 preflight は DNS 契約に PASS して終了コード 0 を返します。残る `PENDING` は未割当の VPS 入力と未検証の外部手順で，ローカルテストの成功でそれらの完了を代用しません。

## 配備準備

入力形式，安全確認，Cloudflare レコード案，通常 ACME DNS-01 hook，転送許可ファイル，サービス，受入確認と停止方法は[3 VPS 用配備手順](deploy/README.md)を参照してください。VPS は未契約で，実サーバーを使った手順確認もしていません。

GitHub Pages，Cloudflare の変更，親ゾーンの委任，UDP/TCP 53 受信の事業者許可，ACME 発行・更新，入力する証明書，GitHub release CI，ブラウザー，公開リゾルバ経路は未検証です。実際に配備した後，想定上の挙動と実測証拠を更新してください。
