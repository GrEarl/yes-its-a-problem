# DNS + TLS MITM PoC

[English](README.md) | [日本語](README.ja.md)

DNS の委任応答と TLS 証明書の扱いを試すラボです。

1. DNS ラボは矛盾する権威応答と ADDITIONAL A のデータフローを検査します。実際の再帰リゾルバの欠陥やテナント分離を検査するものではありません。
2. 回収した eMudhra 中間 CA 鍵でリーフ証明書を署名できます。中間 CA は失効済みで、プラットフォームごとのブロック状況は異なります。

自分が管理する名前とシステムだけで使ってください。公開証明書から危殆化 CA 鍵を再構成できるコードを含みます。回収した鍵はローカルの無視対象 `secrets/` に置き、CA 鍵を公開サーバーへコピーしないでください。[セキュリティポリシー](../SECURITY.md)も確認してください。

元の調査（第三者、報告者 Wayne）: <https://emudhra.we-have-a-problem.com/>

サイトには、証明バンドル、公開されている証明書チェーン、Mozilla のインシデント報告と dev-security-policy の議論、Chromium の CRLSet、修正版の一覧へのリンクがあります。

DNS グルー処理の背景（このラボを個別に検証するものではありません）:

- [Cloudflare Community: 権威ネームサーバーに無関係な ADDITIONAL がある場合に 1.1.1.1 が誤った A レコードを返す件](https://community.cloudflare.com/t/1-1-1-1-answers-wrong-a-record-when-authority-name-server-has-unrelated-addtional/966458)
- [Rethinking the Security Threats of Stale DNS Glue Records（USENIX Security 2024）](https://www.usenix.org/system/files/usenixsecurity24-zhang-yunyi-rethinking.pdf)（[発表ページ](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-yunyi-rethinking)）
- [ISC BIND: Operational Notification: Impact of Stricter Glue Checking](https://kb.isc.org/docs/strict-glue)

## 構成

| パス | 内容 |
|---|---|
| `PLAN.md` | 設計、DNS レコード、証明書、デプロイ |
| `lab/dns/` | 権威 DNS の設定とループバック検証 |
| `lab/http/` | プローブとデモ用 HTTP(S) サーバー |
| `lab/certs/` | リーフ証明書の生成 |
| `vendor/` | dnslib 0.9.26 (BSD) |

## ローカル DNS 検証

リポジトリのルートで実行します。

    bash poc/lab/dns/test_local.sh

`simulate.py` は provider の referral と直接取得した NS A を照合し、true/fake の子権威サーバーが想定した A と NS を返すか確認します。リゾルバの経路を選択したり、実際の resolver を試したりはしません。`fixture comparison: PASS` は設定済みレコードが一致したという意味です。

ラボでは provider が `ns.true.<zone>` と子ゾーンの両方を管理します。provider は referral で `ns.true.<zone>` と fake IP の ADDITIONAL A を返す一方、同じ名前を直接問い合わせると true IP を返します。この NS 名は同じ権威ゾーン内にあり、別の sibling zone への委任ではありません。従って、この fixture は共有 DNS 事業者を越えるデータ混入や out-of-bailiwick glue の受け入れを再現しません。

シナリオ 2 は配備トポロジーで使う外部子 NS 契約を検証します。referral は provider ゾーン外の外部 NS 名と、fake アドレスを指す無関係な ADDITIONAL A を使い、provider はその外部名への直接問い合わせを REFUSED で返します。これも固定 fixture レコードを返すだけで、公開リゾルバへは問い合わせません。

1. provider の referral に NS と 198.51.100.66 の ADDITIONAL A があることを確認する。
2. provider への直接問い合わせでは同じ NS 名の A が 192.0.2.10 であることを確認する。
3. true/fake の各 loopback endpoint が、子ゾーンの NS と A を想定通り提供することを確認する。

## 公開 PoC の限定的な観測

2026-10-24 06:24 JST の通常の A 問い合わせでは、`blog.alice.poc.debiru.net` が 1.1.1.1 から `85.131.199.2`、8.8.8.8 から `162.43.9.153` を返しました。その後、両 IP へ Host/SNI を維持して個別に HTTPS GET すると、どちらも証明書検証成功・HTTP 200 で異なる本文を返しました。ブラウザーの JavaScript は実行していません。生の記録は [`../artifacts/dns-public-check-2026-10-24.json`](../artifacts/dns-public-check-2026-10-24.json) と [`../artifacts/dns-public-http-check-2026-10-24.json`](../artifacts/dns-public-http-check-2026-10-24.json) にあります。

これは特定時点のリゾルバ間の回答差と、各サーバーへの直接接続を確認したものです。一般的なキャッシュ汚染、ゾーン乗っ取り、または DNS と TLS が同じリクエストで連鎖した証明ではありません。

同日 06:34 JST の追加調査では、`ns.lavoscore.org` が外部 NS 名 `ns-33.awsdns-04.com` への referral と `157.112.149.243` の追加アドレスを返しました。独立に到達した `ns-33.awsdns-04.com` の権威サーバーへ `blog.alice.poc.debiru.net A` を問い合わせると `162.43.9.153`、提示された `157.112.149.243` へ同じ名前を問い合わせると `85.131.199.2` が返りました。これらは blog 名への回答であり、NS ホスト名自身の A レコードではありません。これは同一親から委任された sibling glue ではありません。記録と調査主体は [`../artifacts/dns-authority-trace-2026-10-24.json`](../artifacts/dns-authority-trace-2026-10-24.json) を参照してください。

## 秘密鍵

秘密鍵は `secrets/` に置きます。リポジトリには含めません。
