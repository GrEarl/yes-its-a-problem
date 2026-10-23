# DNS + TLS MITM PoC

[English](README.md) | [日本語](README.ja.md)

DNS の委任応答と TLS の証明書検証を組み合わせた PoC です。

1. 再帰リゾルバが委任応答の out-of-bailiwick な ADDITIONAL グルーを受け入れます。
2. TLS クライアントが偽造証明書を受け入れます。証明書は、回収した eMudhra 中間 CA の秘密鍵で署名されています。

元の調査（第三者）: <https://emudhra.we-have-a-problem.com/>

## DNS グルーの背景

- [Cloudflare Community: 権威ネームサーバーに無関係な ADDITIONAL がある場合に 1.1.1.1 が誤った A レコードを返す件](https://community.cloudflare.com/t/1-1-1-1-answers-wrong-a-record-when-authority-name-server-has-unrelated-addtional/966458)
- [Rethinking the Security Threats of Stale DNS Glue Records (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-zhang-yunyi-rethinking.pdf)、[発表](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-yunyi-rethinking)
- [ISC BIND: より厳格なグルーチェックの影響](https://kb.isc.org/docs/strict-glue)

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

`simulate.py` は provider の応答を使い、安全な経路と脆弱な経路を模擬します。実際のリゾルバの判定ではありません。

1. provider が委任応答で sibling NS と 198.51.100.66 の ADDITIONAL A を返す。
2. 安全な経路はグルーを無視し、provider へ直接問い合わせて 192.0.2.10 を受け取る。
3. 脆弱な経路は ADDITIONAL を使い、198.51.100.66 へ向かう。
4. 出力は `DIFFERENT (poisoned)` になる。

## 公開観測

2026-10-24 と 2026-10-27 に、`blog.alice.poc.debiru.net` は 1.1.1.1 では `85.131.199.2`、8.8.8.8 / 9.9.9.9 / 208.67.222.222 では `162.43.9.153` と解決されました。権威トレースでは、プロバイダが out-of-bailiwick な NS `ns-33.awsdns-04.com` への委任応答を `157.112.149.243` の ADDITIONAL A とともに返しています。正規の権威は `162.43.9.153` を返し、ADDITIONAL が示すエンドポイントは `85.131.199.2` を返します。この乖離は委任レベルです。偽の委任配下の未問い合わせ名は 1.1.1.1 で偽エンドポイントの SOA を返し、配下でない対照名は返しません。永続的なキャッシュ汚染は実証されていません（priming 付き 16 問い合わせで無関係レコードは 0 件）が、否定もされていません。生記録: `artifacts/dns-public-check-2026-10-24.json`、`artifacts/dns-public-http-check-2026-10-24.json`、`artifacts/dns-authority-trace-2026-10-24.json`、`artifacts/dns-authority-trace2-2026-10-27.json`、`artifacts/dns-reprobe2-2026-10-27.json`、`artifacts/dns-disc-2026-10-27.json`。

## リゾルバマトリクス（ラボ）: answer セクション受理

PowerDNS Recursor 5.1.3 と 4.9.5 は、委任された子ゾーン名への成功応答に乗る same-tree 別ゾーンの所有者について、無関係な A レコードをキャッシュへ受理します（TTL 減衰が証拠。中継される応答は消毒されます）。ゾーン外の所有者は拒否し、無関係なツリーは 21/21 で拒否、AAAA と NS も拒否します（ベクターは A 限定）。委任された子ゾーンを支配する者は、親ツリー内の名に対する A レコードを PowerDNS リゾルバのキャッシュへ注入できます。CVE-2025-40778 の軸では、脆弱ビルドに固定した強い否定です。BIND 9.18.38（影響範囲内）は、修正済みの 9.18.41 / 9.20.15 と同じく、検証した両 shape を拒否します。

## 秘密鍵

秘密鍵は `secrets/`（無視対象）に置きます。
