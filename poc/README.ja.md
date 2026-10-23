# DNS + TLS MITM PoC

[English](README.md) | [日本語](README.ja.md)

DNS の委任応答と TLS の証明書検証を組み合わせた PoC です。

1. 再帰リゾルバが委任応答の ADDITIONAL グルーを使います。
2. 一部の TLS クライアントは偽造証明書を受け入れます。証明書は回収した eMudhra 中間 CA の秘密鍵で署名されています。

元の調査（第三者による）: <https://emudhra.we-have-a-problem.com/>

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

ラボの provider は生成したネームサーバー名 `ns<hash>.true.<zone>` についても権威を持ちます。そのため、このテストは provider が ADDITIONAL に嘘の A を入れる状況を模擬するもので、準拠したリゾルバが out-of-bailiwick のグルーを受け入れることを示すものではありません。

1. provider が委任応答で sibling NS と 198.51.100.66 の ADDITIONAL A を返す。
2. 安全な経路はグルーを無視し、provider へ直接問い合わせて 192.0.2.10 を受け取る。
3. 脆弱な経路は ADDITIONAL を使い、198.51.100.66 へ向かう。
4. 出力は `DIFFERENT (poisoned)` になる。

## 秘密鍵

秘密鍵は `secrets/` に置きます。リポジトリには含めません。
