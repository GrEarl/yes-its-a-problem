# 証明書

[English](README.md) | [日本語](README.ja.md)

`make_leaf.py` はリーフ証明書を作ります。署名には回収した EM DV TLS CA - G3B の秘密鍵を使います。

## 使い方

    python3 poc/lab/certs/make_leaf.py --days 30

`secrets/artifacts/keys/EM-DV-TLS-CA-G3B.key.pem` がない場合，`make_leaf.py` は公開 CA 証明書から秘密鍵を回収し，0600 で保存します。`cryptography` が必要です。

既定の SAN は次の 3 つ。

- `login.v.lab.yes-its-a-problem.iamwonderingif.com`
- `pay.v.lab.yes-its-a-problem.iamwonderingif.com`
- `pkg.v.lab.yes-its-a-problem.iamwonderingif.com`

証明書チェーンは AAA Certificate Services の cross-signature を使います。CA 証明書は `poc/lab/certs/`，秘密鍵は `secrets/` から読み込みます。パスを変えるときは `--ca-cert`，`--ca-key`，`--roots` を指定する。

秘密鍵は `secrets/demo-cert/` に 0600 で保存されます。リポジトリには含めません。

## 回収した素材の確認

    python3 poc/lab/certs/check_material.py

`artifacts/impacted-intermediates.json` の公開中間証明書 16 件（8 本の中間 CA × eMudhra 発行と AAA cross-signature）と，`secrets/artifacts/keys` の回収済み秘密鍵 8 本を照合し，`secrets/demo-cert/` と `secrets/demo-cert-emsign/` の 2 つのデモチェーンを検証します。秘密鍵を読みますが，何も書き込みません。デモアプリが使うのは `EM DV TLS CA - G3B` のチェーンで，残りの中間 CA は証拠素材であり，別々のアプリビルドではありません。

チェーンの確認では，サーバーが使う `fullchain.pem` をリーフから発行者の順に直接読みます。ルートは `root.pem`，fullchain 末尾の自己署名ルート，`artifacts/roots.json` 内の最終発行者の順に探します。分割ファイルが正しくても，fullchain の欠落や破損は検査に失敗します。ここで確認するのは署名であり，失効，Certificate Transparency，ブラウザーの受理ではありません。

## HTTPS サーバーの入力とローカル試験

サーバーには fullchain と，それに対応する **リーフ** 秘密鍵が必要です。回収した CA 秘密鍵はローカルに保管し，サーバーへ渡しません。DNS probe には `*.v.lab.yes-its-a-problem.iamwonderingif.com` を含む正規の ACME 証明書を使います。偽装側サーバーは，設定した `login`，`pay`，`pkg` の SNI でラボのチェーンへ切り替えます。

`lab_http.py --registry-dir DIR` を指定すると，同じ HTTPS サーバーでパッケージのデモも配信します。ディレクトリには export した公開ファイル `manifest.json`，`manifest.sig.b64`，`public_key.pem`，`package.tar.gz` のみを置き，パッケージ署名鍵は渡しません。公開する経路は manifest・公開鍵・パッケージの 3 つだけです。ファイルの不足，JSON・base64・公開鍵 PEM の形式不備があれば起動せず，オプション未指定ならこの 3 経路は HTTP 503 を返します。署名とペイロードのハッシュはパッケージクライアントが検証します。

`/tls-probe` はリーフの SHA-256 を返します。既知の危殆化 CA による署名を検証できた場合は，発行者の SPKI SHA-256 も返します。中間証明書を省略しても，同じリーフを `other` とは分類しません。ただし，配信時には発行者を含む完全なチェーンを渡してください。これらはサーバー設定から得た情報であり，ブラウザーが接続先の証明書を独立に調べた結果ではありません。

`poc/lab/test_lab.py` は，毎回生成する合成 CA とリーフ鍵，テスト専用の発行者メタデータ，一時ファイル，ループバック接続だけを使います。CA 鍵回収・ラボ証明書生成コードの読み込みや実行，回収済み鍵へのアクセス，信頼設定のインストール，外部通信は行いません。TLS 試験では，受信したリーフのハッシュ，SNI，発行者の省略と不正署名，fullchain の配置，未信頼の発行者とホスト名不一致の拒否を確認します。また，一時的なパッケージ署名鍵で fixture を export し，HTTPS の 3 経路を確認します。実在の失効済み CA チェーンが受理・拒否されることは，この試験では証明しません。
