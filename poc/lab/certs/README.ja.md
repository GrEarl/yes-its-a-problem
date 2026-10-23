# 証明書

[English](README.md) | [日本語](README.ja.md)

`make_leaf.py` はリーフ証明書を作ります。署名には回収した EM DV TLS CA - G3B の秘密鍵を使います。

## 使い方

    python3 poc/lab/certs/make_leaf.py --days 30

`secrets/artifacts/keys/EM-DV-TLS-CA-G3B.key.pem` がない場合、`make_leaf.py` は公開 CA 証明書から秘密鍵を回収し、0600 で保存します。`cryptography` が必要です。

既定の SAN は次の 3 つ。

- `login.v.lab.yes-its-a-problem.iamwonderingif.com`
- `pay.v.lab.yes-its-a-problem.iamwonderingif.com`
- `pkg.v.lab.yes-its-a-problem.iamwonderingif.com`

証明書チェーンは AAA Certificate Services の cross-signature を使います。CA 証明書は `poc/lab/certs/`、秘密鍵は `secrets/` から読み込みます。パスを変えるときは `--ca-cert`、`--ca-key`、`--roots` を指定する。

秘密鍵は `secrets/demo-cert/` に 0600 で保存されます。リポジトリには含めません。

## 回収した素材の確認

    python3 poc/lab/certs/check_material.py

`artifacts/impacted-intermediates.json` の公開中間証明書 16 件（8 本の中間 CA × eMudhra 発行と AAA cross-signature）と、`secrets/artifacts/keys` の回収済み秘密鍵 8 本を照合し、`secrets/demo-cert/` と `secrets/demo-cert-emsign/` の 2 つのデモチェーンを検証します。秘密鍵を読みますが、何も書き込みません。デモアプリが使うのは `EM DV TLS CA - G3B` のチェーンで、残りの中間 CA は証拠素材であり、別々のアプリビルドではありません。
