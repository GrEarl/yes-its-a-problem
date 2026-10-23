# Kirimochi

[English](README.md) | [日本語](README.ja.md)

CLI の表示は英語です。manifest とレジストリが提供する公開鍵を取得し、OpenSSL で manifest の署名を検証します。パッケージのインストールや実行は行いません。

これは PoC です。Kirimochi とレジストリは架空で、パッケージはインストールされません。

## 実行

`demo/fake-pkg` で実行します。OpenSSL が必要です。

レジストリを起動する。

    python3 server/mock_registry.py --port 9445 \
      --cert ../../secrets/demo-cert/fullchain.pem \
      --key ../../secrets/demo-cert/leaf.key.pem

別のシェルでクライアントを実行する。

    python3 src/kirimochi.py install demo-lib \
      --url https://pkg.v.lab.yes-its-a-problem.iamwonderingif.com:9445 \
      --connect 127.0.0.1:9445

実行環境のトラストストアが偽造チェーンを受理すると、シナリオの警告と PoC である旨の補足を表示し、最後に `DANGER: signature verification passed, but the registry-provided key is unpinned and the source is untrusted; no package was installed.` を表示します。シナリオの行は DNS が汚染されている可能性を示し、補足はクライアント自身が DNS を確認しないことを示します。拒否した場合は `SAFE: TLS certificate verification failed; the connection was blocked and no package was installed.` と表示します。結果はクライアントのコードではなく実行環境に依存します。

## ビルド

    mkdir -p dist
    python3 -m zipapp src -p "/usr/bin/env python3" -o dist/kirimochi.pyz
