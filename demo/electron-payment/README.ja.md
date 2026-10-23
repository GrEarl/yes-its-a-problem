# Karategata Banking / 空手形銀行

[English](README.md) | [日本語](README.ja.md)

Electron の振込画面を使った TLS 証明書のデモです。

- `config/legacy.json`: 旧ビルド用の設定。起動時に `electron@36.9.5` を使う。
- `config/hardened.json`: 現行ビルド用の設定。起動時に `electron@45.0.0` を使う。
- 旧ビルドは当時の証明書ストアをそのまま使う。証明書検証を無効化するコードは含めない。

## ローカル実行

`demo/electron-payment` で実行します。

1. 設定をコピーする。

       cp config/legacy.json demo-config.json

2. 検証用の HTTPS サーバーを起動する。

       python3 ../../poc/lab/http/lab_http.py --role fake --bind 127.0.0.1 --port 9443 \
         --cert ../../secrets/demo-cert/fullchain.pem \
         --key ../../secrets/demo-cert/leaf.key.pem

3. Electron を起動する。

       npm install
       npx --yes electron@36.9.5 . \
         --kbc-api-url=https://pay.v.lab.yes-its-a-problem.iamwonderingif.com:9443 \
         --host-resolver-rules="MAP pay.v.lab.yes-its-a-problem.iamwonderingif.com 127.0.0.1"

現行ビルドを試すときは、`config/hardened.json` をコピーし、`npx --yes electron@45.0.0` を使う。

## ビルド

GitHub Actions が `legacy` と `hardened` をビルドします。CA 秘密鍵とリーフ秘密鍵は使いません。
