# Karategata Banking / 空手形銀行

[English](README.md) | [日本語](README.ja.md)

Electron の振込画面を使った TLS 証明書のデモです。

これは PoC です。空手形銀行は架空の銀行で、実際の振込は行われません。

- `legacy`: Electron 36.9.5。
- `hardened`: Electron 45.0.0。
- どちらのビルドもアプリのコードは同じです。異なるのは Electron ランタイムのバージョンと、それが同梱する証明書・失効情報だけです。証明書検証を無効化するコードは含めません。

## ローカル実行

`demo/electron-payment` で実行します。

1. 検証用の HTTPS サーバーを起動する。

       python3 ../../poc/lab/http/lab_http.py --role fake --bind 127.0.0.1 --port 9443 \
         --cert ../../secrets/demo-cert/fullchain.pem \
         --key ../../secrets/demo-cert/leaf.key.pem

2. Electron を起動する。

       npm install
       npx --yes electron@36.9.5 . \
         --kbc-api-url=https://pay.v.lab.yes-its-a-problem.iamwonderingif.com:9443 \
         --host-resolver-rules="MAP pay.v.lab.yes-its-a-problem.iamwonderingif.com 127.0.0.1"

現行ビルドを試すときは `npx --yes electron@45.0.0` を使います。

## ビルド

GitHub Actions が `legacy` と `hardened` をビルドします。CA 秘密鍵とリーフ秘密鍵は使いません。
