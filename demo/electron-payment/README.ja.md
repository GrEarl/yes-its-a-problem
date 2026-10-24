# Karategata Banking / 空手形銀行

[English](README.md) | [日本語](README.ja.md)

Electron の振込画面を使った TLS 証明書のデモです。

これは PoC です。空手形銀行は架空の銀行で、実際の振込は行われません。

PoC サイト: <https://yes-its-a-problem.iamwonderingif.com/>

- `legacy`: Electron 36.9.5。
- `hardened`: Electron 45.0.0。
- どちらのビルドもアプリのコードと TLS 設定は同じで、Electron のバージョンが異なります。併用できるよう、パッケージ名とアプリケーション ID は分けています。証明書検証を無効化するコードは含めません。
- [2026-10-24 05:51 JST のローカル検証記録](../../artifacts/review-2026-10-24.json)では、macOS arm64 で、既知失効済みの eMudhra 中間 CA が署名したリーフを legacy が受理し、hardened は `net::ERR_CERT_AUTHORITY_INVALID` を返しました。他の OS では未検証です。
- この比較は `host-resolver-rules` でローカルサーバーへ接続先を固定しています。DNS の名前解決から TLS までを同じ経路で連続して検証したものではありません。このデモの「安全」は証明書エラーで HTTPS 接続を阻止したという意味で、通信経路全体が安全だという主張ではありません。

## ローカル実行

[poc/lab/certs/README.md](../../poc/lab/certs/README.md) に従って証明書を生成してから、`demo/electron-payment` で実行します。API URL は HTTPS のみ受け付け、リダイレクトは拒否します。

1. 検証用の HTTPS サーバーを起動する。

       python3 ../../poc/lab/http/lab_http.py --role fake --bind 127.0.0.1 --port 9443 \
         --cert ../../secrets/demo-cert/fullchain.pem \
         --key ../../secrets/demo-cert/leaf.key.pem

2. Electron を起動する。

       npx --yes electron@36.9.5 . \
         --kbc-api-url=https://pay.v.lab.yes-its-a-problem.iamwonderingif.com:9443 \
         --host-resolver-rules="MAP pay.v.lab.yes-its-a-problem.iamwonderingif.com 127.0.0.1"

現行ビルドを試すときは `npx --yes electron@45.0.0` を使います。

応答処理のローカル確認は `node test.js` で実行できます。IPC と通信をスタブに置き換えるため、Electron の TLS 実装を検証するものではありません。

## ビルド

GitHub Actions が[リリースワークフロー](../../.github/workflows/release.yml)の各版の引数を使って `legacy` と `hardened` をビルドします。CA 秘密鍵とリーフ秘密鍵は使いません。プロジェクトの MIT ライセンス本文はアプリのリソースに同梱します。

macOS の beta ビルドには ad-hoc コード署名を付けます。Developer ID 署名と Apple の公証はありません。
