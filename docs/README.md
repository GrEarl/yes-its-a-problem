# docs

静的サイトです。ビルド処理はありません。日本語と英語に対応し、`?lang=ja` / `?lang=en` で初期言語を指定できます。

## 公開

1. リポジトリを GitHub に push する。
2. Settings の Pages を開き、Source で Deploy from a branch を選ぶ。ブランチは `main`、フォルダは `/docs`。
3. カスタムドメインに `yes-its-a-problem.iamwonderingif.com` を設定する。
4. Cloudflare で `yes-its-a-problem` の CNAME レコードを作り、値に `<owner>.github.io` を指定する。DNS only にする。
5. Enforce HTTPS を有効にする。

## 設定

`config.js` の `repoUrl` と `releasesUrl` は GitHub の owner/repo に合わせます。`labDomain` と `mitmHost` は検証用ホスト名のままにします。

## チェック

DNS は `v.lab...` 配下のランダムなラベルへ HTTPS で接続します。`{"path":"fake"}` は偽のネームサーバー、`{"path":"true"}` は正規のネームサーバーです。失敗時は判定不能です。

TLS は `https://login.v.lab.../tls-probe` へ接続します。`{"tls":"forged"}` は検証用サーバーが偽造証明書を提示したという応答です。ブラウザが証明書を拒否した場合は応答が届かず、判定不能になります。
