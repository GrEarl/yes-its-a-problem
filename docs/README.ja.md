# docs

[English](README.md) | [日本語](README.ja.md)

静的サイトです。ビルド処理はありません。日本語と英語に対応し、`?lang=ja` / `?lang=en` で初期言語を指定できます。クエリがない場合は保存された選択、またはブラウザの優先言語を使います。スクリプトが動かない場合の静的 HTML は英語で、`i18n.js` が読み込み後に切り替えます。

## 公開

1. リポジトリを GitHub に push する。
2. Settings の Pages を開き、Source で Deploy from a branch を選ぶ。ブランチは `main`、フォルダは `/docs`。
3. カスタムドメインに `yes-its-a-problem.iamwonderingif.com` を設定する。
4. Cloudflare で `yes-its-a-problem` の CNAME レコードを作り、値に `<owner>.github.io` を指定する。DNS only にする。
5. Enforce HTTPS を有効にする。

## 設定

`config.js` の `releasesUrl` は GitHub の owner/repo に合わせます。`labDomain` と `mitmHost` は検証用ホスト名のままにします。`controlUrl` は有効な証明書を持つ対照ホストで、証明書拒否と通信失敗の切り分けの目安に使います。

## チェック

DNS は `v.lab...` 配下のランダムなラベルへ HTTPS で接続します。`{"path":"fake"}` は偽のネームサーバー、`{"path":"true"}` は正規のネームサーバーです。失敗時は判定不能です。

TLS は `https://login.v.lab.../tls-probe` へ接続します。`{"tls":"forged"}` は検証用サーバーが偽造証明書を提示し、ブラウザが受理したという意味です。`{"tls":"valid"}` は有効な証明書で接続が完了したという意味です。リクエストが失敗した場合は `controlUrl` を確認します。対照ホストへ接続できても証明書拒否を証明するものではなく、拒否と矛盾しないというだけです。ブラウザは証明書エラー自体を JavaScript には公開しません。

DNS が `fake` を返すには、偽のネームサーバーがランダムな probe 名には有効な証明書を、MITM ホストには偽造証明書を提示する必要があります。そうでない場合、ブラウザが probe の応答を読む前に証明書を拒否します。

結果には DNS と TLS の状態を別々に表示します。DNS が偽で、TLS 接続が失敗し証明書拒否と矛盾しない中間状態も含みます。2 つの確認は独立したリクエストで、同じ接続を観測したものではありません。
