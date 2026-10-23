# docs

[English](README.md) | [日本語](README.ja.md)

静的サイトです。ビルド処理はありません。日本語と英語に対応し、`?lang=ja` / `?lang=en` で初期言語を指定できます。クエリがない場合は保存された言語設定、またはブラウザーの優先言語を使います。スクリプトが動かない場合の静的 HTML は英語で、`i18n.js` が読み込み後に切り替えます。

## 公開

1. リポジトリを GitHub に push する。
2. Settings の Pages を開き、Source で Deploy from a branch を選ぶ。ブランチは `main`、フォルダは `/docs`。
3. カスタムドメインに `yes-its-a-problem.iamwonderingif.com` を設定する。`docs/CNAME` に設定済み。
4. Cloudflare で `yes-its-a-problem` の CNAME レコードを作り、値に `<owner>.github.io` を指定する。DNS only にする。
5. Enforce HTTPS を有効にする。

## 設定

`config.js` には `releasesUrl`、`labDomain`、`mitmHost` があります。`releasesUrl` は GitHub の owner/repo に合わせます。`labDomain` と `mitmHost` は検証用ホスト名のままにします。

## チェック

DNS は `v.lab...` 配下のランダムなラベルへ HTTPS で接続します。`{"path":"fake"}` は偽のネームサーバーが応答したことを意味し、`{"path":"true"}` は正規のネームサーバーが応答したことを意味します。失敗時は判定不能です。

TLS は `https://login.v.lab.../tls-probe` へ接続します。`{"tls":"forged"}` はサーバーが偽造証明書を提示し、ブラウザーが受理したという意味です。`{"tls":"valid"}` は正規の証明書で確認が完了したという意味です。リクエストが失敗した場合は判定不能です。ブラウザーは証明書エラーをページに渡さないため、拒否と通信の失敗は区別できません。

DNS が `fake` を返すには、偽のネームサーバーがランダムな probe 名には有効な証明書を、MITM ホストには偽造証明書を提示する必要があります。そうでない場合、ブラウザーが probe の応答を読む前に証明書を拒否します。

結果は DNS と TLS の状態の組み合わせを表示します。DNS が偽で TLS の確認が完了しなかった中間状態（DNS の経路は攻撃者側だが、TLS の結果は判定できない状態）も含みます。結果の先頭には「安全」「危険」「注意」「危険の可能性あり」「判定不能」のいずれかを付けます。TLS の確認だけが失敗した状態を「安全」とは表示しません。片方だけ実行した場合は「未判定」と表示します。
