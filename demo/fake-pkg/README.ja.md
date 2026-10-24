# Kirimochi

[English](README.md) | [日本語](README.ja.md)

CLI の表示は英語で、受け付けるパッケージは `demo-lib` だけです。manifest とレジストリが提供する公開鍵を取得し、配布データのチェックサムと manifest の署名を検証します。署名検証には OpenSSL を使います。パッケージのインストールや実行は行いません。

これは PoC です。Kirimochi とレジストリは架空で、パッケージはインストールされません。

PoC サイト: <https://yes-its-a-problem.iamwonderingif.com/>

## 実行

`demo/fake-pkg` で実行します。OpenSSL が必要です。

まず、単独で実行できるローカル確認を行います。

    python3 -B test_kirimochi.py

この確認では、一時的な合成鍵と証明書を作り、公開レジストリファイルの書き出しと検証を行い、配布形式にまとめたクライアントを `127.0.0.1` の HTTPS サーバーへ接続します。既定の信頼設定での拒否、テスト用ルートをプロセスに指定した場合の成功、ホスト名不一致の拒否、manifest・payload の改変検知を確認します。外部サービスや問題の CA の鍵・証明書は使わず、システムの信頼設定も変更しません。既存の配布候補を確認するときは `--pyz /path/to/kirimochi.pyz` を追加します。

準備済みのラボ証明書を使って手動で実行する場合は、レジストリを起動します。

    python3 server/mock_registry.py --port 9445 \
      --cert ../../secrets/demo-cert/fullchain.pem \
      --key ../../secrets/demo-cert/leaf.key.pem

別のシェルでクライアントを実行する。

    SSL_CERT_FILE=../../secrets/demo-cert/root.pem \
      python3 src/kirimochi.py install demo-lib \
      --url https://pkg.v.lab.yes-its-a-problem.iamwonderingif.com:9445 \
      --connect 127.0.0.1:9445

`--connect` はレジストリのホスト名の DNS 解決を迂回します。TLS は引き続き `--url` のホスト名を検証します。`SSL_CERT_FILE` はこのプロセスだけでルートを指定し、システムのトラストストアを変えずに、そのルートを信頼するクライアントを模擬します。`SSL_CERT_FILE` と `SSL_CERT_DIR` の両方を未設定にすると、実行環境の既定の信頼設定と比較できます。出力には接続先の指定と、これらの環境変数が設定されているかを残します。

TLS 検証、配布データのチェックサム、manifest の署名がすべて通ると、`OBSERVED` を表示し、終了コード `0` を返します。検証鍵も署名済み manifest も同じレジストリが提供するため、ここで確認できるのは、その鍵に対応した正しい署名であることです。署名偽造や DNS 汚染が成立した証拠にはなりません。配布者の真正性は引き続きレジストリへの信頼に依存します。

証明書検証に失敗すると、`REJECTED` と実行環境から得た検証理由を表示し、終了コード `2` を返します。それ以外の TLS エラーや接続失敗は `INCONCLUSIVE` と終了コード `3` で示します。チェックサムや署名の検証が失敗した場合、検証できない場合も終了コードは `3` です。どの結果でもパッケージのインストールや実行は行いません。

## 公開レジストリファイル

ラボ共通の HTTPS サーバー向けに、無害なレジストリデータを書き出します。

    python3 server/mock_registry.py --export /path/to/public-registry

出力は `manifest.json`、`manifest.sig.b64`、`public_key.pem`、空の `package.tar.gz` です。一時的な署名鍵は書き出し後に削除し、このディレクトリには含めません。公開ファイル 4 個をまとめて配置し、そのディレクトリを `poc/lab/http/lab_http.py --registry-dir` に指定します。

サーバーは元の manifest のバイト列を `/manifest.json` で返し、`manifest.sig.b64` の末尾の改行を取り除いた値を `X-Kirimochi-Signature` ヘッダーに付けます。残りのレスポンスは `/public_key.pem` と `/package.tar.gz` で返します。payload は意図的に空にしてあり、インストール可能なアーカイブではありません。

## ビルド

    mkdir -p dist
    python3 -m zipapp src -p "/usr/bin/env python3" -o dist/kirimochi.pyz
