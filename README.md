# Yes, it's a problem

DNS の委任応答と TLS の証明書検証を組み合わせた PoC です。

1. 再帰リゾルバが委任応答に含まれる out-of-bailiwick な ADDITIONAL グルーを受け入れます。本来はネームサーバー名を別に解決すべきところで、攻撃側のアドレスを使います。
2. TLS クライアントが偽造証明書を受け入れます。証明書は回収した eMudhra 中間 CA の秘密鍵で署名されています。

元の調査（第三者）: <https://emudhra.we-have-a-problem.com/>

## 構成

| パス | 内容 |
|---|---|
| docs/ | DNS と TLS の確認ページ。GitHub Pages のソース。 |
| demo/electron-payment/ | 振込画面の Electron デモ。旧ビルドと現行ビルドを比較する。 |
| demo/fake-pkg/ | Kirimochi。英語のみのパッケージマネージャーのデモ。 |
| poc/ | DNS 検証、HTTP(S) サーバー、証明書生成、設計ノート。 |
| .github/workflows/release.yml | Electron と kirimochi.pyz をビルドし、v* タグでリリースする。 |

## ローカル確認

最初にリーフ証明書を作ります。初回は公開 CA 証明書から回収した CA 秘密鍵を `secrets/artifacts/keys` に生成します。

    python3 poc/lab/certs/make_leaf.py --days 30

    # DNS のループバック検証
    bash poc/lab/dns/test_local.sh

    # モックレジストリ
    python3 demo/fake-pkg/server/mock_registry.py --port 9445 \
      --cert secrets/demo-cert/fullchain.pem \
      --key secrets/demo-cert/leaf.key.pem

    # パッケージマネージャー
    python3 demo/fake-pkg/src/kirimochi.py install demo-lib \
      --url https://pkg.v.lab.yes-its-a-problem.iamwonderingif.com:9445 \
      --connect 127.0.0.1:9445

証明書と秘密鍵は `secrets/` に置きます。リポジトリには含めません。

## ビルド

v0.1.0 などのタグを push すると、GitHub Actions が Electron の legacy ビルド、hardened ビルド、kirimochi.pyz を生成します。
生成物は GitHub Release にアップロードします。
