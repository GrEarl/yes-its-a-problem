# Yes, it's a problem

[English](README.md) | [日本語](README.ja.md)

> **Beta: 展開と検証は途中です。** 現時点の結果は Proof（証明）ではありません。ラボ、サイト、クライアントの展開と検証が完了するまで、確認済みの証拠として扱わないでください。

DNS の委任応答と TLS の証明書検証を組み合わせた PoC です。空手形銀行と Kirimochi は架空のサービスで、実際の振込やインストールは行われません。

1. 再帰リゾルバが委任応答に含まれる ADDITIONAL グルーを使います。本来はネームサーバー名を別に解決すべきところで、示されたアドレスを使います。
2. 一部の TLS クライアントは偽造証明書を受け入れます。証明書は回収した eMudhra 中間 CA の秘密鍵で署名されています。

元の調査（第三者、報告者 Wayne）: <https://emudhra.we-have-a-problem.com/>

出典と警告:

- [証明バンドル](https://emudhra.we-have-a-problem.com/proof.zip)
- [公開されている証明書チェーン](https://emudhra.we-have-a-problem.com/chains.zip)
- [Mozilla のインシデント報告](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Mozilla dev-security-policy の議論](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE)
- [Chromium の CRLSet](https://www.chromium.org/Home/chromium-security/crlsets/)
- [各 OS・ディストリの修正版](https://emudhra.we-have-a-problem.com/#patched-os)

## 利用上の注意

このリポジトリ内のラボ名、または自分が管理するホストに対してのみ実行してください。偽造証明書を返すサーバーは、公開された中間傍受サービスではありません。ここで使う eMudhra 中間 CA は失効済みで、秘密鍵は含まれていません。`secrets/` はローカルに留めてください。詳細は [SECURITY.md](SECURITY.md)。

## 構成

| パス | 内容 |
|---|---|
| `docs/` | DNS と TLS の確認ページ。GitHub Pages のソース。 |
| `demo/electron-payment/` | 振込画面の Electron デモ。旧ビルド（legacy）と現行ビルド（hardened）を比較する。 |
| `demo/fake-pkg/` | Kirimochi。英語のみのパッケージマネージャーのデモ。 |
| `poc/` | DNS ラボ、HTTP(S) サーバー、証明書生成、設計ノート。 |
| `.github/workflows/release.yml` | Electron デモと `kirimochi.pyz` をビルドし、`v*` タグでリリースする。 |

## ローカル確認

最初にリーフ証明書を作ります。初回の実行では、`make_leaf.py` が公開 CA 証明書から CA 秘密鍵を回収し、`secrets/artifacts/keys` に保存します。

    python3 poc/lab/certs/make_leaf.py --days 30

    # DNS のループバック検証
    bash poc/lab/dns/test_local.sh

    # モックレジストリ
    python3 demo/fake-pkg/server/mock_registry.py --port 9445 \
      --cert secrets/demo-cert/fullchain.pem \
      --key secrets/demo-cert/leaf.key.pem

    # パッケージマネージャー。ラボのルートはシステムでは信頼されていない。
    # この環境変数はローカルテスト専用。
    SSL_CERT_FILE=secrets/demo-cert/root.pem \
      python3 demo/fake-pkg/src/kirimochi.py install demo-lib \
      --url https://pkg.v.lab.yes-its-a-problem.iamwonderingif.com:9445 \
      --connect 127.0.0.1:9445

前提: Python 3、`cryptography`、OpenSSL、`dig`。`dnslib` は `poc/vendor` に同梱しています。

証明書と秘密鍵は `secrets/` に置きます。リポジトリには含めません。

## ビルド

現時点の beta では `v0.1.0-beta.2` タグを push します。安定版の `v0.1.0` は、展開と検証が完了してから作成してください。タグを push すると、GitHub Actions が `macos-latest`、`ubuntu-latest`、`windows-latest` の 3 OS で Electron の旧ビルドと現行ビルドを生成し（3 OS × 2 バージョンの 6 ジョブ）、`kirimochi.pyz` も 1 つ生成して GitHub Release にアップロードします。成果物は macOS の `dmg`/`zip`、Windows の `nsis`/`zip`、Linux の `AppImage` で、Python の zipapp はクロスプラットフォームです。

## ライセンス

MIT。[LICENSE](LICENSE) を参照。第三者の証明書データと調査リンクは、それぞれの出典元の条件に従います。
