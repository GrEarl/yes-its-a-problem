# Yes, it's a problem

[English](README.md) | [日本語](README.ja.md)

DNS の委任応答と TLS の証明書検証を組み合わせた PoC です。

1. 再帰リゾルバが、委任応答に含まれる out-of-bailiwick な ADDITIONAL グルーを受け入れます。本来はネームサーバー名を別に解決すべきところ、攻撃側のアドレスを使います。
2. TLS クライアントが偽造証明書を受け入れます。証明書は、回収した eMudhra 中間 CA の秘密鍵で署名されています。

元の調査（第三者）: <https://emudhra.we-have-a-problem.com/>

## ソースとアドバイザリ

- [証明バンドル](https://emudhra.we-have-a-problem.com/proof.zip)
- [公開証明書チェーン](https://emudhra.we-have-a-problem.com/chains.zip)
- [Mozilla インシデント報告](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Mozilla dev-security-policy スレッド](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE)
- [Chromium CRLSets](https://www.chromium.org/Home/chromium-security/crlsets/)
- [OS・ディストリビューション別の修正バージョン](https://emudhra.we-have-a-problem.com/#patched-os)

## DNS グルーの背景

- [Cloudflare Community: 権威ネームサーバーに無関係な ADDITIONAL がある場合に 1.1.1.1 が誤った A レコードを返す件](https://community.cloudflare.com/t/1-1-1-1-answers-wrong-a-record-when-authority-name-server-has-unrelated-addtional/966458) — このラボが再現するものと同じ誘導形状のコミュニティ報告。
- [Rethinking the Security Threats of Stale DNS Glue Records (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-zhang-yunyi-rethinking.pdf)（[発表](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-yunyi-rethinking)）— ステールグルーの隣接研究。挙動の類型として引用。
- [ISC BIND: より厳格なグルーチェックの影響](https://kb.isc.org/docs/strict-glue) — BIND 9.18.41 / 9.20.15 / 9.21.14 は、NS ターゲットが委任名のサブドメインである場合に限りグルーを信頼します。本プロジェクトが事業者へ求める修正です。

## MITM 後のエスカレーション（CVE-2026-111497、「Node2Shell」/「HTTP2Shell」）

- [Node.js 2026年10月 セキュリティリリース](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) — Brotli デコーダーの境界外書き込みによる RCE。
- [GHSA-9v8h-qqgm-4m35](https://github.com/advisories/GHSA-9v8h-qqgm-4m35) — PyPI Brotli パッケージの同じデコーダー欠陥。
- [Imperva: Node2Shell — Brotli データから RCE へ](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/)
- 公開 PoC: [dimasma0305/CVE-2026-111497-POC](https://github.com/dimasma0305/CVE-2026-111497-POC)、[gh0st-nemesis/node2shell-poc](https://github.com/gh0st-nemesis/node2shell-poc)、[6mile/node-python2shell](https://github.com/6mile/node-python2shell)。RCE の成立は構成依存です。

## 利用と限界

このリポジトリのラボ名、または自分が管理するホストに対してのみ実行してください。ここで使う eMudhra 中間証明書は失効済みです。プラットフォームの対応はリンク先のインシデント報告を参照してください。秘密鍵は同梱していませんが、公開 CA 証明書から危殆化した CA 秘密鍵を再構成するコードは含まれます（元の鍵生成が脆弱だったためです）。回収した鍵は無視対象の `secrets/` にローカルで保持し、CA 鍵を公開サーバーに置かないでください。[SECURITY.md](SECURITY.md) を参照してください。

## 実証した連鎖を超えたエスカレーション

この PoC は二つの立場を個別に示します。クライアントが攻撃者のサーバーへ誘導されること、そしてクライアントがそのサーバーの偽造証明書を受理することです。両方が揃えば攻撃者はセッションを読み書き換えられますが、一つの接続・一つの経路での成立はまだ示していません。

偽ラボサーバーの挙動は `--behavior` で選べます。`redirect`（既定）は見積もりを正規のままにして支払いだけを書き換えます。`observe` は正規の値を映すため、表示値がすべて攻撃者由来でもクライアント自身の検査を通ります。`tamper` は両方を書き換え、ペイロードを検査するクライアントには見積もり段階で検知されます。

同じ立場は、応答本体が google/brotli 1.0.3〜1.2.0 由来の Brotli デコーダーで展開される場合に、コード実行の前提条件に到達します（CVE-2026-111497）。前提条件は実在しますが、RCE の段階自体はここでは生成しておらず、攻撃用ペイロードも同梱しません。振込とパッケージの経路は `Content-Encoding: br` を展開せず、ラボ専用の更新フローだけが意図的に正当な Brotli マーカーをデコーダーへ届けます。Electron アプリの CVE-2026-111497 への露出は、同梱 Node ではなく Chromium バージョンで決まります（Electron 41 以下＝Chromium 148 未満が影響、42 以上は影響なし）。Electron 36 はサポート終了済みです。

## 構成

| パス | 内容 |
|---|---|
| `docs/` | DNS と TLS の確認ページ。GitHub Pages のソース。 |
| `demo/electron-payment/` | 振込画面の Electron デモ。旧ビルドと現行ビルドを比較する。 |
| `demo/fake-pkg/` | Kirimochi。英語のみのパッケージマネージャーのデモ。 |
| `poc/` | DNS ラボ、HTTP(S) サーバー、証明書生成、設計ノート。 |
| `.github/workflows/release.yml` | Electron デモと `kirimochi.pyz` をビルドし、`v*` タグでリリースする。 |

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

前提: Python 3、`cryptography`、OpenSSL、`dig`。

証明書と秘密鍵は `secrets/`（無視対象）に置きます。

## ビルド

`v0.1.0` などのタグを push すると、GitHub Actions が Electron の旧ビルド、現行ビルド、`kirimochi.pyz` を生成し、GitHub Release にアップロードします。
