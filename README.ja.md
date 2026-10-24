# Yes, it's a problem

[English](README.md) | [日本語](README.ja.md)

> **Beta: 展開と検証は途中です。** 現時点の結果は Proof（証明）ではありません。ラボ，サイト，クライアントの展開と検証が完了するまで，確認済みの証拠として扱わないでください。

DNS の委任応答と TLS の証明書検証を題材にする，公開前の教育用 PoC です。空手形銀行と Kirimochi は架空のサービスで，実際の振込やインストールは行われません。

1. 現在の DNS ラボは，固定したローカル権威サーバー間のレコード照合です。実際の再帰リゾルバの挙動や，共有 DNS 事業者を越える委任は再現していません。
2. リポジトリには公開証明書から危殆化した eMudhra 中間 CA の秘密鍵を再構成するコードがあります。これらの中間 CA は失効済みです。含まれる通常の回帰テストは毎回生成する合成 CA のみを使い，実 CA 鍵の回収・署名は行いません。ブラウザー確認ページは実行中のブラウザーだけを調べ，サーバーが報告する TLS 分類もブラウザーのピア証明書と独立に照合するものではありません。

元の調査（第三者，報告者 Wayne）: <https://emudhra.we-have-a-problem.com/>

出典と警告:

- [証明バンドル](https://emudhra.we-have-a-problem.com/proof.zip)
- [公開されている証明書チェーン](https://emudhra.we-have-a-problem.com/chains.zip)
- [Mozilla のインシデント報告](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Mozilla dev-security-policy の議論](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE)
- [Chromium の CRLSet](https://www.chromium.org/Home/chromium-security/crlsets/)
- [各 OS・ディストリの修正版](https://emudhra.we-have-a-problem.com/#patched-os)

DNS グルー処理の背景（このラボを個別に検証するものではありません）:

- [Cloudflare Community: 権威ネームサーバーに無関係な ADDITIONAL がある場合に 1.1.1.1 が誤った A レコードを返す件](https://community.cloudflare.com/t/1-1-1-1-answers-wrong-a-record-when-authority-name-server-has-unrelated-addtional/966458)
- [Rethinking the Security Threats of Stale DNS Glue Records（USENIX Security 2024）](https://www.usenix.org/system/files/usenixsecurity24-zhang-yunyi-rethinking.pdf)（[発表ページ](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-yunyi-rethinking)）
- [ISC BIND: Operational Notification: Impact of Stricter Glue Checking](https://kb.isc.org/docs/strict-glue)

MITM 先のエスカレーション（CVE-2026-111497，Node2Shell / HTTP2Shell。下の「エスカレーション」節で引用）:

- [Node.js October 2026 security releases: Brotli デコーダーの境界外書き込みがリモートコード実行を許す](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [GHSA-9v8h-qqgm-4m35: Brotli 境界外書き込み，PyPI Brotli パッケージも影響](https://github.com/advisories/GHSA-9v8h-qqgm-4m35)
- [Imperva: Node2Shell — Brotli データからリモートコード実行へ](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/)
- 公開 PoC が既に存在: [dimasma0305/CVE-2026-111497-POC](https://github.com/dimasma0305/CVE-2026-111497-POC)（プロファイル固定の RCE ハーネス），[gh0st-nemesis/node2shell-poc](https://github.com/gh0st-nemesis/node2shell-poc)（Docker 再現ラボ），[6mile/node-python2shell](https://github.com/6mile/node-python2shell)（Python 影響証明）

## 利用上の注意

このリポジトリ内のラボ名，または自分が管理するホストに対してのみ実行してください。eMudhra 中間 CA は失効済みです。現在のブラウザーやプラットフォームの対応状況は，リンク先のインシデント報告を確認してください。秘密鍵そのものは含みませんが，元の鍵生成の欠陥により公開証明書から CA 秘密鍵を再構成するコードを含みます。回収した鍵と生成物は無視対象の `secrets/` にローカル保存し，CA 鍵を公開サーバーへ置かないでください。詳細は [SECURITY.md](SECURITY.md)。

## デモ済みチェーンの先のエスカレーション（文書化のみ，実装なし）

このデモで示すチェーンは，攻撃者に二つの立場を与えます。クライアントが攻撃者の管理するサーバーへ誘導されることと，そのサーバーの偽装証明書をクライアントが受理することです。ここから攻撃者はセッションを読み，書き換えられます。ラボの fake サーバーの振る舞いは `--behavior` で選べます。`observe`（既定）は正規と同じ値の quote と支払いを返すため，デモクライアント自身のデータ検査は通り，画面上のすべての値が攻撃者由来でも気づけません。`tamper` は quote と支払いの両方を書き換え，ペイロードを検査するクライアントには不一致として表示されます。`redirect` は quote を正規のまま残し支払いだけを書き換えるため，正しい見積もりを確認した利用者が攻撃者の口座へ送金する状況を表します。同じ立場で，送信された認証情報の収集や通信の改変（情報の詐取）も可能です。

さらに，応答本体がメモリ安全性の欠陥を持つデコーダーに届けば，同じ立場はコード実行へ拡大します。これは現時点で仮説ではなく実在します。CVE-2026-111497（Node2Shell / HTTP2Shell）は Node.js 同梱の Brotli デコーダーの境界外書き込みです。不正な block switch が恒久的な書式エラーではなく「入力が一時的に足りない」として扱われたため，ストリーミングデコーダーは 8 バイトの内部バッファへ入力を追加し続けます。Node.js の勧告は前提を正確に述べています。「node:zlib で展開する Brotli データを供給できる攻撃者は，プロセスメモリを破壊でき，クラッシュ，プロセスメモリの漏えい，またはリモートコード実行につながる」。Node.js は本件を High と評価し，22.23.4 / 24.22.1 / 26.12.1 で修正しました。PyPI の Brotli パッケージと brotlicffi も同じデコーダーを同梱し（修正 1.2.1 / 1.2.1.0，GitHub 勧告は Critical と評価），公開 PoC リポジトリも既に存在し，Node v24.22.0 ラボ上でネットワーク経由のコード実行を達成するプロファイル固定の RCE ハーネスも含まれます。Electron は Node.js を同梱するため，攻撃者由来のデータを `node:zlib` で展開するアプリケーションはこの勧告の対象です。Electron の `net` モジュールやレンダラー経由の通信は Chromium のネットワークスタックとその別途同梱されたデコーダーを使い，上記の勧告群では扱っていません。

このリポジトリはその先の一歩を意図的に踏みません。エクスプロイトコードも不正ストリーム生成器も含まず，`Content-Encoding` の取り扱いも一切ありません。ラボサーバーは送出せず，Kirimochi クライアントは標準ライブラリの `http.client` を使い（Brotli を一切復号しません），Electron デモは Chromium スタック経由で取得します。この PoC は信頼の破綻を実証し，エスカレーションは上記の出典で文書化します。武器化はここでは行いません。

## 構成

| パス | 内容 |
|---|---|
| `docs/` | DNS と TLS の確認ページ。GitHub Pages のソース。 |
| `demo/electron-payment/` | 振込画面の Electron デモ。旧ビルド（legacy）と現行ビルド（hardened）を比較する。 |
| `demo/fake-pkg/` | Kirimochi。英語のみのパッケージマネージャーのデモ。 |
| `poc/` | DNS ラボ，HTTP(S) サーバー，証明書生成，設計ノート。 |
| `.github/workflows/release.yml` | Electron デモと `kirimochi.pyz` をビルドし，`v*` タグでリリースする。 |

## ローカル確認

まず，外部システムや危殆化 CA 鍵を使わないローカル回帰テストを実行します。

    python3 -B poc/lab/test_lab.py
    bash poc/lab/dns/test_local.sh
    python3 -B demo/fake-pkg/test_kirimochi.py
    node demo/electron-payment/test.js
    node docs/test.js
    python3 -B -m unittest discover -s poc/deploy -p 'test_*.py' -v

公開前の配置要件を確認する場合:

    python3 poc/deploy/deploy.py preflight

DNS ラボは必要な外部子 NS 指定に対応済みで，現在の `preflight` は終了コード 0 で，未入力の配備入力（公開 IPv4，SSH alias，ACME 連絡先メール，証明書入力）の `PENDING` 行のみを返します。`preflight --require dns` は入力が揃うまで失敗します。この状態を公開配備可の判定にはしないでください。ローカル確認は Python 3，`cryptography`，OpenSSL，Node.js が必要です。`dnslib` は `poc/vendor` に同梱しています。

CA 秘密鍵をローカルで回収・生成するコマンドは，通常のテストや配備手順に含めません。テスト用ルート証明書は合成 CA から生成し，公開サーバーへ CA 秘密鍵を置かないでください。既存の証明書と秘密鍵は `secrets/` に置き，リポジトリや VPS へ CA 秘密鍵を含めないでください。

## ビルド

現在のソース候補は `0.1.0-beta.3` です。`v0.1.0-beta.2` は以前のコミットを指すタグなので移動・再利用しません。`v0.1.0-beta.3` もまだ作成していません。タグ公開前に DNS のブロッカーを解消し，最新ソースで CI と配備後検証を完了してください。安定版の `v0.1.0` は公開実証が終わってから検討します。現行 workflow は macOS・Ubuntu・Windows 向け Electron 成果物と `kirimochi.pyz` を作る構成ですが，最新ソースの GitHub Actions 実行と全 OS の実ビルドは未検証です。

## ライセンス

MIT。[LICENSE](LICENSE) を参照。第三者の証明書データと調査リンクは，それぞれの出典元の条件に従います。
