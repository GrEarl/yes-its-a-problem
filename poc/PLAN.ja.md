# DNS + TLS MITM PoC: 設計

[English](PLAN.md) | [日本語](PLAN.ja.md)

## 1. 連鎖

1. 再帰リゾルバが親ゾーンの委任応答に含まれる ADDITIONAL A レコードを使います。ネームサーバー名を独立に解決せず、示されたアドレスを使います。
2. 一部の TLS クライアントは回収した eMudhra 中間 CA の秘密鍵で署名された証明書を受け入れます。

## 2. 名前

    public site:  https://yes-its-a-problem.iamwonderingif.com
    parent zone:  iamwonderingif.com (Cloudflare)
    lab zone:     lab.yes-its-a-problem.iamwonderingif.com -> IP1
    child zone:   v.lab.yes-its-a-problem.iamwonderingif.com
    probe:        <random>.v.lab.yes-its-a-problem.iamwonderingif.com
    MITM host:    login.v.lab.yes-its-a-problem.iamwonderingif.com

## 3. DNS の役割

    IP1  provider  lab ゾーンの権威サーバー。NS ns<hash>.true.lab... と
                    IP2 を指す ADDITIONAL A を含む委任応答を返す。
                    ns*.true.lab... の A には IP3 を返す。
    IP3  true NS   正規の A レコードと、resolver probe 用の正規証明書を返す。
    IP2  fake NS   偽の A レコードと、MITM ホスト用の偽造 eMudhra 証明書を返す。
                    ランダムな probe 名には正規のワイルドカード証明書を返し、
                    DNS チェックが path=fake を返せるようにする。

注: このラボでは IP1 が ns<hash>.true.<zone> についても権威を持つため、
ADDITIONAL A は同じ provider の権威データになる。モデルが示すのはデータの
流れであり、厳密な out-of-bailiwick の失敗ではない。

安全なリゾルバ

    resolver -> IP1: 委任応答、NS nsX.true...、ADDITIONAL IP2
    resolver は ADDITIONAL を無視する
    resolver -> IP1: A nsX.true... = IP3
    resolver -> IP3: A <probe> = IP3
    probe の応答: {"path":"true"}

脆弱なリゾルバ

    resolver -> IP1: 同じ委任応答
    resolver は ADDITIONAL の nsX.true... = IP2 を使う
    resolver -> IP2: A <probe> = IP2
    probe の応答: {"path":"fake"}

## 4. HTTP チェック

    GET https://<random>.v.lab.../probe  -> {"path":"true"|"fake"}
    GET https://login.v.lab.../tls-probe -> 偽造コンテキストから {"tls":"forged"}

DNS と TLS は別々に確認します。結果はブラウザのページ内にだけ表示します。

## 5. 証明書

`poc/lab/certs/make_leaf.py` は、回収した EM DV TLS CA - G3B の秘密鍵で署名したリーフ証明書を作ります。チェーンには AAA Certificate Services の cross-signature を使います。秘密鍵は `secrets/` に置き、公開しません。

リーフは公開 CA ではなく、回収した中間 CA の鍵で作ります。probe ホストも同じリーフチェーンを使います。

## 6. デモ

- `demo/electron-payment/`: KBC（空手形銀行）の振込画面。`legacy` は Electron 36.9.5、`hardened` は Electron 45.0.0。
- `demo/fake-pkg/`: Kirimochi。英語のみのパッケージマネージャーのデモ。manifest を取得し、レジストリが提供する pin されていない鍵で署名を検証する。

## 7. デプロイ

1. Cloudflare の DNS レコードと委任を作る。
2. VPS 上で 3 つの DNS 役割と HTTP サーバーを起動する。公開する HTTP サーバーでは `--bind 0.0.0.0` を明示する。
3. 回収した CA 秘密鍵で `poc/lab/certs/make_leaf.py` を実行する。probe ホストには生成したリーフを使う。
4. 正規証明書の HTTP サーバーと、偽造証明書の HTTP サーバーを 1 台ずつ起動する。
5. GitHub Pages で `docs/` を公開する。
6. 公開するラボでは `lab_http.py --log` を有効にしない。`--log` は訪問者の IP アドレスと User-Agent を記録する。
