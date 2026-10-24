# 3 VPS 用の配備準備

このディレクトリは、所有ドメインのラボを **別々の Ubuntu 24.04 LTS VPS 3 台**へ配置するための手順とツールです。1 台に 3 IP を割り当てる構成には対応しません。契約・決済・Cloudflare 操作・GitHub 公開は行いません。

**現状は公開可能の判定ではありません。** 外部子 NS を指定する `--child-ns` 契約は `lab_dns.py` に実装済みで、`preflight` の DNS 行は PASS です。ただし VPS 入力（公開 IPv4、SSH alias、ACME メール、証明書入力）が未入力のため `PENDING` が残り、`preflight --require dns` は入力が揃うまで失敗します。`apply` と `acme` もその時点まで停止します。VPS、委任、ACME、GitHub Pages、本番 HTTPS は未検証です。

## 今すぐ行えるローカル確認

リポジトリルートから実行します。Python 3.9 以上、`cryptography` 40 以上、OpenSSL が必要です。DNS ライブラリは既存の同梱版を使います。

```sh
python3 -m unittest discover -s poc/deploy -p 'test_*.py' -v
python3 poc/deploy/deploy.py preflight
python3 poc/deploy/deploy.py plan --stage dns
```

`preflight` と `plan` は通信・配置・発行を行いません。`PASS [local]` はローカルの対象ファイル検査だけを表します。`PENDING` は未入力・未検証、`BLOCKED` は実装不足や無効な入力です。現時点の `preflight` は DNS 契約に PASS し、残る `PENDING` は未入力の VPS・証明書入力です。`plan` の `null` は未割当で、実際の配置には使用できません。

テストは合成証明書だけを作り、SSH、ACME、公開 DNS、実在 CA の秘密鍵を使いません。`public-registry/` は Kirimochi 用の署名済み公開 fixture 4 ファイルです。配布用の署名秘密鍵は含みません。

## 入力と VPS 条件

| 役割 | 公開 IPv4 | 必要なサービス |
|---|---|---|
| `provider` | IP1 | UDP/TCP 53 |
| `fake` | IP2 | UDP/TCP 53、TCP 443 |
| `true` | IP3 | UDP/TCP 53、TCP 443 |

3 IP は各 VPS のネットワークインターフェースに直接割り当てられた、異なる公開 IPv4 unicast とします。NAT の外側にだけ存在する IP には対応しません。SSH の接続先も 3 台別々にし、ホスト鍵を事業者の管理画面等と照合して `known_hosts` に登録します。ツールは `BatchMode=yes` / `StrictHostKeyChecking=yes` を使い、未知の鍵を自動受諾しません。

SSH alias は `~/.ssh/config` に作成し、接続ユーザーから `sudo -n /usr/bin/python3` を実行できる状態にします。例の `yip-provider`、`yip-fake`、`yip-true` は任意の別名に置き換えられます。`ssh-check` は OS、sudo、割当 IP、待受ポート、3 台の machine-id の違いを確認します。

VPS の事業者側ファイアウォールと OS ファイアウォールの両方で、53/udp と 53/tcp をインターネットから許可します。IP2/IP3 は 443/tcp も許可します。SSH は管理元から許可し、現在の SSH 経路を残してから変更します。ツールはファイアウォールや既存 DNS サービスを無断で停止・上書きしません。80/tcp は DNS-01 発行には不要です。ラボ用の AAAA は作りません。

```sh
mkdir -p secrets
chmod 700 secrets
cp poc/deploy/config.example.json secrets/deploy.json
chmod 600 secrets/deploy.json
```

`secrets/deploy.json` を編集します。

| フィールド | 内容 |
|---|---|
| `hosts.<role>.ipv4` | IP1 / IP2 / IP3 |
| `hosts.<role>.ssh` | その VPS の SSH alias。`user@host` やコマンドは不可 |
| `acme_email` | 通常証明書を発行する ACME アカウントの連絡先 |
| `state_dir` | `null` ならこのリポジトリの `secrets/deploy-state/`。変更する場合は絶対パス |
| `forged_fullchain` | **既に用意されている** lab leaf + 中間証明書の絶対パス |
| `forged_key` | 上記 leaf の秘密鍵の絶対パス。所有者を実行ユーザーまたは root、権限を 0600 にする |

状態ディレクトリをリポジトリ内に置く場合は `secrets/` の下だけを許可します。外に置く場合は、実行ユーザー所有の 0700 ディレクトリを先に用意します。CA 秘密鍵の回収・生成・署名は本手順に含みません。`recover_keys.py`、`make_leaf.py`、`secrets/` 全体を転送しません。

証明書入力は所有者、権限、有効期間、SAN、leaf と鍵の一致、連続したチェーン署名を検査します。通常証明書はシステムの信頼ストアでも検証します。fake 用 leaf の SAN は `login` / `pay` / `pkg` の 3 ホストに限定し、公開された lab issuer と一致する必要があります。CA 証明書を leaf とした入力や CA 鍵の再利用は拒否します。転送する鍵は検証済み leaf 鍵だけを再シリアライズしたもので、入力ファイル末尾の別鍵を転送しません。

## Cloudflare のレコード計画

対象アカウントは **grey**、ゾーンは **iamwonderingif.com** です。値を確定した `plan` で照合し、所有者が設定します。既存レコードとの衝突は先に確認します。

| 種類 | 名前（FQDN） | 値 | Proxy |
|---|---|---|---|
| CNAME | `yes-its-a-problem.iamwonderingif.com` | `grearl.github.io` | DNS only |
| A | `ns1.yes-its-a-problem.iamwonderingif.com` | IP1 | DNS only |
| A | `ns-child.yes-its-a-problem.iamwonderingif.com` | IP3 | DNS only |
| NS | `lab.yes-its-a-problem.iamwonderingif.com` | `ns1.yes-its-a-problem.iamwonderingif.com` | 対象外 |

`ns1` と `ns-child` は委任する `lab...` の**外**にある通常の権威 A レコードです。Cloudflare 上の `ns-child` は常に正規の IP3 です。fake の IP2 をそこへ書きません。Cloudflare の lab 以下の A/TXT を編集しても、委任後の子権威の回答にはなりません。

このラボは DNSSEC 署名を配信しないため、`lab...` の委任に DS がある状態では動作しません。既存 DS、CNAME、競合する NS がある場合は所有者が構成を確認します。親ゾーンの DNSSEC 自体を無効にする必要はありません。祖先の CAA が発行 CA を制限している場合は Let's Encrypt を許可する必要があります。既存 CAA を一括削除しません。

## IP と前提が揃った後の順序

以下は **外部へ接続・変更するコマンド**です。現在は実行していません。`--config` はサブコマンドより前に指定します。

1. `preflight --require dns` の不足を解消し、`plan --stage dns` を確認します。未対応の DNS 契約が残る間は先に進みません。

   ```sh
   python3 poc/deploy/deploy.py --config secrets/deploy.json preflight --require dns
   python3 poc/deploy/deploy.py --config secrets/deploy.json plan --stage dns
   python3 poc/deploy/deploy.py --config secrets/deploy.json ssh-check --stage dns
   python3 poc/deploy/deploy.py --config secrets/deploy.json apply --stage dns
   ```

   `apply` は必要な Ubuntu パッケージを導入し、ログイン不可の `yip` ユーザー、固定 allowlist の公開ファイル、systemd unit を作ります。DNS は各公開 IP の UDP/TCP 53 に待ち受けます。リクエストログは無効です。unit は `CAP_NET_BIND_SERVICE` だけを持ち、コード・証明書・challenge ファイルを読み取り専用で参照します。

2. 上記 Cloudflare レコードを設定します。親の権威 NS に直接照会して NS/A を確認し、1.1.1.1 と 8.8.8.8 からも委任と正規 `ns-child` A=IP3 が引けることを確認します。UDP と TCP の両方が必要です。未反映・到達不能のまま ACME を繰り返し実行しません。

3. **コントローラー側**に Certbot を用意します（macOS は `brew install certbot`、Ubuntu 管理ホストはディストリビューションの Certbot）。まず staging、次に本番の通常 wildcard を発行します。`acme` の実行は Let's Encrypt の利用規約への同意と、設定したメールの登録を含みます。

   ```sh
   python3 poc/deploy/deploy.py --config secrets/deploy.json acme --staging
   python3 poc/deploy/deploy.py --config secrets/deploy.json acme
   ```

   対象は `*.v.lab.yes-its-a-problem.iamwonderingif.com` です。Certbot の auth hook は同じ `_acme-challenge.v.lab...` TXT を IP2/IP3 の `/var/lib/yip/challenges.json` へ原子的に反映します。両権威への UDP/TCP 照会と両公開リゾルバーからの TXT を確認してから ACME へ戻り、cleanup hook が値を削除します。両方への反映に失敗したら発行を進めません。staging の証明書と状態は別ディレクトリで、本番に転送しません。

4. 有効な既存 fake leaf の入力を確認し、HTTPS を配置します。

   ```sh
   python3 poc/deploy/deploy.py --config secrets/deploy.json preflight --require https
   python3 poc/deploy/deploy.py --config secrets/deploy.json plan --stage https
   python3 poc/deploy/deploy.py --config secrets/deploy.json apply --stage https
   ```

   IP3 は通常証明書だけを受け取ります。IP2 は同じ通常証明書に加え、指定された fake leaf とその鍵を受け取ります。provider には秘密鍵を送りません。ランダム probe は両 HTTPS サーバーの通常 wildcard、fake の `login` / `pay` / `pkg` SNI は指定 leaf を使います。Kirimochi の 4 公開 fixture も同じ listener へ配置し、別の 443 サーバーは立てません。`/manifest.json`、`/public_key.pem`、`/package.tar.gz` の 3 ルートを配信します。

5. [GitHub Pages の公開手順](../../docs/README.ja.md)を行います。`main` の `docs/`、custom domain、Enforce HTTPS が必要です。Pages の公開だけでは lab の DNS/HTTPS は動きません。[Release workflow](../../.github/workflows/release.yml)は実際のソース commit と、その package 版に一致する新しい `v` タグが必要です。候補は `v0.1.0-beta.3`、旧 beta.2 タグは再利用・移動しません。`workflow_dispatch` を main から実行する場合はビルドのみです。CI、公開アセット、配布済みアプリは未検証です。

6. 実際の公開経路を記録します。

   ```sh
   python3 poc/deploy/acceptance.py --config secrets/deploy.json --output secrets/acceptance.json
   ```

   両 IP の通常 HTTPS、外部ゾーンへの再帰拒否（UDP/TCP）、指定リゾルバーの A とその IP への pinned HTTPS、システムリゾルバー経由の別の HTTPS、login の TLS、Pages の日本語/英語 URL を確認します。fake の証明書拒否はクライアントの観測として残し、接続不能を成功にしません。`--insecure` は使いません。

   DNS 照会と pinned HTTPS は別観測です。システムリゾルバーとブラウザーの DoH も一致するとは限りません。最後に本番ブラウザーで両言語、DNS/TLS 結果、KBC と Kirimochi の配布物を確認します。Cloudflare Proxy や別の TLS 終端を lab HTTPS の前に置かないでください。どの結果も、全リゾルバー・全ブラウザーの脆弱性や、一つの接続での二段階攻撃を証明しません。

## 通常証明書の更新

[Certbot の manual hook と renewal](https://eff-certbot.readthedocs.io/en/stable/using.html#pre-and-post-validation-hooks)を使います。通常の manual 操作だけでは自動更新できませんが、この controller は保存済み auth/cleanup hook を使って更新し、成功した通常 leaf を両 VPS へ同期します。

```sh
python3 poc/deploy/deploy.py --config secrets/deploy.json renew --dry-run
python3 poc/deploy/deploy.py --config secrets/deploy.json renew
python3 poc/deploy/deploy.py --config secrets/deploy.json schedule
```

`renew --dry-run` は ACME staging 検証までで、証明書を配布しません。通常の `renew` は発行不要でも現在の正常な通常 leaf を再同期するので、一方の VPS だけへの転送失敗も次回に再試行します。証明書ディレクトリの切替は原子的で、更新後のサービス再起動に失敗した場合は前の証明書へ戻します。fake leaf を更新・再署名する機能はありません。有効期限が近づいたら、所有者が別途用意した新しい leaf 入力で `apply --stage https` を行います。

`schedule` は `secrets/deploy-state/schedule/`（状態ディレクトリ変更時はその配下）へファイルを生成するだけです。対応 OS で次を実行して有効にします。どちらも **controller のユーザー**で実行します。

macOS（ログイン中の controller）:

```sh
mkdir -p "$HOME/Library/LaunchAgents"
cp secrets/deploy-state/schedule/com.yip.renew.plist "$HOME/Library/LaunchAgents/"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.yip.renew.plist"
launchctl print "gui/$(id -u)/com.yip.renew"
```

常時稼働する Linux controller:

```sh
mkdir -p "$HOME/.config/systemd/user"
cp secrets/deploy-state/schedule/yip-renew.service secrets/deploy-state/schedule/yip-renew.timer "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now yip-renew.timer
systemctl --user list-timers yip-renew.timer
```

Linux でログアウト後も動かす場合は管理者が当該ユーザーの linger を有効にします。Mac がログアウト・停止・長期オフラインなら更新は実行されません。約 12 時間ごとの job が非対話 SSH と sudo に成功することを、再起動後にも確認します。Mac の結果は状態ディレクトリの `schedule/renew.*.log` と `launchctl print`、Linux は `journalctl --user -u yip-renew.service` で確認します。SSH agent にだけ依存するとログイン後の鍵読込が必要になるため、運用環境で非対話の `renew --dry-run` が通る構成にします。

## 停止と残る外部条件

停止は各 VPS で `sudo systemctl disable --now yip-http.service yip-dns.service`（provider は DNS unit だけ）です。Cloudflare の委任を残すと名前解決は失敗するため、所有者が公開終了のレコード変更も行います。アプリの request/query ログは初期状態で無効ですが、VPS 事業者や OS の通信・管理ログはこの設定とは別です。

公開判定に残る条件は、DNS の未対応契約、3 VPS/SSH/ポート、実際の親委任、ACME email と通常 wildcard 発行、有効な既存 fake leaf 入力、Pages 設定と HTTPS、最新ソースを含む Release CI、実リゾルバー/ブラウザー/配布物による確認です。これらの完了をローカルテストの成功で代用しません。
