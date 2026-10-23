# php-safepatch のテスト

[English](TESTING.md) | [한국어](TESTING.ko.md) | 日本語

php-safepatch は本番サーバーを変更するツールです。そのため、スクリプトを変更するたびに、以下の 3 つのテストすべてに合格する必要があります。テストは本番サーバーではなく、テスト用のマシンで実行してください。

| テスト | コマンド | 必要なもの | 所要時間 |
|---|---|---|---|
| 単体 | `tests/run.sh unit` | bash 4（Linux、macOS、Git Bash） | 1 分未満 |
| コンテナ | `tests/run.sh containers` | Docker または Podman、インターネット | 10〜20 分 |
| Windows | `tests\windows\run.ps1` | Windows、PowerShell 5.1、インターネット | 2〜5 分 |

## 単体テスト

模擬の PHP バイナリ、模擬の `dpkg-query` と `apt-get` を使います。root 権限、PHP、コンテナは不要です。確認する項目は次のとおりです。

- バージョンごとの判定（`VULNERABLE`、`PATCHED`、`VULNERABLE_EOL`、`VULNERABLE_NOFIX`）と Dockerfile タグごとの判定
- 緩和ファイル：`conf.d` ファイル、PHP-FPM の各プールセクションの末尾に付くブロック、8.5 専用ルール、オプトインルール
- べき等性：2 回目の実行では何も変わらない
- ロールバック：ファイルと Dockerfile が最初の状態に戻る
- 最初から壊れている PHP-FPM の設定：そのブランチには手を付けない
- 変更によって設定テストが失敗した場合：すべてのファイルが実行前の状態に戻る
- ブランチの固定：同じブランチ内の更新は実行し、シミュレーションで別ブランチのインストールやパッケージの削除が起きる場合はインストールを中止する

## コンテナテスト

実際のディストリビューションのパッケージを入れた各コンテナで、root として `tests/lib/cases.sh` を実行します。リポジトリは `/src` に読み取り専用でマウントします。

| 対象 | PHP | 確認すること |
|---|---|---|
| `debian12` | `bookworm-security` なしでリリースリポジトリから入れた 8.2 | セキュリティリポジトリによる同じブランチ内の更新、変更履歴の確認、mod_php と PHP-FPM |
| `ubuntu2204` | リリースリポジトリのみから入れた 8.1 | サポート終了ブランチ：バージョン番号は変わらないまま、変更履歴でベンダーのバックポートを認識する |
| `rocky9-appstream` | AppStream モジュール `php:8.2` | モジュールストリーム内での dnf の動作、ベンダーの修正版が未公開のときの緩和設定 |
| `rocky9-remi` | Remi モジュール `php:remi-8.2` | リポジトリに 8.3〜8.5 もあるが、apply が 8.2 にとどまる |

各イメージは、セキュリティリポジトリを無効にした状態で PHP をインストールし、その後リポジトリの一覧を元に戻します。そのため php-safepatch は、パッチ未適用の実サーバーと同じ状況を見ることになります。

`tests/lib/cases.sh` は次の順序で確認します。

1. `scan` が `/etc` を変更しない（実行前後のチェックサムを比較）。
2. `apply --mitigate never` がブランチを維持し、別ブランチのパッケージや既定ブランチのメタパッケージをインストールせず、拡張モジュールもすべて維持する。
3. `apply --no-patch --mitigate always` が `conf.d` ファイルと PHP-FPM のプールブロックを書き込む。`php -i` に新しい値が表示され、`php-fpm -t` と `apachectl -t` に合格する。
4. 同じコマンドをもう一度実行しても `/etc` は変わらない。
5. 緩和の実行を `rollback` するとファイルが消え、パッチの実行を `rollback` すると以前のパッケージバージョンが再インストールされる。
6. 最初から壊れている PHP-FPM の設定があると、`apply` は終了コード 2 で停止し、何も変更しない。

一部の結果は、テスト当日のリポジトリの状態によって変わります。

- パッチ手順の `SKIP` は、リポジトリに新しいパッケージがないことを意味します。ベンダーが修正版をまだ公開していないか、イメージがすでにパッチ済みの場合です。
- RHEL のパッケージロールバックの `WARN` は、以前の RPM がリポジトリから消えていることを意味します。RHEL 系のリポジトリではよくあることです。

コンテナには systemd がないため、`--no-restart` で実行します。サービスの再起動と `--health-url` は仮想マシンで確認してください（後述）。

### 実行

```bash
tests/run.sh containers
```

```bash
tests/run.sh containers debian12 rocky9-remi --runtime podman
```

ログは `tests/out/<対象>.log` に保存されます。以前にビルドしたイメージで再実行するには `--no-build` を付けてください。

### Windows での実行

コンテナテストは Windows の Git Bash でも実行できます。ただし、WSL 2 とコンテナランタイムが必要です。

1. 管理者として WSL 2 をインストールし、Windows を再起動します：`wsl --install -d Debian`
2. コンテナランタイムをインストールします。Docker Desktop は一定規模以上の企業では有料サブスクリプションが必要です。WSL 内に Docker Engine や Podman をインストールすれば、ライセンス費用はかかりません。
3. Git Bash または WSL のシェルで `tests/run.sh containers` を実行します。

Podman を使う場合は、短いイメージ名（`debian:12`）を Docker Hub から解決するよう設定してください。`/etc/containers/registries.conf.d/50-php-safepatch-tests.conf` に次の 2 行を書きます。

```
unqualified-search-registries = ["docker.io"]
short-name-mode = "permissive"
```

2026-10-23 時点で、Rocky AppStream と Remi はすでに PHP 8.2.35 を配布しています。そのため Rocky の 2 つの対象ではパッチ手順が `SKIP` になり、dnf 環境での検出、緩和、ロールバックだけを確認します。

## Windows テスト

公式の古い PHP ビルド（既定は 8.3.35、NTS、x64）を一時ディレクトリにダウンロードし、次を確認します。

- `scan` がバージョンとビルドの種類を認識する。
- `apply` が同じブランチ・同じビルドの最新リリースを SHA-256 で検証してインストールし、拡張モジュールをすべて維持する。
- 緩和ブロックが最初の `[PATH=]` セクションの前に入り、`php -r` で新しい値が見える。
- `apply` をもう一度実行しても何も変わらない。
- `rollback` が以前のバイナリと元の `php.ini` を復元する。

```powershell
powershell -ExecutionPolicy Bypass -File tests\windows\run.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File tests\windows\run.ps1 -OldVersion 8.2.34 -Build nts-Win32-vs16-x64
```

このテストは IIS や Apache には手を付けません。

## 仮想マシンでのエンドツーエンドテスト

本番で `apply` を使う前に、使用している OS 系統ごとに仮想マシン 1 台で試してください。

1. nginx と PHP-FPM を動かす Debian 12、Apache と PHP-FPM（または mod_php）を動かす Rocky 9 を用意します。
2. `sudo bash linux/php-safepatch.sh apply --health-url http://localhost/info.php` を実行します。
3. サービスが再起動すること、ヘルスチェック URL のステータスが変更前後で同じであることを確認します。
4. 変更後にヘルスチェック URL が HTTP 500 を返すようにします（例：緩和設定が有効になると失敗するファイル）。php-safepatch がファイルを元に戻すことを確認します。
5. これらの仮想マシンに対して Ansible プレイブックを実行します。まず `scan`、次に `-e safepatch_mode=apply` の順です。

## リリース前の確認

- `shellcheck -S warning linux/php-safepatch.sh tests/*.sh tests/*/*.sh` の指摘がないこと。
- 3 つのテストすべてに合格していること。`SKIP` と `WARN` がある場合は、すべて理由を説明できること。
- 3 言語のドキュメントが同じ動作を説明していること。
