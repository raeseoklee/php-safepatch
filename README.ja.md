# php-safepatch

[English](README.md) | [한국어](README.ko.md) | 日本語

**PHP2Shell（CVE-2026-109618、CVE-2026-109619）の検査・パッチツール。Linux、Windows、Docker に対応し、PHP のブランチを変えずにパッチを適用します。**

php-safepatch は、サーバー上のすべての PHP ランタイムを見つけ、どれが脆弱かを報告し、**PHP のマイナーバージョンを変えずに**修正します。アプリケーションは同じブランチ（例：8.2 は 8.2 のまま）で動き続けるため、更新によって動作が壊れることはありません。

> PHP2Shell は、認証なしで HTTP リクエスト 1 回によりサーバー上でコマンドを実行できる脆弱性です（CVSS 4.0：9.2）。修正版は **8.2.35、8.3.36、8.4.27、8.5.12** です。PHP 8.1 以前には公式リリースがありません。詳細は [PHP セキュリティアドバイザリ](https://www.php.net/) と各国の CERT（日本では JPCERT/CC）の情報を確認してください。

## 機能

1. **検出**：CLI、PHP-FPM、CGI、mod_php に加え、実行中の Docker コンテナ内の PHP、Dockerfile の `FROM php:` 行、Windows の IIS FastCGI と Apache も検出します。
2. **判定**：各ランタイムをアドバイザリに基づいて判定します。ディストリビューションはバージョン番号を変えずに修正だけをバックポートすることが多いため、パッケージの変更履歴（changelog）も確認します。
3. **同じブランチ内でのパッチ**（承認後のみ）：
   - Debian/Ubuntu：`phpX.Y-*` パッケージだけを更新します。新しいブランチを引き込むおそれがある `php` メタパッケージは更新しません。
   - RHEL/Rocky/Alma：先に提供されるバージョンを確認し、ブランチが変わるパッケージが 1 つでもあれば中止します。
   - Windows：windows.php.net から同じブランチ・同じビルド（TS/NTS、コンパイラー、x64/x86）を取得し、SHA-256 を検証してからインストールします。
4. **緩和**：パッチを適用できないランタイムには暫定的な緩和設定を適用します。PHP2Shell では `session.upload_progress.enabled=0` を設定し、8.5 では `fatal_error_backtraces=0` も設定します。PHP-FPM と mod_php では管理者レベルで値を固定し、アプリケーションから上書きできないようにします。
5. **検証**：拡張モジュールの一覧が変わっていないこと、設定テストに合格すること、指定したヘルスチェック URL が応答し続けることを確認します。失敗した場合は、変更したファイルを自動で元に戻します。
6. **侵害の痕跡の確認**（読み取りのみ）：スクリプト開始前に発生したメモリエラー、ワーカーの異常終了、PHP ワーカーが起動したシェル、最初の攻撃報告以降に変更された PHP ファイルを探します。

## クイックスタート

### Linux（Debian、Ubuntu、RHEL、Rocky、Alma）

```bash
curl -fsSLO https://raw.githubusercontent.com/raeseoklee/php-safepatch/main/linux/php-safepatch.sh
```

```bash
sudo bash php-safepatch.sh scan
```

```bash
sudo bash php-safepatch.sh apply --health-url https://your-site.example/
```

`scan` はシステムを変更しません。`apply` は実行計画を表示し、確認を得てから変更します。

### Windows（PowerShell 5.1、管理者として実行）

```powershell
powershell -ExecutionPolicy Bypass -File .\windows\php-safepatch.ps1 scan
powershell -ExecutionPolicy Bypass -File .\windows\php-safepatch.ps1 apply -HealthUrl https://your-site.example/
```

### 複数サーバー（Ansible）

```bash
cp ansible/inventory.example.ini ansible/inventory.ini
```

```bash
ansible-playbook -i ansible/inventory.ini ansible/site.yml
```

```bash
ansible-playbook -i ansible/inventory.ini ansible/site.yml -e safepatch_mode=apply
```

1 つ目のコマンドはすべてのホストを検査だけします。2 つ目のコマンドは 1 台ずつ適用し、失敗したホストがあればそこで停止します。JSON レポートは `ansible/reports/` に保存されます。

## コマンドとオプション

| Linux | Windows | 説明 |
|---|---|---|
| `scan` | `scan` | 報告のみ。何も変更しません。 |
| `apply` | `apply` | 同じブランチ内でパッチを適用し、それでも脆弱なランタイムに緩和設定を適用します。 |
| `rollback [--run-id ID]` | `rollback [-RunId ID]` | 指定した実行で変更したファイル、ディレクトリ、パッケージを元に戻します（既定：最新の `apply`）。 |
| `--yes` | `-Yes` | 確認なしで実行します。 |
| `--json FILE` | `-Json FILE` | JSON レポートを保存します（`-` は標準出力）。 |
| `--mitigate auto\|always\|never` | `-Mitigate ...` | `auto`：パッチ後も脆弱なランタイムのみ。`always`：パッチ済みのランタイムにも適用。 |
| `--include-optin` | `-IncludeOptIn` | オプトインのルールも適用します。PHP2Shell では `memory_limit=-1`（下記参照）。 |
| `--no-patch` | `-NoPatch` | パッケージやバイナリはインストールせず、緩和設定だけを適用します。 |
| `--no-restart` | `-NoRestart` | サービスを再起動しません。 |
| `--health-url URL` | `-HealthUrl URL` | 変更の前後にこの URL を確認します。複数指定できます。 |
| `--php PATH` | `-Php PATH` | 自動検出で見つからない PHP バイナリまたはディレクトリを追加します。 |
| `--web-root DIR` | `-WebRoot DIR` | 変更ファイル確認の対象に Web ルートを追加します。 |
| `--dockerfiles DIR` | | DIR 以下の Dockerfile を検査します。 |
| `--fix-dockerfiles` | | `apply` と併用すると、固定された `FROM php:X.Y.Z` タグを修正版に書き換えます。 |
| `--no-docker`、`--no-ioc` | `-NoIoc` | コンテナの検査、または侵害の痕跡の確認を省略します。 |
| `--advisory FILE` | `-Advisory FILE` | 別のアドバイザリファイルを使います。 |
| `--state-dir DIR` | `-StateDir DIR` | ログ、レポート、バックアップの保存先（既定 `/var/lib/php-safepatch`、`%ProgramData%\php-safepatch`）。 |

終了コード：`0` はすべてのランタイムがパッチ済みで痕跡なし、`1` は未パッチのランタイムまたは痕跡あり、`2` は実行エラーです。

## ステータス

| ステータス | 意味 | 対応 |
|---|---|---|
| `PATCHED` | 修正版、またはベンダーパッケージの変更履歴に CVE がある | 不要 |
| `VULNERABLE` | 同じブランチに修正版がある | `apply` を実行 |
| `VULNERABLE_EOL` | 7.4〜8.1：公式リリースなし | ディストリビューションや LTS ベンダーのバックポートがあれば適用します。なければ緩和設定を適用し、アプリケーションのテストを行ったうえでアップグレードを計画します。 |
| `VULNERABLE_NOFIX` | 7.3 以前：修正なし | 緩和設定を適用し、インターネットから隔離し、アップグレードを計画します。 |
| `RESTART_REQUIRED` | 置き換えられたバイナリをプロセスがまだ使っている | サービスを再起動します。 |

## 緩和設定について

PHP セキュリティチームは、PHP2Shell を完全に修正できるのは更新だけだとしています。緩和設定は影響範囲を減らすだけです。

- `session.upload_progress.enabled=0` は CVE-2026-109619 に対応します。セッションのアップロード進捗機能を使う進捗バーは動かなくなりますが、この機能を使うアプリケーションは多くありません。
- `memory_limit=-1`（オプトイン）は CVE-2026-109618 の既知の攻撃経路を防ぎます。その代わり、リクエストごとのメモリ上限がなくなります。コンテナ、cgroup、PHP-FPM のメモリ制限と組み合わせて使ってください。`--include-optin` を指定しない限り適用しません。
- `RLIMIT_AS` や `RLIMIT_DATA` を緩和策として使わないでください。攻撃に必要なメモリ確保の失敗を、かえって引き起こすおそれがあります。
- リバースプロキシや WAF でリクエストサイズも制限してください。`Content-Length` のないリクエストも対象にする必要があります。

## 環境ごとの注意

- **Synology DSM などの NAS・アプライアンスのファームウェア**：非対応です。DSM で実行すると、何も変更せずに停止します。メーカーが提供する更新を使ってください（Synology ではパッケージセンターで PHP パッケージを更新します）。
- **Docker**：実行中のコンテナは変更しません。修正版のタグ（例：`php:8.2.35-fpm`）でイメージを再ビルドし、再デプロイしてください。`REBUILD` は、タグがブランチに追従する（`php:8.2-fpm`）ため `--pull` 付きで再ビルドすればよいという意味です。`FLOATING_MAJOR` は、タグ（`php:8`、`php:latest`）が再ビルド時にブランチを変えるおそれがあるという意味です。タグを固定してください。
- **ソースビルド、Plesk、cPanel、LiteSpeed**：検出と緩和設定の適用までを行います。更新は各ベンダーのツールで行ってください。
- **Debian/Ubuntu の PHP 7.4〜8.1**：ondrej PPA や Debian LTS/ELS にバックポートがある場合があります。リポジトリが同じブランチの新しいパッケージを提供していればインストールし、変更履歴で修正を確認します。

## 新しいアドバイザリの追加

`advisories/php2shell.conf` をコピーして値を変更し、`--advisory`/`-Advisory` で指定してください。修正版、緩和ルール、ログの痕跡はすべてこのファイルで定義するため、スクリプトを変更する必要はありません。形式は [SPEC.ja.md](SPEC.ja.md#3-アドバイザリファイル) を参照してください。

## 侵害の痕跡が見つかった場合

1. サーバーをネットワークから隔離してください。電源は切らないでください。再起動するとメモリ上の証拠が消えます。
2. ログ、プロセス一覧、ネットワーク接続の情報を保全してください。
3. JPCERT/CC など所管の機関に報告してください。
4. PHP を更新し、Web シェルを削除したうえで、DB パスワード、API キー、管理者パスワードを変更してください。

インターネット上の PoC でサーバーを試さないでください。多くの PoC にマルウェアが含まれています。

## テスト

テストは 3 種類あります。模擬バイナリによる単体テスト（`tests/run.sh unit`）、実際のディストリビューションをコンテナで動かすテスト（`tests/run.sh containers`）、公式 PHP ビルドによる Windows テスト（`tests\windows\run.ps1`）です。詳細は [TESTING.ja.md](TESTING.ja.md) を参照してください。本番環境で `apply` を使う前に、ステージング環境で試してください。

## ライセンス

[MIT](LICENSE)
