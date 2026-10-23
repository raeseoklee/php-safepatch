# 実際の systemd・RPM 更新テスト

[English](README.md) | [한국어](README.ko.md) | 日本語

`run-rocky9.sh` は使い捨ての Rocky Linux 9 KVM 仮想マシンを作成します。ホストに対して php-safepatch は実行しません。ゲストは、公式の Rocky 9.5 保管リポジトリ（vault）から GPG 署名を確認した PHP 8.2.25 の RPM をインストールし、その後、現在のリポジトリで実際に更新します。

## 必要なもの

- 読み書きできる `/dev/kvm` がある Linux ホスト、空きメモリ 4 GiB、空きディスク約 4 GiB（イメージキャッシュ用に別途 1.5 GiB）、インターネット接続
- コマンド：`qemu-system-x86_64`、`qemu-img`、`cloud-localds`、`ssh`、`ssh-keygen`、`curl`、`tar`、`sha256sum`。Debian/Ubuntu では `qemu-system-x86`、`qemu-utils`、`cloud-image-utils`、`openssh-client` をインストールします。
- ローカルポート `127.0.0.1:22229` が空いている必要があります。使用中の場合（例：`VM_KEEP_RUNNING=1` で残した以前のゲスト）、起動前に停止します。同時に 1 つだけ実行してください。

## 実行

```bash
sudo bash tests/vm/run-rocky9.sh
```

WSL 2 と KVM が使える場合は、PowerShell から実行します（リポジトリのパスは環境に合わせて変更してください）。

```powershell
wsl -d Debian -u root -- bash /mnt/c/Workspace/phpdoctor/tests/vm/run-rocky9.sh
```

## 確認すること

- 実際の dnf トランザクション（`php-safepatch apply`、模擬ツールなし）：ブランチと拡張モジュールが変わらないこと
- 設定の異なる 2 つの PHP-FPM systemd サービス（既定のサービスと `-y` のサービス）：両方を検出すること、両方が再起動すること（MainPID の変化）、更新後に両方が `PATCHED / running=yes` になること
- 緩和後に 2 つの Web SAPI が HTTP で実際に返す値
- auto モードでの緩和の削除：レポートのすべてのランタイムが `mitigation=none` であること、`conf.d` ファイルと 2 つのプールブロックが消えていること、2 つの SAPI が元の値を再び返すこと
- 緩和後に HTTP 500 が発生する場合：終了コード 2 で終わること、ファイルが復元されること（レポートとファイルの両方を確認）、2 つのサービスが active のままであること、2 つの SAPI が元の値を再び返すこと

SELinux は enforcing のままです。古いパッケージは保管リポジトリから取得するため、本番のリポジトリに古い RPM が残っている必要はありません。このテストは AppStream の経路のみを対象とします。Remi、yum、Debian のサービス、mod_php、パッケージのダウングレードの経路は、この結果では証明されません。

## 証拠

証拠は `tests/out/vm-rocky9-<UTC タイムスタンプ>/` に保存されます（git の追跡対象外）。

- `host-sha256.txt`（実行スクリプト、ゲスト用テスト、製品スクリプト、アドバイザリ）と `source-sha256.txt`（ゲスト内で計算）
- `image.txt`、`image-checksum.txt`、`CHECKSUM`：使用したイメージと公式の SHA-256
- `serial.log`、`test.log`、`guest.log`、`selinux.txt`
- `dnf-transaction.txt`、`packages.before.txt`、`packages.after.txt`、`modules.*.txt`
- `patch|mitigation|cleanup|rollback.json` と `.log`：手順ごとの php-safepatch のレポートと出力
- `health-*.json`：手順ごとに 2 つの SAPI が返した HTTP 応答
- `services.after-patch.txt`、`service-journal.txt`

## イメージキャッシュと後片付け

- ベースイメージは `/var/tmp/php-safepatch-vm-cache/Rocky-9.qcow2` にキャッシュします（`VM_CACHE` で場所を変更できます）。実行のたびに公式の HTTPS チェックサム一覧を読みます。Rocky が新しい `latest` イメージを公開するとキャッシュと一致しなくなるため、その場合は 1 回だけ再ダウンロードします。再ダウンロード後も一致しなければ実行を停止します。実行に使ったチェックサムは `image.txt` に記録します。
- 実行の最後に、ゲストを停止し、そのゲストのオーバーレイディスクと SSH 秘密鍵（`/var/tmp/php-safepatch-kvm.*`）を削除します。
- `VM_KEEP_RUNNING=1` を指定すると、デバッグのためにゲストを起動したままにします。`VM_KEEP_FILES=1` を指定すると、ゲストは停止してファイルは残します。残したディレクトリにはゲストの root SSH 鍵があるため、非公開として扱ってください。
- 残したファイルとイメージキャッシュを削除するには、次のコマンドを使います。

```bash
sudo rm -rf /var/tmp/php-safepatch-kvm.* /var/tmp/php-safepatch-vm-cache
```

`VM_OUTPUT` で証拠のディレクトリを変更できます。
