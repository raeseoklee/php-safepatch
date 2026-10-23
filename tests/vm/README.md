# Real systemd and RPM upgrade test

English | [한국어](README.ko.md) | [日本語](README.ja.md)

`run-rocky9.sh` creates a disposable Rocky Linux 9 KVM virtual machine. It does not run
php-safepatch against the host. The guest installs GPG-checked PHP 8.2.25 RPMs from the
official Rocky 9.5 vault, then uses the current repositories for an actual upgrade.

## Requirements

- A Linux host with a readable and writable `/dev/kvm`, 4 GiB free RAM, about 4 GiB free disk
  (plus 1.5 GiB for the image cache), and internet access.
- The commands `qemu-system-x86_64`, `qemu-img`, `cloud-localds`, `ssh`, `ssh-keygen`, `curl`,
  `tar` and `sha256sum`. On Debian/Ubuntu, install `qemu-system-x86`, `qemu-utils`,
  `cloud-image-utils` and `openssh-client`.
- The local port `127.0.0.1:22229` must be free. The runner stops before boot if it is in use
  (for example, by a guest from an earlier run with `VM_KEEP_RUNNING=1`). Run one copy at a time.

## Run

```bash
sudo bash tests/vm/run-rocky9.sh
```

With WSL 2 and KVM enabled, run from PowerShell (adjust the repository path):

```powershell
wsl -d Debian -u root -- bash /mnt/c/Workspace/phpdoctor/tests/vm/run-rocky9.sh
```

## What it checks

- A real dnf transaction (`php-safepatch apply`, no fake tools): branch and extensions stay the same.
- Two independently configured PHP-FPM systemd services (the default one and one with `-y`):
  both are found, both restart (new MainPID), and both are `PATCHED / running=yes` after the upgrade.
- The values that both web SAPIs really return over HTTP after the mitigation.
- Auto-mode cleanup: the report shows `mitigation=none` for every runtime, the `conf.d` file and
  both pool blocks are gone, and both SAPIs return the original value again.
- An HTTP 500 after the mitigation: exit code 2, the files are restored (report and files
  checked), both services stay active, and both SAPIs return the original value again.

SELinux stays enforcing. The old-package fixture comes from the vault, so no production
repository needs to keep old RPMs. This is an AppStream test; it does not prove the Remi, yum,
Debian service, mod_php, or package-downgrade paths.

## Evidence

Evidence goes to `tests/out/vm-rocky9-<UTC timestamp>/` (git-ignored):

- `host-sha256.txt` (runner, guest cases, product script, advisory) and `source-sha256.txt` (in the guest)
- `image.txt`, `image-checksum.txt`, `CHECKSUM`: the image and its official SHA-256
- `serial.log`, `test.log`, `guest.log`, `selinux.txt`
- `dnf-transaction.txt`, `packages.before.txt`, `packages.after.txt`, `modules.*.txt`
- `patch|mitigation|cleanup|rollback.json` and `.log`: php-safepatch reports and output
- `health-*.json`: HTTP responses of both SAPIs at each step
- `services.after-patch.txt`, `service-journal.txt`

## Image cache and cleanup

- The base image is cached in `/var/tmp/php-safepatch-vm-cache/Rocky-9.qcow2` (`VM_CACHE` changes
  the place). Each run reads the official HTTPS checksum list. When Rocky has published a new
  `latest` image, the cached image no longer matches; the runner then downloads it again once.
  A second mismatch stops the run. `image.txt` records the checksum that the run used.
- At the end, the runner stops the guest, then deletes its overlay disk and its private SSH key
  (`/var/tmp/php-safepatch-kvm.*`).
- `VM_KEEP_RUNNING=1` keeps the guest running for debugging; `VM_KEEP_FILES=1` stops it but keeps
  the files. Treat a kept directory as private: it holds the guest's root SSH key.
- To remove kept files and the image cache:

```bash
sudo rm -rf /var/tmp/php-safepatch-kvm.* /var/tmp/php-safepatch-vm-cache
```

`VM_OUTPUT` changes the evidence directory.
