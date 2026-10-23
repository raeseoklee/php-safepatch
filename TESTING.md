# Testing php-safepatch

English | [한국어](TESTING.ko.md) | [日本語](TESTING.ja.md)

php-safepatch changes production servers. Thus every change to the scripts must pass the three test suites below. Run them on a test machine, not on a production server.

| Suite | Command | Needs | Time |
|---|---|---|---|
| Unit | `tests/run.sh unit` | bash 4.4 (Linux, macOS, Git Bash) | 1 min (about 5 min on Git Bash) |
| Containers | `tests/run.sh containers` | Docker or Podman, internet | 10–20 min |
| Windows | `tests\windows\run.ps1` | Windows, PowerShell 5.1, internet | 2–5 min |

## Unit suite

The unit suite uses fake PHP binaries, a fake `dpkg-query` and a fake `apt-get`. It needs no root, no PHP and no container. It checks:

- The status of each version (`VULNERABLE`, `PATCHED`, `VULNERABLE_EOL`, `VULNERABLE_NOFIX`) and of each Dockerfile tag.
- The mitigation files: the `conf.d` file, a block at the end of each PHP-FPM pool section, the 8.5-only rule, and the opt-in rule.
- Idempotency: a second run changes nothing.
- Rollback: the files and the Dockerfile return to their first state.
- A PHP-FPM configuration that is already broken: the branch is not changed.
- A change that breaks the configuration test: all files return to their state before the run.
- The branch lock: an upgrade in the same branch runs, but a simulation that installs another branch or removes a package stops the install.
- Version rules: a branch that is not in the advisory (8.6.0) and a pre-release after the fix (8.5.13-dev) are `UNKNOWN`; a pre-release of the fix (8.5.12RC1) is `VULNERABLE`; a distribution suffix is not a pre-release.
- A runtime that does not read the mitigation is `not_effective` and the run fails.
- PHP-FPM pools: a marked block with a wrong value, or a later pool line that sets the value back, is `not_effective`.
- PHP-FPM include order: `include=z.conf` (0) then `include=a.conf` (1) is `not_effective`; the reverse order is `effective`; a nested include that sets the value back is `not_effective`.
- One PHP-FPM binary with two systemd units (`--fpm-config A`, `-y B -c php.ini`): two runtimes, both pools mitigated, both units restarted, no shifted fields.
- In auto mode, a patched branch loses all old mitigation, also the PHP-FPM pool blocks.
- A health URL that changes from 200 to 404 fails the run and restores the files.
- Advisory files start empty; an invalid file stops the run.
- The dnf transaction check: a module stream change, a removal, a package of another branch, or a failed simulation stops the install.

## Container suite

The container suite installs real distribution packages and runs `tests/lib/cases.sh` in each container as root. The repository is mounted read-only at `/src`.

| Target | PHP | What it shows |
|---|---|---|
| `debian12` | 8.2 from the release pocket, without `bookworm-security` | Same-branch upgrade from the security repository, changelog check, mod_php and PHP-FPM |
| `ubuntu2204` | 8.1 from the release pocket only | End-of-life branch: vendor backport found by the changelog, version number unchanged |
| `rocky9-appstream` | AppStream module `php:8.2` | dnf path inside a module stream; mitigation when the vendor fix is not published yet |
| `rocky9-remi` | Remi module `php:remi-8.2` | The repository also offers 8.3 to 8.5, but apply stays on 8.2 |

Each image installs PHP while the security repository is disabled, then restores the full repository list. Thus php-safepatch sees the same situation as an unpatched server.

`tests/lib/cases.sh` checks, in this order:

1. `scan` does not change `/etc` (checksum before and after).
2. `apply --mitigate never` keeps the branch, installs no package of another branch and no default-branch metapackage, and keeps all extensions.
3. `apply --no-patch --mitigate always` writes the `conf.d` files and the PHP-FPM pool blocks. `php -i` shows the new value, and `php-fpm -t` and `apachectl -t` pass.
4. The same command a second time does not change `/etc`.
5. `rollback` of the mitigation run removes the files. `rollback` of the patch run reinstalls the old package versions.
6. A PHP-FPM configuration that is already broken makes `apply` stop with exit code 2 and change nothing.

Each container also starts PHP-FPM with its own configuration file (`-y /etc/php-custom/php-fpm.conf`). The suite checks that php-safepatch uses that file (not the package default), that the status is `RESTART_REQUIRED` after a package upgrade until the master restarts, and that the mitigation is `pending_restart` until the restart and `effective` after it.

A second master runs from the same binary with `-y /etc/php-custom2/php-fpm.conf`. The suite checks that it is a runtime of its own, that it stays `RESTART_REQUIRED` while only the first master is restarted, that its pool is mitigated, and that a pool line that sets the value back makes it `not_effective`.

Some results depend on the repositories on the day of the test:

- `SKIP` for the patch step means that the repository has no newer package. For example, the vendor has not published the fix yet, or the image was already patched.
- `WARN` for the RHEL package rollback means that the old RPMs are no longer in the repository. This is normal for most RHEL-based repositories.

Containers have no systemd, so the suite runs with `--no-restart`. To test the service restart and `--health-url`, use a virtual machine (see below).

### Run

```bash
tests/run.sh containers
```

```bash
tests/run.sh containers debian12 rocky9-remi --runtime podman
```

The logs go to `tests/out/<target>.log`. Use `--no-build` to run again with the images that you built before.

### Windows hosts

The container suite runs from Git Bash on Windows too. It needs WSL 2 and a container runtime:

1. Install WSL 2 as administrator, then restart Windows: `wsl --install -d Debian`
2. Install a container runtime. Docker Desktop needs a paid subscription for larger companies. Docker Engine or Podman inside WSL has no license fee.
3. Run `tests/run.sh containers` from Git Bash, or from the WSL shell.

With Podman, let short image names (`debian:12`) resolve to Docker Hub. Put these two lines in `/etc/containers/registries.conf.d/50-php-safepatch-tests.conf`:

```
unqualified-search-registries = ["docker.io"]
short-name-mode = "permissive"
```

On 2026-10-23, Rocky AppStream and Remi already shipped PHP 8.2.35. Thus the patch step of the two Rocky targets shows `SKIP`, and those targets test the dnf discovery, the mitigation and the rollback only.

## Windows suite

The Windows suite downloads an old official PHP build (default 8.3.35, NTS, x64) to a temporary directory and checks:

- `scan` detects the version and the build type.
- `apply` installs the newest release of the same branch and build, verified by SHA-256, and keeps all extensions.
- The mitigation block goes before the first `[PATH=]` section, so `php -r` sees the new values.
- A second `apply` changes nothing.
- `rollback` restores the old binaries and the original `php.ini`.
- Function checks without PHP: the assessment, health and argument functions are taken from the script by its syntax tree and tested directly (8.6.0, RC and dev builds, 200 -> 404).
- Service recovery: when the second Apache service fails to stop, the first one starts again; after an exception in the step, both start again.
- After a restore, the report reads the version from disk again (8.3.36 -> 8.3.35 is `VULNERABLE`).
- When the version cannot be read, the result is `UNKNOWN`, not the earlier `PATCHED`.
- In auto mode, a patched installation loses its old mitigation; advisory files start empty and are validated.

```powershell
powershell -ExecutionPolicy Bypass -File tests\windows\run.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File tests\windows\run.ps1 -OldVersion 8.2.34 -Build nts-Win32-vs16-x64
```

The suite does not touch IIS or Apache.

## End-to-end test on a virtual machine

Before you use `apply` in production, run it on one virtual machine for each OS family that you use:

1. Debian 12 with nginx and PHP-FPM, Rocky 9 with Apache and PHP-FPM (or mod_php).
2. `sudo bash linux/php-safepatch.sh apply --health-url http://localhost/info.php`
3. Check that the services restart and that the health URL gives the same status before and after.
4. Make the health URL return HTTP 500 after the change (for example, with a file that fails when the mitigation is active). Check that php-safepatch restores the files.
5. Run the Ansible playbook against these machines: first `scan`, then `-e safepatch_mode=apply`.

### Automated Rocky KVM test

`sudo bash tests/vm/run-rocky9.sh` boots a disposable Rocky 9 VM and installs signed PHP 8.2.25
packages from the Rocky 9.5 vault. It verifies an actual same-branch dnf upgrade, real systemd
restarts of two PHP-FPM services, HTTP mitigation values, and automatic configuration recovery
after an HTTP 500. Logs and reports are saved under `tests/out/vm-rocky9-<timestamp>/`.
See [the VM test instructions](tests/vm/README.md) for dependencies and WSL usage. Remi, yum,
Debian service integration and package downgrades still need separate VM coverage.

## Before a release

- `shellcheck -S warning linux/php-safepatch.sh tests/*.sh tests/*/*.sh` has no findings.
- All three suites pass, or every `SKIP` and `WARN` has a known reason.
- The documents in all three languages describe the same behavior.
