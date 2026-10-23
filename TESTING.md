# Testing php-safepatch

English | [한국어](TESTING.ko.md) | [日本語](TESTING.ja.md)

php-safepatch changes production servers. Thus every change to the scripts must pass the three test suites below. Run them on a test machine, not on a production server.

| Suite | Command | Needs | Time |
|---|---|---|---|
| Unit | `tests/run.sh unit` | bash 4 (Linux, macOS, Git Bash) | < 1 min |
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

## Before a release

- `shellcheck -S warning linux/php-safepatch.sh tests/*.sh tests/*/*.sh` has no findings.
- All three suites pass, or every `SKIP` and `WARN` has a known reason.
- The documents in all three languages describe the same behavior.
