# php-safepatch Requirements Specification

English | [한국어](SPEC.ko.md) | [日本語](SPEC.ja.md)

## 1. Purpose

php-safepatch finds the PHP runtimes on a server and checks them against an advisory. The first advisory is PHP2Shell (CVE-2026-109618, CVE-2026-109619). When the operator approves, php-safepatch installs the fix inside the same minor branch. When no fix is available for a runtime, it applies the interim mitigations that the advisory defines.

The main constraint is that existing applications must continue to work. Thus php-safepatch never changes the PHP major or minor version (for example, it never changes 8.2 to 8.3).

A second constraint is that the report must not say "safe" too early. A runtime is safe only when the fixed code is on disk **and** the running processes use it. A mitigation is in effect only when the service really reads it.

## 2. Scope

| Environment | Scan | Patch | Mitigate |
|---|---|---|---|
| Debian / Ubuntu (apt, including the ondrej PPA) | Yes | Yes (`phpX.Y-*` packages only) | Yes |
| RHEL / Rocky / Alma (dnf or yum, including Remi) | Yes | Yes (stops if the transaction changes the branch) | Yes |
| Windows (IIS FastCGI, Apache, standalone) | Yes | Yes (windows.php.net zip of the same branch and build) | Yes |
| Running Docker containers | Yes | No (instructions to rebuild the image) | No |
| Dockerfiles | Yes | Yes (changes only the patch version in `FROM php:` tags) | Not applicable |
| Source builds and other paths | Yes | No (manual instructions) | Yes |

## 3. Advisory file

An advisory file (`advisories/*.conf`) holds all data that is specific to one vulnerability. To support a new PHP vulnerability, you add a new file. You do not change the scripts.

| Key | Required | Meaning |
|---|---|---|
| `id` | Yes | Name. Only `A-Z a-z 0-9 . _ -`. Also used in file names and markers. |
| `cves` | Yes | CVE identifiers, separated by spaces. |
| `fixed` | Yes | Lowest fixed release (`X.Y.Z`) for each supported branch. |
| `eol_backport` | No | End-of-life branches (`X.Y`) that have only vendor or source backports. |
| `ioc_since` | No | Reference date (`YYYY-MM-DD`) for the changed-file check. Without it, that check does not run. |
| `mitigate` | No | Interim mitigation rule: `INI_KEY=VALUE[@MIN_BRANCH]`. One rule per line. |
| `mitigate_optin` | No | Same format. Applied only with `--include-optin`, because it can change application behavior. |
| `ioc_log` | No | Log indicator: `LABEL|EXTENDED_REGEX`. |

An advisory file given with `--advisory` starts empty. Nothing is inherited from the built-in PHP2Shell data. php-safepatch validates every key and value before it reads the system. An unknown key, a missing required key or a wrong format stops the run with exit code 2 and no change.

## 4. State model

php-safepatch records four separate facts for each runtime. It does not merge them into one value.

| Field | Values | Meaning |
|---|---|---|
| `installed` | `PATCHED`, `VULNERABLE`, `VULNERABLE_EOL`, `VULNERABLE_NOFIX`, `UNKNOWN` | Assessment of the binary on disk (section 5). |
| `running` | `yes`, `no`, `stale`, `unknown` | `stale`: a process still runs a binary or library that was replaced on disk. `unknown`: containers. |
| `mitigation` | `none`, `effective`, `pending_restart`, `not_effective`, `unknown` | `effective`: the service reads the values now. `pending_restart`: the files are in place, but running processes started before the change. `not_effective`: the files are in place, but the runtime does not read them. |
| `status` | the `installed` value, or `RESTART_REQUIRED` | `RESTART_REQUIRED` when `running` is `stale`. The exit code uses this field. |

Indicators of compromise are a separate list for the host.

## 5. Assessment rules (`installed`)

| Value | Condition |
|---|---|
| `PATCHED` | A release version (no pre-release suffix) equal to or higher than the fixed version of its branch, or a distribution package changelog that lists all advisory CVEs. |
| `VULNERABLE` | The branch has a fixed version and the runtime is older. A pre-release of the fixed version (for example `8.5.12RC1`) is also older. |
| `VULNERABLE_EOL` | The branch is in `eol_backport`. php-safepatch installs a distribution or LTS backport if one exists. If not, it applies mitigations. |
| `VULNERABLE_NOFIX` | The branch is lower than all fixed branches and is not in `eol_backport`. Only mitigation and isolation are possible. |
| `UNKNOWN` | The version cannot be read, the branch is not in the advisory (for example `8.6.0`), or the runtime is a pre-release build after the fixed version (for example `8.5.13-dev`). |

Distribution suffixes such as `-1ubuntu2.28` are not pre-release suffixes.

## 6. Functional requirements

- **FR-1 Discovery**: Find PHP runtimes (CLI, FPM, CGI, mod_php) from known paths, running processes, the package database, and the IIS and Apache configuration.
- **FR-2 Service configuration**: For each runtime, find the configuration that its service really uses.
  - Linux PHP-FPM: the configuration file in the process title of the running master, then `-y`/`--fpm-config`, `-c`/`--php-ini` and `PHP_INI_SCAN_DIR` from the systemd unit, then the default of the binary.
  - Windows: the `php.ini` of the CLI, of each IIS FastCGI application (its `arguments` and `PHPRC`), and of Apache (`PHPIniDir`).
  - php-safepatch runs every check, configuration test and verification with these options.
  - A runtime is one binary with one service configuration. When one PHP-FPM binary runs several services with different `-y` files (systemd units or running masters), each service is a runtime of its own: it is mitigated, verified, restarted and assessed by itself. The `running` state comes from the master of that configuration.
- **FR-3 Assessment**: Record the four fields of section 4 for each runtime.
- **FR-4 Report**: Write a table for people and a JSON report for tools. The exit code is 0 when every `status` is `PATCHED` and no indicator is found, 1 when a runtime is not `PATCHED` or an indicator is found, and 2 when an error occurs.
- **FR-5 No change by default**: `scan` does not change the system. Only `apply` and `rollback` make changes. Without `--yes`, they ask for confirmation on each host.
- **FR-6 Branch-locked patching**: Before it installs packages, php-safepatch simulates the complete transaction.
  - apt: `apt-get -s install --only-upgrade`. php-safepatch does not upgrade metapackages that follow the default branch (`php`, `php-fpm`, `php-cli`, and similar).
  - dnf/yum: `upgrade --assumeno`. php-safepatch reads the transaction table with dependencies.
  - The patch step stops if the transaction removes, downgrades, obsoletes or replaces a package, changes a module stream, or touches a PHP package of another branch.
  - A simulation that fails is an error, not "no update".
  - Windows: php-safepatch installs only the zip of the same branch, thread-safety mode, compiler and architecture.
- **FR-7 Preflight**: Before any change, run the PHP-FPM configuration test with the configuration of the service. If it fails, do not change that branch.
- **FR-8 Mitigation**: If the binary on disk is still not `PATCHED` after the patch step, apply the `mitigate` rules (and the `mitigate_optin` rules with `--include-optin`).
  - Linux: a `conf.d` file for each SAPI, `php_admin_value` lines in each pool of the PHP-FPM configuration in use, and `php_admin_value` lines in the Apache configuration for mod_php.
  - Windows: a marked block in each `php.ini` from FR-2, put before the first `[PATH=]` or `[HOST=]` section. Values after such a section apply only to that path or host.
  - After the change, php-safepatch reads the values the way each service reads them. A runtime that does not get the values is an error (`not_effective`).
  - For PHP-FPM, php-safepatch computes the final value of each key in each pool: the last `php_admin_value`/`php_admin_flag`, else the last `php_value`/`php_flag`, else the `php.ini` and `conf.d` value. Every pool must end with the advisory value. The marker of a block alone is not proof.
- **FR-9 Mitigation removal**: In `--mitigate auto`, when every runtime of a branch is `PATCHED`, remove all php-safepatch mitigation for the advisory: `conf.d` files, PHP-FPM pool blocks, the Apache file, and the Windows `php.ini` blocks.
- **FR-10 Backup and rollback**: Before it changes a file, php-safepatch copies it to a directory for the run ID. If a configuration test, the extension check or the health check fails, php-safepatch restores the files automatically. For packages, php-safepatch records the previous versions, and the `rollback` command reinstalls them. On Windows, php-safepatch keeps a full copy of each PHP directory that it updates.
- **FR-11 Restart and recheck**: Restart the services that use a changed runtime (PHP-FPM, Apache, IIS application pools), including systemd units found in FR-2. Then read the versions on disk, the processes and the mitigation again and assess again; after an automatic restore, the report shows the restored version. With `--no-restart`, or when a restart is not possible, the `status` stays `RESTART_REQUIRED` and the mitigation stays `pending_restart`.
- **FR-12 Windows service recovery**: On Windows, a binary update stops IIS or Apache, because Windows locks files that are in use. The steps from the first stopped service to the last copied file run in one `try`/`finally` block. Each service is recorded as soon as it is stopped. The `finally` part restores a partial copy and starts every stopped service again in every case, also when a later stop fails or an exception occurs. Directory restores during a rollback use the same block.
- **FR-13 Verification**: Compare the extension list (`php -m`) before and after the change. If an extension is missing, the run fails. If you give `--health-url`, every URL must give the same HTTP status code after the change as before it. A URL that already failed before the change is not used.
- **FR-14 Indicators of compromise**: Read-only checks for the advisory log patterns, shells started by PHP or web workers, and PHP files in web directories that changed after `ioc_since`, including common web shell patterns.
- **FR-15 Fleet execution**: An Ansible playbook runs the scan and the apply step on many hosts. The apply step runs on one host at a time (`serial: 1`). It stops at the first host with an error (exit code 2) and, by default, at the first host that is still not patched or shows an indicator (exit code 1, `safepatch_fail_on_unpatched: true`). The report of that host is fetched before the stop.

## 7. Non-functional requirements

- **NFR-1 Dependencies**: On Linux, php-safepatch uses only bash 4.4 or later and standard utilities (coreutils, grep, sed, awk, findutils; no jq, no diffutils). On Windows, it uses only PowerShell 5.1.
- **NFR-2 Idempotency**: If you run the same command again, the result is the same. Markers surround each mitigation block, so php-safepatch does not add a block two times.
- **NFR-3 Integrity**: On Windows, php-safepatch installs a zip only if its SHA-256 matches the value in releases.json.
- **NFR-4 Traceability**: Each run keeps its log, report, and backups in `/var/lib/php-safepatch/<run-id>` (on Windows, `%ProgramData%\php-safepatch\<run-id>`).

## 8. Out of scope

- Minor or major version upgrades
- Synology DSM and other NAS or appliance firmware. php-safepatch detects DSM and stops without a change.
- Active exploitation tests, such as running a proof of concept
- Automatic removal of compromise artifacts (php-safepatch only reports them, to keep evidence)
- Credential rotation (the report only recommends it)
