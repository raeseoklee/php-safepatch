# php-safepatch Requirements Specification

English | [한국어](SPEC.ko.md) | [日本語](SPEC.ja.md)

## 1. Purpose

php-safepatch finds the PHP runtimes on a server and checks them against an advisory. The first advisory is PHP2Shell (CVE-2026-109618, CVE-2026-109619). When the operator approves, php-safepatch installs the fix inside the same minor branch. When no fix is available for a runtime, it applies the interim mitigations that the advisory defines.

The main constraint is that existing applications must continue to work. Thus php-safepatch never changes the PHP major or minor version (for example, it never changes 8.2 to 8.3).

## 2. Scope

| Environment | Scan | Patch | Mitigate |
|---|---|---|---|
| Debian / Ubuntu (apt, including the ondrej PPA) | Yes | Yes (`phpX.Y-*` packages only) | Yes |
| RHEL / Rocky / Alma (dnf or yum, including Remi) | Yes | Yes (stops if the branch would change) | Yes |
| Windows (IIS FastCGI, Apache, standalone) | Yes | Yes (windows.php.net zip of the same branch and build) | Yes |
| Running Docker containers | Yes | No (instructions to rebuild the image) | No |
| Dockerfiles | Yes | Yes (changes only the patch version in `FROM php:` tags) | Not applicable |
| Source builds and other paths | Yes | No (manual instructions) | Yes |

## 3. Advisory file

An advisory file (`advisories/*.conf`) holds all data that is specific to one vulnerability. To support a new PHP vulnerability, you add a new file. You do not change the scripts.

| Key | Meaning |
|---|---|
| `id`, `cves` | Name and CVE identifiers. The name is also used in file names and markers. |
| `fixed` | Lowest fixed release for each supported branch. |
| `eol_backport` | End-of-life branches that have only vendor or source backports. |
| `ioc_since` | Reference date for the changed-file check. |
| `mitigate` | Interim mitigation rule: `INI_KEY=VALUE[@MIN_BRANCH]`. One rule per line. |
| `mitigate_optin` | Same format. Applied only with `--include-optin`, because it can change application behavior. |
| `ioc_log` | Log indicator: `LABEL|EXTENDED_REGEX`. |

## 4. Status rules

| Status | Condition |
|---|---|
| `PATCHED` | The version is equal to or higher than the fixed version of its branch, or the distribution package changelog lists all advisory CVEs. |
| `VULNERABLE` | The branch has a fixed version, and the runtime version is lower. |
| `VULNERABLE_EOL` | The branch is in `eol_backport`. php-safepatch installs a distribution or LTS backport if one is available. If not, it applies mitigations. |
| `VULNERABLE_NOFIX` | The branch is lower than all fixed branches and is not in `eol_backport`. Only mitigation and isolation are possible. |
| `RESTART_REQUIRED` | A running process still uses a binary that was replaced on disk. |
| `UNKNOWN` | php-safepatch cannot read the version. |

## 5. Functional requirements

- **FR-1 Discovery**: Find PHP runtimes (CLI, FPM, CGI, mod_php) from known paths, running processes, the package database, and the IIS and Apache configuration.
- **FR-2 Assessment**: Give each runtime a status as defined in section 4.
- **FR-3 Report**: Write a table for people and a JSON report for tools. The exit code is 0 when all runtimes are safe and no indicator is found, 1 when at least one runtime is not patched or an indicator is found, and 2 when an error occurs.
- **FR-4 No change by default**: `scan` does not change the system. Only `apply` and `rollback` make changes. Without `--yes`, they ask for confirmation on each host.
- **FR-5 Branch-locked patching**: Before it installs packages, php-safepatch simulates the transaction. If a package in the simulation changes branch, or if the apt simulation removes a package, php-safepatch does not patch that branch. On Debian-based systems, php-safepatch does not upgrade metapackages that follow the default branch (`php`, `php-fpm`, `php-cli`, and similar). On Windows, it installs only the zip of the same branch, thread-safety mode, compiler, and architecture.
- **FR-6 Compatibility check**: Compare the extension list (`php -m`) before and after the change. If an extension is missing after the change, the step fails. If you give `--health-url`, php-safepatch also compares the HTTP status before and after the change.
- **FR-7 Mitigation**: If a runtime is still vulnerable after the patch step, apply the `mitigate` rules of the advisory (and the `mitigate_optin` rules with `--include-optin`).
  - Linux: a `conf.d` file for each SAPI, `php_admin_value` lines in each PHP-FPM pool, and `php_admin_value` lines in the Apache configuration for mod_php. The admin-level values prevent `.user.ini` files and later pool lines from overriding them.
  - Windows: a marked block in the loaded `php.ini`, put before the first `[PATH=]` or `[HOST=]` section. Values after such a section apply only to that path or host.
- **FR-8 Backup and rollback**: Before it changes a file, php-safepatch copies it to a directory for the run ID. If a configuration test (`php-fpm -t`, `apachectl -t`) or a check in FR-6 fails, php-safepatch restores the files automatically. For packages, php-safepatch records the previous versions, and the `rollback` command reinstalls them. On Windows, php-safepatch keeps a full copy of each PHP directory that it updates.
- **FR-9 Restart**: Restart the services that use a changed runtime (PHP-FPM, Apache, IIS application pools). With `--no-restart`, php-safepatch only reports that a restart is necessary. On Windows, a binary update always stops and starts IIS or Apache, because Windows locks files that are in use.
- **FR-10 Indicators of compromise**: Read-only checks for: the advisory log patterns, shells started by PHP or web workers, and PHP files in web directories that changed after `ioc_since`, including common web shell patterns.
- **FR-11 Fleet execution**: An Ansible playbook runs the scan and the apply step on many hosts. The apply step runs on one host at a time (`serial: 1`) and stops at the first failed host.

## 6. Non-functional requirements

- **NFR-1 Dependencies**: On Linux, php-safepatch uses only bash 4 and standard utilities (no jq). On Windows, it uses only PowerShell 5.1.
- **NFR-2 Idempotency**: If you run the same command again, the result is the same. Markers surround each mitigation block, so php-safepatch does not add a block two times.
- **NFR-3 Integrity**: On Windows, php-safepatch installs a zip only if its SHA-256 matches the value in releases.json.
- **NFR-4 Traceability**: Each run keeps its log, report, and backups in `/var/lib/php-safepatch/<run-id>` (on Windows, `%ProgramData%\php-safepatch\<run-id>`).

## 7. Out of scope

- Minor or major version upgrades
- Synology DSM and other NAS or appliance firmware. php-safepatch detects DSM and stops without a change.
- Active exploitation tests, such as running a proof of concept
- Automatic removal of compromise artifacts (php-safepatch only reports them, to keep evidence)
- Credential rotation (the report only recommends it)
