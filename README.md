# php-safepatch

English | [한국어](README.ko.md) | [日本語](README.ja.md)

**PHP2Shell (CVE-2026-109618, CVE-2026-109619) scanner and same-branch patcher for Linux, Windows and Docker.**

php-safepatch finds every PHP runtime on a server, tells you which ones are vulnerable, and fixes them **without changing the PHP minor version**. Your applications continue to run on the same PHP branch (for example, 8.2 stays 8.2), so the update does not break them.

> PHP2Shell lets an unauthenticated attacker run commands on the server with one HTTP request (CVSS 4.0: 9.2). Fixed releases: **8.2.35, 8.3.36, 8.4.27, 8.5.12**. PHP 8.1 and older have no official release. See the [PHP security advisory](https://www.php.net/) and your national CERT for details.

## What it does

1. **Finds** PHP runtimes: CLI, PHP-FPM, CGI, mod_php, PHP in running Docker containers, `FROM php:` lines in Dockerfiles, IIS FastCGI and Apache on Windows.
2. **Checks** each runtime against the advisory. It also reads distribution changelogs, because vendors often backport fixes without changing the version number.
3. **Patches inside the same branch** (only after your approval):
   - Debian/Ubuntu: upgrades only the `phpX.Y-*` packages. It never upgrades the `php` metapackage, which can pull in a new branch.
   - RHEL/Rocky/Alma: checks the available versions first. If any package would change branch, it stops.
   - Windows: downloads the same branch, the same build (TS/NTS, compiler, x64/x86) from windows.php.net, and checks its SHA-256.
4. **Mitigates** what it cannot patch: for PHP2Shell it sets `session.upload_progress.enabled=0` (and `fatal_error_backtraces=0` on 8.5). In PHP-FPM and mod_php it locks these values at the admin level.
5. **Verifies** the result: the extension list must be the same, configuration tests must pass, and optional health URLs must still respond. If a check fails, php-safepatch restores the files automatically.
6. **Looks for indicators of compromise** (read-only): memory errors that occur before a script starts, worker crashes, shells started by PHP workers, and PHP files changed after the first exploitation reports.

## Quick start

### Linux (Debian, Ubuntu, RHEL, Rocky, Alma)

```bash
curl -fsSLO https://raw.githubusercontent.com/raeseoklee/php-safepatch/main/linux/php-safepatch.sh
```

```bash
sudo bash php-safepatch.sh scan
```

```bash
sudo bash php-safepatch.sh apply --health-url https://your-site.example/
```

`scan` makes no changes. `apply` shows the plan and asks for confirmation before it changes anything.

### Windows (PowerShell 5.1, run as Administrator)

```powershell
powershell -ExecutionPolicy Bypass -File .\windows\php-safepatch.ps1 scan
powershell -ExecutionPolicy Bypass -File .\windows\php-safepatch.ps1 apply -HealthUrl https://your-site.example/
```

### Many servers (Ansible)

```bash
cp ansible/inventory.example.ini ansible/inventory.ini
```

```bash
ansible-playbook -i ansible/inventory.ini ansible/site.yml
```

```bash
ansible-playbook -i ansible/inventory.ini ansible/site.yml -e safepatch_mode=apply
```

The first command scans all hosts. The second command applies the fix on one host at a time and stops at the first failed host. The JSON reports go to `ansible/reports/`.

## Commands and options

| Linux | Windows | Meaning |
|---|---|---|
| `scan` | `scan` | Report only. No changes. |
| `apply` | `apply` | Patch inside the branch, then mitigate what is still vulnerable. |
| `rollback [--run-id ID]` | `rollback [-RunId ID]` | Restore the files, directories and packages of a run (default: the latest `apply` run). |
| `--yes` | `-Yes` | Do not ask for confirmation. |
| `--json FILE` | `-Json FILE` | Write the JSON report (`-` for stdout). |
| `--mitigate auto\|always\|never` | `-Mitigate ...` | `auto`: only runtimes that stay vulnerable. `always`: also patched runtimes. |
| `--include-optin` | `-IncludeOptIn` | Also apply opt-in rules. For PHP2Shell: `memory_limit=-1` (see below). |
| `--no-patch` | `-NoPatch` | Mitigate only. Do not install packages or binaries. |
| `--no-restart` | `-NoRestart` | Do not restart services. |
| `--health-url URL` | `-HealthUrl URL` | Check this URL before and after the change. Repeatable. |
| `--php PATH` | `-Php PATH` | Add a PHP binary or directory that discovery does not find. |
| `--web-root DIR` | `-WebRoot DIR` | Add a web root for the changed-file check. |
| `--dockerfiles DIR` | | Scan Dockerfiles under DIR. |
| `--fix-dockerfiles` | | With `apply`: change pinned `FROM php:X.Y.Z` tags to the fixed patch release. |
| `--no-docker`, `--no-ioc` | `-NoIoc` | Skip the container check or the indicator check. |
| `--advisory FILE` | `-Advisory FILE` | Use another advisory file. |
| `--state-dir DIR` | `-StateDir DIR` | Logs, reports and backups (default `/var/lib/php-safepatch`, `%ProgramData%\php-safepatch`). |

Exit codes: `0` = all runtimes patched and no indicator, `1` = a runtime is not patched or an indicator was found, `2` = error.

## Statuses

| Status | Meaning | What to do |
|---|---|---|
| `PATCHED` | Fixed release, or the vendor package lists the CVEs | Nothing |
| `VULNERABLE` | A fixed release of the same branch exists | `apply` |
| `VULNERABLE_EOL` | 7.4 to 8.1: no official release | Use a distribution or LTS backport if one exists. Otherwise mitigate and plan an upgrade with application tests. |
| `VULNERABLE_NOFIX` | 7.3 or older: no fix exists | Mitigate, isolate from the internet, plan an upgrade |
| `RESTART_REQUIRED` | The fix is on disk, but a process still runs the replaced binary | Restart the service |
| `UNKNOWN` | Version not readable, branch not in the advisory (for example 8.6), or a pre-release build | Check the PHP and vendor advisories manually |

The report also shows two more fields for each runtime, so that "patched" and "safe" are not mixed:

- `running`: `yes`, `no`, or `stale` (a process runs the old code).
- `mitigation`: `none`, `effective` (the service reads the values), `pending_restart` (written, but processes started before the change), or `not_effective` (written, but the service does not read it; this is an error).

php-safepatch reads the configuration that each service really uses: the `-y` file of a running PHP-FPM master, `-c` and `PHP_INI_SCAN_DIR` from its systemd unit, and on Windows the `arguments` and `PHPRC` of each IIS FastCGI application and Apache `PHPIniDir`. A health URL passes only if it gives the same status code after the change as before. With Ansible, `apply` stops at the first host that is still not patched (set `safepatch_fail_on_unpatched=false` to continue).

## About the mitigations

The PHP security team says that only the update fully fixes PHP2Shell. The mitigations only reduce the exposure.

- `session.upload_progress.enabled=0` addresses CVE-2026-109619. It disables upload progress bars that use the session upload progress feature. Few applications use this feature.
- `memory_limit=-1` (opt-in) blocks the known path of CVE-2026-109618. It also removes the per-request memory cap. Use it only together with a container, cgroup or PHP-FPM memory limit. php-safepatch does not apply it unless you give `--include-optin`.
- Do not use `RLIMIT_AS` or `RLIMIT_DATA` as a mitigation. They can cause the allocation failures that the attack needs.
- Also limit the request size at the reverse proxy or WAF, including requests without `Content-Length`. See the next section.

## Block at the reverse proxy or WAF

If you cannot patch at once, these rules stop the known attack requests before they reach PHP. They do not replace the update. We tested each rule with attack-shaped and normal requests on ModSecurity 2.9 with OWASP CRS, nginx (stable) and Apache 2.4.

| Rule | ModSecurity | nginx | Apache |
|---|---|---|---|
| Block the `PHP_SESSION_UPLOAD_PROGRESS` field (CVE-2026-109619) | All paths | Paths without uploads only | Paths without uploads only |
| Block very long parameter names (CVE-2026-109618) | Yes | No | No |
| Limit the body size, also for chunked requests | Yes (CRS default) | Yes | Yes |

**ModSecurity (v2 or v3, with or without CRS).** Put the rules in a file that loads before the CRS rules, for example `REQUEST-899-PHP2SHELL.conf`. If `session.upload_progress.name` is not the default, use your value in the first rule.

```apache
# CVE-2026-109619: block the session upload progress field in multipart requests.
SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
    "id:1026101,phase:2,deny,status:403,log,t:none,msg:'PHP2Shell: session upload progress field (CVE-2026-109619)'"
# CVE-2026-109618: block very long parameter names (the known attack uses one of about 3.5 MB).
SecRule ARGS_NAMES "@gt 1024" \
    "id:1026102,phase:2,deny,status:403,log,t:none,t:length,msg:'PHP2Shell: parameter name longer than 1024 bytes (CVE-2026-109618)'"
```

Keep `SecRequestBodyNoFilesLimit` small (the default is 128 KB) and `SecRequestBodyLimitAction Reject`.

**nginx.** nginx cannot read the form field names, so it blocks multipart requests on the locations that do not accept uploads.

```nginx
client_max_body_size 8m;          # also applies to chunked requests

location / {                      # locations without file uploads
    if ($content_type ~* "^multipart/form-data") { return 403; }
    # ... your fastcgi_pass or proxy_pass ...
}
```

**Apache without ModSecurity.** Use `%{HTTP:Content-Type}`, not `%{CONTENT_TYPE}`. In Apache expressions, `%{CONTENT_TYPE}` is the content type of the response, so a rule that uses it blocks nothing.

```apache
LimitRequestBody 8388608          # also applies to chunked requests

<LocationMatch "^/(?!upload)">    # paths without file uploads
    <If "%{HTTP:Content-Type} =~ m#^multipart/form-data#i">
        Require all denied
    </If>
</LocationMatch>
```

Notes:

- The WAF or proxy must see the decrypted traffic. Put the rules where TLS ends.
- Choose the size limit from your real uploads. A limit that is too small breaks file uploads.
- nginx and Apache cannot block the field on upload paths. Patch the servers that have upload paths first, or use ModSecurity there.
- Test the rules on a staging server before production.

## Environment notes

- **Synology DSM and other NAS or appliance firmware**: not supported. On DSM, php-safepatch stops without a change. Use the vendor's update (for Synology, update the PHP package in Package Center).
- **Docker**: php-safepatch does not change running containers. Rebuild the image on a fixed tag (for example `php:8.2.35-fpm`) and deploy it again. `REBUILD` means that the tag follows the branch (`php:8.2-fpm`), so a rebuild with `--pull` is enough. `FLOATING_MAJOR` means that the tag (`php:8`, `php:latest`) can change the branch when you rebuild. Pin it.
- **Source builds, Plesk, cPanel, LiteSpeed**: php-safepatch finds them and applies mitigations. Update them with the vendor's tools.
- **PHP 7.4 to 8.1 on Debian/Ubuntu**: the ondrej PPA and Debian LTS/ELS may have backports. php-safepatch installs them when the repository offers a newer package in the same branch, and it reads the changelog to confirm the fix.

## Add a new advisory

Copy `advisories/php2shell.conf`, change the values, and run with `--advisory`/`-Advisory`. The file defines the fixed versions, the mitigation rules and the log indicators. No change to the scripts is necessary. See [SPEC.md](SPEC.md#3-advisory-file).

## If you find indicators of compromise

1. Isolate the server from the network. Do not turn it off, because a restart deletes evidence from memory.
2. Keep the logs, the process list and the network connections.
3. Report the incident to your CERT.
4. Update PHP, remove web shells, and rotate the database passwords, API keys and administrator passwords.

Do not run proof-of-concept exploits from the internet to test your servers. Many of them contain malware.

## Tests

There are three test suites: unit tests with fake binaries (`tests/run.sh unit`), real distributions in containers (`tests/run.sh containers`), and official PHP builds on Windows (`tests\windows\run.ps1`). See [TESTING.md](TESTING.md). Test on a staging server before you use `apply` in production.

## License

[MIT](LICENSE)
