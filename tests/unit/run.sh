#!/usr/bin/env bash
# php-safepatch unit tests with fake PHP binaries and fake package tools (dpkg-query, apt-get,
# rpm, dnf, curl). No root, no container, no real PHP. Runs on Linux, macOS (bash 4.4+) and Git Bash.
# SPDX-License-Identifier: MIT

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# shellcheck source=../lib/assert.sh
. "$REPO/tests/lib/assert.sh"
S="$REPO/linux/php-safepatch.sh"
ADV="$REPO/advisories/php2shell.conf"
T="$(mktemp -d 2>/dev/null || mktemp -d -t sp)"
trap 'rm -rf "$T"' EXIT
export PHP_SAFEPATCH_TEST_NONROOT=1

# fake_php NAME VERSION SAPI [deaf]
# "-i" prints the scan dir and the ini values that the conf.d files set. A "deaf" binary ignores
# conf.d, like a service that runs with "-n" or another scan dir.
fake_php() {
  local deaf="${4:-}"
  cat >"$T/bin/$1" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do
  case "\$a" in
    -v) echo "PHP $2 ($3) (built: Oct  1 2026 00:00:00) (NTS)"; exit 0 ;;
    -m) printf '[PHP Modules]\nCore\ndate\njson\nmbstring\n\n[Zend Modules]\n'; exit 0 ;;
    -i) dir="\${PHP_INI_SCAN_DIR:-$T/scan.d}"
        echo "Scan this dir for additional .ini files => \$dir"
        declare -A v=([session.upload_progress.enabled]=On [memory_limit]=128M [fatal_error_backtraces]=On)
        if [ "$deaf" != deaf ]; then
          for f in "\$dir"/*.ini; do
            [ -f "\$f" ] || continue
            while IFS='=' read -r k val; do
              k="\${k// /}"; val="\${val# }"; case "\$k" in ''|';'*) continue ;; esac
              v[\$k]="\$val"
            done <"\$f"
          done
        fi
        for k in "\${!v[@]}"; do echo "\$k => \${v[\$k]} => \${v[\$k]}"; done
        exit 0 ;;
    -t) y=""; prev=""; for b in "\$@"; do [ "\$prev" = -y ] && y="\$b"; prev="\$b"; done
        conf="\${y:-$T/fpm/php-fpm.conf}"; pdir="\$(dirname "\$conf")/pool.d"
        if grep -q 'not-a-valid-mode' "\$pdir"/*.conf; then echo "ERROR: bad pm"; exit 78; fi
        if [ -e "$T/fail-after-change" ] && grep -q php-safepatch "\$pdir"/*.conf; then echo "ERROR: rejected"; exit 78; fi
        echo "NOTICE: configuration file \$conf test is successful"; exit 0 ;;
  esac
done
EOF
  chmod +x "$T/bin/$1"
}

setup() {
  rm -rf "${T:?}/bin" "$T/df" "$T/state" "$T/scan.d" "$T/fpm" "$T/fakebin" "$T/fail-after-change" "$T"/*.calls
  mkdir -p "$T/bin" "$T/df/app1" "$T/df/app2" "$T/state" "$T/scan.d" "$T/fpm/pool.d" "$T/fakebin"
  fake_php php8.2 8.2.10 cli
  fake_php php8.3 8.3.36 cli
  fake_php php-fpm8.4 8.4.20 fpm-fcgi
  fake_php php8.0 8.0.30 cli
  fake_php php7.2 7.2.34 cli
  fake_php php8.5 8.5.3 cli
  printf 'FROM php:8.2.10-fpm-alpine AS base\nRUN echo hi\nFROM php:8.3-apache\n' >"$T/df/app1/Dockerfile"
  printf 'FROM --platform=linux/amd64 docker.io/library/php:8.4.27-cli\nFROM php:latest\nFROM php:${PHPV}-fpm\n' >"$T/df/app2/Containerfile"
  printf '[global]\npid = /run/php.pid\ninclude=%s/fpm/pool.d/*.conf\n' "$T" >"$T/fpm/php-fpm.conf"
  printf '[www]\nuser = www-data\npm = dynamic\n\n[api]\nuser = api\nphp_admin_value[memory_limit] = 128M\n' >"$T/fpm/pool.d/www.conf"
}

rt_field() {  # rt_field JSON PATH_SUFFIX FIELD
  grep -o "{\"path\":\"[^\"]*$2\"[^}]*" "$1" | grep -o "\"$3\":\"[^\"]*\"" | head -1 | cut -d'"' -f4
}
status_of() { rt_field "$1" "$2" status; }
INI="$T/scan.d/99-php-safepatch-php2shell.ini"

# ---------------------------------------------------------------------------
section "Assessment"
setup
fake_php php8.6 8.6.0 cli
mkdir -p "$T/bin/rc" "$T/bin/dev" "$T/bin/ubu"; fake_php rc/php8.5 8.5.12RC1 cli
fake_php dev/php8.5 8.5.13-dev cli
fake_php ubu/php8.1 "8.1.2-1ubuntu2.28" cli
bash "$S" scan --no-docker --no-ioc --quiet --state-dir "$T/state" --advisory "$ADV" \
  --php "$T/bin/php8.2" --php "$T/bin/php8.3" --php "$T/bin/php-fpm8.4" --php "$T/bin/php8.0" \
  --php "$T/bin/php7.2" --php "$T/bin/php8.5" --php "$T/bin/php8.6" --php "$T/bin/rc/php8.5" \
  --php "$T/bin/dev/php8.5" --php "$T/bin/ubu/php8.1" --dockerfiles "$T/df" --json "$T/scan.json" >/dev/null 2>&1
check_eq "scan exit code with vulnerable runtimes" 1 "$?"
check_eq "8.2.10 is VULNERABLE" VULNERABLE "$(status_of "$T/scan.json" /php8.2)"
check_eq "8.3.36 is PATCHED" PATCHED "$(status_of "$T/scan.json" /php8.3)"
check_eq "8.4.20 FPM is VULNERABLE" VULNERABLE "$(status_of "$T/scan.json" /php-fpm8.4)"
check_eq "8.0.30 is VULNERABLE_EOL" VULNERABLE_EOL "$(status_of "$T/scan.json" /php8.0)"
check_eq "7.2.34 is VULNERABLE_NOFIX" VULNERABLE_NOFIX "$(status_of "$T/scan.json" /php7.2)"
check_eq "8.5.3 is VULNERABLE" VULNERABLE "$(status_of "$T/scan.json" /bin/php8.5)"
check_eq "8.6.0 (branch not in the advisory) is UNKNOWN, not PATCHED" UNKNOWN "$(status_of "$T/scan.json" /php8.6)"
check_eq "8.5.12RC1 keeps its suffix" 8.5.12RC1 "$(rt_field "$T/scan.json" /rc/php8.5 version)"
check_eq "8.5.12RC1 (pre-release of the fix) is VULNERABLE" VULNERABLE "$(status_of "$T/scan.json" /rc/php8.5)"
check_eq "8.5.13-dev (pre-release after the fix) is UNKNOWN" UNKNOWN "$(status_of "$T/scan.json" /dev/php8.5)"
check_eq "distribution suffix is not a pre-release (8.1.2-1ubuntu2.28 -> 8.1.2)" 8.1.2 "$(rt_field "$T/scan.json" /ubu/php8.1 version)"
check_eq "a runtime with no process is running=no" no "$(rt_field "$T/scan.json" /php8.2 running)"
check "Dockerfile pinned tag gets a fix" grep -q '"from":"php:8.2.10-fpm-alpine","status":"VULNERABLE","fix":"php:8.2.35-fpm-alpine"' "$T/scan.json"
check "Dockerfile floating minor tag is REBUILD" grep -q '"from":"php:8.3-apache","status":"REBUILD"' "$T/scan.json"
check "Dockerfile fixed tag is PATCHED" grep -q '"from":"docker.io/library/php:8.4.27-cli","status":"PATCHED"' "$T/scan.json"
check "Dockerfile latest is FLOATING_MAJOR" grep -q '"from":"php:latest","status":"FLOATING_MAJOR"' "$T/scan.json"
check "Dockerfile variable tag is MANUAL" grep -q '"status":"MANUAL"' "$T/scan.json"

# ---------------------------------------------------------------------------
section "Mitigation, verification, idempotency and rollback"
setup
ARGS=(--no-docker --no-ioc --no-restart --no-patch --include-optin --state-dir "$T/state" --yes --quiet
      --advisory "$ADV" --php "$T/bin/php8.2" --php "$T/bin/php-fpm8.4" --dockerfiles "$T/df" --fix-dockerfiles)
bash "$S" apply "${ARGS[@]}" --json "$T/a1.json" >"$T/a1.out" 2>&1
check_eq "apply exit code is 1 (still not patched, no error)" 1 "$?"
check "ini file created" test -f "$INI"
check "ini sets session.upload_progress.enabled = 0" grep -qx 'session.upload_progress.enabled = 0' "$INI"
check "opt-in memory_limit = -1 written with --include-optin" grep -qx 'memory_limit = -1' "$INI"
check "8.5-only rule not written for 8.2/8.4" bash -c "! grep -q fatal_error_backtraces '$INI'"
check_eq "both pool sections get a block" 2 "$(grep -c '^; >>> php-safepatch PHP2Shell mitigation >>>' "$T/fpm/pool.d/www.conf")"
check "block comes after the existing memory_limit line (later value wins)" \
  bash -c "awk '/\\[api\\]/{a=1} a&&/memory_limit\\] = 128M/{m=NR} a&&/memory_limit\\] = -1/{n=NR} END{exit !(m&&n&&n>m)}' '$T/fpm/pool.d/www.conf'"
check_eq "Dockerfile tag fixed" "FROM php:8.2.35-fpm-alpine AS base" "$(head -1 "$T/df/app1/Dockerfile")"
check_eq "the runtime reads the new values (mitigation=effective)" effective "$(rt_field "$T/a1.json" /php8.2 mitigation)"
check_eq "status stays VULNERABLE: a mitigation is not a fix" VULNERABLE "$(status_of "$T/a1.json" /php8.2)"
cp "$T/fpm/pool.d/www.conf" "$T/pool.after1"
bash "$S" apply "${ARGS[@]}" --json "$T/a2.json" >/dev/null 2>&1
check "second run leaves the pool unchanged" same_file "$T/fpm/pool.d/www.conf" "$T/pool.after1"
check "second run has an empty manifest" test ! -s "$(json_field "$T/a2.json" run_dir)/manifest"
RUN1="$(basename "$(json_field "$T/a1.json" run_dir)")"
bash "$S" rollback --run-id "$RUN1" --state-dir "$T/state" --yes --no-restart --quiet >/dev/null 2>&1
check_eq "rollback exit code" 0 "$?"
check "rollback removes the ini file" test ! -f "$INI"
check "rollback removes the pool blocks" bash -c "! grep -q php-safepatch '$T/fpm/pool.d/www.conf'"
check_eq "rollback restores the Dockerfile" "FROM php:8.2.10-fpm-alpine AS base" "$(head -1 "$T/df/app1/Dockerfile")"

section "A runtime that does not read the mitigation is reported, not counted as mitigated"
setup
mkdir -p "$T/bin/deaf"; fake_php deaf/php8.1 8.1.30 cli deaf
bash "$S" apply --no-docker --no-ioc --no-restart --no-patch --state-dir "$T/state" --yes --quiet \
  --advisory "$ADV" --php "$T/bin/deaf/php8.1" --json "$T/deaf.json" >"$T/deaf.out" 2>&1
check_eq "apply exit code is 2" 2 "$?"
check_eq "mitigation=not_effective" not_effective "$(rt_field "$T/deaf.json" /deaf/php8.1 mitigation)"
check "error says the runtime does not use the mitigation" grep -q 'does not use it' "$T/deaf.out"

section "PHP-FPM: the final value of each pool counts, not the marker"
setup
printf 'session.upload_progress.enabled = 0\n' >"$INI"
# A marked block with a wrong value in every pool.
awk '/^\[api\]/ { print "; >>> php-safepatch PHP2Shell mitigation >>>\nphp_admin_value[session.upload_progress.enabled] = 1\n; <<< php-safepatch PHP2Shell mitigation <<<" } { print } END { print "; >>> php-safepatch PHP2Shell mitigation >>>\nphp_admin_value[session.upload_progress.enabled] = 1\n; <<< php-safepatch PHP2Shell mitigation <<<" }' \
  "$T/fpm/pool.d/www.conf" >"$T/www.tmp" && mv "$T/www.tmp" "$T/fpm/pool.d/www.conf"
bash "$S" scan --no-docker --no-ioc --quiet --state-dir "$T/state" --advisory "$ADV" --php "$T/bin/php-fpm8.4" --json "$T/wrong.json" >/dev/null 2>&1
check_eq "marked block with value 1 is not_effective" not_effective "$(rt_field "$T/wrong.json" /php-fpm8.4 mitigation)"
setup
bash "$S" apply --no-docker --no-ioc --no-restart --no-patch --state-dir "$T/state" --yes --quiet --advisory "$ADV" \
  --php "$T/bin/php-fpm8.4" --json "$T/good.json" >/dev/null 2>&1
check_eq "correct blocks: effective" effective "$(rt_field "$T/good.json" /php-fpm8.4 mitigation)"
printf 'php_admin_flag[session.upload_progress.enabled] = on\n' >>"$T/fpm/pool.d/www.conf"   # later line in [api]
bash "$S" scan --no-docker --no-ioc --quiet --state-dir "$T/state" --advisory "$ADV" --php "$T/bin/php-fpm8.4" --json "$T/over.json" >/dev/null 2>&1
check_eq "a later admin line that sets the value back is not_effective" not_effective "$(rt_field "$T/over.json" /php-fpm8.4 mitigation)"

section "PHP-FPM: include order is the reading order (not sorted), nested includes count"
setup
printf 'session.upload_progress.enabled = 0\n' >"$INI"
mkdir -p "$T/fpm/inc/deeper"
printf '[w]\nphp_admin_value[session.upload_progress.enabled] = 0\n' >"$T/fpm/inc/z.conf"
printf '[w]\nphp_admin_value[session.upload_progress.enabled] = 1\n' >"$T/fpm/inc/a.conf"
printf '[global]\ninclude=%s/fpm/inc/z.conf\ninclude=%s/fpm/inc/a.conf\n' "$T" "$T" >"$T/fpm/php-fpm.conf"
bash "$S" scan --no-docker --no-ioc --quiet --state-dir "$T/state" --advisory "$ADV" --php "$T/bin/php-fpm8.4" --json "$T/order1.json" >/dev/null 2>&1
check_eq "z.conf (0) then a.conf (1): the final value is 1, not_effective" not_effective "$(rt_field "$T/order1.json" /php-fpm8.4 mitigation)"
printf '[global]\ninclude=%s/fpm/inc/a.conf\ninclude=%s/fpm/inc/z.conf\n' "$T" "$T" >"$T/fpm/php-fpm.conf"
bash "$S" scan --no-docker --no-ioc --quiet --state-dir "$T/state" --advisory "$ADV" --php "$T/bin/php-fpm8.4" --json "$T/order2.json" >/dev/null 2>&1
check_eq "a.conf (1) then z.conf (0): the final value is 0, effective" effective "$(rt_field "$T/order2.json" /php-fpm8.4 mitigation)"
printf '[w]\nphp_admin_value[session.upload_progress.enabled] = 0\ninclude=%s/fpm/inc/deeper/*.conf\n' "$T" >"$T/fpm/inc/z.conf"
printf 'php_admin_value[session.upload_progress.enabled] = 1\n' >"$T/fpm/inc/deeper/late.conf"
bash "$S" scan --no-docker --no-ioc --quiet --state-dir "$T/state" --advisory "$ADV" --php "$T/bin/php-fpm8.4" --json "$T/order3.json" >/dev/null 2>&1
check_eq "a nested include that sets the value back: not_effective" not_effective "$(rt_field "$T/order3.json" /php-fpm8.4 mitigation)"

section "One PHP-FPM binary with two services (-y A and -y B): two runtimes"
setup
for x in A B; do
  mkdir -p "$T/fpm$x/pool.d"
  printf '[global]\ninclude=%s/fpm%s/pool.d/*.conf\n' "$T" "$x" >"$T/fpm$x/php-fpm.conf"
  printf '[site%s]\nuser = www-data\n' "$x" >"$T/fpm$x/pool.d/site.conf"
done
cat >"$T/fakebin/systemctl" <<EOF
#!/usr/bin/env bash
echo "systemctl \$*" >>"$T/systemctl.calls"
case "\$*" in
  *list-units*) printf 'php-site-a.service loaded active running A\nphp-site-b.service loaded active running B\n' ;;
  *ExecStart*php-site-a*) echo "{ path=$T/bin/php-fpm8.4 ; argv[]=$T/bin/php-fpm8.4 --nodaemonize --fpm-config $T/fpmA/php-fpm.conf ; }" ;;
  *ExecStart*php-site-b*) echo "{ path=$T/bin/php-fpm8.4 ; argv[]=$T/bin/php-fpm8.4 --nodaemonize -y $T/fpmB/php-fpm.conf -c $T/fpmB/php.ini ; }" ;;
  *Environment*) echo "" ;;
esac
exit 0
EOF
chmod +x "$T/fakebin/systemctl"
PATH="$T/fakebin:$PATH" PHP_SAFEPATCH_TEST_SYSTEMD=1 bash "$S" scan --no-docker --no-ioc --quiet --state-dir "$T/state" \
  --advisory "$ADV" --php "$T/bin/php-fpm8.4" --json "$T/multi.json" >/dev/null 2>&1
check_eq "two PHP-FPM runtimes for one binary" 2 "$(grep -o '"sapi":"fpm-fcgi"' "$T/multi.json" | wc -l | tr -d ' ')"
check "runtime with config A" grep -q "\"fpm_conf\":\"$T/fpmA/php-fpm.conf\"" "$T/multi.json"
check "runtime with config B" grep -q "\"fpm_conf\":\"$T/fpmB/php-fpm.conf\"" "$T/multi.json"
check "unit A is recorded (no -c: fields do not shift)" grep -q "\"php_ini\":\"\",\"scan_dir_env\":\"\",\"unit\":\"php-site-a.service\"" "$T/multi.json"
check "unit B keeps its -c php.ini" grep -q "\"php_ini\":\"$T/fpmB/php.ini\",\"scan_dir_env\":\"\",\"unit\":\"php-site-b.service\"" "$T/multi.json"
rm -f "$T/systemctl.calls"
PATH="$T/fakebin:$PATH" PHP_SAFEPATCH_TEST_SYSTEMD=1 bash "$S" apply --no-docker --no-ioc --no-patch --state-dir "$T/state" --yes --quiet \
  --advisory "$ADV" --php "$T/bin/php-fpm8.4" --json "$T/multi2.json" >/dev/null 2>&1
check "pool of service A carries the block" grep -q 'php_admin_value\[session.upload_progress.enabled\] = 0' "$T/fpmA/pool.d/site.conf"
check "pool of service B carries the block" grep -q 'php_admin_value\[session.upload_progress.enabled\] = 0' "$T/fpmB/pool.d/site.conf"
check "unit A is restarted" grep -q 'restart php-site-a.service' "$T/systemctl.calls"
check "unit B is restarted" grep -q 'restart php-site-b.service' "$T/systemctl.calls"

section "Patched branch: old mitigation is removed everywhere (ini and PHP-FPM pools)"
setup
fake_php php-fpm8.3 8.3.36 fpm-fcgi
bash "$S" apply --no-docker --no-ioc --no-restart --no-patch --mitigate always --include-optin --state-dir "$T/state" \
  --yes --quiet --advisory "$ADV" --php "$T/bin/php-fpm8.3" >/dev/null 2>&1
check "setup: pool block present" grep -q 'php-safepatch PHP2Shell' "$T/fpm/pool.d/www.conf"
bash "$S" apply --no-docker --no-ioc --no-restart --no-patch --state-dir "$T/state" --yes --quiet \
  --advisory "$ADV" --php "$T/bin/php-fpm8.3" --json "$T/clean.json" >/dev/null 2>&1
check_eq "apply exit code is 0" 0 "$?"
check "ini file removed" test ! -f "$INI"
check "pool blocks removed (memory_limit=-1 does not stay)" bash -c "! grep -q 'php-safepatch\|memory_limit\] = -1' '$T/fpm/pool.d/www.conf'"
check_eq "mitigation=none after cleanup" none "$(rt_field "$T/clean.json" /php-fpm8.3 mitigation)"

# ---------------------------------------------------------------------------
section "Config already broken before the run: branch is not touched"
setup
printf 'pm = not-a-valid-mode\n' >>"$T/fpm/pool.d/www.conf"
cp "$T/fpm/pool.d/www.conf" "$T/pool.broken"
bash "$S" apply --no-docker --no-ioc --no-restart --no-patch --state-dir "$T/state" --yes --quiet \
  --advisory "$ADV" --php "$T/bin/php-fpm8.4" >"$T/broken.out" 2>&1
check_eq "apply exit code is 2" 2 "$?"
check "error says the test fails before any change" grep -q 'Config test fails before any change' "$T/broken.out"
check "pool file unchanged" same_file "$T/fpm/pool.d/www.conf" "$T/pool.broken"
check "no ini file written" test ! -f "$INI"

section "Change breaks the config test: files are restored"
setup
cp "$T/fpm/pool.d/www.conf" "$T/pool.orig"
: >"$T/fail-after-change"
bash "$S" apply --no-docker --no-ioc --no-restart --no-patch --state-dir "$T/state" --yes --quiet \
  --advisory "$ADV" --php "$T/bin/php-fpm8.4" >"$T/broken2.out" 2>&1
check_eq "apply exit code is 2" 2 "$?"
check "error names the failed config test" grep -q 'Config test failed' "$T/broken2.out"
check "pool file restored to the original" same_file "$T/fpm/pool.d/www.conf" "$T/pool.orig"
check "ini file created by the failed run removed" test ! -f "$INI"

section "Health check needs the same status code before and after"
setup
cat >"$T/fakebin/curl" <<EOF
#!/usr/bin/env bash
c="\$(head -1 "$T/curl.codes")"; sed -i '1d' "$T/curl.codes"; [ -s "$T/curl.codes" ] || echo "\$c" >"$T/curl.codes"
printf '%s' "\$c"
EOF
chmod +x "$T/fakebin/curl"
printf '200\n404\n' >"$T/curl.codes"
PATH="$T/fakebin:$PATH" bash "$S" apply --no-docker --no-ioc --no-restart --no-patch --state-dir "$T/state" --yes --quiet \
  --advisory "$ADV" --php "$T/bin/php8.2" --health-url http://app.test/health >"$T/health.out" 2>&1
check_eq "200 before and 404 after: apply exit code is 2" 2 "$?"
check "error names the health check" grep -q 'Health check failed' "$T/health.out"
check "files restored after the failed health check" test ! -f "$INI"
printf '200\n' >"$T/curl.codes"
PATH="$T/fakebin:$PATH" bash "$S" apply --no-docker --no-ioc --no-restart --no-patch --state-dir "$T/state" --yes --quiet \
  --advisory "$ADV" --php "$T/bin/php8.2" --health-url http://app.test/health >/dev/null 2>&1
check_eq "200 before and after: apply exit code is 1 (only not patched)" 1 "$?"

# ---------------------------------------------------------------------------
section "Advisory files start empty and are validated"
setup
printf 'id=OTHER-TEST\ncves=CVE-2099-0001\nfixed=8.6.1\n' >"$T/other.conf"
bash "$S" apply --no-docker --no-ioc --no-restart --no-patch --mitigate always --include-optin --state-dir "$T/state" \
  --yes --quiet --advisory "$T/other.conf" --php "$T/bin/php8.2" >/dev/null 2>&1
check "no PHP2Shell rule is inherited (no ini written)" bash -c "! ls '$T/scan.d'/*.ini >/dev/null 2>&1"
printf 'id=BAD\ncves=CVE-2099-0002\nfixed=8.2\nmitigate=memory_limit\n' >"$T/bad.conf"
bash "$S" scan --no-docker --no-ioc --state-dir "$T/state" --advisory "$T/bad.conf" --php "$T/bin/php8.2" >"$T/bad.out" 2>&1
check_eq "invalid advisory: exit code 2" 2 "$?"
check "invalid 'fixed' value is named" grep -q "'fixed' value '8.2' is not X.Y.Z" "$T/bad.out"
check "invalid mitigation rule is named" grep -q "mitigation rule 'memory_limit' is not KEY=VALUE" "$T/bad.out"
printf 'cves=CVE-2099-0003\nfixed=8.2.40\n' >"$T/noid.conf"
bash "$S" scan --no-docker --no-ioc --state-dir "$T/state" --advisory "$T/noid.conf" --php "$T/bin/php8.2" >"$T/noid.out" 2>&1
check_eq "advisory without id: exit code 2" 2 "$?"

# ---------------------------------------------------------------------------
section "Synology DSM is not supported"
setup
printf 'majorversion="7"\nproductversion="7.2.2"\n' >"$T/dsm-version"
for cmd in scan apply; do
  PHP_SAFEPATCH_TEST_DSM_FILE="$T/dsm-version" bash "$S" "$cmd" --no-docker --no-ioc --yes --state-dir "$T/state" \
    --php "$T/bin/php8.2" >"$T/dsm.out" 2>&1
  check_eq "$cmd on DSM exits with code 2" 2 "$?"
  check "$cmd on DSM says it is not supported" grep -q 'Synology DSM is not supported' "$T/dsm.out"
done
check "no ini written on DSM" test ! -f "$INI"

# ---------------------------------------------------------------------------
section "Branch lock (fake apt-get)"
setup
cat >"$T/fakebin/dpkg-query" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  -S) echo "php8.2-cli: $2" ;;
  -W)
    case "$2" in
      -f='${Version}') echo "8.2.10-1" ;;
      *Status*) printf 'install ok installed\tphp8.2-cli\ninstall ok installed\tphp8.2-common\ninstall ok installed\tphp8.2-fpm\n' ;;
      *) printf 'php8.2-cli=8.2.10-1\nphp8.2-common=8.2.10-1\nphp8.2-fpm=8.2.10-1\n' ;;
    esac ;;
esac
EOF
cat >"$T/fakebin/apt-get" <<EOF
#!/usr/bin/env bash
echo "apt-get \$*" >>"$T/apt.calls"
[ "\$1" = "-s" ] && { cat "$T/apt.sim"; exit "\$(cat "$T/apt.rc" 2>/dev/null || echo 0)"; }
exit 0
EOF
chmod +x "$T/fakebin/"*
APT_ARGS=(--no-docker --no-ioc --no-restart --mitigate never --state-dir "$T/state" --yes --quiet --advisory "$ADV" --php "$T/bin/php8.2")

printf 'Inst php8.2-common [8.2.10-1] (8.2.35-1+deb12u1 Debian-Security:12 [amd64])\nInst php8.2-cli [8.2.10-1] (8.2.35-1+deb12u1 Debian-Security:12 [amd64])\n' >"$T/apt.sim"
PATH="$T/fakebin:$PATH" bash "$S" apply "${APT_ARGS[@]}" >/dev/null 2>&1
check "same-branch upgrade runs apt-get install --only-upgrade" grep -q '^apt-get install -y -q --only-upgrade' "$T/apt.calls"
check "only phpX.Y packages are passed (no metapackage)" bash -c "grep '^apt-get install' '$T/apt.calls' | grep -qv ' php \| php-cli\| php-fpm '"

rm -f "$T/apt.calls"
printf 'Inst php8.3-common (8.3.36-1 Debian:13 [amd64])\nInst php8.2-cli [8.2.10-1] (8.2.35-1 Debian-Security:12 [amd64])\n' >"$T/apt.sim"
PATH="$T/fakebin:$PATH" bash "$S" apply "${APT_ARGS[@]}" >"$T/b.out" 2>&1
check "another branch in the simulation blocks the install" bash -c "! grep -q '^apt-get install -y' '$T/apt.calls'"
check "the error names the other-branch package" grep -q 'php8.3-common' "$T/b.out"

rm -f "$T/apt.calls"
printf 'Remv php8.2-mysql [8.2.10-1]\nInst php8.2-cli [8.2.10-1] (8.2.35-1 Debian-Security:12 [amd64])\n' >"$T/apt.sim"
PATH="$T/fakebin:$PATH" bash "$S" apply "${APT_ARGS[@]}" >"$T/c.out" 2>&1
check "a removal in the simulation blocks the install" bash -c "! grep -q '^apt-get install -y' '$T/apt.calls'"

rm -f "$T/apt.calls"; printf 'E: Unable to locate package\n' >"$T/apt.sim"; echo 100 >"$T/apt.rc"
PATH="$T/fakebin:$PATH" bash "$S" apply "${APT_ARGS[@]}" >"$T/d.out" 2>&1
check_eq "a failed simulation is an error (exit 2), not 'no update'" 2 "$?"
check "a failed simulation blocks the install" bash -c "! grep -q '^apt-get install -y' '$T/apt.calls'"
rm -f "$T/apt.rc"

# ---------------------------------------------------------------------------
section "RHEL transaction check (fake rpm and dnf)"
setup
cat >"$T/fakebin/rpm" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *-qf*) echo "php-cli" ;;
  *--changelog*) : ;;
  *-qa*) printf 'php\nphp-cli\nphp-common\nphp-fpm\nphp-pecl-redis5\n' ;;
  *'%{NAME}-%{VERSION}'*) printf 'php-cli-8.2.10-1.el9.x86_64\n' ;;
  *) echo "8.2.10-1.el9" ;;
esac
EOF
cat >"$T/fakebin/dnf" <<EOF
#!/usr/bin/env bash
echo "dnf \$*" >>"$T/dnf.calls"
case "\$*" in *--assumeno*) cat "$T/dnf.sim"; exit 1 ;; esac
exit 0
EOF
chmod +x "$T/fakebin/"*
RPM_ARGS=(--no-docker --no-ioc --no-restart --mitigate never --state-dir "$T/state" --yes --quiet --advisory "$ADV" --php "$T/bin/php8.2")
dnf_case() {  # dnf_case LABEL SHOULD_INSTALL(yes|no) -- reads the simulation from $T/dnf.sim
  rm -f "$T/dnf.calls"
  PATH="$T/fakebin:$PATH" bash "$S" apply "${RPM_ARGS[@]}" >"$T/dnf.out" 2>&1
  if [ "$2" = yes ]; then check "$1" grep -q '^dnf -y -q upgrade' "$T/dnf.calls"
  else check "$1" bash -c "! grep -q '^dnf -y -q upgrade' '$T/dnf.calls'"; fi
}
hdr='Dependencies resolved.
================================================================================
 Package           Arch     Version                         Repository     Size
================================================================================'
printf '%s\nUpgrading:\n php-cli           x86_64   8.2.35-1.module+el9.8.0         appstream     3.6 M\n php-common        x86_64   8.2.35-1.module+el9.8.0         appstream     700 k\n php-pecl-redis5   x86_64   5.3.7-2.el9                     appstream     190 k\n\nTransaction Summary\n================================================================================\nUpgrade  3 Packages\n\nOperation aborted.\n' "$hdr" >"$T/dnf.sim"
dnf_case "same-branch transaction is installed (pecl version is ignored)" yes
printf '%s\nUpgrading:\n php-cli           x86_64   8.2.35-1.module+el9.8.0         appstream     3.6 M\nEnabling module streams:\n php                        8.3\n\nOperation aborted.\n' "$hdr" >"$T/dnf.sim"
dnf_case "a module stream change blocks the install" no
check "the error names the module stream change" grep -q 'changes module streams' "$T/dnf.out"
printf '%s\nUpgrading:\n php-cli           x86_64   8.2.35-1                        appstream     3.6 M\nRemoving dependent packages:\n php-mysqlnd       x86_64   8.2.10-1                        @appstream    500 k\n\nOperation aborted.\n' "$hdr" >"$T/dnf.sim"
dnf_case "a removal in the transaction blocks the install" no
printf '%s\nUpgrading:\n php-cli           x86_64   8.3.36-1                        remi-modular  3.6 M\n\nOperation aborted.\n' "$hdr" >"$T/dnf.sim"
dnf_case "another branch in the transaction blocks the install" no
printf '%s\nInstalling dependencies:\n php83-php-common x86_64   8.3.36-1.el9.remi               remi-safe     700 k\nUpgrading:\n php-cli           x86_64   8.2.35-1                        appstream     3.6 M\n\nOperation aborted.\n' "$hdr" >"$T/dnf.sim"
dnf_case "a dependency from another branch (php83-*) blocks the install" no
printf 'Error: Failed to download metadata for repo appstream\n' >"$T/dnf.sim"
dnf_case "a failed simulation blocks the install" no
check "a failed simulation is reported as an error" grep -q 'could not simulate' "$T/dnf.out"
printf 'Dependencies resolved.\nNothing to do.\nComplete!\n' >"$T/dnf.sim"
dnf_case "nothing to do: no install" no
check "nothing to do is not an error" bash -c "! grep -q ERROR '$T/dnf.out'"

summary
