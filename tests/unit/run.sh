#!/usr/bin/env bash
# php-safepatch unit tests with fake PHP binaries, a fake dpkg-query and a fake apt-get.
# No root, no container, no real PHP. Runs on Linux, macOS (bash 4+) and Git Bash.
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

fake_php() {  # fake_php NAME VERSION SAPI
  cat >"$T/bin/$1" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do
  case "\$a" in
    -v) echo "PHP $2 ($3) (built: Oct  1 2026 00:00:00) (NTS)"; exit 0 ;;
    -m) printf '[PHP Modules]\nCore\ndate\njson\nmbstring\n\n[Zend Modules]\n'; exit 0 ;;
    -i) echo "Scan this dir for additional .ini files => $T/scan.d"; exit 0 ;;
    -t) if grep -q 'not-a-valid-mode' "$T"/fpm/pool.d/*.conf; then echo "ERROR: bad pm"; exit 78; fi
        if [ -e "$T/fail-after-change" ] && grep -q php-safepatch "$T"/fpm/pool.d/*.conf; then echo "ERROR: rejected"; exit 78; fi
        echo "NOTICE: configuration file $T/fpm/php-fpm.conf test is successful"; exit 0 ;;
  esac
done
EOF
  chmod +x "$T/bin/$1"
}

setup() {
  rm -rf "${T:?}/bin" "$T/df" "$T/state" "$T/scan.d" "$T/fpm" "$T/fakebin" "$T/fail-after-change"
  mkdir -p "$T/bin" "$T/df/app1" "$T/df/app2" "$T/state" "$T/scan.d" "$T/fpm/pool.d"
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

status_of() {  # status_of JSON PATH_SUFFIX
  grep -o "{\"path\":\"[^\"]*$2\"[^}]*}" "$1" | grep -o '"status":"[A-Z_]*"' | cut -d'"' -f4
}

# ---------------------------------------------------------------------------
section "Assessment"
setup
bash "$S" scan --no-docker --no-ioc --quiet --state-dir "$T/state" --advisory "$ADV" \
  --php "$T/bin/php8.2" --php "$T/bin/php8.3" --php "$T/bin/php-fpm8.4" --php "$T/bin/php8.0" \
  --php "$T/bin/php7.2" --php "$T/bin/php8.5" --dockerfiles "$T/df" --json "$T/scan.json" >/dev/null 2>&1
check_eq "scan exit code with vulnerable runtimes" 1 "$?"
check_eq "8.2.10 is VULNERABLE" VULNERABLE "$(status_of "$T/scan.json" /php8.2)"
check_eq "8.3.36 is PATCHED" PATCHED "$(status_of "$T/scan.json" /php8.3)"
check_eq "8.4.20 FPM is VULNERABLE" VULNERABLE "$(status_of "$T/scan.json" /php-fpm8.4)"
check_eq "8.0.30 is VULNERABLE_EOL" VULNERABLE_EOL "$(status_of "$T/scan.json" /php8.0)"
check_eq "7.2.34 is VULNERABLE_NOFIX" VULNERABLE_NOFIX "$(status_of "$T/scan.json" /php7.2)"
check_eq "8.5.3 is VULNERABLE" VULNERABLE "$(status_of "$T/scan.json" /php8.5)"
check "Dockerfile pinned tag gets a fix" grep -q '"from":"php:8.2.10-fpm-alpine","status":"VULNERABLE","fix":"php:8.2.35-fpm-alpine"' "$T/scan.json"
check "Dockerfile floating minor tag is REBUILD" grep -q '"from":"php:8.3-apache","status":"REBUILD"' "$T/scan.json"
check "Dockerfile fixed tag is PATCHED" grep -q '"from":"docker.io/library/php:8.4.27-cli","status":"PATCHED"' "$T/scan.json"
check "Dockerfile latest is FLOATING_MAJOR" grep -q '"from":"php:latest","status":"FLOATING_MAJOR"' "$T/scan.json"
check "Dockerfile variable tag is MANUAL" grep -q '"status":"MANUAL"' "$T/scan.json"

# ---------------------------------------------------------------------------
section "Mitigation, idempotency and rollback"
setup
ARGS=(--no-docker --no-ioc --no-restart --no-patch --include-optin --state-dir "$T/state" --yes --quiet
      --advisory "$ADV" --php "$T/bin/php8.2" --php "$T/bin/php-fpm8.4" --dockerfiles "$T/df" --fix-dockerfiles)
bash "$S" apply "${ARGS[@]}" --json "$T/a1.json" >/dev/null 2>&1
INI="$T/scan.d/99-php-safepatch-php2shell.ini"
check "ini file created" test -f "$INI"
check "ini sets session.upload_progress.enabled = 0" grep -qx 'session.upload_progress.enabled = 0' "$INI"
check "opt-in memory_limit = -1 written with --include-optin" grep -qx 'memory_limit = -1' "$INI"
check "8.5-only rule not written for 8.2/8.4" bash -c "! grep -q fatal_error_backtraces '$INI'"
check_eq "both pool sections get a block" 2 "$(grep -c '^; >>> php-safepatch PHP2Shell mitigation >>>' "$T/fpm/pool.d/www.conf")"
check "block comes after the existing memory_limit line (later value wins)" \
  bash -c "awk '/\\[api\\]/{a=1} a&&/memory_limit\\] = 128M/{m=NR} a&&/memory_limit\\] = -1/{n=NR} END{exit !(m&&n&&n>m)}' '$T/fpm/pool.d/www.conf'"
check_eq "Dockerfile tag fixed" "FROM php:8.2.35-fpm-alpine AS base" "$(head -1 "$T/df/app1/Dockerfile")"
check "report marks interim mitigation" grep -q 'interim mitigation applied' "$T/a1.json"
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

section "Branch lock (fake apt-get)"
setup
mkdir -p "$T/fakebin"
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
[ "\$1" = "-s" ] && cat "$T/apt.sim"
exit 0
EOF
chmod +x "$T/fakebin/"*
APT_ARGS=(--no-docker --no-ioc --no-restart --mitigate never --state-dir "$T/state" --yes --quiet --advisory "$ADV" --php "$T/bin/php8.2")

rm -f "$T/apt.calls"
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

summary
