#!/usr/bin/env bash
# php-safepatch test cases. Runs inside a disposable container as root.
# Usage: cases.sh   (the repository is mounted read-only at /src)
# SPDX-License-Identifier: MIT

set -u
SRC="${SRC:-/src}"
# shellcheck source=assert.sh
. "$SRC/tests/lib/assert.sh"

S="$SRC/linux/php-safepatch.sh"
W=/tmp/sp-test; rm -rf "$W"; mkdir -p "$W"
COMMON=(--no-docker --no-restart --quiet)

# ---------------------------------------------------------------------------
# Facts about this container
# ---------------------------------------------------------------------------
if command -v dpkg-query >/dev/null 2>&1; then FAMILY=debian; else FAMILY=rhel; fi
BRANCH="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
FPM="$(ls /usr/sbin/php-fpm* 2>/dev/null | head -1)"
if [ "$FAMILY" = debian ]; then
  INI_DIRS=(/etc/php/"$BRANCH"/*/conf.d)
  APACHE_CONF=/etc/apache2/conf-available/php-safepatch-php2shell.conf
  APACHECTL=apache2ctl
else
  INI_DIRS=(/etc/php.d)
  APACHE_CONF=/etc/httpd/conf.d/zz-php-safepatch-php2shell.conf
  APACHECTL=apachectl
fi
HAS_MOD_PHP=0
for so in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so; do
  [ -e "$so" ] && HAS_MOD_PHP=1
done

pkgs() {  # installed PHP-related packages, "name version" sorted
  if [ "$FAMILY" = debian ]; then
    dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null | awk '$1 ~ /^ii/ {print $2, $3}' | sort
  else
    rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 'php*' | sort
  fi
}
etc_sum() { find /etc -xdev -type f -print0 2>/dev/null | sort -z | xargs -0 md5sum 2>/dev/null | md5sum | cut -d' ' -f1; }
modules() { php -m 2>/dev/null | grep -v '^\[' | grep -v '^$' | sort -u; }
upload_progress() { php -i 2>/dev/null | awk -F' => ' '/^session.upload_progress.enabled/ {print $2; exit}'; }
run_dir_of() { json_field "$1" run_dir; }
fpm_field() {  # fpm_field JSON FIELD -- a field of the PHP-FPM runtime in a report
  grep -o '{"path":"[^"]*","sapi":"fpm-fcgi"[^}]*' "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | cut -d'"' -f4
}

# A PHP-FPM master that runs with its own configuration file (-y). php-safepatch must find this
# file from the running process, and must not use the package default.
CUSTOM=/etc/php-custom
POOL_DIR="$CUSTOM/pool.d"
fpm_start() { "$FPM" -y "$CUSTOM/php-fpm.conf" && sleep 1 && [ -s /run/php-custom-fpm.pid ]; }
fpm_stop() { [ -s /run/php-custom-fpm.pid ] && kill "$(cat /run/php-custom-fpm.pid)" 2>/dev/null; sleep 2; }
fpm_restart() { fpm_stop; fpm_start; }
# A second master from the same binary with another configuration: a runtime of its own.
CUSTOM2=/etc/php-custom2
fpm2_start() { "$FPM" -y "$CUSTOM2/php-fpm.conf" && sleep 1 && [ -s /run/php-custom2-fpm.pid ]; }
fpm2_stop() { [ -s /run/php-custom2-fpm.pid ] && kill "$(cat /run/php-custom2-fpm.pid)" 2>/dev/null; sleep 2; }
fpm2_restart() { fpm2_stop; fpm2_start; }
conf_field() {  # conf_field JSON FPM_CONF FIELD -- a field of the PHP-FPM runtime that uses FPM_CONF
  grep -o "{\"path\":\"[^\"]*\",\"sapi\":\"fpm-fcgi\"[^}]*\"fpm_conf\":\"$2\"" "$1" | grep -o "\"$3\":\"[^\"]*\"" | head -1 | cut -d'"' -f4
}
if [ -n "$FPM" ]; then
  mkdir -p "$POOL_DIR" "$CUSTOM2/pool.d"
  printf '[global]\npid = /run/php-custom-fpm.pid\nerror_log = /tmp/php-custom-fpm.log\ndaemonize = yes\ninclude = %s/*.conf\n' "$POOL_DIR" >"$CUSTOM/php-fpm.conf"
  printf '[custom]\nuser = daemon\nlisten = 127.0.0.1:9901\npm = static\npm.max_children = 1\n' >"$POOL_DIR/custom.conf"
  printf '[global]\npid = /run/php-custom2-fpm.pid\nerror_log = /tmp/php-custom2-fpm.log\ndaemonize = yes\ninclude = %s/pool.d/*.conf\n' "$CUSTOM2" >"$CUSTOM2/php-fpm.conf"
  printf '[second]\nuser = daemon\nlisten = 127.0.0.1:9902\npm = static\npm.max_children = 1\n' >"$CUSTOM2/pool.d/second.conf"
fi

printf 'php-safepatch container test: family=%s branch=%s fpm=%s mod_php=%s\n' "$FAMILY" "$BRANCH" "${FPM:-none}" "$HAS_MOD_PHP"
php -v | head -1
pkgs >"$W/pkgs.0"; modules >"$W/mods.0"; VER0="$(php -r 'echo PHP_VERSION;')"
[ -n "$FPM" ] && { fpm_start && pass "PHP-FPM runs with -y $CUSTOM/php-fpm.conf" || fail "PHP-FPM with -y $CUSTOM/php-fpm.conf does not start"; }
[ -n "$FPM" ] && { fpm2_start && pass "second PHP-FPM (same binary) runs with -y $CUSTOM2/php-fpm.conf" || fail "second PHP-FPM does not start"; }

# ---------------------------------------------------------------------------
section "1. scan makes no change and finds the real service configuration"
SUM0="$(etc_sum)"
bash "$S" scan "${COMMON[@]}" --json "$W/scan.json" >"$W/scan.out" 2>&1; rc=$?
check_in "scan exit code is 0 or 1" "$rc" 0 1
check_eq "scan does not change /etc" "$SUM0" "$(etc_sum)"
check "scan JSON lists at least one runtime" grep -q '"runtimes":\[{' "$W/scan.json"
grep -q '"sapi":"fpm-fcgi"' "$W/scan.json" && pass "scan finds PHP-FPM" || fail "scan finds PHP-FPM"
if [ "$HAS_MOD_PHP" -eq 1 ]; then
  grep -q '"sapi":"apache2handler"' "$W/scan.json" && pass "scan finds mod_php" || fail "scan finds mod_php"
fi
if [ -n "$FPM" ]; then
  check_eq "PHP-FPM is running" yes "$(fpm_field "$W/scan.json" running)"
  check_eq "PHP-FPM config is the one of the running master (-y)" "$CUSTOM/php-fpm.conf" "$(fpm_field "$W/scan.json" fpm_conf)"
  check_eq "the second master is a runtime of its own" yes "$(conf_field "$W/scan.json" "$CUSTOM2/php-fpm.conf" running)"
fi
STATUS0="$(grep -o '"status":"[A-Z_]*"' "$W/scan.json" | head -1 | cut -d'"' -f4)"
printf 'info  status before apply: %s\n' "$STATUS0"
sed -n '/^STATUS/,/^$/p' "$W/scan.out"

# ---------------------------------------------------------------------------
section "2. apply (patch only) stays in branch $BRANCH; a running old process is RESTART_REQUIRED"
bash "$S" apply "${COMMON[@]}" --yes --mitigate never --json "$W/patch.json" >"$W/patch.out" 2>&1; rc=$?
check_in "apply exit code is 0 or 1" "$rc" 0 1
RUN_P="$(run_dir_of "$W/patch.json")"
pkgs >"$W/pkgs.1"; modules >"$W/mods.1"
check_eq "PHP branch unchanged" "$BRANCH" "$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
NEW_PKGS="$(comm -13 <(cut -d' ' -f1 "$W/pkgs.0") <(cut -d' ' -f1 "$W/pkgs.1") | tr '\n' ' ')"
OTHER_BRANCH="$(cut -d' ' -f1 "$W/pkgs.1" | grep -E '^(php|libapache2-mod-php|libphp)[0-9]+\.[0-9]+' | grep -v -E "^(php|libapache2-mod-php|libphp)${BRANCH//./\\.}" | tr '\n' ' ')"
check_eq "no package of another branch installed" "" "${OTHER_BRANCH% }"
if [ "$FAMILY" = debian ]; then
  META="$(printf '%s\n' $NEW_PKGS | grep -E '^php(-cli|-fpm|-common)?$' | tr '\n' ' ')"
  check_eq "no default-branch metapackage newly installed" "" "${META% }"
fi
MISSING="$(comm -23 "$W/mods.0" "$W/mods.1" | tr '\n' ' ')"
check_eq "no extension lost" "" "${MISSING% }"
if [ -s "$RUN_P/packages.before" ]; then
  pass "packages upgraded and previous versions recorded ($(wc -l <"$RUN_P/packages.before") packages)"
  printf 'info  %s -> %s\n' "$VER0" "$(php -r 'echo PHP_VERSION;')"
  if [ -n "$FPM" ]; then
    # No systemd in the container, so php-safepatch cannot restart PHP-FPM: the old code still runs.
    check_eq "binary on disk is PATCHED" PATCHED "$(fpm_field "$W/patch.json" installed)"
    check_eq "running master uses the replaced binary (running=stale)" stale "$(fpm_field "$W/patch.json" running)"
    check_eq "status is RESTART_REQUIRED, not PATCHED" RESTART_REQUIRED "$(fpm_field "$W/patch.json" status)"
    check_eq "second master is RESTART_REQUIRED too" RESTART_REQUIRED "$(conf_field "$W/patch.json" "$CUSTOM2/php-fpm.conf" status)"
    fpm_restart
    bash "$S" scan "${COMMON[@]}" --json "$W/scan2.json" >/dev/null 2>&1
    check_eq "after the restart: status PATCHED" PATCHED "$(conf_field "$W/scan2.json" "$CUSTOM/php-fpm.conf" status)"
    check_eq "after the restart: running=yes" yes "$(conf_field "$W/scan2.json" "$CUSTOM/php-fpm.conf" running)"
    check_eq "the master that was not restarted stays RESTART_REQUIRED" RESTART_REQUIRED "$(conf_field "$W/scan2.json" "$CUSTOM2/php-fpm.conf" status)"
    fpm2_restart
  fi
else
  skip "no newer package in the repositories (already patched, or vendor fix not published yet)"
fi

# ---------------------------------------------------------------------------
section "3. mitigation (--no-patch --mitigate always) reaches the configuration in use"
bash "$S" apply "${COMMON[@]}" --yes --no-patch --mitigate always --json "$W/mit.json" >"$W/mit.out" 2>&1; rc=$?
check_in "apply exit code is 0 or 1" "$rc" 0 1
RUN_M="$(run_dir_of "$W/mit.json")"
for d in "${INI_DIRS[@]}"; do
  [ -d "$d" ] || continue
  check "mitigation ini in $d" test -f "$d/99-php-safepatch-php2shell.ini"
done
check_eq "CLI sees session.upload_progress.enabled = Off" "Off" "$(upload_progress)"
if [ -n "$FPM" ]; then
  check "php-fpm config test passes for the running configuration" "$FPM" -t -y "$CUSTOM/php-fpm.conf"
  check "the pool of the running master carries the admin-locked block" grep -q 'php_admin_value\[session.upload_progress.enabled\] = 0' "$POOL_DIR/custom.conf"
  check "the pool of the second master carries the block too" grep -q 'php_admin_value\[session.upload_progress.enabled\] = 0' "$CUSTOM2/pool.d/second.conf"
  check_eq "running master started before the change: mitigation=pending_restart" pending_restart "$(conf_field "$W/mit.json" "$CUSTOM/php-fpm.conf" mitigation)"
  fpm_restart; fpm2_restart
  bash "$S" scan "${COMMON[@]}" --json "$W/scan3.json" >/dev/null 2>&1
  check_eq "after the restart: mitigation=effective" effective "$(conf_field "$W/scan3.json" "$CUSTOM/php-fpm.conf" mitigation)"
  check_eq "second master: mitigation=effective" effective "$(conf_field "$W/scan3.json" "$CUSTOM2/php-fpm.conf" mitigation)"
  # A later pool line that sets the value back must not count as mitigated.
  cp "$CUSTOM2/pool.d/second.conf" "$W/second.orig"
  printf 'php_admin_flag[session.upload_progress.enabled] = on\n' >>"$CUSTOM2/pool.d/second.conf"
  bash "$S" scan "${COMMON[@]}" --json "$W/scan4.json" >/dev/null 2>&1
  check_eq "a pool that sets the value back: mitigation=not_effective" not_effective "$(conf_field "$W/scan4.json" "$CUSTOM2/php-fpm.conf" mitigation)"
  cp "$W/second.orig" "$CUSTOM2/pool.d/second.conf"
fi
if [ "$HAS_MOD_PHP" -eq 1 ]; then
  check "Apache mitigation config exists" test -f "$APACHE_CONF"
  check "Apache config test passes" "$APACHECTL" -t
fi

# ---------------------------------------------------------------------------
section "4. idempotency"
SUM1="$(etc_sum)"
bash "$S" apply "${COMMON[@]}" --yes --no-patch --mitigate always --json "$W/mit2.json" >/dev/null 2>&1
check_eq "second identical apply does not change /etc" "$SUM1" "$(etc_sum)"
check "second run has an empty manifest" test ! -s "$(run_dir_of "$W/mit2.json")/manifest"

# ---------------------------------------------------------------------------
section "5. rollback"
bash "$S" rollback --run-id "$(basename "$RUN_M")" --yes --no-restart >"$W/rb-m.out" 2>&1
check "rollback of the mitigation run succeeds" test $? -eq 0
for d in "${INI_DIRS[@]}"; do
  [ -d "$d" ] || continue
  check "mitigation ini removed from $d" test ! -f "$d/99-php-safepatch-php2shell.ini"
done
[ -n "$FPM" ] && check "FPM pool blocks removed (both masters)" bash -c "! grep -q 'php-safepatch PHP2Shell' $POOL_DIR/*.conf $CUSTOM2/pool.d/*.conf"
check_eq "CLI value back to On" "On" "$(upload_progress)"
if [ "$HAS_MOD_PHP" -eq 1 ]; then
  check "Apache mitigation config removed" test ! -e "$APACHE_CONF"
  [ "$FAMILY" = debian ] && check "Apache conf-enabled link removed" test ! -e /etc/apache2/conf-enabled/php-safepatch-php2shell.conf
  check "Apache config test passes after rollback" "$APACHECTL" -t
fi
if [ -s "$RUN_P/packages.before" ]; then
  bash "$S" rollback --run-id "$(basename "$RUN_P")" --yes --no-restart >"$W/rb-p.out" 2>&1; rc=$?
  if [ "$rc" -eq 0 ] && [ "$(php -r 'echo PHP_VERSION;')" = "$VER0" ]; then
    pass "package rollback restores PHP $VER0"
  elif [ "$FAMILY" = rhel ]; then
    twarn "package rollback did not restore $VER0 (old RPMs are often gone from the repository)"
  else
    fail "package rollback restores PHP $VER0 (rc=$rc, now $(php -r 'echo PHP_VERSION;'))"
  fi
  [ -n "$FPM" ] && { fpm_restart; fpm2_restart; }
else
  skip "package rollback (no packages were upgraded)"
fi

# ---------------------------------------------------------------------------
section "6. a PHP-FPM config that is already broken is not touched"
if [ -n "$FPM" ]; then
  POOL="$POOL_DIR/custom.conf"
  cp "$POOL" "$W/pool.orig"
  printf 'pm = not-a-valid-mode\n' >>"$POOL"           # makes "php-fpm -t" fail
  cp "$POOL" "$W/pool.broken"
  bash "$S" apply "${COMMON[@]}" --yes --no-patch --mitigate always >"$W/broken.out" 2>&1; rc=$?
  check_eq "apply reports an error" 2 "$rc"
  check "error says the test fails before any change" grep -q 'Config test fails before any change' "$W/broken.out"
  check "pool file unchanged" same_file "$POOL" "$W/pool.broken"
  for d in "${INI_DIRS[@]}"; do
    [ -d "$d" ] || continue
    check "no ini written to $d" test ! -f "$d/99-php-safepatch-php2shell.ini"
  done
  cp "$W/pool.orig" "$POOL"
  fpm_stop; fpm2_stop
else
  skip "no PHP-FPM in this image"
fi

summary
