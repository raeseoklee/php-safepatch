#!/usr/bin/env bash
# Only for the disposable guest created by run-rocky9.sh.
set -euo pipefail
test "$(systemd-detect-virt)" = kvm
test -f /run/phpdoctor-disposable-vm
SRC=/root/phpdoctor
W=/root/vm-results
mkdir -p "$W"
source "$SRC/tests/lib/assert.sh"
S="$SRC/linux/php-safepatch.sh"
sha256sum "$S" "$SRC/advisories/php2shell.conf" "$SRC/tests/vm/rocky9-cases.sh" >"$W/source-sha256.txt"
exec > >(tee "$W/guest.log") 2>&1
cat /etc/os-release
uname -a
systemd-detect-virt
test "$(ps -p 1 -o comm=)" = systemd

section 'Install actual old, signed PHP 8.2.25 packages from the Rocky 9.5 vault'
cat >/etc/yum.repos.d/phpdoctor-vault.repo <<'EOF'
[phpdoctor-vault-base]
name=PHPDoctor test fixture Rocky 9.5 BaseOS
baseurl=https://dl.rockylinux.org/vault/rocky/9.5/BaseOS/x86_64/os/
enabled=0
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
[phpdoctor-vault-app]
name=PHPDoctor test fixture Rocky 9.5 AppStream
baseurl=https://dl.rockylinux.org/vault/rocky/9.5/AppStream/x86_64/os/
enabled=0
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
EOF
dnf -y -q install nginx curl python3 diffutils policycoreutils-python-utils
OLD=(dnf -y --disablerepo='*' '--enablerepo=phpdoctor-vault-base,phpdoctor-vault-app')
"${OLD[@]}" module enable php:8.2
"${OLD[@]}" install php-cli-8.2.25 php-fpm-8.2.25 php-mbstring-8.2.25
old="$(php -r 'echo PHP_VERSION;')"
rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 'php*' | sort | tee "$W/packages.before.txt"
test "$old" = 8.2.25
php -m | sort >"$W/modules.before.txt"

section 'Start two real systemd PHP-FPM services and HTTP health endpoints'
mkdir -p /etc/phpdoctor-extra/pool.d
cat >/etc/phpdoctor-extra/php-fpm.conf <<'EOF'
[global]
pid=/run/php-fpm/phpdoctor-extra.pid
error_log=/var/log/php-fpm/phpdoctor-extra.log
include=/etc/phpdoctor-extra/pool.d/*.conf
EOF
cat >/etc/phpdoctor-extra/pool.d/extra.conf <<'EOF'
[extra]
user=apache
group=apache
listen=/run/php-fpm/phpdoctor-extra.sock
listen.acl_users=nginx
pm=static
pm.max_children=1
EOF
cat >/etc/systemd/system/phpdoctor-extra.service <<'EOF'
[Unit]
Description=PHPDoctor real second PHP-FPM service
After=network.target php-fpm.service
[Service]
Type=simple
ExecStart=/usr/sbin/php-fpm -F -y /etc/phpdoctor-extra/php-fpm.conf
[Install]
WantedBy=multi-user.target
EOF
cat >/usr/share/nginx/html/health.php <<'EOF'
<?php
if (file_exists('/run/phpdoctor-fail-on-mitigation') && !ini_get('session.upload_progress.enabled')) {
    http_response_code(500);
}
header('Content-Type: application/json');
echo json_encode(['version'=>PHP_VERSION, 'progress'=>ini_get('session.upload_progress.enabled'), 'pid'=>getmypid()]);
EOF
for port in 8080 8081; do
  sock=/run/php-fpm/www.sock
  [ "$port" = 8080 ] || sock=/run/php-fpm/phpdoctor-extra.sock
  cat >"/etc/nginx/conf.d/phpdoctor-$port.conf" <<EOF
server {
 listen $port;
 server_name localhost;
 root /usr/share/nginx/html;
 location = /health.php {
  include fastcgi_params;
  fastcgi_param SCRIPT_FILENAME /usr/share/nginx/html/health.php;
  fastcgi_pass unix:$sock;
 }
}
EOF
done
restorecon -RF /etc/phpdoctor-extra /usr/share/nginx/html
# Keep SELinux enforcing; label the two fixture HTTP ports explicitly.
for port in 8080 8081; do
  semanage port -a -t http_port_t -p tcp "$port" 2>/dev/null \
    || semanage port -m -t http_port_t -p tcp "$port"
done
getenforce | tee "$W/selinux.txt"
systemctl daemon-reload
systemctl start php-fpm phpdoctor-extra nginx
check 'first FPM is active under systemd' systemctl is-active --quiet php-fpm
check 'second FPM is active under systemd' systemctl is-active --quiet phpdoctor-extra
for port in 8080 8081; do curl -fsS "http://127.0.0.1:$port/health.php" | tee "$W/health-$port.before.json"; echo; done
common=(--yes --no-docker --no-ioc --quiet --advisory "$SRC/advisories/php2shell.conf"
  --health-url http://127.0.0.1:8080/health.php --health-url http://127.0.0.1:8081/health.php)
run_apply() {
  local rc
  set +e
  bash "$S" apply "${common[@]}" "$@"
  rc=$?
  set -e
  return "$rc"
}
pid_a="$(systemctl show -p MainPID --value php-fpm)"
pid_b="$(systemctl show -p MainPID --value phpdoctor-extra)"

section 'Actual dnf transaction, old PHP -> current fixed PHP, without a branch change'
run_apply --mitigate never --json "$W/patch.json" >"$W/patch.log" 2>&1 && rc=0 || rc=$?
check_eq 'real package update and health verification exit 0' 0 "$rc"
new="$(php -r 'echo PHP_VERSION;')"
check_eq 'PHP branch remains 8.2' 8.2 "${new%.*}"
check 'PHP version increased' test "$old" != "$new"
check 'actual dnf upgrade was recorded' grep -q 'packages:php8.2' "$W/patch.json"
check 'first service restarted by the tool' test "$pid_a" != "$(systemctl show -p MainPID --value php-fpm)"
check 'second service restarted by the tool' test "$pid_b" != "$(systemctl show -p MainPID --value phpdoctor-extra)"
check 'both FPM runtimes are patched and no stale process remains' python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); f=[x for x in r["runtimes"] if x["sapi"]=="fpm-fcgi"]; assert len(f)==2 and all(x["status"]=="PATCHED" and x["running"]=="yes" for x in f)' "$W/patch.json"
php -m | sort >"$W/modules.after.txt"
check 'extensions preserved' cmp "$W/modules.before.txt" "$W/modules.after.txt"
rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 'php*' | sort >"$W/packages.after.txt"
dnf history info last >"$W/dnf-transaction.txt"
systemctl show php-fpm phpdoctor-extra -p MainPID -p ExecStart -p ActiveState >"$W/services.after-patch.txt"

section 'Real mitigation restart and values returned by both web SAPIs'
pid_a="$(systemctl show -p MainPID --value php-fpm)"
pid_b="$(systemctl show -p MainPID --value phpdoctor-extra)"
run_apply --no-patch --mitigate always --json "$W/mitigation.json" >"$W/mitigation.log" 2>&1 && rc=0 || rc=$?
check_eq 'mitigation apply exit 0' 0 "$rc"
check 'first service restarted for mitigation' test "$pid_a" != "$(systemctl show -p MainPID --value php-fpm)"
check 'second service restarted for mitigation' test "$pid_b" != "$(systemctl show -p MainPID --value phpdoctor-extra)"
for port in 8080 8081; do
  curl -fsS "http://127.0.0.1:$port/health.php" >"$W/health-$port.mitigated.json"
  check "web SAPI $port actually uses mitigation" python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["progress"] in ("", "0")' "$W/health-$port.mitigated.json"
done
run_apply --no-patch --json "$W/cleanup.json" >"$W/cleanup.log" 2>&1 && rc=0 || rc=$?
check_eq 'auto cleanup exit 0' 0 "$rc"
# The report and the files must both show that every mitigation is gone.
no_mitigation() {  # no_mitigation REPORT -- every runtime has mitigation=none, and no file carries it
  python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["runtimes"] and all(x["mitigation"]=="none" for x in r["runtimes"])' "$1" \
    && [ ! -e /etc/php.d/99-php-safepatch-php2shell.ini ] \
    && ! grep -q 'php-safepatch PHP2Shell' /etc/php-fpm.d/*.conf /etc/phpdoctor-extra/pool.d/*.conf
}
check 'cleanup: every runtime reports mitigation=none and no mitigation file remains' no_mitigation "$W/cleanup.json"
check 'cleanup: the report lists the removed ini and both pool files' python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["changes"]; assert "removed:/etc/php.d/99-php-safepatch-php2shell.ini" in c and "removed:fpm-pool:/etc/php-fpm.d/www.conf" in c and "removed:fpm-pool:/etc/phpdoctor-extra/pool.d/extra.conf" in c' "$W/cleanup.json"
for port in 8080 8081; do
  curl -fsS "http://127.0.0.1:$port/health.php" >"$W/health-$port.cleanup.json"
  check "cleanup: web SAPI $port reads the original value again" python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["progress"]=="1"' "$W/health-$port.cleanup.json"
done

section 'HTTP failure triggers actual file restore and systemd recovery'
touch /run/phpdoctor-fail-on-mitigation
run_apply --no-patch --mitigate always --json "$W/rollback.json" >"$W/rollback.log" 2>&1 && rc=0 || rc=$?
check_eq 'health regression causes exit 2' 2 "$rc"
check 'verification rollback was recorded' grep -q 'Verification failed' "$W/rollback.log"
for port in 8080 8081; do
  check "health $port returns 200 after automatic restore" curl -fsS "http://127.0.0.1:$port/health.php"
  curl -fsS "http://127.0.0.1:$port/health.php" >"$W/health-$port.restored.json"
  check "restore: web SAPI $port reads the original value again" python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["progress"]=="1"' "$W/health-$port.restored.json"
done
check 'restore: every runtime reports mitigation=none and no mitigation file remains' no_mitigation "$W/rollback.json"
check 'restore: the files were written first, then restored' python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["changes"]; assert "ini:/etc/php.d/99-php-safepatch-php2shell.ini" in c and "fpm-pool:/etc/phpdoctor-extra/pool.d/extra.conf" in c' "$W/rollback.json"
check 'FPM still active after rollback' systemctl is-active --quiet php-fpm
check 'second FPM still active after rollback' systemctl is-active --quiet phpdoctor-extra
journalctl -u php-fpm -u phpdoctor-extra -u nginx --no-pager >"$W/service-journal.txt"
summary
