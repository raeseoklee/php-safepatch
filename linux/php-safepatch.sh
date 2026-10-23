#!/usr/bin/env bash
# php-safepatch - find PHP runtimes, check them against an advisory (default: PHP2Shell,
# CVE-2026-109618 / CVE-2026-109619), and fix them without changing the PHP minor branch.
#
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 php-safepatch contributors

set -uo pipefail
umask 077

SAFEPATCH_VERSION="0.1.0"

# ---------------------------------------------------------------------------
# Advisory defaults (override with --advisory FILE)
# ---------------------------------------------------------------------------
ADV_ID="PHP2Shell"
ADV_CVES="CVE-2026-109618 CVE-2026-109619"
ADV_FIXED="8.2.35 8.3.36 8.4.27 8.5.12"
ADV_EOL_BACKPORT="7.4 8.0 8.1"
ADV_IOC_SINCE="2026-10-17"
# Mitigation rules: "ini.key=value" or "ini.key=value@MIN_BRANCH" (applied only on MIN_BRANCH and newer).
ADV_MITIGATE=("session.upload_progress.enabled=0" "fatal_error_backtraces=0@8.5")
# Opt-in rules: applied only with --include-optin, because they can change application behavior.
ADV_MITIGATE_OPTIN=("memory_limit=-1")
# Log indicators: "label|extended regex". The first "|" separates the label from the regex.
ADV_IOC_LOG=(
  "pre-script memory exhaustion errors ('in Unknown on line 0')|Allowed memory size of [0-9]+ bytes exhausted.* in Unknown on line 0"
  "worker segmentation faults|Segmentation fault|SIGSEGV|exited on signal 11"
)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
CMD=""
OPT_JSON=""
OPT_YES=0
OPT_MITIGATE="auto"        # auto | always | never
OPT_OPTIN=0
OPT_NO_RESTART=0
OPT_NO_PATCH=0
OPT_NO_IOC=0
OPT_FIX_DOCKERFILES=0
OPT_NO_DOCKER=0
OPT_RUN_ID=""
OPT_STATE_DIR="/var/lib/php-safepatch"
OPT_ADVISORY=""
OPT_QUIET=0
HEALTH_URLS=()
DOCKERFILE_DIRS=()
WEB_ROOTS=()
EXTRA_PHP=()

# ---------------------------------------------------------------------------
# Runtime table. One index per runtime.
# ---------------------------------------------------------------------------
RT_PATH=(); RT_SAPI=(); RT_VERSION=(); RT_BRANCH=(); RT_PKGMGR=(); RT_PKG=(); RT_PKGVER=()
RT_STATUS=(); RT_REASON=(); RT_ACTION=(); RT_CONTAINER=(); RT_IMAGE=()
# Separate facts per runtime: the binary on disk, the running processes, and the mitigation.
RT_INSTALLED=(); RT_RUNNING=(); RT_MITIG=()
# Service configuration actually used (PHP-FPM -y, -c and PHP_INI_SCAN_DIR from the service).
RT_FPMCONF=(); RT_INI=(); RT_SCANENV=()
DF_FILE=(); DF_LINE=(); DF_TAG=(); DF_STATUS=(); DF_FIX=()
IOC_LINES=()
ACTIONS_DONE=()
ERRORS=()

OS_ID=""; OS_LIKE=""; OS_FAMILY="unknown"
RUN_DIR=""; LOG_FILE=""
HAVE_TIMEOUT=0

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
_log_line() { [ -n "$LOG_FILE" ] && printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$*" >>"$LOG_FILE"; return 0; }
info() { _log_line "INFO $*"; [ "$OPT_QUIET" -eq 1 ] || printf '[php-safepatch] %s\n' "$*" >&2; }
warn() { _log_line "WARN $*"; printf '[php-safepatch] WARNING: %s\n' "$*" >&2; }
err()  { _log_line "ERROR $*"; ERRORS+=("$*"); printf '[php-safepatch] ERROR: %s\n' "$*" >&2; }
die()  { err "$*"; exit 2; }

usage() {
  cat <<'EOF'
Usage: php-safepatch.sh <command> [options]

Commands:
  scan        Find PHP runtimes and report their status. Makes no changes.
  apply       Scan, then patch inside the same minor branch and apply mitigations.
  rollback    Restore the files and packages that a previous run changed.
  version     Show the php-safepatch version.

Options:
  --json FILE             Write the JSON report to FILE ("-" for stdout).
  --yes                   Do not ask for confirmation (apply, rollback).
  --mitigate MODE         auto (default): mitigate only runtimes that stay vulnerable.
                          always: mitigate all affected branches. never: do not mitigate.
  --include-optin         Also apply the advisory's opt-in mitigations (for PHP2Shell:
                          memory_limit=-1, admin-locked). These can change application behavior.
  --no-patch              Do not install packages. Only mitigate.
  --no-restart            Do not restart services. Report that a restart is necessary.
  --health-url URL        Check this URL before and after changes (repeatable).
  --dockerfiles DIR       Scan Dockerfiles under DIR (repeatable).
  --fix-dockerfiles       With apply: change pinned "FROM php:X.Y.Z" tags to the fixed patch release.
  --no-docker             Do not inspect running Docker containers.
  --web-root DIR          Add a web root for indicator checks (repeatable).
  --no-ioc                Skip the indicator-of-compromise checks.
  --php PATH              Add a PHP binary that discovery does not find (repeatable).
  --advisory FILE         Load the advisory from FILE (key=value format).
  --state-dir DIR         Directory for logs, reports and backups (default /var/lib/php-safepatch).
  --run-id ID             With rollback: the run to roll back (default: the latest apply run).
  --quiet                 Print only warnings, errors and the final report.
  -h, --help              Show this help.

Exit codes: 0 = no vulnerable runtime and no indicator, 1 = vulnerable runtime or
indicator found, 2 = error.
EOF
}

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

run_t() {  # run_t SECONDS cmd args... -- run with a timeout when possible
  local secs="$1"; shift
  if [ "$HAVE_TIMEOUT" -eq 1 ]; then timeout "$secs" "$@"; else "$@"; fi
}

# ver_cmp A B -> prints -1, 0 or 1. Compares dot-separated numeric parts.
ver_cmp() {
  local a="$1" b="$2" i x y
  local -a pa pb
  IFS=. read -r -a pa <<<"$a"
  IFS=. read -r -a pb <<<"$b"
  for ((i = 0; i < 4; i++)); do
    x="${pa[i]:-0}"; y="${pb[i]:-0}"
    x="${x%%[!0-9]*}"; y="${y%%[!0-9]*}"
    x="${x:-0}"; y="${y:-0}"
    if ((10#$x < 10#$y)); then echo -1; return; fi
    if ((10#$x > 10#$y)); then echo 1; return; fi
  done
  echo 0
}
ver_ge() { [ "$(ver_cmp "$1" "$2")" -ge 0 ]; }

branch_of() { local v="$1"; printf '%s' "${v%.*}"; }  # 8.2.10 -> 8.2

fixed_for_branch() {  # prints the fixed version for a branch, or nothing
  local b="$1" f
  for f in $ADV_FIXED; do
    [ "$(branch_of "$f")" = "$b" ] && { printf '%s' "$f"; return 0; }
  done
  return 1
}

newest_fixed_branch() {  # lowest branch in ADV_FIXED
  local f low=""
  for f in $ADV_FIXED; do
    if [ -z "$low" ] || [ "$(ver_cmp "$(branch_of "$f")" "$low")" -lt 0 ]; then low="$(branch_of "$f")"; fi
  done
  printf '%s' "$low"
}

in_list() { local x="$1" e; shift; for e in "$@"; do [ "$e" = "$x" ] && return 0; done; return 1; }

json_str() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
  s="$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')"
  printf '"%s"' "$s"
}

sanitize() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }

load_advisory() {  # an external advisory starts empty: nothing is inherited from the built-in PHP2Shell data
  local f="$1" k v n=0 bad=0 x
  [ -r "$f" ] || die "Cannot read advisory file: $f"
  ADV_ID=""; ADV_CVES=""; ADV_FIXED=""; ADV_EOL_BACKPORT=""; ADV_IOC_SINCE=""
  ADV_MITIGATE=(); ADV_MITIGATE_OPTIN=(); ADV_IOC_LOG=()
  while IFS= read -r x || [ -n "$x" ]; do
    n=$((n + 1)); x="${x%$'\r'}"
    case "$x" in ''|'#'*) continue ;; esac
    k="${x%%=*}"; v="${x#*=}"; k="${k//[[:space:]]/}"
    if [ "$k" = "$x" ]; then err "$f:$n: not key=value"; bad=1; continue; fi
    case "$k" in
      id) ADV_ID="$v" ;;
      cves) ADV_CVES="$v" ;;
      fixed) ADV_FIXED="$v" ;;
      eol_backport) ADV_EOL_BACKPORT="$v" ;;
      ioc_since) ADV_IOC_SINCE="$v" ;;
      mitigate) ADV_MITIGATE+=("$v") ;;
      mitigate_optin) ADV_MITIGATE_OPTIN+=("$v") ;;
      ioc_log) ADV_IOC_LOG+=("$v") ;;
      *) err "$f:$n: unknown key '$k'"; bad=1 ;;
    esac
  done <"$f"
  # Validate. A wrong advisory must stop the run, not change servers in an unexpected way.
  [[ "$ADV_ID" =~ ^[A-Za-z0-9._-]+$ ]] || { err "$f: 'id' is missing or has characters other than A-Z a-z 0-9 . _ -"; bad=1; }
  [ -n "${ADV_CVES// /}" ] || { err "$f: 'cves' is missing"; bad=1; }
  [ -n "${ADV_FIXED// /}" ] || { err "$f: 'fixed' is missing"; bad=1; }
  for x in $ADV_FIXED; do [[ "$x" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { err "$f: 'fixed' value '$x' is not X.Y.Z"; bad=1; }; done
  for x in $ADV_EOL_BACKPORT; do [[ "$x" =~ ^[0-9]+\.[0-9]+$ ]] || { err "$f: 'eol_backport' value '$x' is not X.Y"; bad=1; }; done
  [ -z "$ADV_IOC_SINCE" ] || [[ "$ADV_IOC_SINCE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { err "$f: 'ioc_since' is not YYYY-MM-DD"; bad=1; }
  for x in ${ADV_MITIGATE[@]+"${ADV_MITIGATE[@]}"} ${ADV_MITIGATE_OPTIN[@]+"${ADV_MITIGATE_OPTIN[@]}"}; do
    [[ "$x" =~ ^[A-Za-z0-9_.]+=[^@]*(@[0-9]+\.[0-9]+)?$ ]] || { err "$f: mitigation rule '$x' is not KEY=VALUE[@X.Y]"; bad=1; }
  done
  for x in ${ADV_IOC_LOG[@]+"${ADV_IOC_LOG[@]}"}; do
    [[ "$x" == ?*'|'?* ]] || { err "$f: ioc_log '$x' is not LABEL|REGEX"; bad=1; }
  done
  [ "$bad" -eq 0 ] || die "Advisory file $f is not valid. No change was made."
}

# mitigation_rules BRANCH -> "key value" lines that apply to BRANCH
mitigation_rules() {
  local b="$1" r kv minb
  local rules=("${ADV_MITIGATE[@]}")
  [ "$OPT_OPTIN" -eq 1 ] && rules+=("${ADV_MITIGATE_OPTIN[@]}")
  for r in "${rules[@]}"; do
    kv="${r%@*}"; minb=""
    [ "$kv" != "$r" ] && minb="${r##*@}"
    [ -n "$minb" ] && [ "$(ver_cmp "$b" "$minb")" -lt 0 ] && continue
    printf '%s %s\n' "${kv%%=*}" "${kv#*=}"
  done
}

detect_os() {
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    OS_ID="$(. /etc/os-release; printf '%s' "${ID:-}")"
    OS_LIKE="$(. /etc/os-release; printf '%s' "${ID_LIKE:-}")"
  fi
  # Synology DSM is out of scope: Web Station rewrites the PHP configuration and only Package
  # Center may update the PHP packages. Stop before anything is read or changed.
  local dsm="${PHP_SAFEPATCH_TEST_DSM_FILE:-/etc.defaults/VERSION}"
  if [ -r "$dsm" ] && grep -qi 'productversion' "$dsm" 2>/dev/null; then
    die "Synology DSM is not supported. Update the PHP packages in Package Center. No change was made."
  fi
  case " $OS_ID $OS_LIKE " in
    *" debian "*|*" ubuntu "*) OS_FAMILY="debian" ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*|*" amzn "*) OS_FAMILY="rhel" ;;
    *) if have dpkg-query; then OS_FAMILY="debian"; elif have rpm; then OS_FAMILY="rhel"; fi ;;
  esac
}

# ---------------------------------------------------------------------------
# Run directory, backups and manifest
# ---------------------------------------------------------------------------
init_run_dir() {
  local id="$1"
  RUN_DIR="$OPT_STATE_DIR/$id"
  mkdir -p "$RUN_DIR/backup" "$RUN_DIR/modules" 2>/dev/null || {
    RUN_DIR=""; warn "Cannot create $OPT_STATE_DIR/$id. Continuing without a run directory."; return 1; }
  LOG_FILE="$RUN_DIR/php-safepatch.log"
  : >"$RUN_DIR/manifest"
  printf '%s\n' "$CMD" >"$RUN_DIR/command"
  return 0
}

backup_file() {  # backup_file PATH -- call before any change to PATH
  local p="$1"
  [ -n "$RUN_DIR" ] || die "No run directory. Refusing to change $p without a backup."
  grep -qxF "MODIFIED $p" "$RUN_DIR/manifest" 2>/dev/null && return 0
  grep -qxF "CREATED $p" "$RUN_DIR/manifest" 2>/dev/null && return 0
  if [ -e "$p" ] || [ -L "$p" ]; then
    mkdir -p "$RUN_DIR/backup$(dirname "$p")"
    cp -a "$p" "$RUN_DIR/backup$p" || die "Backup failed for $p"
    printf 'MODIFIED %s\n' "$p" >>"$RUN_DIR/manifest"
  else
    printf 'CREATED %s\n' "$p" >>"$RUN_DIR/manifest"
  fi
}

restore_files() {  # restore_files RUN_DIR
  local rd="$1" kind p
  [ -r "$rd/manifest" ] || return 0
  while read -r kind p; do
    case "$kind" in
      MODIFIED) cp -a "$rd/backup$p" "$p" && info "Restored $p" ;;
      CREATED)  rm -f -- "$p" && info "Removed $p" ;;
    esac
  done < <(tac "$rd/manifest" 2>/dev/null || tail -r "$rd/manifest")
  : >"$rd/manifest.restored"
}

# ---------------------------------------------------------------------------
# Package helpers
# ---------------------------------------------------------------------------
pkg_owner() {  # pkg_owner PATH -> package name
  local p="$1" o=""
  case "$OS_FAMILY" in
    debian) have dpkg-query && o="$(dpkg-query -S -- "$p" 2>/dev/null | grep -v '^diversion' | head -1 | cut -d: -f1)" ;;
    rhel)   have rpm && o="$(rpm -qf --qf '%{NAME}\n' -- "$p" 2>/dev/null | head -1)"; [[ "$o" == *"not owned"* ]] && o="" ;;
  esac
  printf '%s' "$o"
}

pkg_version() {
  local pkg="$1"
  case "$OS_FAMILY" in
    debian) dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null ;;
    rhel)   rpm -q --qf '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null ;;
  esac
}

pkg_changelog_has_cves() {  # true if the package changelog lists every advisory CVE
  local pkg="$1" text="" cve f
  case "$OS_FAMILY" in
    debian)
      for f in "/usr/share/doc/$pkg/changelog.Debian.gz" "/usr/share/doc/$pkg/changelog.gz"; do
        [ -r "$f" ] && { text="$(zcat -- "$f" 2>/dev/null | head -c 2000000)"; break; }
      done ;;
    rhel)
      text="$(rpm -q --changelog "$pkg" 2>/dev/null | head -c 2000000)" ;;
  esac
  [ -n "$text" ] || return 1
  for cve in $ADV_CVES; do
    grep -qF -- "$cve" <<<"$text" || return 1
  done
  return 0
}

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
is_php_name() {
  case "$1" in
    phpize*|php-config*|phpdbg*) return 1 ;;
  esac
  [[ "$1" =~ ^(php[0-9.]*|php-?fpm[0-9.]*|php[0-9.]*-fpm|php-cgi[0-9.]*|php[0-9.]*-cgi|lsphp[0-9.]*)$ ]]
}

declare -A SEEN_BIN=()
CANDIDATES=()
add_candidate() {
  local p="$1" stale="${2:-0}" real
  [ -n "$p" ] || return 0
  real="$(readlink -f -- "$p" 2>/dev/null || printf '%s' "$p")"
  [ -f "$real" ] && [ -x "$real" ] || return 0
  is_php_name "$(basename -- "$real")" || is_php_name "$(basename -- "$p")" || return 0
  if [ -n "${SEEN_BIN[$real]:-}" ]; then
    [ "$stale" = 1 ] && SEEN_BIN[$real]=stale
    return 0
  fi
  SEEN_BIN[$real]=$([ "$stale" = 1 ] && echo stale || echo yes)
  CANDIDATES+=("$real")
}

discover_binaries() {
  local p pid exe
  local globs=(
    /usr/bin/php* /usr/sbin/php* /usr/local/bin/php* /usr/local/sbin/php*
    /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/bin/php-cgi /opt/remi/php*/root/usr/sbin/php-fpm
    /opt/rh/*php*/root/usr/bin/php /opt/rh/*php*/root/usr/sbin/php-fpm
    /opt/plesk/php/*/bin/php /opt/plesk/php/*/bin/php-cgi /opt/plesk/php/*/sbin/php-fpm
    /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/bin/php-cgi /opt/cpanel/ea-php*/root/usr/sbin/php-fpm
    /usr/local/php*/bin/php /usr/local/php*/bin/php-cgi /usr/local/php*/sbin/php-fpm
    /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/lsphp*/bin/php
  )
  shopt -s nullglob
  for p in "${globs[@]}"; do add_candidate "$p"; done
  shopt -u nullglob
  for p in php php-fpm php-cgi; do
    while read -r exe; do add_candidate "$exe"; done < <(type -a -p "$p" 2>/dev/null)
  done
  for p in "${EXTRA_PHP[@]}"; do add_candidate "$p"; done
  # Running processes. "(deleted)" means the binary was replaced on disk but the old code still runs.
  for pid in /proc/[0-9]*; do
    exe="$(readlink -- "$pid/exe" 2>/dev/null)" || continue
    case "$exe" in
      *" (deleted)") exe="${exe% (deleted)}"; is_php_name "$(basename -- "$exe")" && add_candidate "$exe" 1 ;;
      *) is_php_name "$(basename -- "$exe")" && add_candidate "$exe" ;;
    esac
  done
}

php_version_line() {  # php_version_line BIN -> first line of "BIN -v"
  run_t 15 "$1" -n -v 2>/dev/null | head -1
}

# parse_php_version LINE -> "8.2.10", or "8.5.12RC1" / "8.6.0-dev" for pre-release builds.
# Distribution suffixes such as "-1ubuntu2.28" are not part of the result.
parse_php_version() {
  local re='^PHP ([0-9]+\.[0-9]+\.[0-9]+)(-?(alpha|beta|rc|dev)[0-9]*)?' out=""
  shopt -s nocasematch
  [[ "$1" =~ $re ]] && out="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
  shopt -u nocasematch
  printf '%s' "$out"
}
ver_base() { [[ "$1" =~ ^([0-9]+\.[0-9]+\.[0-9]+) ]] && printf '%s' "${BASH_REMATCH[1]}"; }
ver_pre() { local b; b="$(ver_base "$1")"; printf '%s' "${1#"$b"}"; }

add_runtime() {  # path sapi version pkgmgr pkg pkgver stale container image
  local i=${#RT_PATH[@]}
  RT_PATH[i]="$1"; RT_SAPI[i]="$2"; RT_VERSION[i]="$3"; RT_BRANCH[i]=""
  [ -n "$3" ] && RT_BRANCH[i]="$(branch_of "$3")"
  RT_PKGMGR[i]="$4"; RT_PKG[i]="$5"; RT_PKGVER[i]="$6"
  RT_CONTAINER[i]="$8"; RT_IMAGE[i]="$9"
  RT_STATUS[i]=""; RT_REASON[i]=""; RT_ACTION[i]=""
  RT_INSTALLED[i]=""; RT_RUNNING[i]="unknown"; RT_MITIG[i]="none"
  RT_FPMCONF[i]=""; RT_INI[i]=""; RT_SCANENV[i]=""
}

inspect_binaries() {
  local bin line ver sapi pkg pkgver mgr stale
  for bin in "${CANDIDATES[@]}"; do
    line="$(php_version_line "$bin")"
    ver="$(parse_php_version "$line")"
    if [[ "$line" =~ \((cli|fpm-fcgi|cgi-fcgi|litespeed|embed)\) ]]; then sapi="${BASH_REMATCH[1]}"; else sapi="unknown"; fi
    [ -z "$ver" ] && [ -z "$line" ] && continue   # not a PHP binary (for example a wrapper script)
    pkg="$(pkg_owner "$bin")"; pkgver=""; mgr="none"
    if [ -n "$pkg" ]; then mgr="$OS_FAMILY"; pkgver="$(pkg_version "$pkg")"; fi
    stale=0; [ "${SEEN_BIN[$bin]}" = "stale" ] && stale=1
    add_runtime "$bin" "$sapi" "$ver" "$mgr" "$pkg" "$pkgver" "$stale" "" ""
  done
}

discover_mod_php() {
  local so pkg pkgver ver b mgr
  shopt -s nullglob
  for so in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so \
            /usr/lib/httpd/modules/libphp*.so /usr/local/apache2/modules/libphp*.so \
            /opt/remi/php*/root/usr/lib64/httpd/modules/libphp*.so; do
    so="$(readlink -f -- "$so")"
    pkg="$(pkg_owner "$so")"; pkgver=""; ver=""; mgr="none"
    if [ -n "$pkg" ]; then
      mgr="$OS_FAMILY"; pkgver="$(pkg_version "$pkg")"
      [[ "$pkgver" =~ ^([0-9]+:)?([0-9]+\.[0-9]+\.[0-9]+) ]] && ver="${BASH_REMATCH[2]}"
    fi
    if [ -z "$ver" ]; then
      # libphp8.2.so -> branch 8.2; take the exact version from a CLI of that branch, if one exists.
      [[ "$(basename "$so")" =~ libphp([0-9]+\.[0-9]+)\.so ]] && b="${BASH_REMATCH[1]}" || b=""
      local j
      for j in "${!RT_PATH[@]}"; do
        [ -n "$b" ] && [ "${RT_BRANCH[j]}" = "$b" ] && [ -z "${RT_CONTAINER[j]}" ] && { ver="${RT_VERSION[j]}"; break; }
      done
    fi
    add_runtime "$so" "apache2handler" "$ver" "$mgr" "$pkg" "$pkgver" 0 "" ""
  done
  shopt -u nullglob
}

discover_containers() {
  [ "$OPT_NO_DOCKER" -eq 1 ] && return 0
  have docker || return 0
  run_t 10 docker info >/dev/null 2>&1 || { warn "docker is installed but not reachable. Skipping containers."; return 0; }
  local id image name line ver sapi
  while read -r id image name; do
    [ -n "$id" ] || continue
    line="$(run_t 20 docker exec "$id" sh -c 'for b in php php-fpm /usr/local/sbin/php-fpm php-cgi; do if command -v "$b" >/dev/null 2>&1; then "$b" -n -v 2>/dev/null | head -1; exit 0; fi; done' 2>/dev/null)"
    [ -n "$line" ] || continue
    ver="$(parse_php_version "$line")"
    if [[ "$line" =~ \((cli|fpm-fcgi|cgi-fcgi)\) ]]; then sapi="${BASH_REMATCH[1]}"; else sapi="unknown"; fi
    add_runtime "container:$name" "$sapi" "$ver" "docker" "" "" 0 "$id" "$image"
  done < <(run_t 15 docker ps --format '{{.ID}} {{.Image}} {{.Names}}' 2>/dev/null)
}

# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------
assess_one() {
  local i="$1" v="${RT_VERSION[$1]}" b="${RT_BRANCH[$1]}" fixed="" low base pre
  low="$(newest_fixed_branch)"
  if [ -z "$v" ]; then
    RT_STATUS[i]="UNKNOWN"; RT_INSTALLED[i]="UNKNOWN"; RT_REASON[i]="Version not readable"; RT_ACTION[i]="Check this runtime manually"
    return
  fi
  base="$(ver_base "$v")"; pre="$(ver_pre "$v")"
  fixed="$(fixed_for_branch "$b")"
  # Only a release that the advisory names as fixed, or a vendor changelog, counts as safe.
  if [ -n "$fixed" ] && [ -z "$pre" ] && ver_ge "$base" "$fixed"; then
    RT_STATUS[i]="PATCHED"; RT_REASON[i]="Version $v >= $fixed"
  elif [ -n "${RT_PKG[i]}" ] && [ "${RT_PKGMGR[i]}" = "$OS_FAMILY" ] && pkg_changelog_has_cves "${RT_PKG[i]}"; then
    RT_STATUS[i]="PATCHED"; RT_REASON[i]="Vendor backport: changelog of ${RT_PKG[i]} lists all CVEs"
  elif [ -n "$fixed" ] && [ -n "$pre" ] && [ "$(ver_cmp "$base" "$fixed")" -gt 0 ]; then
    RT_STATUS[i]="UNKNOWN"; RT_REASON[i]="Pre-release build $v after the fixed release $fixed; the advisory does not say it is fixed"
  elif [ -n "$fixed" ]; then
    RT_STATUS[i]="VULNERABLE"; RT_REASON[i]="Version $v is older than the fixed release $fixed"
  elif in_list "$b" $ADV_EOL_BACKPORT; then
    RT_STATUS[i]="VULNERABLE_EOL"; RT_REASON[i]="Branch $b is end-of-life; only vendor or source backports exist"
  elif [ -n "$low" ] && [ "$(ver_cmp "$b" "$low")" -lt 0 ]; then
    RT_STATUS[i]="VULNERABLE_NOFIX"; RT_REASON[i]="Branch $b has no upstream fix"
  else
    RT_STATUS[i]="UNKNOWN"; RT_REASON[i]="Branch $b is not covered by advisory $ADV_ID"
  fi
  RT_INSTALLED[i]="${RT_STATUS[i]}"

  case "${RT_STATUS[i]}" in
    PATCHED) RT_ACTION[i]="None" ;;
    UNKNOWN) RT_ACTION[i]="Check the vendor and PHP advisories for $v manually" ;;
    *)
      case "${RT_PKGMGR[i]}" in
        debian|rhel) RT_ACTION[i]="Upgrade ${RT_PKG[i]} inside branch $b; mitigate if no fixed package exists" ;;
        docker)      RT_ACTION[i]="Rebuild image ${RT_IMAGE[i]} on a fixed $b tag and redeploy" ;;
        *)           RT_ACTION[i]="Not package-managed: rebuild $b from patched source or vendor build; mitigate now" ;;
      esac ;;
  esac
  if [ "${RT_RUNNING[i]}" = stale ]; then
    RT_REASON[i]="${RT_REASON[i]}; a process still runs a replaced (deleted) binary"
    RT_STATUS[i]="RESTART_REQUIRED"
    RT_ACTION[i]="Restart the service that runs this binary"
  fi
}

assess_all() { local i; for i in "${!RT_PATH[@]}"; do assess_one "$i"; done; }

is_bad_status() { case "$1" in PATCHED) return 1 ;; *) return 0 ;; esac; }

# ---------------------------------------------------------------------------
# Dockerfiles
# ---------------------------------------------------------------------------
scan_dockerfiles() {
  local dir f n line ref tag ver rest fixed b
  for dir in "${DOCKERFILE_DIRS[@]}"; do
    [ -d "$dir" ] || { warn "Not a directory: $dir"; continue; }
    while IFS= read -r -d '' f; do
      n=0
      while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        [[ "$line" =~ ^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?((docker\.io/)?(library/)?php:([^[:space:]]+)) ]] || continue
        ref="${BASH_REMATCH[2]}"; tag="${BASH_REMATCH[5]}"
        local i=${#DF_FILE[@]}
        DF_FILE[i]="$f"; DF_LINE[i]="$n"; DF_TAG[i]="$ref"; DF_FIX[i]=""
        if [[ "$tag" == *'$'* || "$ref" == *@sha256:* ]]; then
          DF_STATUS[i]="MANUAL"; continue
        fi
        if [[ "$tag" =~ ^([0-9]+\.[0-9]+\.[0-9]+)(.*)$ ]]; then
          ver="${BASH_REMATCH[1]}"; rest="${BASH_REMATCH[2]}"; b="$(branch_of "$ver")"
          if fixed="$(fixed_for_branch "$b")"; then
            if ver_ge "$ver" "$fixed"; then DF_STATUS[i]="PATCHED"
            else DF_STATUS[i]="VULNERABLE"; DF_FIX[i]="${ref%%:*}:$fixed$rest"; fi
          elif in_list "$b" $ADV_EOL_BACKPORT; then DF_STATUS[i]="VULNERABLE_EOL"
          else DF_STATUS[i]="VULNERABLE_NOFIX"; fi
        elif [[ "$tag" =~ ^[0-9]+\.[0-9]+(-.*)?$ ]]; then
          b="${tag%%-*}"
          if fixed_for_branch "$b" >/dev/null; then DF_STATUS[i]="REBUILD"   # floating minor tag: rebuild with --pull
          elif in_list "$b" $ADV_EOL_BACKPORT; then DF_STATUS[i]="VULNERABLE_EOL"
          else DF_STATUS[i]="VULNERABLE_NOFIX"; fi
        else
          DF_STATUS[i]="FLOATING_MAJOR"   # "8", "latest", "fpm": the branch can change on rebuild
        fi
      done <"$f"
    done < <(find "$dir" -type f \( -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name '*.Dockerfile' -o -name 'Containerfile' \) -not -path '*/.git/*' -print0 2>/dev/null)
  done
}

fix_dockerfiles() {
  local i f
  for i in "${!DF_FILE[@]}"; do
    [ "${DF_STATUS[i]}" = "VULNERABLE" ] && [ -n "${DF_FIX[i]}" ] || continue
    f="${DF_FILE[i]}"
    backup_file "$f"
    sed -i "${DF_LINE[i]}s#${DF_TAG[i]//./\\.}#${DF_FIX[i]}#" "$f" && {
      info "Dockerfile $f:${DF_LINE[i]}: ${DF_TAG[i]} -> ${DF_FIX[i]}"
      ACTIONS_DONE+=("dockerfile:$f:${DF_TAG[i]}->${DF_FIX[i]}")
      DF_STATUS[i]="FIXED_REBUILD_REQUIRED"
    }
  done
}

# ---------------------------------------------------------------------------
# Indicators of compromise (read-only)
# ---------------------------------------------------------------------------
ioc_add() { IOC_LINES+=("$1"); warn "Indicator: $1"; }

check_iocs() {
  [ "$OPT_NO_IOC" -eq 1 ] && return 0
  local f c pid comm ppid pcomm user cmd
  shopt -s nullglob
  local logs=(/var/log/php*fpm*.log* /var/log/php-fpm/*log* /var/log/apache2/error*.log* /var/log/httpd/*error*
              /var/log/nginx/error.log* /var/log/php_errors.log* /var/log/php/*.log* /var/opt/remi/php*/log/php-fpm/*log*)
  shopt -u nullglob
  local rule label rx
  for f in "${logs[@]}"; do
    [ -r "$f" ] || continue
    for rule in "${ADV_IOC_LOG[@]}"; do
      label="${rule%%|*}"; rx="${rule#*|}"
      c="$( { case "$f" in *.gz) zcat -- "$f" ;; *) cat -- "$f" ;; esac; } 2>/dev/null | grep -cE -- "$rx")"
      [ "${c:-0}" -gt 0 ] && ioc_add "log $f: $c $label"
    done
  done

  # Shells or download tools whose parent is a PHP or web worker.
  for pid in /proc/[0-9]*; do
    pid="${pid#/proc/}"
    comm="$(cat "/proc/$pid/comm" 2>/dev/null)" || continue
    case "$comm" in sh|bash|dash|ash|zsh|ksh|curl|wget|nc|ncat|socat|python|python3|perl|busybox) ;; *) continue ;; esac
    ppid="$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null)"
    [ -n "$ppid" ] || continue
    pcomm="$(cat "/proc/$ppid/comm" 2>/dev/null)"
    case "$pcomm" in php*|lsphp*|httpd|apache2) ;; *) continue ;; esac
    user="$(stat -c %U "/proc/$pid" 2>/dev/null)"
    cmd="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | head -c 300)"
    ioc_add "process $pid ($user) '$cmd' started by $pcomm ($ppid)"
  done

  # PHP files changed after the reference date in web roots (only if the advisory gives a date).
  [ -n "$ADV_IOC_SINCE" ] || return 0
  local roots=(/var/www /srv/www /srv/http /usr/share/nginx/html /var/lib/nginx/html ${WEB_ROOTS[@]+"${WEB_ROOTS[@]}"})
  shopt -s nullglob
  roots+=(/home/*/public_html /home/*/www)
  shopt -u nullglob
  local r cnt list sus
  for r in "${roots[@]}"; do
    [ -d "$r" ] || continue
    list="$(find "$r" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' -o -name '*.phar' -o -name '.user.ini' \) \
              -newermt "$ADV_IOC_SINCE" 2>/dev/null | head -2000)"
    [ -n "$list" ] || continue
    cnt="$(printf '%s\n' "$list" | wc -l | tr -d ' ')"
    sus="$(printf '%s\n' "$list" | tr '\n' '\0' | xargs -0 -r grep -lE 'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13|\$_(POST|GET|REQUEST|COOKIE))|assert[[:space:]]*\([[:space:]]*\$_|(system|passthru|shell_exec|proc_open|popen)[[:space:]]*\([[:space:]]*\$_' 2>/dev/null | head -50)"
    if [ -n "$sus" ]; then
      while IFS= read -r f; do ioc_add "web shell pattern in $f"; done <<<"$sus"
    fi
    _log_line "INFO $cnt PHP-related files in $r changed since $ADV_IOC_SINCE"
    [ "$cnt" -gt 0 ] && IOC_LINES+=("info: $cnt PHP-related files in $r changed since $ADV_IOC_SINCE (review them; list in log)")
    [ -n "$LOG_FILE" ] && printf '%s\n' "$list" >>"$LOG_FILE"
  done
}

ioc_count() {  # counts real indicators (lines that do not start with "info:")
  local l n=0
  for l in "${IOC_LINES[@]}"; do [[ "$l" == info:* ]] || n=$((n + 1)); done
  echo "$n"
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
print_report() {
  local i
  printf '\nphp-safepatch %s  advisory %s (%s)  host %s  os %s\n' "$SAFEPATCH_VERSION" "$ADV_ID" "$ADV_CVES" "$(hostname 2>/dev/null)" "$OS_FAMILY"
  printf '%-18s %-15s %-11s %-8s %-16s %-40s %s\n' "STATUS" "SAPI" "VERSION" "RUNNING" "MITIGATION" "RUNTIME" "PACKAGE"
  for i in "${!RT_PATH[@]}"; do
    printf '%-18s %-15s %-11s %-8s %-16s %-40s %s\n' "${RT_STATUS[i]}" "${RT_SAPI[i]}" "${RT_VERSION[i]:--}" \
      "${RT_RUNNING[i]}" "${RT_MITIG[i]}" "${RT_PATH[i]}" \
      "${RT_PKG[i]:+${RT_PKG[i]} ${RT_PKGVER[i]}}${RT_IMAGE[i]:+image ${RT_IMAGE[i]}}"
    is_bad_status "${RT_STATUS[i]}" && printf '%-18s -> %s. %s\n' "" "${RT_REASON[i]}" "${RT_ACTION[i]}"
  done
  [ "${#RT_PATH[@]}" -eq 0 ] && printf '(no PHP runtime found)\n'
  if [ "${#DF_FILE[@]}" -gt 0 ]; then
    printf '\nDockerfiles:\n'
    for i in "${!DF_FILE[@]}"; do
      printf '%-22s %s:%s %s%s\n' "${DF_STATUS[i]}" "${DF_FILE[i]}" "${DF_LINE[i]}" "${DF_TAG[i]}" "${DF_FIX[i]:+ -> ${DF_FIX[i]}}"
    done
  fi
  if [ "${#IOC_LINES[@]}" -gt 0 ]; then
    printf '\nIndicators (review; php-safepatch does not delete anything):\n'
    for i in "${IOC_LINES[@]}"; do printf '  - %s\n' "$i"; done
  fi
  if [ "${#ACTIONS_DONE[@]}" -gt 0 ]; then
    printf '\nChanges in this run (%s):\n' "${RUN_DIR:-no run dir}"
    for i in "${ACTIONS_DONE[@]}"; do printf '  - %s\n' "$i"; done
  fi
  if [ "$(bad_count)" -gt 0 ] || [ "$(ioc_count)" -gt 0 ]; then
    printf '\nReminder: rotate DB passwords, API keys and admin passwords on hosts that were exposed before the fix.\n'
  fi
}

bad_count() { local i n=0; for i in "${!RT_PATH[@]}"; do is_bad_status "${RT_STATUS[i]}" && n=$((n + 1)); done; echo "$n"; }

write_json() {
  local out="$1" i first
  {
    printf '{"tool":"php-safepatch","version":%s,"advisory":{"id":%s,"cves":%s,"fixed":%s},' \
      "$(json_str "$SAFEPATCH_VERSION")" "$(json_str "$ADV_ID")" "$(json_str "$ADV_CVES")" "$(json_str "$ADV_FIXED")"
    printf '"host":%s,"os":{"id":%s,"family":%s},"time":%s,"command":%s,"run_dir":%s,' \
      "$(json_str "$(hostname 2>/dev/null)")" "$(json_str "$OS_ID")" "$(json_str "$OS_FAMILY")" \
      "$(json_str "$(date -u '+%Y-%m-%dT%H:%M:%SZ')")" "$(json_str "$CMD")" "$(json_str "$RUN_DIR")"
    printf '"runtimes":['
    first=1
    for i in "${!RT_PATH[@]}"; do
      [ $first -eq 1 ] || printf ','; first=0
      printf '{"path":%s,"sapi":%s,"version":%s,"branch":%s,"manager":%s,"package":%s,"package_version":%s,"container":%s,"image":%s,"status":%s,"installed":%s,"running":%s,"mitigation":%s,"config":{"fpm_conf":%s,"php_ini":%s,"scan_dir_env":%s,"unit":%s},"reason":%s,"action":%s}' \
        "$(json_str "${RT_PATH[i]}")" "$(json_str "${RT_SAPI[i]}")" "$(json_str "${RT_VERSION[i]}")" "$(json_str "${RT_BRANCH[i]}")" \
        "$(json_str "${RT_PKGMGR[i]}")" "$(json_str "${RT_PKG[i]}")" "$(json_str "${RT_PKGVER[i]}")" \
        "$(json_str "${RT_CONTAINER[i]}")" "$(json_str "${RT_IMAGE[i]}")" \
        "$(json_str "${RT_STATUS[i]}")" "$(json_str "${RT_INSTALLED[i]}")" "$(json_str "${RT_RUNNING[i]}")" "$(json_str "${RT_MITIG[i]}")" \
        "$(json_str "${RT_FPMCONF[i]}")" "$(json_str "${RT_INI[i]}")" "$(json_str "${RT_SCANENV[i]}")" "$(json_str "${RT_UNIT[i]:-}")" \
        "$(json_str "${RT_REASON[i]}")" "$(json_str "${RT_ACTION[i]}")"
    done
    printf '],"dockerfiles":['
    first=1
    for i in "${!DF_FILE[@]}"; do
      [ $first -eq 1 ] || printf ','; first=0
      printf '{"file":%s,"line":%s,"from":%s,"status":%s,"fix":%s}' "$(json_str "${DF_FILE[i]}")" "${DF_LINE[i]}" \
        "$(json_str "${DF_TAG[i]}")" "$(json_str "${DF_STATUS[i]}")" "$(json_str "${DF_FIX[i]}")"
    done
    printf '],"indicators":['
    first=1
    for i in "${IOC_LINES[@]}"; do [ $first -eq 1 ] || printf ','; first=0; json_str "$i"; done
    printf '],"changes":['
    first=1
    for i in "${ACTIONS_DONE[@]}"; do [ $first -eq 1 ] || printf ','; first=0; json_str "$i"; done
    printf '],"errors":['
    first=1
    for i in "${ERRORS[@]}"; do [ $first -eq 1 ] || printf ','; first=0; json_str "$i"; done
    printf '],"summary":{"runtimes":%s,"not_patched":%s,"indicators":%s}}\n' "${#RT_PATH[@]}" "$(bad_count)" "$(ioc_count)"
  } >"$out"
}

# ---------------------------------------------------------------------------
# Compatibility checks (FR-6)
# ---------------------------------------------------------------------------
snapshot_modules() {  # snapshot_modules SUFFIX  (before | after)
  local i f
  [ -n "$RUN_DIR" ] || return 0
  for i in "${!RT_PATH[@]}"; do
    [ -z "${RT_CONTAINER[i]}" ] && [ "${RT_SAPI[i]}" != "apache2handler" ] || continue
    f="$RUN_DIR/modules/$(sanitize "${RT_PATH[i]}").$1"
    run_t 15 "${RT_PATH[i]}" -m 2>/dev/null | grep -v '^\[' | grep -v '^$' | sort -u >"$f"
  done
}

compare_modules() {  # prints missing modules; returns 1 if something is missing
  local f base missing rc=0
  [ -n "$RUN_DIR" ] || return 0
  for f in "$RUN_DIR"/modules/*.before; do
    [ -e "$f" ] || continue
    base="${f%.before}"
    [ -e "$base.after" ] || continue
    missing="$(comm -23 "$f" "$base.after" | tr '\n' ' ')"
    if [ -n "${missing// /}" ]; then
      err "Extensions missing after change for $(basename "$base"): $missing"; rc=1
    fi
  done
  return $rc
}

http_code() {
  local u="$1"
  if have curl; then curl -k -s -o /dev/null -m 15 -w '%{http_code}' -- "$u" 2>/dev/null || echo 000
  elif have wget; then wget -q -S -O /dev/null -T 15 --no-check-certificate -- "$u" 2>&1 | awk '/^  HTTP\//{c=$2} END{print c?c:"000"}'
  else echo "000"; fi
}

declare -A HEALTH_BEFORE=()
health_before() { local u; for u in "${HEALTH_URLS[@]}"; do HEALTH_BEFORE[$u]="$(http_code "$u")"; info "Health before: $u -> ${HEALTH_BEFORE[$u]}"; done; }

health_after() {  # returns 1 if a URL does not give the same status code as before the change
  local u now before rc=0
  for u in "${HEALTH_URLS[@]}"; do
    before="${HEALTH_BEFORE[$u]:-000}"
    if [ "$before" = "000" ] || [ "${before:0:1}" = "5" ]; then
      warn "Health URL $u already failed before the change ($before); it cannot verify this run"
      continue
    fi
    for _ in 1 2 3 4 5; do   # services can need a few seconds after a restart
      now="$(http_code "$u")"
      [ "$now" = "$before" ] && break
      sleep 3
    done
    info "Health after: $u -> $now (before $before)"
    if [ "$now" != "$before" ]; then
      err "Health check failed: $u gave $before before the change and $now after it"; rc=1
    fi
  done
  return $rc
}

# ---------------------------------------------------------------------------
# Patching (FR-5): stays inside the branch
# ---------------------------------------------------------------------------
APT_UPDATED=0

debian_branch_packages() {  # installed packages that belong to branch B only
  local b="$1"
  dpkg-query -W -f='${Status}\t${Package}\n' "php${b}" "php${b}-*" "libapache2-mod-php${b}" "libphp${b}-embed" 2>/dev/null \
    | awk -F'\t' '$1 ~ /install ok installed/ {print $2}' | sort -u
}

patch_debian_branch() {  # returns 0 if packages were upgraded
  local b="$1" pkgs sim line name newv bad=0 count=0
  mapfile -t pkgs < <(debian_branch_packages "$b")
  [ "${#pkgs[@]}" -gt 0 ] || { warn "No installed php$b packages found"; return 1; }
  if [ "$APT_UPDATED" -eq 0 ]; then
    info "apt-get update"
    run_t 600 apt-get update -qq >>"${LOG_FILE:-/dev/null}" 2>&1 || warn "apt-get update reported errors"
    APT_UPDATED=1
  fi
  local simrc
  sim="$(LC_ALL=C apt-get -s install --only-upgrade "${pkgs[@]}" 2>&1)"; simrc=$?
  printf '%s\n' "$sim" >>"${LOG_FILE:-/dev/null}"
  if [ "$simrc" -ne 0 ]; then
    err "apt-get could not simulate the upgrade for branch $b (exit $simrc); see the log. Not patching."; return 1
  fi
  while IFS= read -r line; do
    if [[ "$line" =~ ^Remv\ ([^ ]+) ]]; then err "Simulation removes ${BASH_REMATCH[1]}. Not patching branch $b."; bad=1; fi
    [[ "$line" =~ ^Inst\ ([^ ]+)\ .*\(([^ ]+)\  ]] || continue
    name="${BASH_REMATCH[1]}"; newv="${BASH_REMATCH[2]}"; newv="${newv#*:}"
    count=$((count + 1))
    if [[ "$name" =~ ^(php|libapache2-mod-php|libphp)([0-9]+\.[0-9]+) ]]; then
      if [ "${BASH_REMATCH[2]}" != "$b" ]; then err "Simulation installs $name (other branch). Not patching branch $b."; bad=1; fi
      if [[ "$newv" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] && [ "$(branch_of "${BASH_REMATCH[0]}")" != "$b" ]; then
        err "Simulation moves $name to $newv (other branch). Not patching branch $b."; bad=1
      fi
    fi
  done <<<"$sim"
  [ "$bad" -eq 0 ] || return 1
  [ "$count" -gt 0 ] || { info "No newer packages for branch $b in the configured repositories"; return 1; }
  dpkg-query -W -f='${Package}=${Version}\n' "${pkgs[@]}" >>"$RUN_DIR/packages.before" 2>/dev/null
  info "Upgrading $count package(s) for branch $b"
  if DEBIAN_FRONTEND=noninteractive run_t 1800 apt-get install -y -q --only-upgrade \
       -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef "${pkgs[@]}" >>"${LOG_FILE:-/dev/null}" 2>&1; then
    ACTIONS_DONE+=("packages:php$b upgraded ($count)")
    return 0
  fi
  err "apt-get install failed for branch $b (see log)"
  return 1
}

rhel_branch_packages() {  # packages of the same PHP build as the owner package
  local owner="$1"
  if [[ "$owner" =~ ^(php[0-9]+)-php ]]; then   # Remi SCL, for example php82-php-cli
    rpm -qa --qf '%{NAME}\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[1]}-*" 2>/dev/null | sort -u
  elif [[ "$owner" =~ ^(ea-php[0-9]+) ]]; then  # cPanel EasyApache
    rpm -qa --qf '%{NAME}\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[1]}-*" 2>/dev/null | sort -u
  else
    rpm -qa --qf '%{NAME}\n' php 'php-*' 2>/dev/null | sort -u
  fi
}

# check_rpm_transaction BRANCH OUTPUT -- reads the transaction table that "dnf/yum upgrade --assumeno"
# prints. Sets RPM_TX_COUNT. Returns 1 if the transaction removes, downgrades or replaces a package,
# or touches a PHP core package of another branch.
RPM_TX_COUNT=0
check_rpm_transaction() {
  local b="$1" out="$2" line section="" name ver carry="" bad=0 f1 f2 f3
  RPM_TX_COUNT=0
  while IFS= read -r line; do
    case "$line" in
      [A-Za-z]*:)                                                   # section header at column 0
        carry=""
        case "$line" in
          *[Rr]epositor*|Transaction*) section="" ;;
          *[Mm]odule*) err "Transaction changes module streams ($line). Not patching branch $b."; bad=1; section="" ;;
          Upgrad*|Updat*|Install*|Reinstall*|Remov*|Eras*|Downgrad*|Obsolet*|Replac*) section="$line" ;;
          *) section="" ;;
        esac
        continue ;;
      Transaction*) section=""; continue ;;
    esac
    [ -n "$section" ] || continue
    case "$line" in " "*) ;; *) continue ;; esac
    read -r f1 f2 f3 _ <<<"$line"
    [ -n "$f1" ] || continue
    [ "$f1" = "replacing" ] && continue                             # dnf5 detail line under an upgrade
    if [ -z "$f2" ]; then carry="$f1"; continue; fi                  # yum wraps long names to their own line
    if [ -n "$carry" ]; then name="$carry"; ver="$f2"; carry=""; else name="$f1"; ver="$f3"; fi
    ver="${ver#*:}"
    RPM_TX_COUNT=$((RPM_TX_COUNT + 1))
    case "$section" in
      *[Rr]emov*|*[Dd]owngrad*|*[Oo]bsolet*|*[Ee]ras*|*[Rr]eplac*)
        err "Transaction would ${section%:} $name. Not patching branch $b."; bad=1; continue ;;
    esac
    case "$name" in *pecl*|*pear*) continue ;; esac                 # own version numbers
    if [[ "$name" =~ ^(php|php-.+|php[0-9]+-php.*|ea-php[0-9]+.*)$ ]]; then
      if [[ "$name" =~ ^(ea-)?php([0-9])([0-9]+)- ]] && [ "${BASH_REMATCH[2]}.${BASH_REMATCH[3]}" != "$b" ]; then
        err "Transaction installs $name (branch ${BASH_REMATCH[2]}.${BASH_REMATCH[3]}). Not patching branch $b."; bad=1
      elif [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] && [ "$(branch_of "${BASH_REMATCH[0]}")" != "$b" ]; then
        err "Transaction moves $name to $ver (other branch). Not patching branch $b."; bad=1
      fi
    fi
  done <<<"$out"
  return $bad
}

patch_rhel_branch() {
  local b="$1" owner="$2" pkgs tool="" sim rc
  mapfile -t pkgs < <(rhel_branch_packages "$owner")
  [ "${#pkgs[@]}" -gt 0 ] || return 1
  if have dnf; then tool=dnf; elif have yum; then tool=yum; else warn "No dnf or yum"; return 1; fi
  # Simulate the real transaction, with dependencies, before anything is installed.
  sim="$(LC_ALL=C run_t 900 "$tool" upgrade --assumeno "${pkgs[@]}" 2>&1)"; rc=$?
  printf '%s\n' "$sim" >>"${LOG_FILE:-/dev/null}"
  if grep -qiE '^(Nothing to do|No packages marked for update)' <<<"$sim"; then
    info "No newer packages for branch $b in the configured repositories"; return 1
  fi
  if ! grep -qiE 'Operation aborted|Exiting on user command|Is this ok' <<<"$sim"; then
    err "$tool could not simulate the upgrade for branch $b (exit $rc); see the log. Not patching."; return 1
  fi
  check_rpm_transaction "$b" "$sim" || return 1
  local count="$RPM_TX_COUNT"
  [ "$count" -gt 0 ] || { err "$tool simulation for branch $b listed no packages; see the log. Not patching."; return 1; }
  rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "${pkgs[@]}" >>"$RUN_DIR/packages.before" 2>/dev/null
  info "Upgrading $count package(s) for branch $b with $tool"
  if run_t 1800 "$tool" -y -q upgrade "${pkgs[@]}" >>"${LOG_FILE:-/dev/null}" 2>&1; then
    ACTIONS_DONE+=("packages:php$b ($owner group) upgraded ($count)")
    return 0
  fi
  err "$tool upgrade failed for branch $b (see log)"
  return 1
}

# ---------------------------------------------------------------------------
# Mitigation (FR-7)
# ---------------------------------------------------------------------------
MARK_BEGIN=""; MARK_END=""; INI_NAME=""; APACHE_CONF_NAME=""
CHANGED_FPM_IDX=()
CHANGED_APACHE=0

set_adv_names() {  # file names and markers come from the advisory id, so advisories do not collide
  local slug
  slug="$(printf '%s' "$ADV_ID" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '-')"
  MARK_BEGIN="; >>> php-safepatch $ADV_ID mitigation >>>"
  MARK_END="; <<< php-safepatch $ADV_ID mitigation <<<"
  INI_NAME="99-php-safepatch-$slug.ini"
  APACHE_CONF_NAME="php-safepatch-$slug.conf"
}

ini_body() {  # ini_body BRANCH
  local b="$1" k v
  printf '; Managed by php-safepatch. Interim mitigation for %s (%s).\n' "$ADV_ID" "$ADV_CVES"
  printf '; Remove this file after the runtime is patched (or run: php-safepatch.sh rollback).\n'
  while read -r k v; do [ -n "$k" ] && printf '%s = %s\n' "$k" "$v"; done < <(mitigation_rules "$b")
  return 0
}

fpm_block() {  # php_admin_value: .user.ini files and later pool lines cannot override it
  local b="$1" k v
  printf '%s\n' "$MARK_BEGIN"
  while read -r k v; do [ -n "$k" ] && printf 'php_admin_value[%s] = %s\n' "$k" "$v"; done < <(mitigation_rules "$b")
  printf '%s\n' "$MARK_END"
}

write_file_if_changed() {  # write_file_if_changed PATH CONTENT
  local p="$1" c="$2"
  if [ -f "$p" ] && [ "$(cat -- "$p")" = "$c" ]; then return 1; fi
  backup_file "$p"
  mkdir -p "$(dirname -- "$p")"
  printf '%s\n' "$c" >"$p"
  chmod 644 "$p"
  return 0
}

rt_php() {  # rt_php INDEX ARGS... -- runs a runtime with the -c and PHP_INI_SCAN_DIR of its service
  local i="$1"; shift
  local -a pre=() opt=()
  [ -n "${RT_SCANENV[i]}" ] && pre=(env "PHP_INI_SCAN_DIR=${RT_SCANENV[i]}")
  [ -n "${RT_INI[i]}" ] && opt=(-c "${RT_INI[i]}")
  run_t 30 ${pre[@]+"${pre[@]}"} "${RT_PATH[i]}" ${opt[@]+"${opt[@]}"} "$@"
}

fpm_test() {  # fpm_test INDEX -- "php-fpm -t" with the configuration that the service really uses
  local i="$1"
  if [ -n "${RT_FPMCONF[i]}" ]; then rt_php "$i" -t -y "${RT_FPMCONF[i]}"; else rt_php "$i" -t; fi
}

php_info() {  # php_info INDEX -- "php -i" as "key => local => master" lines, also for php-cgi (HTML output)
  local i="$1"
  if [ "${RT_SAPI[i]}" = "cgi-fcgi" ]; then
    rt_php "$i" -q -i 2>/dev/null \
      | sed -E 's#<tr><td class="e">([^<]*)</td><td class="v">([^<]*)</td>(<td class="v">([^<]*)</td>)?</tr>#\1 => \2 => \4#' \
      | awk -F' => ' -v OFS=' => ' 'NF >= 2 { for (k = 1; k <= NF; k++) gsub(/^[ \t]+|[ \t]+$/, "", $k); if ($NF == "") NF--; print }'
  else
    rt_php "$i" -i 2>/dev/null
  fi
}

scan_dir_of() {  # scan_dir_of INDEX -> "Scan this dir for additional .ini files" (first dir)
  local d
  d="$(php_info "$1" | awk -F' => ' '/^Scan this dir for additional \.ini files/ {print $2; exit}')"
  [ -n "$d" ] && [ "$d" != "(none)" ] && printf '%s' "${d%%:*}"
}

ini_dirs_for_branch() {  # all conf.d dirs used by the runtimes of branch B
  local b="$1" i d
  {
    if [ -d "/etc/php/$b" ]; then
      for d in /etc/php/"$b"/*/conf.d; do [ -d "$d" ] && printf '%s\n' "$d"; done
    fi
    for i in "${!RT_PATH[@]}"; do
      [ "${RT_BRANCH[i]}" = "$b" ] && [ -z "${RT_CONTAINER[i]}" ] && [ "${RT_SAPI[i]}" != "apache2handler" ] || continue
      d="$(scan_dir_of "$i")"
      [ -n "$d" ] && printf '%s\n' "$d"
    done
  } | sort -u
}

fpm_default_conf() {  # fpm_default_conf BIN -> php-fpm.conf that the binary uses without -y
  run_t 15 "$1" -t 2>&1 | sed -n 's/.*configuration file \(.*\) test is successful.*/\1/p' | head -1
}

# ---------------------------------------------------------------------------
# Running processes: which runtimes run, and which run a binary that was replaced on disk
# ---------------------------------------------------------------------------
declare -A RUN_STATE=() RUN_START=()
note_proc() {  # note_proc PATH START_EPOCH
  local p="$1" st="$2" state=yes
  case "$p" in *" (deleted)") p="${p% (deleted)}"; state=stale ;; esac
  [ "${RUN_STATE[$p]:-}" = stale ] || RUN_STATE[$p]="$state"
  if [ -n "$st" ] && { [ -z "${RUN_START[$p]:-}" ] || [ "$st" -lt "${RUN_START[$p]}" ]; }; then RUN_START[$p]="$st"; fi
}

scan_processes() {
  RUN_STATE=(); RUN_START=()
  local pid exe st m
  for pid in /proc/[0-9]*; do
    exe="$(readlink -- "$pid/exe" 2>/dev/null)" || continue
    st="$(stat -c %Y "$pid" 2>/dev/null)"     # start time of the process
    note_proc "$exe" "$st"
    case "$(basename -- "${exe% (deleted)}")" in
      apache2|httpd|httpd.worker|httpd.event)  # mod_php is a library inside the web server
        while IFS= read -r m; do note_proc "$m" "$st"; done \
          < <(awk '$6 ~ /libphp/ {p = $6; for (k = 7; k <= NF; k++) p = p " " $k; print p}' "$pid/maps" 2>/dev/null | sort -u) ;;
    esac
  done
}

set_running() {  # set_running INDEX -- yes, no, stale (old code still runs) or unknown (containers)
  local i="$1"
  if [ -n "${RT_CONTAINER[i]}" ]; then RT_RUNNING[i]="unknown"; return; fi
  RT_RUNNING[i]="${RUN_STATE[${RT_PATH[i]}]:-no}"
}

# ---------------------------------------------------------------------------
# Service configuration: the files that the running service really reads
# ---------------------------------------------------------------------------
RT_UNIT=()
service_config() {  # service_config INDEX -- fills RT_FPMCONF, RT_INI, RT_SCANENV, RT_UNIT
  local i="$1" bin="${RT_PATH[$1]}" pid exe t u ex argv envs
  local re_y='(^| )(-y|--fpm-config)[= ]([^ ]+)' re_c='(^| )(-c|--php-ini)[= ]([^ ]+)' re_s='(^| )PHP_INI_SCAN_DIR=([^ ]+)'
  RT_UNIT[i]=""
  [ -z "${RT_CONTAINER[i]}" ] || return 0
  [ "${RT_SAPI[i]}" = "fpm-fcgi" ] || return 0
  # 1. A running master shows its configuration file in its process title.
  for pid in /proc/[0-9]*; do
    exe="$(readlink -- "$pid/exe" 2>/dev/null)" || continue
    [ "${exe% (deleted)}" = "$bin" ] || continue
    t="$(tr '\0' ' ' <"$pid/cmdline" 2>/dev/null)"
    if [[ "$t" =~ master\ process\ \(([^\)]+)\) ]]; then RT_FPMCONF[i]="${BASH_REMATCH[1]}"; break; fi
  done
  # 2. The systemd unit gives -y, -c and PHP_INI_SCAN_DIR.
  if have systemctl && [ -d /run/systemd/system ]; then
    while read -r u; do
      ex="$(systemctl show -p ExecStart --value "$u" 2>/dev/null)"
      [[ "$ex" == *"$bin"* ]] || continue
      argv="${ex#*argv[]=}"; argv="${argv%% ;*}"
      [ -z "${RT_FPMCONF[i]}" ] && [[ "$argv" =~ $re_y ]] && RT_FPMCONF[i]="${BASH_REMATCH[3]}"
      [[ "$argv" =~ $re_c ]] && RT_INI[i]="${BASH_REMATCH[3]}"
      envs="$(systemctl show -p Environment --value "$u" 2>/dev/null)"
      [[ "$envs" =~ $re_s ]] && RT_SCANENV[i]="${BASH_REMATCH[2]}"
      RT_UNIT[i]="$u"
      break
    done < <(systemctl list-units --type=service --all --no-legend --plain 2>/dev/null | awk '{print $1}' | grep -Ei 'php|fpm')
  fi
  # 3. Default of the binary.
  [ -n "${RT_FPMCONF[i]}" ] || RT_FPMCONF[i]="$(fpm_default_conf "$bin")"
  return 0
}

# ---------------------------------------------------------------------------
# Mitigation state: is it there, does the runtime really use it, and is it loaded?
# ---------------------------------------------------------------------------
norm_ini() {  # norm_ini VALUE -> 1 / 0 for booleans, the value otherwise
  local v; v="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/^ *//; s/ *$//')"
  case "$v" in on|1|true|yes) echo 1 ;; off|0|false|no|"") echo 0 ;; *) printf '%s\n' "$v" ;; esac
}

apache_mitigation_conf() {  # path of the Apache mitigation file for this OS (may not exist)
  if [ -d /etc/apache2/conf-available ]; then printf '%s' "/etc/apache2/conf-enabled/$APACHE_CONF_NAME"
  elif [ -d /etc/httpd/conf.d ]; then printf '%s' "/etc/httpd/conf.d/zz-$APACHE_CONF_NAME"; fi
}

mitigation_state() {  # mitigation_state INDEX -> RT_MITIG: none, effective, pending_restart, not_effective
  local i="$1" b="${RT_BRANCH[$1]}" files=() f d k v got info newest=0 m bad=0 pools=0 blocked=0
  if [ -n "${RT_CONTAINER[i]}" ] || [ -z "$b" ]; then RT_MITIG[i]="unknown"; return; fi
  local rules; rules="$(mitigation_rules "$b")"
  case "${RT_SAPI[i]}" in
    apache2handler)
      f="$(apache_mitigation_conf)"; [ -n "$f" ] && [ -e "$f" ] && files+=("$f") ;;
    *)
      d="$(scan_dir_of "$i")"; [ -n "$d" ] && [ -f "$d/$INI_NAME" ] && files+=("$d/$INI_NAME")
      if [ "${RT_SAPI[i]}" = "fpm-fcgi" ] && [ -n "${RT_FPMCONF[i]}" ]; then
        while read -r f; do
          pools=$((pools + 1))
          grep -qxF "$MARK_BEGIN" "$f" 2>/dev/null && { blocked=$((blocked + 1)); files+=("$f"); }
        done < <(fpm_pool_files "${RT_FPMCONF[i]}" | sort -u)
      fi ;;
  esac
  if [ "${#files[@]}" -eq 0 ]; then RT_MITIG[i]="none"; return; fi
  if [ -z "$rules" ]; then RT_MITIG[i]="effective"; return; fi
  # Check the values that the runtime really reads (same -c and PHP_INI_SCAN_DIR as its service).
  if [ "${RT_SAPI[i]}" != "apache2handler" ]; then
    info="$(php_info "$i")"
    while read -r k v; do
      [ -n "$k" ] || continue
      got="$(awk -F' => ' -v k="$k" '$1 == k {print $2; exit}' <<<"$info")"
      [ "$(norm_ini "$got")" = "$(norm_ini "$v")" ] || bad=1
    done <<<"$rules"
    # PHP-FPM pools with an admin-locked block enforce the values even when conf.d is not read.
    [ "$bad" -eq 1 ] && [ "$pools" -gt 0 ] && [ "$blocked" -eq "$pools" ] && bad=0
  fi
  if [ "$bad" -eq 1 ]; then RT_MITIG[i]="not_effective"; return; fi
  for f in "${files[@]}"; do
    m="$(stat -c %Y "$f" 2>/dev/null || echo 0)"; [ "$m" -gt "$newest" ] && newest="$m"
  done
  # Processes that started before the newest change still use the old configuration.
  if [ "${RT_RUNNING[i]}" != "no" ] && [ -n "${RUN_START[${RT_PATH[i]}]:-}" ] && [ "${RUN_START[${RT_PATH[i]}]}" -lt "$newest" ]; then
    RT_MITIG[i]="pending_restart"
  else
    RT_MITIG[i]="effective"
  fi
}

fpm_pool_files() {  # fpm_pool_files MAIN_CONF
  local conf="$1" inc dir f
  [ -r "$conf" ] || return 0
  grep -q '^[[:space:]]*\[[^]]*\]' "$conf" && awk '/^[[:space:]]*\[/{s=$0; gsub(/[][ \t]/,"",s); if (s!="global") {found=1}} END{exit !found}' "$conf" && printf '%s\n' "$conf"
  dir="$(dirname -- "$conf")"
  while read -r inc; do
    inc="${inc%%;*}"; inc="${inc//\"/}"; inc="$(printf '%s' "$inc" | sed 's/[[:space:]]*$//')"
    inc="${inc//\$\{prefix\}/\/usr}"
    case "$inc" in /*) ;; *) inc="$dir/${inc#./}" ;; esac
    for f in $inc; do [ -f "$f" ] && printf '%s\n' "$f"; done
  done < <(sed -n 's/^[[:space:]]*include[[:space:]]*=[[:space:]]*//p' "$conf")
}

patch_pool_file() {  # patch_pool_file FILE BRANCH [remove] -- adds (or removes) the block in every non-global section
  local f="$1" b="$2" mode="${3:-add}" tmp blk
  tmp="$(mktemp)"; blk="$(mktemp)"
  if [ "$mode" = remove ]; then : >"$blk"; else fpm_block "$b" >"$blk"; fi
  awk -v bfile="$blk" -v mb="$MARK_BEGIN" -v me="$MARK_END" '
    BEGIN { while ((getline l < bfile) > 0) block = block l "\n" }
    $0 == mb { skip = 1; next }
    $0 == me { skip = 0; next }
    skip { next }
    /^[ \t]*\[[^]]+\][ \t]*$/ {
      if (insec) printf "%s", block
      s = $0; gsub(/[][ \t]/, "", s); insec = (s != "global")
    }
    { print }
    END { if (insec) printf "%s", block }
  ' "$f" >"$tmp"
  # cksum is in coreutils; cmp (diffutils) is missing on minimal images.
  if [ "$(cksum <"$f")" = "$(cksum <"$tmp")" ]; then rm -f "$tmp" "$blk"; return 1; fi
  backup_file "$f"
  cat "$tmp" >"$f"
  rm -f "$tmp" "$blk"
  return 0
}

apache_mitigation() {  # apache_mitigation BRANCH  (mod_php only)
  local b="$1" conf content mod k v lines=""
  while read -r k v; do [ -n "$k" ] && lines="$lines    php_admin_value $k $v
"; done < <(mitigation_rules "$b")
  [ -n "$lines" ] || return 0
  content="# Managed by php-safepatch. Interim mitigation for $ADV_ID ($ADV_CVES)."
  for mod in php_module php7_module php5_module; do
    content="$content
<IfModule $mod>
${lines}</IfModule>"
  done
  if [ -d /etc/apache2/conf-available ]; then
    conf="/etc/apache2/conf-available/$APACHE_CONF_NAME"
    if write_file_if_changed "$conf" "$content"; then CHANGED_APACHE=1; fi
    if [ ! -e "/etc/apache2/conf-enabled/$APACHE_CONF_NAME" ]; then
      backup_file "/etc/apache2/conf-enabled/$APACHE_CONF_NAME"
      ln -s "../conf-available/$APACHE_CONF_NAME" "/etc/apache2/conf-enabled/$APACHE_CONF_NAME"
      CHANGED_APACHE=1
    fi
  elif [ -d /etc/httpd/conf.d ]; then
    conf="/etc/httpd/conf.d/zz-$APACHE_CONF_NAME"
    if write_file_if_changed "$conf" "$content"; then CHANGED_APACHE=1; fi
  else
    warn "Apache configuration directory not found. Add these php_admin_value lines to the Apache configuration manually:"
    printf '%s' "$lines" >&2
    return 1
  fi
  [ "$CHANGED_APACHE" -eq 1 ] && ACTIONS_DONE+=("apache:$conf")
  return 0
}

mark_fpm_changed() { in_list "$1" ${CHANGED_FPM_IDX[@]+"${CHANGED_FPM_IDX[@]}"} || CHANGED_FPM_IDX+=("$1"); }

mitigate_branch() {  # mitigate_branch BRANCH
  local b="$1" d i f
  if [ -z "$(mitigation_rules "$b")" ]; then
    warn "Advisory $ADV_ID has no mitigation rule for branch $b. Nothing to mitigate."
    return 0
  fi
  for d in $(ini_dirs_for_branch "$b"); do
    [ -d "$d" ] || continue
    if write_file_if_changed "$d/$INI_NAME" "$(ini_body "$b")"; then
      info "Mitigation file $d/$INI_NAME"; ACTIONS_DONE+=("ini:$d/$INI_NAME")
    fi
  done
  for i in "${!RT_PATH[@]}"; do
    [ "${RT_BRANCH[i]}" = "$b" ] && [ -z "${RT_CONTAINER[i]}" ] || continue
    case "${RT_SAPI[i]}" in
      fpm-fcgi)
        [ -n "${RT_FPMCONF[i]}" ] || { err "Cannot find the php-fpm.conf that ${RT_PATH[i]} uses"; continue; }
        while read -r f; do
          if patch_pool_file "$f" "$b"; then
            info "FPM pool $f: admin-locked mitigation"; ACTIONS_DONE+=("fpm-pool:$f"); mark_fpm_changed "$i"
          fi
        done < <(fpm_pool_files "${RT_FPMCONF[i]}" | sort -u)
        ;;
      apache2handler) apache_mitigation "$b" ;;
    esac
  done
}

unmitigate_branch() {  # removes every php-safepatch mitigation of a branch that is now patched
  local b="$1" d i f c
  for d in $(ini_dirs_for_branch "$b"); do
    if [ -f "$d/$INI_NAME" ]; then backup_file "$d/$INI_NAME"; rm -f "$d/$INI_NAME"; ACTIONS_DONE+=("removed:$d/$INI_NAME"); fi
  done
  for i in "${!RT_PATH[@]}"; do
    [ "${RT_BRANCH[i]}" = "$b" ] && [ -z "${RT_CONTAINER[i]}" ] || continue
    case "${RT_SAPI[i]}" in
      fpm-fcgi)
        [ -n "${RT_FPMCONF[i]}" ] || continue
        while read -r f; do
          if patch_pool_file "$f" "$b" remove; then
            ACTIONS_DONE+=("removed:fpm-pool:$f"); mark_fpm_changed "$i"
          fi
        done < <(fpm_pool_files "${RT_FPMCONF[i]}" | sort -u)
        ;;
      apache2handler)
        for c in "/etc/apache2/conf-enabled/$APACHE_CONF_NAME" "/etc/apache2/conf-available/$APACHE_CONF_NAME" "/etc/httpd/conf.d/zz-$APACHE_CONF_NAME"; do
          if [ -e "$c" ] || [ -L "$c" ]; then backup_file "$c"; rm -f -- "$c"; ACTIONS_DONE+=("removed:$c"); CHANGED_APACHE=1; fi
        done ;;
    esac
  done
}

has_mitigation() {  # has_mitigation BRANCH -- true if php-safepatch files of this advisory exist for the branch
  local b="$1" i
  for i in "${!RT_PATH[@]}"; do
    [ "${RT_BRANCH[i]}" = "$b" ] && [ -z "${RT_CONTAINER[i]}" ] || continue
    [ "${RT_MITIG[i]}" != "none" ] && [ "${RT_MITIG[i]}" != "unknown" ] && return 0
  done
  local d; for d in $(ini_dirs_for_branch "$b"); do [ -f "$d/$INI_NAME" ] && return 0; done
  return 1
}

config_tests() {  # returns 1 if a changed config does not pass its test
  local i rc=0
  for i in ${CHANGED_FPM_IDX[@]+"${CHANGED_FPM_IDX[@]}"}; do
    if ! fpm_test "$i" >>"${LOG_FILE:-/dev/null}" 2>&1; then err "Config test failed: ${RT_PATH[i]} -t -y ${RT_FPMCONF[i]}"; rc=1; fi
  done
  if [ "$CHANGED_APACHE" -eq 1 ]; then
    local ctl=""
    for ctl in apache2ctl apachectl httpd; do have "$ctl" && break; ctl=""; done
    if [ -n "$ctl" ] && ! run_t 30 "$ctl" -t >>"${LOG_FILE:-/dev/null}" 2>&1; then err "Config test failed: $ctl -t"; rc=1; fi
  fi
  return $rc
}

# ---------------------------------------------------------------------------
# Services (FR-9)
# ---------------------------------------------------------------------------
restart_services() {  # restart_services "BRANCHES" -- restarts PHP and web services that host PHP
  local branches="$1" units u b want restarted=()
  if [ "$OPT_NO_RESTART" -eq 1 ]; then
    warn "Restart skipped (--no-restart). Restart PHP-FPM / Apache now to load the fix."
    ACTIONS_DONE+=("restart:skipped")
    return 0
  fi
  if have systemctl && [ -d /run/systemd/system ]; then
    mapfile -t units < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}' \
      | grep -E '^(php[0-9.]*-fpm|php-fpm|php[0-9]+-php-fpm|rh-php[0-9]+-php-fpm|ea-php[0-9]+-php-fpm|plesk-php[0-9]+-fpm|apache2|httpd|lsws|lshttpd)\.service$')
    # Units found from the runtimes themselves (custom unit names) are restarted too.
    local i
    for i in "${!RT_PATH[@]}"; do
      [ -n "${RT_UNIT[i]:-}" ] || continue
      for b in $branches; do
        [ "${RT_BRANCH[i]}" = "$b" ] && ! in_list "${RT_UNIT[i]}" "${units[@]}" && units+=("${RT_UNIT[i]}")
      done
    done
    for u in "${units[@]}"; do
      want=0
      in_list "$u" ${RT_UNIT[@]+"${RT_UNIT[@]}"} && want=1
      case "$u" in
        apache2.service|httpd.service) [ "$HAS_MOD_PHP" -eq 1 ] || [ "$CHANGED_APACHE" -eq 1 ] && want=1 ;;
        lsws.service|lshttpd.service) want=1 ;;
        php-fpm.service) want=1 ;;
        *) for b in $branches; do [[ "$u" == *"$b"* || "$u" == *"${b/./}"* ]] && want=1; done ;;
      esac
      [ "$want" -eq 1 ] || continue
      info "Restarting $u"
      if systemctl restart "$u" >>"${LOG_FILE:-/dev/null}" 2>&1; then restarted+=("$u"); else err "Restart failed: $u"; fi
    done
  else
    warn "systemd not found. Restart PHP-FPM / Apache manually."
  fi
  [ "${#restarted[@]}" -gt 0 ] && ACTIONS_DONE+=("restart:${restarted[*]}")
  return 0
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
HAS_MOD_PHP=0

do_scan() {
  discover_binaries
  inspect_binaries
  discover_mod_php
  discover_containers
  local i
  for i in "${!RT_SAPI[@]}"; do [ "${RT_SAPI[i]}" = "apache2handler" ] && HAS_MOD_PHP=1; done
  scan_processes
  for i in "${!RT_PATH[@]}"; do set_running "$i"; service_config "$i"; done
  assess_all
  for i in "${!RT_PATH[@]}"; do mitigation_state "$i"; done
  scan_dockerfiles
  check_iocs
}

refresh_state() {  # reads processes, versions and mitigation state again (after changes and restarts)
  local i
  scan_processes
  for i in "${!RT_PATH[@]}"; do
    [ -z "${RT_CONTAINER[i]}" ] || continue
    set_running "$i"
    assess_one "$i"
    mitigation_state "$i"
  done
}

confirm() {
  [ "$OPT_YES" -eq 1 ] && return 0
  if [ -t 0 ]; then
    local a; read -r -p "$1 [y/N] " a
    [[ "$a" =~ ^[Yy]([Ee][Ss])?$ ]]
  else
    err "No terminal for confirmation. Use --yes to apply without a prompt."
    return 1
  fi
}

do_apply() {
  [ "$(id -u)" -eq 0 ] || [ "${PHP_SAFEPATCH_TEST_NONROOT:-0}" = 1 ] || die "apply must run as root"
  local i b todo_branches=() patched_branches=() mitig_branches=() cleanup_branches=() bad_b
  for i in "${!RT_PATH[@]}"; do
    [ -z "${RT_CONTAINER[i]}" ] && [ -n "${RT_BRANCH[i]}" ] || continue
    b="${RT_BRANCH[i]}"
    if is_bad_status "${RT_STATUS[i]}" || [ "$OPT_MITIGATE" = "always" ]; then
      in_list "$b" ${todo_branches[@]+"${todo_branches[@]}"} || todo_branches+=("$b")
    fi
  done
  # Branches where every runtime is patched and runs the patched code, but an old mitigation is
  # still in place (for example memory_limit=-1): remove it in auto mode.
  if [ "$OPT_MITIGATE" = "auto" ]; then
    for i in "${!RT_PATH[@]}"; do
      [ -z "${RT_CONTAINER[i]}" ] && [ -n "${RT_BRANCH[i]}" ] || continue
      b="${RT_BRANCH[i]}"
      in_list "$b" ${todo_branches[@]+"${todo_branches[@]}"} ${cleanup_branches[@]+"${cleanup_branches[@]}"} && continue
      has_mitigation "$b" && cleanup_branches+=("$b")
    done
  fi
  local df_todo=0
  for i in "${!DF_FILE[@]}"; do [ "${DF_STATUS[i]}" = "VULNERABLE" ] && [ -n "${DF_FIX[i]}" ] && df_todo=1; done
  [ "$OPT_FIX_DOCKERFILES" -eq 1 ] || df_todo=0

  if [ "${#todo_branches[@]}" -eq 0 ] && [ "${#cleanup_branches[@]}" -eq 0 ] && [ "$df_todo" -eq 0 ]; then
    info "Nothing to apply on this host."
    return 0
  fi
  print_report
  printf '\nPlanned: branches [%s]%s%s. Patch: %s. Mitigate: %s. Restart: %s.\n' "${todo_branches[*]-}" \
    "$([ "${#cleanup_branches[@]}" -gt 0 ] && echo " + remove old mitigation for [${cleanup_branches[*]}]")" \
    "$([ "$df_todo" -eq 1 ] && echo ' + Dockerfile tags')" "$([ "$OPT_NO_PATCH" -eq 1 ] && echo no || echo 'same branch only')" \
    "$OPT_MITIGATE$([ "$OPT_OPTIN" -eq 1 ] && echo ' +opt-in rules')" "$([ "$OPT_NO_RESTART" -eq 1 ] && echo no || echo yes)"
  confirm "Apply these changes on $(hostname)?" || { info "Cancelled."; return 0; }

  # Preflight: a PHP-FPM whose configuration already fails its test would not start again after
  # a restart. Leave such a branch untouched and report it.
  local keep=() all_b=()
  all_b=(${todo_branches[@]+"${todo_branches[@]}"} ${cleanup_branches[@]+"${cleanup_branches[@]}"})
  for b in ${all_b[@]+"${all_b[@]}"}; do
    bad_b=0
    for i in "${!RT_PATH[@]}"; do
      [ "${RT_BRANCH[i]}" = "$b" ] && [ -z "${RT_CONTAINER[i]}" ] && [ "${RT_SAPI[i]}" = "fpm-fcgi" ] || continue
      if [ -z "${RT_FPMCONF[i]}" ] || ! fpm_test "$i" >>"${LOG_FILE:-/dev/null}" 2>&1; then
        err "Config test fails before any change: ${RT_PATH[i]} -t ${RT_FPMCONF[i]:+-y ${RT_FPMCONF[i]}}. Fix it first; branch $b is not changed."
        bad_b=1
      fi
    done
    [ "$bad_b" -eq 0 ] && keep+=("$b")
  done
  local t=() c=()
  for b in ${todo_branches[@]+"${todo_branches[@]}"}; do in_list "$b" ${keep[@]+"${keep[@]}"} && t+=("$b"); done
  for b in ${cleanup_branches[@]+"${cleanup_branches[@]}"}; do in_list "$b" ${keep[@]+"${keep[@]}"} && c+=("$b"); done
  todo_branches=(${t[@]+"${t[@]}"}); cleanup_branches=(${c[@]+"${c[@]}"})
  [ "${#todo_branches[@]}" -gt 0 ] || [ "${#cleanup_branches[@]}" -gt 0 ] || [ "$df_todo" -eq 1 ] || return 0

  health_before
  snapshot_modules before

  # 1. Patch inside the branch.
  if [ "$OPT_NO_PATCH" -eq 0 ]; then
    for b in ${todo_branches[@]+"${todo_branches[@]}"}; do
      local owner="" mgr=""
      for i in "${!RT_PATH[@]}"; do
        [ "${RT_BRANCH[i]}" = "$b" ] && [ -z "${RT_CONTAINER[i]}" ] && [ -n "${RT_PKG[i]}" ] && { owner="${RT_PKG[i]}"; mgr="${RT_PKGMGR[i]}"; break; }
      done
      case "$mgr" in
        debian) patch_debian_branch "$b" && patched_branches+=("$b") ;;
        rhel)   patch_rhel_branch "$b" "$owner" && patched_branches+=("$b") ;;
        *)      warn "Branch $b is not package-managed. php-safepatch cannot patch it; mitigation only." ;;
      esac
    done
  fi

  # 2. Assess the binaries on disk again. Processes are checked after the restart (step 7).
  if [ "${#patched_branches[@]}" -gt 0 ]; then
    for i in "${!RT_PATH[@]}"; do
      [ -z "${RT_CONTAINER[i]}" ] || continue
      in_list "${RT_BRANCH[i]}" "${patched_branches[@]}" || continue
      if [ "${RT_SAPI[i]}" = "apache2handler" ]; then
        RT_PKGVER[i]="$(pkg_version "${RT_PKG[i]}")"
        [[ "${RT_PKGVER[i]}" =~ ^([0-9]+:)?([0-9]+\.[0-9]+\.[0-9]+) ]] && RT_VERSION[i]="${BASH_REMATCH[2]}"
      else
        RT_VERSION[i]="$(parse_php_version "$(php_version_line "${RT_PATH[i]}")")"
        [ -n "${RT_PKG[i]}" ] && RT_PKGVER[i]="$(pkg_version "${RT_PKG[i]}")"
      fi
      if [ "$(branch_of "${RT_VERSION[i]}")" != "${RT_BRANCH[i]}" ]; then
        err "Branch changed for ${RT_PATH[i]}: ${RT_BRANCH[i]} -> ${RT_VERSION[i]}. Run: php-safepatch.sh rollback --run-id $(basename "$RUN_DIR")"
      fi
      assess_one "$i"
    done
  fi

  # 3. Mitigate what is still vulnerable on disk (or everything with --mitigate always).
  #    Remove the mitigation of branches that are now patched.
  if [ "$OPT_MITIGATE" != "never" ]; then
    for b in ${todo_branches[@]+"${todo_branches[@]}"}; do
      local still_bad=0
      for i in "${!RT_PATH[@]}"; do
        [ "${RT_BRANCH[i]}" = "$b" ] && [ -z "${RT_CONTAINER[i]}" ] || continue
        case "${RT_INSTALLED[i]}" in PATCHED) ;; *) still_bad=1 ;; esac
      done
      if [ "$still_bad" -eq 1 ] || [ "$OPT_MITIGATE" = "always" ]; then
        mitig_branches+=("$b"); mitigate_branch "$b"
      elif [ "$OPT_MITIGATE" = "auto" ]; then
        unmitigate_branch "$b"
      fi
    done
    for b in ${cleanup_branches[@]+"${cleanup_branches[@]}"}; do unmitigate_branch "$b"; done
  fi

  # 4. Config tests. Restore on failure.
  if ! config_tests; then
    err "Configuration test failed. Restoring the files that this run changed."
    restore_files "$RUN_DIR"
    CHANGED_FPM_IDX=(); CHANGED_APACHE=0; mitig_branches=()
    ACTIONS_DONE+=("rollback:config-files")
  fi

  # 5. Dockerfiles.
  [ "$OPT_FIX_DOCKERFILES" -eq 1 ] && fix_dockerfiles

  # 6. Restart.
  local restart_b=(${todo_branches[@]+"${todo_branches[@]}"} ${cleanup_branches[@]+"${cleanup_branches[@]}"})
  if [ "${#patched_branches[@]}" -gt 0 ] || [ "${#CHANGED_FPM_IDX[@]}" -gt 0 ] || [ "$CHANGED_APACHE" -eq 1 ] \
     || grep -q '\.ini$' "$RUN_DIR/manifest" 2>/dev/null; then
    restart_services "${restart_b[*]-}"
  fi

  # 7. Verify: processes, mitigation, extensions, health.
  refresh_state
  snapshot_modules after
  local verify_ok=1
  compare_modules || verify_ok=0
  health_after || verify_ok=0
  for i in "${!RT_PATH[@]}"; do
    [ -z "${RT_CONTAINER[i]}" ] || continue
    in_list "${RT_BRANCH[i]}" ${mitig_branches[@]+"${mitig_branches[@]}"} || continue
    case "${RT_MITIG[i]}" in
      not_effective) err "Mitigation is written but ${RT_PATH[i]} does not use it. Check how its service loads php.ini." ;;
      none) [ -n "$(mitigation_rules "${RT_BRANCH[i]}")" ] && err "No mitigation file reaches ${RT_PATH[i]}." ;;
    esac
  done
  if [ "$verify_ok" -eq 0 ]; then
    err "Verification failed. Restoring configuration files and restarting."
    restore_files "$RUN_DIR"
    CHANGED_APACHE=1
    restart_services "${restart_b[*]-}"
    refresh_state
    if [ -s "$RUN_DIR/packages.before" ]; then
      err "Packages were upgraded. To downgrade them, run: php-safepatch.sh rollback --run-id $(basename "$RUN_DIR")"
    fi
  fi
}

do_rollback() {
  [ "$(id -u)" -eq 0 ] || [ "${PHP_SAFEPATCH_TEST_NONROOT:-0}" = 1 ] || die "rollback must run as root"
  local rd
  if [ -n "$OPT_RUN_ID" ]; then rd="$OPT_STATE_DIR/$OPT_RUN_ID"
  else rd="$(grep -lx apply "$OPT_STATE_DIR"/*/command 2>/dev/null | xargs -r -n1 dirname | sort | tail -1)"; fi
  [ -n "$rd" ] && [ -d "$rd" ] || die "Run not found. Use --run-id (see $OPT_STATE_DIR)."
  info "Rolling back $rd"
  [ -s "$rd/manifest" ] && cat "$rd/manifest"
  [ -s "$rd/packages.before" ] && { printf 'Packages to restore:\n'; cat "$rd/packages.before"; }
  confirm "Restore the files and packages listed above?" || { info "Cancelled."; return 0; }
  restore_files "$rd"
  if [ -s "$rd/packages.before" ]; then
    mapfile -t pk <"$rd/packages.before"
    case "$OS_FAMILY" in
      debian) DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold "${pk[@]}" || err "Package downgrade failed. Old versions may be gone from the repository; see /var/cache/apt/archives." ;;
      rhel)   if have dnf; then dnf -y downgrade "${pk[@]}" || err "dnf downgrade failed"; else yum -y downgrade "${pk[@]}" || err "yum downgrade failed"; fi ;;
    esac
  fi
  CHANGED_APACHE=1
  HAS_MOD_PHP=1
  restart_services "$(sed -n 's/^php\([0-9]*\.[0-9]*\).*/\1/p' "$rd/packages.before" 2>/dev/null | sort -u | tr '\n' ' ') 7.4 8.0 8.1 8.2 8.3 8.4 8.5"
  info "Rollback finished."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  [ $# -gt 0 ] || { usage; exit 2; }
  CMD="$1"; shift
  case "$CMD" in -h|--help|help) usage; exit 0 ;; version|--version) echo "php-safepatch $SAFEPATCH_VERSION"; exit 0 ;; esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) OPT_JSON="${2:?--json needs a value}"; shift ;;
      --yes|-y) OPT_YES=1 ;;
      --mitigate) OPT_MITIGATE="${2:?}"; shift; in_list "$OPT_MITIGATE" auto always never || die "--mitigate must be auto, always or never" ;;
      --include-optin) OPT_OPTIN=1 ;;
      --no-patch) OPT_NO_PATCH=1 ;;
      --no-restart) OPT_NO_RESTART=1 ;;
      --no-ioc) OPT_NO_IOC=1 ;;
      --no-docker) OPT_NO_DOCKER=1 ;;
      --health-url) HEALTH_URLS+=("${2:?}"); shift ;;
      --dockerfiles) DOCKERFILE_DIRS+=("${2:?}"); shift ;;
      --fix-dockerfiles) OPT_FIX_DOCKERFILES=1 ;;
      --web-root) WEB_ROOTS+=("${2:?}"); shift ;;
      --php) EXTRA_PHP+=("${2:?}"); shift ;;
      --advisory) OPT_ADVISORY="${2:?}"; shift ;;
      --state-dir) OPT_STATE_DIR="${2:?}"; shift ;;
      --run-id) OPT_RUN_ID="${2:?}"; shift ;;
      --quiet|-q) OPT_QUIET=1 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1 (see --help)" ;;
    esac
    shift
  done

  have timeout && HAVE_TIMEOUT=1
  [ -n "$OPT_ADVISORY" ] && load_advisory "$OPT_ADVISORY"
  set_adv_names
  detect_os

  case "$CMD" in
    scan)
      [ -w "$OPT_STATE_DIR" ] || [ -w "$(dirname "$OPT_STATE_DIR")" ] && init_run_dir "$(date '+%Y%m%d-%H%M%S')-scan-$$" >/dev/null 2>&1
      do_scan ;;
    apply)
      init_run_dir "$(date '+%Y%m%d-%H%M%S')-apply-$$" || die "apply needs a writable --state-dir"
      do_scan
      do_apply ;;
    rollback)
      do_rollback
      [ "${#ERRORS[@]}" -eq 0 ] || exit 2
      exit 0 ;;
    *) usage; exit 2 ;;
  esac

  print_report
  if [ -n "$OPT_JSON" ]; then
    if [ "$OPT_JSON" = "-" ]; then write_json /dev/stdout; else write_json "$OPT_JSON"; fi
  fi
  [ -n "$RUN_DIR" ] && write_json "$RUN_DIR/report.json"

  [ "${#ERRORS[@]}" -gt 0 ] && exit 2
  [ "$(bad_count)" -gt 0 ] || [ "$(ioc_count)" -gt 0 ] && exit 1
  exit 0
}

main "$@"
