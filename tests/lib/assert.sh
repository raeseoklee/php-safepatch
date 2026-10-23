# shellcheck shell=bash
# Small assertion helpers shared by the php-safepatch tests. Source this file.
# SPDX-License-Identifier: MIT

T_PASS=0; T_FAIL=0; T_SKIP=0; T_WARN=0

pass() { T_PASS=$((T_PASS + 1)); printf 'PASS  %s\n' "$*"; }
fail() { T_FAIL=$((T_FAIL + 1)); printf 'FAIL  %s\n' "$*"; }
skip() { T_SKIP=$((T_SKIP + 1)); printf 'SKIP  %s\n' "$*"; }
twarn() { T_WARN=$((T_WARN + 1)); printf 'WARN  %s\n' "$*"; }
section() { printf '\n== %s\n' "$*"; }

check() {  # check "description" command args...
  local d="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi
}

check_eq() {  # check_eq "description" expected actual
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}

check_in() {  # check_in "description" actual allowed...
  local d="$1" a="$2" x; shift 2
  for x in "$@"; do [ "$a" = "$x" ] && { pass "$d"; return; }; done
  fail "$d (got '$a', allowed: $*)"
}

summary() {
  printf '\nResult: %d passed, %d failed, %d skipped, %d warnings\n' "$T_PASS" "$T_FAIL" "$T_SKIP" "$T_WARN"
  [ "$T_FAIL" -eq 0 ]
}

json_field() {  # json_field FILE KEY -> first string value of "KEY":"..."
  grep -o "\"$2\":\"[^\"]*\"" "$1" 2>/dev/null | head -1 | sed "s/^\"$2\":\"//; s/\"\$//"
}

same_file() {  # same_file A B -- byte comparison with coreutils only (cmp is missing on minimal images)
  [ -e "$1" ] && [ -e "$2" ] && [ "$(cksum <"$1")" = "$(cksum <"$2")" ]
}
