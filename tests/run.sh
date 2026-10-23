#!/usr/bin/env bash
# Runs the php-safepatch test suites.
#
#   tests/run.sh unit                     fake binaries, no container (any bash, also Git Bash)
#   tests/run.sh containers [TARGET...]   real distributions in Docker or Podman
#   tests/run.sh all                      both
#
# Targets: debian12 ubuntu2204 rocky9-appstream rocky9-remi (default: all)
# Options: --runtime docker|podman, --no-build (reuse images), --keep-logs
# SPDX-License-Identifier: MIT

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
OUT="$HERE/out"
ALL_TARGETS=(debian12 ubuntu2204 rocky9-appstream rocky9-remi)
RUNTIME=""; BUILD=1; SUITE="${1:-all}"; [ $# -gt 0 ] && shift
TARGETS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --runtime) RUNTIME="$2"; shift ;;
    --no-build) BUILD=0 ;;
    --keep-logs) ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) TARGETS+=("$1") ;;
  esac
  shift
done
[ ${#TARGETS[@]} -gt 0 ] || TARGETS=("${ALL_TARGETS[@]}")
mkdir -p "$OUT"

run_unit() {
  echo "### unit tests (fake PHP binaries)"
  bash "$HERE/unit/run.sh"
}

run_containers() {
  if [ -z "$RUNTIME" ]; then
    if command -v docker >/dev/null 2>&1; then RUNTIME=docker
    elif command -v podman >/dev/null 2>&1; then RUNTIME=podman
    else echo "No docker or podman found. Install one, or run: tests/run.sh unit"; return 2; fi
  fi
  local src="$REPO" ctx="$HERE/containers"
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)   # Git Bash: give Windows paths to Docker and stop MSYS path conversion
      src="$(cd "$REPO" && pwd -W)"; ctx="$(cd "$HERE/containers" && pwd -W)"; export MSYS_NO_PATHCONV=1 ;;
  esac
  local t rc=0 results=()
  for t in "${TARGETS[@]}"; do
    local df="$HERE/containers/$t.Dockerfile" img="php-safepatch-test:$t" log="$OUT/$t.log"
    [ -f "$df" ] || { echo "Unknown target: $t"; rc=2; continue; }
    echo "### $t ($RUNTIME)"
    if [ "$BUILD" -eq 1 ]; then
      if ! "$RUNTIME" build -q -t "$img" -f "$ctx/$t.Dockerfile" "$ctx" >"$OUT/$t.build.log" 2>&1; then
        echo "BUILD FAILED: $t (see $OUT/$t.build.log)"; results+=("$t: build failed"); rc=1; continue
      fi
    fi
    "$RUNTIME" run --rm -v "$src:/src:ro" -e SRC=/src "$img" bash /src/tests/lib/cases.sh 2>&1 | tee "$log"
    if [ "${PIPESTATUS[0]}" -eq 0 ]; then results+=("$t: ok"); else results+=("$t: FAILED"); rc=1; fi
  done
  echo; echo "### container summary"; printf '  %s\n' "${results[@]}"
  echo "  logs: $OUT"
  return $rc
}

case "$SUITE" in
  unit) run_unit ;;
  containers) run_containers ;;
  all) run_unit; u=$?; run_containers; c=$?; [ $u -eq 0 ] && [ $c -eq 0 ] ;;
  -h|--help|help) sed -n '2,12p' "$0" ;;
  *) sed -n '2,12p' "$0"; exit 2 ;;
esac
