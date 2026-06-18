# install/tests/lib.sh — sourced by test scripts. POSIX sh.
# shellcheck shell=sh
FIXTURE_PORT="${FIXTURE_PORT:-8771}"

start_fixture() {
  fixture_root="$1"
  ( cd "$fixture_root" && exec python3 -m http.server "$FIXTURE_PORT" >/dev/null 2>&1 ) &
  FIXTURE_PID=$!
  FIXTURE_URL="http://127.0.0.1:${FIXTURE_PORT}"
  i=0
  while ! curl -fsS "${FIXTURE_URL}/" >/dev/null 2>&1; do
    i=$((i+1))
    [ "$i" -gt 50 ] && { echo "fixture server failed to start"; kill "$FIXTURE_PID" 2>/dev/null || true; exit 1; }
    sleep 0.1
  done
  export FIXTURE_URL
}

stop_fixture() {
  if [ -n "${FIXTURE_PID:-}" ]; then kill "$FIXTURE_PID" 2>/dev/null || true; fi
}

assert_contains() {
  printf '%s' "$1" | grep -qF "$2" || { echo "FAIL: [$1] missing [$2] — $3"; exit 1; }
}
