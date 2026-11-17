#!/usr/bin/env bash
# Starts the TypeSafe Guardrail Studio demo server.
#
#   ./start.sh            → serve on PORT (default 3100)
#   ./start.sh 3200       → serve on port 3200
#   ./start.sh --test     → serve, run the enforce-mode calibration, then stop
#   ./start.sh --test 3200
#
# Needs TYPESAFE_API_KEY in .env (gitignored).
set -euo pipefail
cd "$(dirname "$0")"

MODE=""
for arg in "$@"; do
  case "$arg" in
    --test) MODE="test" ;;
    [0-9]*) PORT="$arg" ;;
    *) echo "start.sh: unknown argument '$arg'" >&2; exit 2 ;;
  esac
done

PORT="${PORT:-3100}"
ROUNDS="${ROUNDS:-3}"

# Free the port: an older instance left running would just fail with EADDRINUSE.
if pids=$(lsof -t -i :"$PORT" -sTCP:LISTEN 2>/dev/null) && [[ -n "$pids" ]]; then
  echo "start.sh: port $PORT busy (pid $pids) — stopping it"
  kill $pids 2>/dev/null || true
  for _ in $(seq 1 10); do
    lsof -t -i :"$PORT" -sTCP:LISTEN >/dev/null 2>&1 || break
    sleep 1
  done
  if lsof -t -i :"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "start.sh: port $PORT still busy, forcing" >&2
    kill -9 $(lsof -t -i :"$PORT" -sTCP:LISTEN) 2>/dev/null || true
    sleep 1
  fi
fi

[[ -f .env ]] || { echo "start.sh: .env not found — TYPESAFE_API_KEY is required" >&2; exit 1; }
grep -q '^TYPESAFE_API_KEY=".\+"' .env || {
  echo "start.sh: TYPESAFE_API_KEY is empty in .env" >&2; exit 1; }

# server.ts imports fixtures from evaluator.test.ts, which bun refuses to load
# outside its test runner — tsx is the supported entrypoint here.
run_server() { PORT="$PORT" npx tsx server.ts; }

wait_for_api() {
  for _ in $(seq 1 40); do
    if curl -sf -m 5 "http://localhost:$PORT/api/typesafe-status" \
         | grep -q '"connected":true'; then return 0; fi
    sleep 1
  done
  echo "start.sh: server did not become ready on port $PORT" >&2
  return 1
}

if [[ "$MODE" == "test" ]]; then
  run_server > /tmp/jev-server.log 2>&1 &
  SERVER_PID=$!
  trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
  wait_for_api || { tail -20 /tmp/jev-server.log; exit 1; }
  echo "server ready on http://localhost:$PORT — running $ROUNDS enforce rounds"
  PORT="$PORT" ROUNDS="$ROUNDS" npx tsx scripts/run-enforce-rounds.ts
  PORT="$PORT" npx tsx scripts/check-negatives.ts
  exit 0
fi

echo "TypeSafe Guardrail Studio → http://localhost:$PORT"
exec_server() { run_server; }
exec_server
