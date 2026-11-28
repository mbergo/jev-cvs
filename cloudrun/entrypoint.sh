#!/bin/sh
# One container, two processes: the Vertex adapter (shim, 127.0.0.1:8765) and the demo (PORT, default 8080).
set -eu
[ -n "${TYPESAFE_API_KEY:-}" ] || { echo "TYPESAFE_API_KEY is not set" >&2; exit 1; }
# the same secret is the demo's bearer key and the shim's accepted key
umask 077
printf '%s' "$TYPESAFE_API_KEY" > "$JEV_SHIM_KEY_FILE"
cd /srv/shim
/opt/venv/bin/uvicorn jev_shim:app --host 127.0.0.1 --port 8765 &
i=0
until python3 -c "import socket; socket.create_connection(('127.0.0.1', 8765), 1)" 2>/dev/null; do
  i=$((i + 1)); [ "$i" -ge 60 ] && { echo "shim did not start" >&2; exit 1; }; sleep 1
done
cd /app
exec npx tsx server.ts
