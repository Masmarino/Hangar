#!/usr/bin/env bash
# Runs the backend and frontend locally for development, with Angular hot
# reload. Postgres comes from docker-compose (started here if not already
# running) rather than a separate container — same data, one less thing to
# keep track of. Ctrl+C stops the backend and frontend; Postgres is left
# running (docker-compose's own `restart: unless-stopped` policy already
# manages it).
#
# The backend still runs as a local `cargo run` process on its own port
# (8081), not the docker-compose hangar-api container (8080) — that's what
# gives the frontend hot reload against a fast-rebuilding local binary.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# docker-compose reads POSTGRES_PASSWORD from .env itself; source it here too
# so the locally-run backend connects with the same credentials.
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

export DATABASE_URL="postgres://hangar:${POSTGRES_PASSWORD:-hangar}@localhost:5432/hangar"
export JWT_SECRET="local-dev-secret-not-for-production"
export HANGAR_BASE_DOMAIN="${HANGAR_BASE_DOMAIN:-hangar.localhost}"
export BIND_ADDR="0.0.0.0:8081"
# The browser only ever talks to the Angular dev server on 4200 (proxy.conf.json
# forwards /api, /npm, /v2 to :8081) — it never sees :8081 directly. Without this,
# the backend computes its WebAuthn relying-party origin from BIND_ADDR's own port
# (8081), which never matches the :4200 origin a passkey ceremony's clientDataJSON
# actually records, and every passkey registration/login fails with InvalidRPOrigin.
export PUBLIC_URL="${PUBLIC_URL:-http://localhost:4200}"
export STORAGE_ROOT="$ROOT_DIR/data"
export HANGAR_BOOTSTRAP_ADMIN_USERNAME="admin"
export HANGAR_BOOTSTRAP_ADMIN_PASSWORD="admin123"
export RUST_LOG="${RUST_LOG:-info}"

echo "==> Starting Postgres (docker-compose, port 5432)"
docker compose up -d --wait postgres

echo "==> Running migrations"
sqlx migrate run --source crates/hangar-infrastructure/migrations

echo "==> Starting backend (cargo run -p hangar-api, port 8081)"
cargo run -p hangar-api &
BACKEND_PID=$!

CLEANED_UP=0
cleanup() {
  [ "$CLEANED_UP" = 1 ] && return
  CLEANED_UP=1
  echo
  echo "==> Stopping backend"
  kill "$BACKEND_PID" 2>/dev/null || true
  wait "$BACKEND_PID" 2>/dev/null || true
  # Postgres is left running — stop it manually if you want it down too:
  #   docker compose stop postgres
  exit 0
}
trap cleanup EXIT INT TERM

echo "==> Starting frontend (npm start, port 4200, hot reload)"
npm start --prefix frontend
