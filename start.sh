
#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$ROOT_DIR/.venv/bin/python"
BACKEND_DIR="$ROOT_DIR/backend"

if [[ ! -x "$PYTHON" ]]; then
    echo "ERROR: Python virtual environment not found: $PYTHON"
    exit 1
fi

if [[ ! -d "$BACKEND_DIR/node_modules" ]]; then
    echo "ERROR: Node dependencies are missing."
    echo "Run: cd \"$BACKEND_DIR\" && npm install"
    exit 1
fi

if ! command -v node >/dev/null 2>&1; then
    echo "ERROR: Node.js is not installed or not on PATH."
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required to check backend readiness."
    exit 1
fi

cleanup() {
    echo
    echo "Stopping OPC017 services..."
    [[ -z "${PY_PID:-}" ]] || kill "$PY_PID" 2>/dev/null || true
    [[ -z "${NODE_PID:-}" ]] || kill "$NODE_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "Starting OPC017 Python forensic engine..."
cd "$ROOT_DIR"
"$PYTHON" -m uvicorn app.main:app --reload --port 8000 &
PY_PID=$!

echo "Starting OPC017 Node.js backend..."
cd "$BACKEND_DIR"
npm run dev &
NODE_PID=$!

echo
echo "Waiting for the Node.js backend..."

for attempt in {1..30}; do
    if curl --silent --fail http://127.0.0.1:4000/api/health >/dev/null; then
        echo "Backend is ready!"
        break
    fi

    if ! kill -0 "$NODE_PID" 2>/dev/null; then
        echo "ERROR: Node.js backend exited. Check the error above."
        exit 1
    fi

    if [[ "$attempt" -eq 30 ]]; then
        echo "WARNING: Backend did not become ready within 30 seconds."
        echo "You can open http://127.0.0.1:4000 manually once it is running."
    fi

    sleep 1
done

echo
echo "OPC017 services:"
echo "Dashboard:  http://127.0.0.1:4000"
echo "Health:     http://127.0.0.1:4000/api/health"
echo "Python API: http://127.0.0.1:8000/docs"
echo "Press Ctrl+C to stop both services."

if command -v xdg-open >/dev/null 2>&1; then
    xdg-open http://127.0.0.1:4000 >/dev/null 2>&1 &
else
    echo "Open http://127.0.0.1:4000 in your browser."
fi

wait
