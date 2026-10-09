
#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$ROOT_DIR/.venv/bin/python"
BACKEND_DIR="$ROOT_DIR/backend"

if [[ ! -x "$PYTHON" ]]; then
    echo "ERROR: Python virtual environment not found at $PYTHON"
    echo "Create it and install the project's Python dependencies first."
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
echo "OPC017 services are starting."
echo "Dashboard:  http://127.0.0.1:4000"
echo "Health:     http://127.0.0.1:4000/api/health"
echo "Python API: http://127.0.0.1:8000/docs"
echo "Press Ctrl+C to stop both services."
echo

wait
