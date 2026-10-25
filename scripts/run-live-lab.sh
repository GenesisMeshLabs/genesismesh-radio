#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
: "${GM_EDGE_BINARY:?Set GM_EDGE_BINARY to a built genesis-mesh-edge executable}"
radio_python="${GM_RADIO_PYTHON:-python3}"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$repo_dir/src${GM_CORE_SOURCE:+:$GM_CORE_SOURCE}${PYTHONPATH:+:$PYTHONPATH}"
exec "$radio_python" "$repo_dir/scripts/live_lab.py" --edge-binary "$GM_EDGE_BINARY" "$@"
