#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="$project_dir/.venv/bin/python"
if [[ ! -x "$python_bin" ]]; then
  python_bin="python3"
fi

cd "$project_dir"
PYTHONPATH="$project_dir/src" "$python_bin" -m cyberdetect.cli phase0 --config configs/pilot.yaml

