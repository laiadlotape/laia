#!/usr/bin/env bash
LAIA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
required_dirs=(
    "build" "config/security" "config/ai" "config/openclaw"
    "config/packages" "gui/laia-configurator" "gui/laia-setup-wizard"
    "scripts" "tests" "docs" ".github/workflows"
)
for d in "${required_dirs[@]}"; do
    [[ -d "$LAIA_ROOT/$d" ]] || { echo "Missing dir: $d"; exit 1; }
done
