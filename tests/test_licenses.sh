#!/usr/bin/env bash
LAIA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ -f "$LAIA_ROOT/LICENSE" ]] || exit 1
# LICENSE should be GPL-3.0
grep -q "GNU GENERAL PUBLIC LICENSE" "$LAIA_ROOT/LICENSE" || exit 1
