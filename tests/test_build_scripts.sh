#!/usr/bin/env bash
LAIA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Build files must exist
[[ -f "$LAIA_ROOT/build/Makefile" ]] || exit 1
[[ -f "$LAIA_ROOT/build/build-iso.sh" ]] || exit 1
bash -n "$LAIA_ROOT/build/build-iso.sh" || exit 1
bash -n "$LAIA_ROOT/scripts/install.sh" || exit 1
