#!/usr/bin/env bash
# Verify package lists are well-formed
LAIA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Base list must exist and have content
[[ -f "$LAIA_ROOT/config/packages/base.list" ]] || exit 1
PKG_COUNT=$(grep -v '^#' "$LAIA_ROOT/config/packages/base.list" | grep -v '^$' | wc -l)
[[ $PKG_COUNT -gt 10 ]] || exit 1

# AI list must exist
[[ -f "$LAIA_ROOT/config/packages/ai.list" ]] || exit 1

# No package name should have spaces (invalid)
INVALID=$(grep -v '^#' "$LAIA_ROOT/config/packages/base.list" | grep ' ' | grep -v '^$' | wc -l)
[[ $INVALID -eq 0 ]] || exit 1
