#!/usr/bin/env bash
LAIA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# All shell scripts must be valid bash
ERRORS=0
while IFS= read -r -d '' script; do
    if ! bash -n "$script" 2>/dev/null; then
        echo "Syntax error: $script"
        ERRORS=$((ERRORS+1))
    fi
done < <(find "$LAIA_ROOT" -name "*.sh" -not -path "*/\.*" -print0)
[[ $ERRORS -eq 0 ]]
