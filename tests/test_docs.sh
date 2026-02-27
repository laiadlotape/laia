#!/usr/bin/env bash
LAIA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
required_docs=(
    "README.md" "docs/INSTALL.md" "docs/SECURITY.md"
    "docs/AI_MODELS.md" "docs/BUILD.md" "docs/USER_GUIDE.md"
    "LICENSE"
)
for f in "${required_docs[@]}"; do
    [[ -f "$LAIA_ROOT/$f" ]] || { echo "Missing doc: $f"; exit 1; }
    WORDS=$(wc -w < "$LAIA_ROOT/$f")
    [[ $WORDS -gt 20 ]] || { echo "Doc too short: $f ($WORDS words)"; exit 1; }
done
