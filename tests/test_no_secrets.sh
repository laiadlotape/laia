#!/usr/bin/env bash
# Verify no secrets/keys are committed
LAIA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FOUND=0
patterns=(
    "password\s*=\s*['\"][^'\"]+['\"]"
    "secret\s*=\s*['\"][^'\"]+['\"]"
    "api_key\s*=\s*['\"][^'\"]+['\"]"
    "ANTHROPIC_API_KEY"
    "-----BEGIN.*PRIVATE KEY-----"
)
for pattern in "${patterns[@]}"; do
    matches=$(grep -rn --include="*.json" --include="*.yaml" --include="*.sh" \
        -i "$pattern" "$LAIA_ROOT" 2>/dev/null | \
        grep -v "test_no_secrets.sh" | wc -l)
    FOUND=$((FOUND + matches))
done
[[ $FOUND -eq 0 ]] || { echo "Potential secrets found ($FOUND matches)"; exit 1; }
