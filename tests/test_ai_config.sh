#!/usr/bin/env bash
LAIA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# AI config files
[[ -f "$LAIA_ROOT/config/ai/models.yaml" ]] || exit 1
[[ -f "$LAIA_ROOT/config/ai/install-ollama.sh" ]] || exit 1
[[ -f "$LAIA_ROOT/config/ai/install-models.sh" ]] || exit 1
[[ -f "$LAIA_ROOT/config/ai/install-ai-stack.sh" ]] || exit 1
bash -n "$LAIA_ROOT/config/ai/install-ollama.sh" || exit 1
bash -n "$LAIA_ROOT/config/ai/install-models.sh" || exit 1
# models.yaml must have at least 3 models
MODEL_COUNT=$(grep -c "^\s*- id:" "$LAIA_ROOT/config/ai/models.yaml" 2>/dev/null || echo 0)
[[ $MODEL_COUNT -ge 3 ]] || exit 1
