#!/usr/bin/env bash
LAIA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$LAIA_ROOT/config/openclaw/openclaw-restricted.json"
[[ -f "$CONFIG" ]] || exit 1
python3 -c "import json; json.load(open('$CONFIG'))" || exit 1
# Verify bind is localhost
python3 -c "
import json, sys
c = json.load(open('$CONFIG'))
bind = c.get('security', {}).get('bind', '')
assert bind == '127.0.0.1', f'bind={bind}, expected 127.0.0.1'
ask = c.get('security', {}).get('exec', {}).get('ask', '')
assert ask in ('always',), f'ask={ask}, expected always'
print('OpenClaw config: secure defaults verified')
"
