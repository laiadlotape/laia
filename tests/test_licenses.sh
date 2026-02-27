#!/usr/bin/env bash
LAIA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ -f "$LAIA_ROOT/LICENSE" ]] || exit 1
# LICENSE should reference GPL-3.0
grep -qiE "GPL-3.0|GPL 3|General Public License" "$LAIA_ROOT/LICENSE" || exit 1
