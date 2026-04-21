#!/usr/bin/env bash
# Project rule: never merge a pull request.
# Blocks: gh pr merge

# shellcheck source=/dev/null
. "$(dirname "$0")/_parse_input.sh"

if echo "$cmd" | grep -qE '(^|[;&|])[[:space:]]*gh pr merge'; then
  echo '{"continue":false,"stopReason":"Project rule: never merge a pull request."}'
fi
