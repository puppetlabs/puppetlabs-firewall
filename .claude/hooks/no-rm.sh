#!/usr/bin/env bash
# Project rule: never delete a file without explicit permission.
# Blocks: rm, sudo rm, xargs rm, /bin/rm, /usr/bin/rm (and similar absolute paths).
# Does not cover: find -exec rm (rm as a subprocess argument, not a shell token).

# shellcheck source=/dev/null
. "$(dirname "$0")/_parse_input.sh"

if echo "$cmd" | grep -qE '(^|[;&|])[[:space:]]*(sudo[[:space:]]+|xargs[[:space:]]+)?([^[:space:]]*/)?rm([[:space:]]|$)'; then
  echo '{"continue":false,"stopReason":"Project rule: never delete a file without explicit permission."}'
fi
