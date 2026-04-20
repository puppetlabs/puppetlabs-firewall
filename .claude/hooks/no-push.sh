#!/usr/bin/env bash
# Project rule: never push a branch without explicit instruction.
# Blocks: git push

# shellcheck source=/dev/null
. "$(dirname "$0")/_parse_input.sh"

if echo "$cmd" | grep -qE '(^|[;&|`(])[[:space:]]*(([[:alpha:]_][[:alnum:]_]*=[^[:space:]]*[[:space:]]+)*)([^[:space:]]*/)?git[[:space:]]+push([[:space:]]|$|[;&|])'; then
  echo '{"continue":false,"stopReason":"Project rule: never push a branch without explicit instruction."}'
fi
