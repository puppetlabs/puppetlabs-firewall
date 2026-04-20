#!/usr/bin/env bash
# Shared helper: reads hook JSON from stdin and sets $cmd to the Bash tool command.
# Sources into each hook with: . "$(dirname "$0")/_parse_input.sh"
# Exits 0 (allow) if no JSON parser is available.

if command -v jq >/dev/null 2>&1; then
  # shellcheck disable=SC2034  # cmd is used by the sourcing hook script
  cmd=$(jq -r '.tool_input.command // ""' 2>/dev/null || echo "")
elif command -v python3 >/dev/null 2>&1; then
  # shellcheck disable=SC2034  # cmd is used by the sourcing hook script
  cmd=$(python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_input',{}).get('command',''))" 2>/dev/null || echo "")
else
  exit 0
fi
