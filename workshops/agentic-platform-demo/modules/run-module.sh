#!/usr/bin/env bash
# run-module.sh - Extract and execute ```bash blocks from module markdown files.

set -uo pipefail

usage() {
  cat <<EOF
Usage:
  ./modules/run-module.sh <MODULE_ID> [--step]      e.g. ./modules/run-module.sh G2
  ./modules/run-module.sh <MODULE_ID> --cleanup   run only the module's Cleanup commands
  ./modules/run-module.sh --all                      runs every module that has a \`\`\`bash block, except S0 and draft cards
EOF
}

WANT_SECTION=steps
# Determine script directory and DEMO root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEMO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source environment if available
if [ -f "$DEMO_ROOT/env.sh" ]; then
  # shellcheck disable=SC1091
  . "$DEMO_ROOT/env.sh" >/dev/null 2>&1
fi

# Bold text for the command echo (empty if tput is unavailable)
B="$(tput bold 2>/dev/null || true)"; R="$(tput sgr0 2>/dev/null || true)"

extract_bash_blocks() {
  local file="$1"
  local in_block=0
  local line block="" blocks=()
  local section=steps
  while IFS= read -r line || [ -n "$line" ]; do
    # "## Cleanup" starts the cleanup section; its blocks run only with --cleanup.
    if [ "$in_block" -eq 0 ] && [ "${line#\#\# }" != "$line" ]; then
      if [ "$line" = "## Cleanup" ]; then section=cleanup; else section=steps; fi
    fi
    if [ "$in_block" -eq 0 ] && [ "$line" = '```bash' ] && [ "$section" != "$WANT_SECTION" ]; then
      continue
    fi
    if [ "$in_block" -eq 0 ] && [ "$line" = '```bash' ]; then
      in_block=1
      block=""
    elif [ "$in_block" -eq 1 ] && [ "$line" = '```' ]; then
      blocks+=("$block")
      in_block=0
    elif [ "$in_block" -eq 1 ]; then
      if [ -z "$block" ]; then
        block="$line"
      else
        block="${block}"$'\n'"${line}"
      fi
    fi
  done < "$file"
  # Output blocks separated by a delimiter that won't appear in bash code
  for b in ${blocks[@]+"${blocks[@]}"}; do
    printf '%s\n' "$b"
    printf '\x1eDELIM\x1e\n'
  done
}

run_module() {
  local id="$1"
  local step_mode="$2"
  local file=""
  local files=()

  # Find the module file matching <ID>-*.md
  for f in "$DEMO_ROOT/modules/${id}"-*.md; do
    if [ -f "$f" ]; then
      files+=("$f")
    fi
  done

  if [ "${#files[@]}" -eq 0 ]; then
    echo "Error: no module file found for $id in modules/" >&2
    return 1
  elif [ "${#files[@]}" -gt 1 ]; then
    echo "Error: multiple module files found for $id:" >&2
    for f in "${files[@]}"; do
      echo "  $f" >&2
    done
    return 1
  fi

  file="${files[0]}"

  local commands=0 nonzero=0 rc=0
  local block_blocks blocks_str line joined_line skipped_msg skip_this_block

  # Extract all bash blocks into an array using a delimiter
  blocks_str="$(extract_bash_blocks "$file")"
  if [ -z "$blocks_str" ]; then
    # No bash blocks found; treat as zero commands
    echo "${id}: 0 commands, 0 non-zero exits"
    return 0
  fi

  local blocks=()
  local tmp_block=""
  while IFS= read -r line; do
    if [ "$line" = $'\x1eDELIM\x1e' ]; then
      blocks+=("$tmp_block")
      tmp_block=""
    else
      if [ -z "$tmp_block" ]; then
        tmp_block="$line"
      else
        tmp_block="${tmp_block}"$'\n'"${line}"
      fi
    fi
  done <<< "$blocks_str"

  # Process each block
  local in_backslash=0 joined=""
  for block in "${blocks[@]}"; do
    while IFS= read -r line || [ -n "$line" ]; do
      # Skip empty lines and comment-only lines
      if [ -z "$line" ] || [[ "$line" =~ ^[[:space:]]*# ]]; then
        continue
      fi

      # Handle backslash continuation
      if [ "$in_backslash" -eq 1 ]; then
        joined="${joined}${line}"
        # Check if this line ends with backslash
        if [[ "$line" == *\\ ]]; then
          joined="${joined%\\}"
          in_backslash=1
          continue
        else
          # Finished joining
          line="$joined"
          in_backslash=0
        fi
      else
        if [[ "$line" == *\\ ]]; then
          joined="${line%\\}"
          in_backslash=1
          continue
        fi
      fi

      # Check for long-running commands to skip
      if [[ "$line" =~ logs\ deploy/mcp-gateway\ -f ]] || [[ "$line" =~ port-forward ]]; then
        echo "${B}$(printf '$ %s' "$line")${R}"
        echo "(skipped: long-running, run it in its own terminal)"
        commands=$((commands + 1))
        continue
      fi

      # Step mode: wait for Enter before executing
      if [ "$step_mode" -eq 1 ]; then
        echo "${B}$(printf '$ %s' "$line")${R}"
        read -r -p "press Enter" _ || true
      else
        echo "${B}$(printf '$ %s' "$line")${R}"
      fi

      # Execute the line in current shell
      eval "$line"
      rc=$?
      commands=$((commands + 1))
      # Lines whose comment says the gateway refuses them are expected to exit non-zero.
      if printf '%s' "$line" | grep -qiE '#.*(refused|403|401|blocked|denied|not allowed)'; then
        :   # refusal shown in the output (some tools print the 403 and exit 0)
      elif [ "$rc" -ne 0 ]; then
        nonzero=$((nonzero + 1))
      fi
    done <<< "$block"
  done

  echo "${id}: ${commands} commands, ${nonzero} non-zero exits"
  return $((nonzero > 0 ? 1 : 0))
}

# Main logic
if [ $# -eq 0 ]; then
  usage >&2
  exit 1
fi

case "$1" in
  --all)
    shift
    declare -a summary=()
    any_nonzero=0
    for f in "$DEMO_ROOT/modules/"*.md; do
      if [ ! -f "$f" ]; then continue; fi
      basename_f="$(basename "$f")"
      # Match ^[A-Z][0-9]-
      if [[ "$basename_f" =~ ^([A-Z][0-9])- ]]; then
        id="${BASH_REMATCH[1]}"
        [ "$id" = "S0" ] && continue
        # Draft cards (not yet rehearsed, may install third-party software) only run when named.
        grep -q '^\*\*Status:\*\* draft' "$f" && { echo "${id}: skipped (draft)"; continue; }
        # Check if file has any ```bash block
        if grep -q '^```bash$' "$f" 2>/dev/null; then
          # Run module and capture output to get counts
          run_output="$(run_module "$id" 0 2>&1)" || true
          # Extract command/nonzero counts from last line
          if [[ "$run_output" =~ ([A-Z][0-9]):[[:space:]]*([0-9]+)[[:space:]]+commands,[[:space:]]*([0-9]+)[[:space:]]+non-zero ]]; then
            c_count="${BASH_REMATCH[2]}"
            nz_count="${BASH_REMATCH[3]}"
          else
            c_count=0
            nz_count=0
          fi
          if [ "$nz_count" -gt 0 ]; then
            any_nonzero=1
          fi
          summary+=("${id} ${c_count} ${nz_count}")
        fi
      fi
    done

    # Print summary table
    echo "ID  commands  nonzero"
    for entry in "${summary[@]}"; do
      printf '%s\n' "$entry"
    done

    exit $((any_nonzero > 0 ? 1 : 0))
    ;;
  --help|-h)
    usage
    exit 0
    ;;
  *)
    module_id="$1"
    shift
    step_mode=0
    case "${1:-}" in
      --step) step_mode=1 ;;
      --cleanup) WANT_SECTION=cleanup ;;
    esac
    run_module "$module_id" "$step_mode"
    exit $?
    ;;
esac
