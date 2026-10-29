#!/usr/bin/env bash
#
# Print the CHANGELOG.md section for one version, used by the release
# workflow to build the GitHub Release body.
#
#   script/extract-changelog.sh 1.0.0
#
# Matches a header like "## 1.0.0 (2026-10-25)" and prints everything up
# to the next "## " header.
#
set -euo pipefail

version="${1:?usage: extract-changelog.sh VERSION}"
changelog="${2:-CHANGELOG.md}"

awk -v ver="$version" '
  # Start at the header for this version. Escape dots so 1.0.0 is literal.
  {
    header = "^## " ver "([^0-9]|$)"
    gsub(/\./, "\\.", header)
  }
  $0 ~ header { found = 1; next }
  found && /^## / { exit }
  found { print }
' "$changelog" | sed -e '/./,$!d'
