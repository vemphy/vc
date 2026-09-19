#!/usr/bin/env bash
# Fails when a banned word appears in any tracked file.
# The pattern is assembled from pieces so this script does not match itself.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

pattern="f""ake|f""orged|f""raud"

hits=$(git ls-files -z \
  ':!docs/specs' ':!docs/plans' ':!pnpm-lock.yaml' ':!vc-go/go.sum' ':!LICENSE' \
  | xargs -0 grep -niE "$pattern" || true)

if [ -n "$hits" ]; then
  echo "Banned wording found:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "wording ok"
