#!/usr/bin/env bash
# The Go module embeds its own copies of the JSON-LD contexts (go:embed cannot
# reach outside the module). This fails when a copy differs from the original.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

status=0
for src in packages/vc/src/context/*.json; do
  copy="vc-go/vcctx/$(basename "$src")"
  if ! cmp -s "$src" "$copy"; then
    echo "context out of sync: $src != $copy" >&2
    status=1
  fi
done
[ $status -eq 0 ] && echo "contexts in sync"
exit $status
