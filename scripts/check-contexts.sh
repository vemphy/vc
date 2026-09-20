#!/usr/bin/env bash
# The Go module embeds its own copies of the JSON-LD contexts and of the
# schemas (go:embed cannot reach outside the module). This fails when a copy
# differs from the original, or when one side has a file the other lacks.
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
for kind in core meta envelope; do
  if ! diff -r "packages/vc/schemas/$kind" "vc-go/schema/$kind" > /dev/null; then
    echo "schemas out of sync: packages/vc/schemas/$kind != vc-go/schema/$kind" >&2
    status=1
  fi
done
[ $status -eq 0 ] && echo "contexts and schemas in sync"
exit $status
