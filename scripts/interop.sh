#!/usr/bin/env bash
# Cross-checks the TypeScript package and the Go module against each other
# with a key generated on the spot, so neither side can pass by remembering
# a fixture:
#   1. both produce the same canonical N-Quads for every claim in vectors/
#   2. TypeScript signs, Go verifies
#   3. Go signs, TypeScript verifies
#   4. both sign the same document and produce the same proofValue
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

(cd vc-go && go build -o "$work/vcinterop" ./cmd/vcinterop)
go_tool="$work/vcinterop"
ts_tool() { (cd packages/vc && pnpm exec tsx scripts/interop.ts "$@"); }

seed=$(openssl rand -hex 32)
key=$(ts_tool pubkey --seed "$seed")
vm="did:web:vemphy.com:i:gcb#key-1"
created="2026-06-01T12:00:00Z"
echo "fresh key $key"

count=0
for claim in vectors/claims/*.json; do
  name=$(basename "$claim" .json)
  # Strip the proof. gcb-009 carries a context neither side will load, by design.
  [ "$name" = "gcb-009" ] && continue
  node -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1]));delete c.proof;process.stdout.write(JSON.stringify(c))' "$claim" > "$work/$name.unsigned.json"

  ts_tool canon < "$work/$name.unsigned.json" > "$work/$name.ts.nq"
  "$go_tool" canon < "$work/$name.unsigned.json" > "$work/$name.go.nq"
  cmp "$work/$name.ts.nq" "$work/$name.go.nq" || { echo "canonical forms differ for $name" >&2; exit 1; }

  ts_tool sign --seed "$seed" --vm "$vm" --created "$created" < "$work/$name.unsigned.json" > "$work/$name.ts.signed.json"
  "$go_tool" verify --key "$key" < "$work/$name.ts.signed.json" > /dev/null || { echo "Go rejected a TypeScript signature on $name" >&2; exit 1; }

  "$go_tool" sign --seed "$seed" --vm "$vm" --created "$created" < "$work/$name.unsigned.json" > "$work/$name.go.signed.json"
  ts_tool verify --key "$key" < "$work/$name.go.signed.json" > /dev/null || { echo "TypeScript rejected a Go signature on $name" >&2; exit 1; }

  a=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).proof.proofValue' "$work/$name.ts.signed.json")
  b=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).proof.proofValue' "$work/$name.go.signed.json")
  [ "$a" = "$b" ] || { echo "proofValue differs for $name" >&2; exit 1; }

  # And a signature must not survive a change, on either side.
  sed 's/"validFrom": "20/"validFrom": "21/' "$work/$name.ts.signed.json" > "$work/$name.altered.json"
  if "$go_tool" verify --key "$key" < "$work/$name.altered.json" > /dev/null 2>&1; then echo "Go accepted an altered $name" >&2; exit 1; fi
  if ts_tool verify --key "$key" < "$work/$name.altered.json" > /dev/null 2>&1; then echo "TypeScript accepted an altered $name" >&2; exit 1; fi

  count=$((count + 1))
done
echo "interop ok: $count claims, both directions"
