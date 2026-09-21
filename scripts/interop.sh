#!/usr/bin/env bash
# Cross-checks the TypeScript package and the Go module against each other
# with a key generated on the spot, so neither side can pass by remembering
# a fixture:
#   1. both produce the same canonical N-Quads for every claim in vectors/
#   2. TypeScript signs, Go verifies
#   3. Go signs, TypeScript verifies
#   4. both sign the same document and produce the same proofValue
#   5. both generate the same context, byte for byte, from a schema made up on the spot
#   6. the same four checks hold for the signed issuer directory too, whose @context
#      carries its whole term vocabulary inline, and an altered entry is refused by both
#   7. the real directory entry points — vcinterop's directory subcommand and the
#      TypeScript verify-directory CLI — both accept a properly signed directory and
#      both reject one that has expired or been altered
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

(cd vc-go && go build -o "$work/vcinterop" ./cmd/vcinterop)
go_tool="$work/vcinterop"
cache="$PWD/vectors/cache"
ts_tool() { (cd packages/vc && pnpm exec tsx scripts/interop.ts "$@"); }
vc_cli() { (cd packages/vc && pnpm exec tsx cli/main.ts "$@"); }

seed=$(openssl rand -hex 32)
key=$(ts_tool pubkey --seed "$seed")
vm="did:web:vemphy.com:i:gcb#key-1"
created="2026-06-01T12:00:00Z"
echo "fresh key $key"

count=0
for claim in vectors/claims/*.json; do
  name=$(basename "$claim" .json)
  # Strip the proof. gcb-009 and ug-002 carry a context neither side will load, by design.
  [ "$name" = "gcb-009" ] || [ "$name" = "ug-002" ] && continue
  node -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1]));delete c.proof;process.stdout.write(JSON.stringify(c))' "$claim" > "$work/$name.unsigned.json"

  ts_tool canon --cache "$cache" < "$work/$name.unsigned.json" > "$work/$name.ts.nq"
  "$go_tool" canon --cache "$cache" < "$work/$name.unsigned.json" > "$work/$name.go.nq"
  cmp "$work/$name.ts.nq" "$work/$name.go.nq" || { echo "canonical forms differ for $name" >&2; exit 1; }

  ts_tool sign --cache "$cache" --seed "$seed" --vm "$vm" --created "$created" < "$work/$name.unsigned.json" > "$work/$name.ts.signed.json"
  "$go_tool" verify --cache "$cache" --key "$key" < "$work/$name.ts.signed.json" > /dev/null || { echo "Go rejected a TypeScript signature on $name" >&2; exit 1; }

  "$go_tool" sign --cache "$cache" --seed "$seed" --vm "$vm" --created "$created" < "$work/$name.unsigned.json" > "$work/$name.go.signed.json"
  ts_tool verify --cache "$cache" --key "$key" < "$work/$name.go.signed.json" > /dev/null || { echo "TypeScript rejected a Go signature on $name" >&2; exit 1; }

  a=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).proof.proofValue' "$work/$name.ts.signed.json")
  b=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).proof.proofValue' "$work/$name.go.signed.json")
  [ "$a" = "$b" ] || { echo "proofValue differs for $name" >&2; exit 1; }

  # And a signature must not survive a change, on either side.
  sed 's/"validFrom": "20/"validFrom": "21/' "$work/$name.ts.signed.json" > "$work/$name.altered.json"
  if "$go_tool" verify --cache "$cache" --key "$key" < "$work/$name.altered.json" > /dev/null 2>&1; then echo "Go accepted an altered $name" >&2; exit 1; fi
  if ts_tool verify --cache "$cache" --key "$key" < "$work/$name.altered.json" > /dev/null 2>&1; then echo "TypeScript accepted an altered $name" >&2; exit 1; fi

  count=$((count + 1))
done

# The signed issuer directory gets the same treatment as a claim, using the
# vector a receiver would actually be handed: vectors/directory/good.json.
node -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1]));delete c.proof;process.stdout.write(JSON.stringify(c))' vectors/directory/good.json > "$work/directory.unsigned.json"

# This is the single most valuable assertion in this script: the directory's
# @context carries an inline term vocabulary (did, slug, status, legalName,
# and the two types) rather than pointing at a published one, and if the two
# JSON-LD implementations disagreed about it at all, every signature over a
# directory would disagree too.
ts_tool canon --cache "$cache" < "$work/directory.unsigned.json" > "$work/directory.ts.nq"
"$go_tool" canon --cache "$cache" < "$work/directory.unsigned.json" > "$work/directory.go.nq"
cmp "$work/directory.ts.nq" "$work/directory.go.nq" || { echo "canonical forms differ for the directory" >&2; exit 1; }

ts_tool sign --cache "$cache" --seed "$seed" --vm "$vm" --created "$created" < "$work/directory.unsigned.json" > "$work/directory.ts.signed.json"
"$go_tool" verify --cache "$cache" --key "$key" < "$work/directory.ts.signed.json" > /dev/null || { echo "Go rejected a TypeScript signature on the directory" >&2; exit 1; }

"$go_tool" sign --cache "$cache" --seed "$seed" --vm "$vm" --created "$created" < "$work/directory.unsigned.json" > "$work/directory.go.signed.json"
ts_tool verify --cache "$cache" --key "$key" < "$work/directory.go.signed.json" > /dev/null || { echo "TypeScript rejected a Go signature on the directory" >&2; exit 1; }

a=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).proof.proofValue' "$work/directory.ts.signed.json")
b=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).proof.proofValue' "$work/directory.go.signed.json")
[ "$a" = "$b" ] || { echo "proofValue differs for the directory" >&2; exit 1; }

# An altered entry must be refused too, and it has to be a field the inline
# vocabulary covers, an issuer's status, rather than a top-level field: that
# is what proves the vocabulary is genuinely inside what was signed.
node -e '
const c = JSON.parse(require("fs").readFileSync(process.argv[1]))
c.credentialSubject.issuers[0].status = c.credentialSubject.issuers[0].status === "active" ? "suspended" : "active"
process.stdout.write(JSON.stringify(c))
' "$work/directory.ts.signed.json" > "$work/directory.altered.json"
if "$go_tool" verify --cache "$cache" --key "$key" < "$work/directory.altered.json" > /dev/null 2>&1; then echo "Go accepted an altered directory" >&2; exit 1; fi
if ts_tool verify --cache "$cache" --key "$key" < "$work/directory.altered.json" > /dev/null 2>&1; then echo "TypeScript accepted an altered directory" >&2; exit 1; fi

# Finally, the real end-to-end paths against the committed, properly signed
# good.json: vcinterop's directory subcommand, which resolves the signing key
# from an apex DID document the way a receiver would, and the TypeScript
# verify-directory CLI. now comes from expected.json so the expired vector is
# genuinely expired as of the instant both sides check against.
apex_now=$(node -p 'JSON.parse(require("fs").readFileSync("vectors/expected.json")).now')

"$go_tool" directory --apex vectors/keys/apex.did.json --now "$apex_now" < vectors/directory/good.json > /dev/null \
  || { echo "vcinterop directory rejected a valid directory" >&2; exit 1; }
vc_cli verify-directory ../../vectors/directory/good.json --apex-doc ../../vectors/keys/apex.did.json --now "$apex_now" > /dev/null \
  || { echo "verify-directory rejected a valid directory" >&2; exit 1; }

if "$go_tool" directory --apex vectors/keys/apex.did.json --now "$apex_now" < vectors/directory/expired.json > /dev/null 2>&1; then
  echo "vcinterop directory accepted an expired directory" >&2; exit 1
fi
if vc_cli verify-directory ../../vectors/directory/expired.json --apex-doc ../../vectors/keys/apex.did.json --now "$apex_now" > /dev/null 2>&1; then
  echo "verify-directory accepted an expired directory" >&2; exit 1
fi

if "$go_tool" directory --apex vectors/keys/apex.did.json --now "$apex_now" < vectors/directory/altered-status.json > /dev/null 2>&1; then
  echo "vcinterop directory accepted an altered directory" >&2; exit 1
fi
if vc_cli verify-directory ../../vectors/directory/altered-status.json --apex-doc ../../vectors/keys/apex.did.json --now "$apex_now" > /dev/null 2>&1; then
  echo "verify-directory accepted an altered directory" >&2; exit 1
fi

# A claim type nobody has seen before: random name, random keys, every kind of field.
suffix=$(openssl rand -hex 4 | tr '0-9' 'g-p')
ns="https://vemphy.com/ns/i/gcb/Fresh${suffix}/v1#"
node -e '
const [suffix] = process.argv.slice(1)
const x = (label, order) => ({ "x-vemphy": { label: { en: label }, disclosable: true, pii: false, order } })
process.stdout.write(JSON.stringify({
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  additionalProperties: false,
  "x-vemphy": { name: `Fresh${suffix}`, displayName: { en: "Fresh" } },
  properties: {
    [`text${suffix}`]: { type: "string", maxLength: 50, ...x("Text", 1) },
    [`day${suffix}`]: { type: "string", format: "date", ...x("Day", 2) },
    [`at${suffix}`]: { type: "string", format: "date-time", ...x("At", 3) },
    [`count${suffix}`]: { type: "integer", minimum: 0, maximum: 10, ...x("Count", 4) },
    [`flag${suffix}`]: { type: "boolean", ...x("Flag", 5) },
    [`choice${suffix}`]: { type: "string", enum: ["a", "b"], ...x("Choice", 6) },
  },
  required: [`text${suffix}`],
}))' "$suffix" > "$work/fresh.schema.json"
ts_tool context --namespace "$ns" < "$work/fresh.schema.json" > "$work/fresh.ts.json"
"$go_tool" context --namespace "$ns" < "$work/fresh.schema.json" > "$work/fresh.go.json"
cmp "$work/fresh.ts.json" "$work/fresh.go.json" || { echo "generated contexts differ" >&2; exit 1; }

echo "interop ok: $count claims, both directions; fresh context Fresh${suffix} identical; directory canon, cross-signing, and both entry points agree"
