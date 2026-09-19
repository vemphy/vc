# `vemphy/vc` — toolkit design

Date: 2026-09-19
Status: awaiting review

## Purpose

`vemphy/vc` is the open verification toolkit for Vemphy claims: a TypeScript
package (`@vemphy/vc`), a Go module (`github.com/vemphy/vc/vc-go`) and a shared
set of test vectors. Anyone can verify a Vemphy claim with it, offline, without
a Vemphy account. The Vemphy registry uses the Go module for the same job, so
the public verifier and the registry cannot drift apart.

The two implementations must agree on every vector, byte for byte at the
canonicalization layer and outcome for outcome at the verification layer.

## Standards

- W3C Verifiable Credentials Data Model 2.0.
- Data Integrity proof, cryptosuite `eddsa-rdfc-2022`, `proofPurpose: assertionMethod`.
- RDF Dataset Canonicalization RDFC-1.0.
- `did:web`, `Multikey` verification methods, `publicKeyMultibase` (`z6Mk…`).
- Bitstring Status List 1.0 (131,072 bits, gzip, base64url).

Out of scope, seams only: JWT-VC (`Serializer`), SD-JWT, BBS+, holder wallets,
OCR, offline tokens.

## Layout

```
packages/vc/src/
  schema/      zod schemas + JSON Schema export, one file per claim type
  context/     credentials-v2.json, claims-v1.json, static document loader
  canon.ts     RDFC-1.0 (jsonld + rdf-canonize)
  proof.ts     eddsa-rdfc-2022 create (test / issuer-held only) + verify
  did.ts       did:web → URL, DID document parsing, Multikey decode
  status.ts    Bitstring Status List decode + bit check
  code.ts      Crockford base32, check character, parse / format (zero deps)
  verify.ts    verifyCredential()
  index.ts
packages/vc/cli/   npx @vemphy/vc verify <file>
vc-go/             canon/ proof/ did/ status/ code/ verify/ context/
vectors/           claims/ keys/ status/ canon/ codes.json expected.json
```

Package entry points: `@vemphy/vc` (everything), `@vemphy/vc/code` (no
dependencies; safe for a browser bundle), `@vemphy/vc/schema` (zod only).

## Identifiers

- Issuer slug: 2–4 letters. Uppercase in codes, lowercase in DIDs and URLs.
- DID: `did:web:vemphy.com:i:<slug>` → `https://vemphy.com/i/<slug>/did.json`.
- Verification method: `did:web:vemphy.com:i:<slug>#<kid>`, `kid` = `key-1`, `key-2`, …
- Credential id: `urn:vemphy:claim:<CODE>`.
- Status list: `https://vemphy.com/i/<slug>/status/<n>`.

## Codes

Format `<SLUG>-<XXXX>-<XXXX>`: seven random Crockford base32 characters and one
check character, displayed as two groups of four.

Check character: Crockford mod-37 with the extended alphabet `*~$=U`, computed
over the slug and the body together so that a mistyped slug is caught the same
way a mistyped body character is:

```
s     = slug read as a base-26 number (A = 0 … Z = 25), most significant first
n     = body read as a base-32 number (7 characters, 35 bits)
check = (s · 2^35 + n) mod 37
```

37 is prime and every per-character weight is coprime to it, so any single
character substitution, in the slug or the body, changes the check value. The
plain `checkChar(n)` function is exposed separately and tested against
Crockford's published vectors.

Decoding is case-insensitive. In the body, `O → 0` and `I`, `L → 1`. The slug
is letters and is never folded. Hyphens and whitespace are ignored. `parse`
accepts a bare code or a `https://vemphy.com/v/<CODE>` link.

`parse` returns either the normalised code or a failure carrying the position
most likely to be wrong, which the verify app turns into "check the 5th
character". A failed check character is reported before any network or
database access.

Codes whose check character is one of `* ~ $ =` are valid to decode but are
marked `issuable: false`: chat applications treat `*` and `~` as formatting
marks. `isIssuable(code)` is exported; issuers draw again when it is false.

## Credential shape

```jsonc
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://vemphy.com/ns/claims/v1"
  ],
  "id": "urn:vemphy:claim:GCB-7K2M-9QXT",
  "type": ["VerifiableCredential", "BankReferenceLetter"],
  "issuer": "did:web:vemphy.com:i:gcb",
  "validFrom": "2026-01-10T09:00:00Z",
  "validUntil": "2026-04-10T09:00:00Z",
  "credentialSubject": { "accountHolderName": "…" },
  "credentialStatus": {
    "id": "https://vemphy.com/i/gcb/status/1#94567",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://vemphy.com/i/gcb/status/1"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2026-01-10T09:00:00Z",
    "verificationMethod": "did:web:vemphy.com:i:gcb#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z…"
  }
}
```

## Claims context v1

Served at `https://vemphy.com/ns/claims/v1`. `@protected: true`. Vocabulary
base `https://vemphy.com/ns/claims#`. Date fields are typed `xsd:date`.

The context is append-only. A signed claim's hash depends on how each term
expands, so an existing term definition is never edited or removed; changes
that are not purely additive go in a `v2` context at a new URL.

### Claim types

Fields marked ● are in the type's default disclosure set. `?` = optional.

**BankReferenceLetter**

| Field | Type | |
|---|---|---|
| accountHolderName | string | ● |
| accountType | `current` \| `savings` \| `business` | ● |
| accountNumberLast4 | 4 digits | |
| accountOpenedOn | date | |
| branch | string | |
| standing | `satisfactory` \| `unsatisfactory` | ● |
| addressedTo? | string | |
| referenceDate | date | ● |

**DegreeCertificate**

| Field | Type | |
|---|---|---|
| graduateName | string | ● |
| studentNumber | string | |
| qualification | string (e.g. `BSc`) | ● |
| programme | string | ● |
| classification? | string | ● |
| conferredOn | date | ● |

**EmploymentLetter**

| Field | Type | |
|---|---|---|
| employeeName | string | ● |
| staffNumber? | string | |
| jobTitle | string | ● |
| employmentType | `permanent` \| `contract` \| `temporary` \| `internship` | |
| startDate | date | ● |
| endDate? | date | |
| currentlyEmployed | boolean | ● |

Monetary amounts (balances, salary) are deliberately absent from v1.

Each type exports: a zod schema for `credentialSubject`, a zod schema for the
whole credential, the JSON Schema form (`z.toJSONSchema`), and its default
disclosure list. Schemas are `strict`: unknown fields are rejected, because a
term missing from the context would otherwise be dropped silently during
canonicalization and end up unsigned.

## Document loader

Both implementations use a static document loader that knows exactly two
contexts — W3C credentials v2 and Vemphy claims v1 — bundled with the library.
Any other context URL is an error. Nothing is fetched from the network during
canonicalization. This is what allows offline verification, and it removes
remote contexts as a way to alter what a signature covers.

`vc-go/context/` carries copies of the two JSON files (Go embeds only from
inside its own module). CI fails if they differ from `packages/vc/src/context/`.

## Proof

Per the W3C EdDSA cryptosuite:

1. Proof options = the proof without `proofValue`, with the document's `@context`.
2. `hash = SHA-256(RDFC(proof options)) ‖ SHA-256(RDFC(document without proof))` — 64 bytes.
3. Ed25519 over those 64 bytes.
4. `proofValue` = multibase base58btc (`z…`) of the 64-byte signature.

Signing sits behind an interface so the hash, not a key, crosses the boundary:

```ts
interface Signer {
  readonly verificationMethod: string
  sign(hash: Uint8Array): Promise<Uint8Array>
}
```

```go
type Signer interface {
    VerificationMethod() string
    Sign(ctx context.Context, hash []byte) ([]byte, error)
}
```

The toolkit ships one in-memory implementation, for tests and for issuers who
hold their own keys. The registry supplies a Vault Transit implementation.

## `verifyCredential`

```ts
verifyCredential(credential, {
  now: Date,
  resolveDid(did): Promise<DidDocument>,
  fetchStatusList(url): Promise<StatusListCredential>,
}): Promise<{
  result: 'valid' | 'revoked' | 'expired' | 'unknown',
  reason?: Reason,
  checks: Check[],
}>
```

Pure: no clock, network or filesystem access except through the injected
functions. The Go signature mirrors it.

Order of checks — the first that fails decides the result:

| # | Check | On failure |
|---|---|---|
| 1 | Shape: zod schema, known contexts only, one proof of the expected type and cryptosuite | `unknown` / `malformed` |
| 2 | Resolve issuer DID; `verificationMethod` belongs to the issuer DID; find it by `kid` | `unknown` / `did_unresolvable`, `key_not_found` |
| 3 | Key window: the key's `revoked` / `expires`, when present, must be later than `proof.created` | `unknown` / `key_window_violation` |
| 4 | Canonicalize, hash, verify Ed25519 | `unknown` / `signature_failure` |
| 5 | Status list: fetch, verify its own proof by the same rules, same issuer, `now` within its validity, purpose matches | `unknown` / `status_list_unverifiable` |
| 6 | Status bit set | `revoked` |
| 7 | `now` outside `[validFrom, validUntil]` | `expired` |
| 8 | — | `valid` |

The signature is checked before status and dates so that an altered document
can only ever produce `unknown`. `reason` exists for operators and for the
registry's alerting; user-facing surfaces show the four result words only.

A retired key stays in the DID document without `revoked`, outside
`assertionMethod`; claims it signed keep verifying. A revoked key carries
`revoked`; claims with `proof.created` before that instant keep verifying.
For new proofs, `create` refuses a key that is not in `assertionMethod`.

## CLI

```
npx @vemphy/vc verify <file> [--now <iso>] [--did-doc <file>] [--status-list <file>] [--verbose]
```

Prints one word. With `--did-doc` / `--status-list`, or when run inside a
checkout where `vectors/` is present, no network is used. Exit code 0 for
`valid`, 1 otherwise, 2 for usage errors.

## Vectors

Generated by `packages/vc/scripts/gen-vectors.ts` from a fixed seed committed
under `vectors/keys/` and labelled as test material. Ed25519 signatures are
deterministic, so regeneration reproduces the files exactly; CI regenerates and
fails on any diff.

`expected.json` fixes `now` and lists the expected result and reason per vector:

| Vector | Result |
|---|---|
| `gcb-001` BankReferenceLetter | valid |
| `ug-001` DegreeCertificate | valid |
| `emp-001` EmploymentLetter | valid |
| `gcb-002` field altered after signing | unknown / signature_failure |
| `gcb-003` signed by a key not in the DID document | unknown / key_not_found |
| `gcb-004` status bit set | revoked |
| `gcb-005` past `validUntil` | expired |
| `gcb-006` key revoked before `proof.created` | unknown / key_window_violation |
| `gcb-007` signed under `key-1`, since retired for `key-2` | valid |
| `gcb-008` status list past its `validUntil` | unknown / status_list_unverifiable |
| `gcb-009` extra `@context` entry | unknown / malformed |
| `gcb-010` revoked and expired | revoked |

`vectors/canon/<name>.nq` holds the expected canonical N-Quads for each claim;
both implementations must reproduce them byte for byte. `codes.json` lists
valid, invalid and non-issuable codes with the expected parse result and error
position.

## Testing

- Unit tests per module in both languages.
- Known-answer test: the `eddsa-rdfc-2022` test vector published in the W3C
  specification (key, canonical forms, hash, `proofValue`) — anchors both
  implementations to the standard, not only to each other.
- RDFC-1.0 test-suite cases relevant to credentials (blank nodes, typed
  literals, language tags, escaping).
- Crockford published check-symbol vectors.
- `interop.yml`: TS verifies all vectors; Go verifies all vectors; TS signs
  with a fresh key → Go verifies; Go signs → TS verifies; canonical N-Quads
  compared byte for byte; vectors regenerated with no diff; context copies
  identical; wording check on user-facing files.
- `publish.yml`: npm publish with provenance and a `vc-go/vX.Y.Z` tag, on release.

## Dependencies

TypeScript: `jsonld`, `@noble/ed25519`, `@noble/hashes`, `@scure/base`, `zod` 4.
gzip through the platform `DecompressionStream`. Built with tsup (ESM + types),
tested with vitest, Node 20+.

Go 1.23+: `github.com/piprate/json-gold`, `github.com/mr-tron/base58`, standard
library for Ed25519, SHA-256 and gzip.

All versions pinned; lockfiles committed.

## Licence

Apache-2.0. Nothing in this repository depends on a Vemphy service or account.
