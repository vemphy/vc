# `vemphy/vc` Toolkit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A TypeScript package and a Go module that verify Vemphy claims identically, proven by shared vectors and an interop CI workflow.

**Architecture:** Small single-purpose modules (`code`, `canon`, `proof`, `did`, `status`, `schema`) composed by one pure `verifyCredential` pipeline with injected fetchers. The TS generator is the only producer of `vectors/`; both languages consume them. Design: `docs/specs/2026-09-19-vc-toolkit-design.md`.

**Tech Stack:** TypeScript strict, pnpm workspace, tsup, vitest, `jsonld`, `@noble/ed25519`, `@noble/hashes`, `@scure/base`, `zod` 4. Go 1.23+, `github.com/piprate/json-gold`, `github.com/mr-tron/base58`.

## Global Constraints

- Results are exactly `valid | revoked | expired | unknown`. The words "fake", "forged", "fraud" appear in no source file, test name, log line, fixture or doc. `scripts/check-wording.sh` enforces it.
- Licence Apache-2.0. Nothing proprietary; no dependency on any Vemphy service.
- Credential format: VC 2.0, `DataIntegrityProof`, `eddsa-rdfc-2022`, `proofPurpose: assertionMethod`, `did:web:vemphy.com:i:<slug>`, Bitstring Status List 1.0 (131,072 bits, gzip, base64url).
- No network access during canonicalization: static document loader, two contexts only.
- `verifyCredential` is pure: clock and I/O only through injected arguments.
- Slug: 2–4 letters, uppercase in codes, lowercase in DIDs and URLs.
- Go module path `github.com/vemphy/vc/vc-go`, `go 1.23`. npm name `@vemphy/vc`. Node 20+.
- All dependency versions pinned exactly (no `^`), lockfiles committed.
- Commit messages: imperative subject, no trailers of any kind.
- Not in scope: JWT-VC, SD-JWT, BBS+, wallets, OCR, offline tokens.

## File map

```
package.json  pnpm-workspace.yaml  tsconfig.base.json  LICENSE  README.md  .gitignore
scripts/check-wording.sh  scripts/check-contexts.sh
packages/vc/
  package.json  tsconfig.json  tsup.config.ts  vitest.config.ts  README.md
  src/code.ts                      code.test.ts
  src/context/credentials-v2.json  claims-v1.json  loader.ts  loader.test.ts
  src/canon.ts                     canon.test.ts
  src/schema/common.ts  bank-reference-letter.ts  degree-certificate.ts
             employment-letter.ts  index.ts  schema.test.ts
  src/multibase.ts                 multibase.test.ts
  src/did.ts                       did.test.ts
  src/proof.ts                     proof.test.ts
  src/status.ts                    status.test.ts
  src/verify.ts                    verify.test.ts
  src/index.ts
  cli/main.ts                      cli.test.ts
  scripts/gen-vectors.ts
vc-go/
  go.mod  go.sum
  code/  context/  canon/  multibase/  did/  proof/  status/  verify/   (each: x.go + x_test.go)
  internal/vectors/vectors.go      (locates and loads ../vectors for tests)
  cmd/vcinterop/main.go            (sign / verify / canon, used by interop.yml)
vectors/
  codes.json  expected.json  claims/  keys/  status/  canon/  w3c/
.github/workflows/interop.yml  publish.yml
```

---

### Task 1: Workspace scaffold

**Files:** root `package.json`, `pnpm-workspace.yaml`, `tsconfig.base.json`, `.gitignore`, `LICENSE`, `packages/vc/{package.json,tsconfig.json,tsup.config.ts,vitest.config.ts}`, `vc-go/go.mod`, `scripts/check-wording.sh`.

**Produces:** `pnpm test`, `pnpm build`, `pnpm typecheck`, `(cd vc-go && go test ./...)`, `scripts/check-wording.sh` all runnable.

- [ ] Root `package.json`: private, `"packageManager": "pnpm@12.4.1"`, scripts `test`, `build`, `typecheck`, `gen:vectors`, `check:wording`, each delegating with `pnpm -r` / `pnpm --filter @vemphy/vc`.
- [ ] `packages/vc/package.json`: `"type": "module"`, `"engines": {"node": ">=20"}`, `"bin": {"vemphy-vc": "./dist/cli/main.js"}`, `exports` for `.`, `./code`, `./schema` (each `types` + `import`), `files: ["dist"]`, `"sideEffects": false`.
- [ ] `tsconfig.base.json`: `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`, `module`/`moduleResolution` `NodeNext`, `target` `ES2022`, `resolveJsonModule`.
- [ ] `tsup.config.ts`: entries `src/index.ts`, `src/code.ts`, `src/schema/index.ts`, `cli/main.ts`; `format: ['esm']`, `dts: true`, `clean: true`.
- [ ] `vc-go/go.mod`: `module github.com/vemphy/vc/vc-go`, `go 1.23`.
- [ ] `scripts/check-wording.sh`: `grep -rniE 'fake|forged|fraud'` over tracked files excluding itself, this plan, the design doc and lockfiles; exit 1 on a hit. The script builds its pattern from pieces (`f''ake`) so it does not match itself.
- [ ] `LICENSE`: Apache-2.0 full text.
- [ ] Verify: `pnpm install && pnpm typecheck && scripts/check-wording.sh` succeed. Commit `Scaffold workspace`.

---

### Task 2: Codes — TypeScript

**Files:** `packages/vc/src/code.ts`, `code.test.ts`, `vectors/codes.json`.

**Produces:**

```ts
export const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
export const CHECK_ALPHABET = ALPHABET + '*~$=U'
export function checkChar(n: bigint): string                       // Crockford mod 37
export function checkCharFor(slug: string, body: string): string   // slug-inclusive
export type ParseFailure =
  | { ok: false; error: 'format' }                                  // wrong length / slug / characters
  | { ok: false; error: 'check'; suspects: number[] }               // 1-based positions in SLUG+8 chars, best first
export type ParseResult = { ok: true; code: string; slug: string; body: string; check: string } | ParseFailure
export function parseCode(input: string): ParseResult              // accepts bare code or https://vemphy.com/v/<CODE>
export function formatCode(slug: string, body: string): string     // → 'GCB-7K2M-9QXD'
export function isIssuable(code: string): boolean                  // false when check ∈ * ~ $ =
```

Arithmetic: `2^35 mod 37 = 19`, so `check = (19 · (s mod 37) + (n mod 37)) mod 37`, each reduced by Horner's rule — no BigInt needed except in `checkChar`.

- [ ] **Failing tests first** (`code.test.ts`), exact expectations:
  - `checkChar(0n) === '0'`, `checkChar(32n) === '*'`, `checkChar(36n) === 'U'`, `checkChar(37n) === '0'`, `checkChar(1234n) === 'D'`.
  - `checkCharFor('GCB', '0000000') === '1'`; `checkCharFor('UG', '0000000') === '4'`; `checkCharFor('GCB', '7K2M9QX') === 'D'`.
  - `parseCode('GCB-7K2M-9QXD')` → ok, `code: 'GCB-7K2M-9QXD'`.
  - Same result for `'gcb 7k2m 9qxd'`, `'GCB7K2M9QXD'`, `'https://vemphy.com/v/GCB-7K2M-9QXD'`, `' gcb-7k2m-9qxd\n'`.
  - Folding in body only: `'GCB-OOOO-OOO1'` parses as body `0000000`, check `1`. Slug is not folded: `'G0B-0000-0001'` → `format`.
  - Every single-character substitution of `GCB-7K2M-9QXD` (each of 11 positions × every other alphabet symbol, slug positions × 25 letters) → `{ok:false, error:'check'}`. This loop is the proof of acceptance criterion 7.
  - `'GCD-7K2M-9QXD'` → `check` (slug typo caught).
  - `'GCB-7K2M-9QX'`, `'TOOLONG-0000-0001'`, `'G-0000-0001'`, `''` → `format`.
  - `isIssuable('GCB-0000-0001') === true`; a code with check `*` → `false` but `parseCode` ok.
- [ ] Run `pnpm --filter @vemphy/vc test code` → fails (module missing).
- [ ] Implement everything except the ranking inside `suspects` — return candidate positions in ascending order for now. **The ranking heuristic is reserved for the repository owner** (see "Owner contribution" below).
- [ ] Tests pass.
- [ ] Write `vectors/codes.json`: `[{ "input", "ok", "code"?, "error"?, "issuable"? }]` with every case above plus ten more valid codes across slugs `GCB`, `UG`, `KNUST`-style 4-letter `KNUS`, `AB`.
- [ ] Add a test that replays `codes.json`. Commit `Add code parsing and check character (TS)`.

**Owner contribution.** A mod-37 checksum detects an error but cannot locate it: for most positions there is exactly one replacement character that would repair the checksum. `rankSuspects(typed: string, candidates: {position:number, typed:string, repair:string}[]): number[]` decides which position the user is told to re-check. Options: prefer pairs that look alike (`8/B`, `5/S`, `2/Z`, `U/V`, `0/D`), prefer adjacent-key slips, prefer later positions (attention fades), or return several. 5–10 lines; it is what a person sees when they mistype.

---

### Task 3: Codes — Go

**Files:** `vc-go/code/code.go`, `code_test.go`, `vc-go/internal/vectors/vectors.go`.

**Produces:**

```go
package code
type Code struct{ Slug, Body, Check string }
func (c Code) String() string
type ErrorKind string  // "format" | "check"
type ParseError struct{ Kind ErrorKind; Suspects []int }
func (e *ParseError) Error() string
func CheckChar(n *big.Int) byte
func CheckCharFor(slug, body string) byte
func Parse(input string) (Code, error)
func Format(slug, body string) string
func IsIssuable(c Code) bool
```

`internal/vectors`: `func Dir() string` (walks up from the test's working directory to the first `vectors/` directory), `func Load(t testing.TB, rel string, v any)`.

- [ ] Table test replaying `vectors/codes.json` plus the `CheckChar` constants from Task 2. Run → fails.
- [ ] Implement; `Suspects` ordering must equal the TS output for every `codes.json` entry (port the owner's `rankSuspects` once written).
- [ ] `go test ./code/...` passes; `go vet ./...` clean. Commit `Add code parsing and check character (Go)`.

---

### Task 4: Contexts, loader, canonicalization — TypeScript

**Files:** `src/context/credentials-v2.json` (verbatim from `https://www.w3.org/ns/credentials/v2`; record its SHA-256 in a comment in `loader.ts` — the W3C publishes the expected digest), `src/context/claims-v1.json`, `src/context/loader.ts`, `src/canon.ts`, tests.

**Produces:**

```ts
export const CREDENTIALS_V2 = 'https://www.w3.org/ns/credentials/v2'
export const CLAIMS_V1 = 'https://vemphy.com/ns/claims/v1'
export type DocumentLoader = (url: string) => Promise<{ contextUrl: null; documentUrl: string; document: unknown }>
export function staticLoader(extra?: Record<string, unknown>): DocumentLoader   // `extra` is for tests (W3C example context)
export class UnknownContextError extends Error { url: string }
export async function canonicalize(doc: object, loader?: DocumentLoader): Promise<string>  // RDFC-1.0 N-Quads
```

`claims-v1.json`: `@protected: true`; `"vemphy": "https://vemphy.com/ns/claims#"`; the three credential type terms (`BankReferenceLetter`, `DegreeCertificate`, `EmploymentLetter`) map to `vemphy:<Name>`. Subject properties are defined at the top level of the context, not as type-scoped contexts, so they resolve inside `credentialSubject` without the subject needing its own `type`. Terms: all fields from the design's three tables; date fields `{"@id": "vemphy:<name>", "@type": "xsd:date"}`; `currentlyEmployed` `xsd:boolean`. Field names are unique across types (no two types share a term with different meaning).

`canonicalize`: `jsonld.canonize(doc, { algorithm: 'RDFC-1.0', format: 'application/n-quads', documentLoader, safe: true })`. `safe: true` makes jsonld throw on any property that is not defined in a context instead of dropping it.

- [ ] Tests: loader returns both contexts; any other URL rejects with `UnknownContextError`; a minimal `BankReferenceLetter` canonicalizes to a snapshot committed as `vectors/canon/minimal.nq`; key order in the input does not change output; an undefined property throws (safe mode); a credential with an extra remote `@context` throws `UnknownContextError` and performs no fetch (assert with a `globalThis.fetch` spy).
- [ ] Implement. Commit `Add contexts, static loader and canonicalization (TS)`.

---

### Task 5: Contexts and canonicalization — Go

**Files:** `vc-go/context/{credentials-v2.json,claims-v1.json,context.go}`, `vc-go/canon/canon.go`, tests, `scripts/check-contexts.sh`.

**Produces:**

```go
package context // import path .../vc-go/context; callers alias it `vcctx`
const CredentialsV2, ClaimsV1 = "https://www.w3.org/ns/credentials/v2", "https://vemphy.com/ns/claims/v1"
func Loader(extra map[string][]byte) ld.DocumentLoader
var ErrUnknownContext = errors.New("unknown context")

package canon
func Canonicalize(doc map[string]any, loader ld.DocumentLoader) (string, error)
```

`Canonicalize`: `ld.NewJsonLdProcessor().Normalize` with `Algorithm = ld.AlgorithmURDNA2015`, `Format = "application/n-quads"`, `SafeMode = true` where the pinned json-gold version supports it; otherwise expand first and reject when any key was dropped (compare property counts against the compacted input) — decide by reading the pinned version's `JsonLdOptions`.

- [ ] Test: `vectors/canon/minimal.nq` reproduced byte for byte from the same input JSON (store the input as `vectors/canon/minimal.json`); unknown context → `ErrUnknownContext`; undefined property → error.
- [ ] `scripts/check-contexts.sh`: `cmp` each JSON in `packages/vc/src/context/` against `vc-go/context/`.
- [ ] If any byte differs between TS and Go N-Quads, stop and resolve before continuing: every later task depends on this. Commit `Add contexts and canonicalization (Go)`.

---

### Task 6: Schemas — TypeScript

**Files:** `src/schema/*.ts`, `schema.test.ts`.

**Produces:**

```ts
export const CLAIM_TYPES = ['BankReferenceLetter', 'DegreeCertificate', 'EmploymentLetter'] as const
export type ClaimType = (typeof CLAIM_TYPES)[number]
export const subjectSchemas: Record<ClaimType, z.ZodObject<any>>      // strict
export const defaultDisclosure: Record<ClaimType, readonly string[]>
export const proofSchema, statusEntrySchema, credentialSchema          // credentialSchema: discriminated on type[1]
export const statusListCredentialSchema, didDocumentSchema
export type Credential, Proof, DidDocument, VerificationMethod, StatusListCredential
export function jsonSchemaFor(type: ClaimType): object                 // z.toJSONSchema
```

Rules: every object `.strict()`. `@context` must equal exactly `[CREDENTIALS_V2, CLAIMS_V1]`. `type` exactly `['VerifiableCredential', <ClaimType>]`. `issuer` matches `^did:web:vemphy\.com:i:[a-z]{2,4}$`. `id` matches `^urn:vemphy:claim:[A-Z]{2,4}-[0-9A-Z]{4}-[0-9A-Z*~$=]{4}$`. Dates: `xsd:date` fields `^\d{4}-\d{2}-\d{2}$` and a real calendar date; `validFrom`/`validUntil`/`created` are `z.iso.datetime({offset: true})`. `accountNumberLast4` `^\d{4}$`. Strings trimmed, 1–200 chars. `endDate >= startDate`; `currentlyEmployed === true` forbids `endDate`.

- [ ] Tests: one accepted and at least three rejected documents per type (unknown field, bad enum, bad date `2026-02-30`); extra context rejected; `defaultDisclosure` entries are all keys of the matching schema; `jsonSchemaFor` output has `additionalProperties: false`.
- [ ] Implement. Commit `Add claim schemas`.

Go performs the same shape checks with plain structs and `json.Decoder.DisallowUnknownFields` inside `verify` (Task 12); it does not need form-level rules.

---

### Task 7: Multibase, Multikey, DID — both languages

**Files:** `src/multibase.ts`, `src/did.ts`, `vc-go/multibase/`, `vc-go/did/`, tests.

**Produces (TS; Go mirrors with exported names):**

```ts
export function encodeBase58btc(bytes: Uint8Array): string            // 'z…'
export function decodeBase58btc(s: string): Uint8Array                // throws unless 'z' prefix
export function encodeMultikey(publicKey: Uint8Array): string         // 0xed 0x01 ‖ 32 bytes → 'z6Mk…'
export function decodeMultikey(s: string): Uint8Array                 // 32 bytes; throws on other codec or length
export function didToUrl(did: string): string                         // did:web:vemphy.com:i:gcb → https://vemphy.com/i/gcb/did.json
export function slugOf(did: string): string
export function findKey(doc: DidDocument, verificationMethod: string):
  { publicKey: Uint8Array; revoked?: Date; expires?: Date; inAssertionMethod: boolean } | undefined
```

`findKey` requires `vm.controller === doc.id`, `vm.id === verificationMethod`, `vm.type === 'Multikey'`, and that the verification method's DID part equals `doc.id`.

- [ ] Tests: round trip; the W3C key `z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2` decodes to 32 bytes and re-encodes identically; wrong multicodec prefix rejected; `didToUrl` rejects any host other than `vemphy.com` and any path shape other than `i:<slug>`; percent-encoded or port-bearing DIDs rejected; `findKey` ignores a method whose `controller` differs.
- [ ] Implement both. Commit `Add multikey and did:web helpers`.

---

### Task 8: Proof — TypeScript

**Files:** `src/proof.ts`, `proof.test.ts`, `vectors/w3c/eddsa-rdfc-2022.json`.

**Produces:**

```ts
export interface Signer { readonly verificationMethod: string; sign(hash: Uint8Array): Promise<Uint8Array> }
export function memorySigner(seed: Uint8Array, verificationMethod: string): Signer & { publicKey: Uint8Array }
export async function hashForProof(unsigned: object, proofOptions: object, loader?): Promise<Uint8Array>   // 64 bytes
export async function createProof(unsigned: object, signer: Signer, opts: { created: string }, loader?): Promise<Credential>
export async function verifyProof(signed: object, publicKey: Uint8Array, loader?): Promise<boolean>
```

`proofOptions` = proof minus `proofValue`, plus the document's `@context`. `createProof` takes `created` from the caller (no clock). `verifyProof` returns `false` for a bad signature and throws only for canonicalization errors.

- [ ] Copy the `eddsa-rdfc-2022` test vector from the W3C "Data Integrity EdDSA Cryptosuites" specification (appendix "Test Vectors → Representation: eddsa-rdfc-2022") verbatim into `vectors/w3c/eddsa-rdfc-2022.json`: key pair, unsigned credential, canonical document, document hash, proof options, canonical proof options, proof hash, signature, signed credential. Include the examples context it uses so `staticLoader(extra)` can serve it.
- [ ] Known-answer tests: canonical document equals the fixture string; both SHA-256 hex digests equal; `createProof` reproduces the fixture `proofValue` exactly; `verifyProof` true; flipping one character of any subject value → false.
- [ ] Implement with `@noble/ed25519` (set `etc.sha512Sync` from `@noble/hashes`). Commit `Add eddsa-rdfc-2022 proofs (TS)`.

---

### Task 9: Proof — Go

**Files:** `vc-go/proof/proof.go`, `proof_test.go`.

**Produces:**

```go
type Signer interface {
    VerificationMethod() string
    Sign(ctx context.Context, hash []byte) ([]byte, error)
}
func NewMemorySigner(seed []byte, verificationMethod string) *MemorySigner   // doc comment: test and issuer-held use
func Hash(unsigned, proofOptions map[string]any, loader ld.DocumentLoader) ([]byte, error)
func Create(ctx context.Context, unsigned map[string]any, s Signer, created time.Time, loader ld.DocumentLoader) (map[string]any, error)
func Verify(signed map[string]any, publicKey ed25519.PublicKey, loader ld.DocumentLoader) (bool, error)
```

- [ ] Same known-answer tests against `vectors/w3c/eddsa-rdfc-2022.json`. `Create` formats `created` as RFC 3339 UTC with `Z`, second precision — identical to the TS side.
- [ ] Implement. Commit `Add eddsa-rdfc-2022 proofs (Go)`.

---

### Task 10: Status lists — both languages

**Files:** `src/status.ts`, `vc-go/status/status.go`, tests.

**Produces:**

```ts
export const LIST_BITS = 131_072
export async function decodeList(encodedList: string): Promise<Uint8Array>       // multibase 'u' base64url → gunzip; length must be 16,384
export async function encodeList(bits: Uint8Array): Promise<string>
export function getBit(bits: Uint8Array, index: number): boolean                // bit 0 = MSB of byte 0
export function setBit(bits: Uint8Array, index: number): void
```

Go: `Decode`, `Encode`, `Get`, `Set` with the same semantics. Bit order is most-significant-bit first, per Bitstring Status List 1.0.

- [ ] Tests: empty list round trip; set index 0 → first byte `0x80`; set 131,071 → last byte `0x01`; index out of range throws; wrong decompressed length rejected; decompression capped at 16,384 bytes (a gzip bomb fixture of 10 MB of zeros is rejected without allocating it); a list encoded in TS decodes in Go and the reverse (fixture in `vectors/status/`).
- [ ] Implement. Commit `Add bitstring status lists`.

---

### Task 11: `verifyCredential`, vector generator, vectors — TypeScript

**Files:** `src/verify.ts`, `verify.test.ts`, `src/index.ts`, `scripts/gen-vectors.ts`, all of `vectors/{claims,keys,status,canon}` and `expected.json`.

**Produces:**

```ts
export type Result = 'valid' | 'revoked' | 'expired' | 'unknown'
export type Reason = 'malformed' | 'did_unresolvable' | 'key_not_found' | 'key_window_violation'
  | 'signature_failure' | 'status_list_unverifiable'
export type Check = { name: string; ok: boolean }
export interface VerifyDeps {
  now: Date
  resolveDid(did: string): Promise<unknown>
  fetchStatusList(url: string): Promise<unknown>
}
export async function verifyCredential(input: unknown, deps: VerifyDeps): Promise<{ result: Result; reason?: Reason; checks: Check[] }>
```

Order exactly as the design table (shape → DID/key → key window → signature → status list proof, issuer, validity, purpose → bit → dates). `verifyCredential` never throws: any exception from a dependency or from canonicalization becomes `unknown` with the matching reason. The status list credential must have the same `issuer` as the claim, `credentialSubject.statusPurpose === 'revocation'`, and `validFrom <= now < validUntil`.

Generator: seeds in `vectors/keys/test-seeds.json` with a top-level `"warning": "TEST KEYS. Public. Never use outside tests."`. Issuers `gcb` (keys `key-1` retired, `key-2` active, `key-3` revoked at a fixed instant), `ug`, `emp`. Fixed `now = 2026-06-01T12:00:00Z`. Emits the twelve vectors in the design, DID documents, status lists, `canon/<name>.nq`, and `expected.json` = `{ now, vectors: { "<name>": { result, reason? } } }`. Output is stable: sorted keys, two-space indent, trailing newline.

- [ ] Write `verify.test.ts` first as a loop over `expected.json` with file-backed `resolveDid` / `fetchStatusList` — it fails because no vectors exist.
- [ ] Add targeted tests: `resolveDid` rejecting → `unknown/did_unresolvable`; `fetchStatusList` rejecting → `unknown/status_list_unverifiable`; never throws on `null`, `42`, `{}`; a `valid` result has no `reason`.
- [ ] Implement `verify.ts`, then the generator; run `pnpm gen:vectors`; tests pass.
- [ ] Run the generator twice; `git status --porcelain vectors/` is empty after the second run.
- [ ] Commit `Add verifyCredential and test vectors`.

---

### Task 12: `verify` — Go

**Files:** `vc-go/verify/verify.go`, `verify_test.go`.

**Produces:**

```go
type Result string  // "valid" | "revoked" | "expired" | "unknown"
type Reason string
type Deps struct {
    Now             time.Time
    ResolveDID      func(ctx context.Context, did string) ([]byte, error)
    FetchStatusList func(ctx context.Context, url string) ([]byte, error)
}
type Outcome struct{ Result Result; Reason Reason; Checks []Check }
func Credential(ctx context.Context, raw []byte, deps Deps) Outcome
```

- [ ] Test: loop over `expected.json`; result and reason must both match. Second test: canonicalize every `vectors/claims/*.json` (without proof) and compare with `vectors/canon/<name>.nq` byte for byte.
- [ ] Implement; shape checks via typed structs with `DisallowUnknownFields`, exact `@context` and `type` comparison.
- [ ] Commit `Add credential verification (Go)`.

---

### Task 13: CLI

**Files:** `packages/vc/cli/main.ts`, `cli.test.ts`.

`vemphy-vc verify <file> [--now <iso>] [--did-doc <file>] [--status-list <file>] [--vectors <dir>] [--verbose]`. Resolution order for DID documents and status lists: explicit flag → `--vectors` directory or a `vectors/` directory found by walking up from the file → HTTPS fetch. When `--now` is absent and the file lives under a `vectors/` directory, `expected.json`'s `now` is used so `npx @vemphy/vc verify vectors/claims/gcb-001.json` prints `valid` deterministically. Prints the result word only; `--verbose` adds reason and checks on stderr. Exit 0 `valid`, 1 otherwise, 2 usage.

- [ ] Tests run the built CLI with `node:child_process`: `gcb-001` → `valid`/0; `gcb-004` → `revoked`/1; missing file → 2; with `fetch` stubbed to throw, `gcb-001` still prints `valid` (offline proof for acceptance criterion 1).
- [ ] Implement with `node:util` `parseArgs` (no CLI dependency). Commit `Add verify CLI`.

---

### Task 14: Interop tool, CI, READMEs

**Files:** `vc-go/cmd/vcinterop/main.go`, `packages/vc/scripts/interop.ts`, `.github/workflows/interop.yml`, `publish.yml`, `README.md`, `packages/vc/README.md`.

`vcinterop sign --seed <hex> --vm <id> --created <iso> < unsigned.json > signed.json`, `vcinterop verify --key <multibase> < signed.json` (exit 0/1), `vcinterop canon < doc.json`. `interop.ts` offers the same three subcommands.

`interop.yml` jobs (Node 24, Go 1.23 and stable): `ts` (install, typecheck, test, build), `go` (vet, test), `cross` (fresh random seed → TS signs, Go verifies; Go signs, TS verifies; both `canon` outputs `cmp`-equal for every vector), `hygiene` (`gen:vectors` then `git diff --exit-code vectors/`, `check-contexts.sh`, `check-wording.sh`, `pnpm audit --prod`, `govulncheck ./...`). Actions pinned by commit SHA.

`publish.yml`: on release — `pnpm publish --provenance --access public`; create tag `vc-go/<version>`.

READMEs: root explains the repository and one command to run everything (`pnpm install && pnpm test && (cd vc-go && go test ./...)`). Package README opens with the ten-line verification example using `verifyCredential` with `fetch`-based resolvers, then the CLI, then the four results and what each means.

- [ ] Run each CI step locally in order; all pass. Commit `Add interop workflow, publish workflow and READMEs`. Push.

---

## Spec coverage

| Requirement | Task |
|---|---|
| Crockford codes, check char, folding, reject before I/O | 2, 3 |
| RDFC-1.0 byte-identical | 4, 5, 12, 14 |
| Claim schemas + JSON Schema export | 6 |
| did:web, Multikey | 7 |
| eddsa-rdfc-2022 create/verify, `Signer` seam | 8, 9 |
| Bitstring Status List | 10 |
| `verifyCredential` pure pipeline, mirrored | 11, 12 |
| Vectors + `expected.json` at fixed `now` | 11 |
| CLI prints `valid` offline | 13 |
| interop.yml, publish.yml | 14 |
| Wording rule | 1, 14 |
| README a stranger can follow | 14 |
