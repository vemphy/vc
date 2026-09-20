# vemphy/vc

The open verification toolkit for [Vemphy](https://vemphy.com) claims.

Issuers — banks, universities, employers — sign claims about documents they
produce. Anyone can check a claim from the short code or QR code on any copy
of the document. This repository is everything needed to do that check
yourself, in TypeScript or Go, without an account and without trusting
Vemphy's servers to tell you the answer.

| | |
|---|---|
| [`packages/vc`](packages/vc) | TypeScript: `@vemphy/vc` on npm, with a CLI |
| [`vc-go`](vc-go) | Go: `github.com/vemphy/vc/vc-go` |
| [`vectors`](vectors) | Signed claims, keys, status lists and codes, with the answer each must produce |

The answer is always one of `valid`, `revoked`, `expired` or `unknown`.

## Run everything

Node 20+, pnpm and Go 1.23+.

```sh
pnpm install && pnpm test && (cd vc-go && go test ./...) && scripts/interop.sh
```

Then verify a claim from the vectors, offline:

```sh
pnpm build
node packages/vc/dist/cli/main.js verify vectors/claims/gcb-001.json   # valid
node packages/vc/dist/cli/main.js verify vectors/claims/gcb-004.json   # revoked
```

## TypeScript

```ts
import { didToUrl, verifyCredential } from '@vemphy/vc'

const getJson = (url: string) => fetch(url).then((response) => response.json())

const { result } = await verifyCredential(claim, {
  now: new Date(),
  resolveDid: (did) => getJson(didToUrl(did)),
  fetchStatusList: getJson,
})
```

More in [`packages/vc/README.md`](packages/vc/README.md).

## Go

```go
import (
	"github.com/vemphy/vc/vc-go/did"
	"github.com/vemphy/vc/vc-go/verify"
)

outcome := verify.Credential(ctx, claimJSON, verify.Deps{
	Now: time.Now(),
	ResolveDID: func(ctx context.Context, id string) ([]byte, error) {
		url, err := did.URL(id)
		if err != nil {
			return nil, err
		}
		return get(ctx, url)
	},
	FetchStatusList: get,
})
// outcome.Result is verify.Valid, verify.Revoked, verify.Expired or verify.Unknown
```

`get` is your HTTP client: `func(ctx context.Context, url string) ([]byte, error)`.

## Standards

- [Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [Data Integrity EdDSA Cryptosuites](https://www.w3.org/TR/vc-di-eddsa/): `eddsa-rdfc-2022`
- [RDF Dataset Canonicalization (RDFC-1.0)](https://www.w3.org/TR/rdf-canon/)
- [Bitstring Status List 1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
- [`did:web`](https://w3c-ccg.github.io/did-method-web/) with `Multikey` verification methods

Issuer identifiers are `did:web:vemphy.com:i:<slug>`. A claim uses two JSON-LD
contexts: the W3C credentials context, and the context of its claim type.

## Claim types

A claim type is a document, not code: a small JSON Schema that says which
fields a claim of that type has. There are two kinds.

- **Core types** are curated by Vemphy and open to every issuer:
  `BankReferenceLetter`, `BankBalanceLetter`, `SalaryConfirmation`,
  `EmploymentLetter`, `DegreeCertificate`, `InsuranceCertificate`, and
  `Attestation` for a one-off statement. Their schemas are in
  [`packages/vc/schemas/core`](packages/vc/schemas/core) and ship with both
  libraries, so claims of core types verify offline.
- **Custom types** are defined by one issuer for its own documents, and only
  that issuer can sign claims of them.

Every published version of every type has its own context and its own schema
document, at addresses that never change:

| | Context | Schema |
|---|---|---|
| Core | `https://vemphy.com/ns/core/<Type>/v<n>` | `https://vemphy.com/schemas/core/<Type>/v<n>.json` |
| Custom | `https://vemphy.com/ns/i/<issuer>/<Type>/v<n>` | `https://vemphy.com/schemas/i/<issuer>/<Type>/v<n>.json` |

A type is changed by publishing version `n + 1`. A claim names the exact
version it was issued under, in `@context` and in `credentialSchema`, so it
reads the same for as long as it exists. Claims issued before 0.2.0 use the
shared context [`https://vemphy.com/ns/claims/v1`](packages/vc/src/context/claims-v1.json),
which is kept exactly as first published and still verifies.

### Custom types

To verify a claim of an issuer's own type, a verifier needs that type's
context. Both libraries resolve contexts the same way:

1. bundled documents: the W3C context, `claims/v1` and every core type;
2. your cache; a published context never changes, so nothing in it expires;
3. the network, and only `https://www.w3.org/ns/credentials/v2`,
   `https://w3id.org/security/*` and `https://vemphy.com/ns/*`. Any other
   address is refused before a request is made, because what a signature
   covers depends on the context, and that cannot be left to whoever serves a
   URL named inside the document being checked.

```ts
import { documentLoader, memoryCache, schemaLoader, verifyCredential } from '@vemphy/vc'

const documents = { cache: memoryCache(), fetch }
const outcome = await verifyCredential(claim, {
  now: new Date(),
  resolveDid, fetchStatusList,
  documentLoader: documentLoader(documents),
  fetchSchema: schemaLoader(documents),
})
```

```go
cache := vcctx.DirCache("/var/cache/vemphy")
outcome := verify.Credential(ctx, claimJSON, verify.Deps{
	Now: time.Now(), ResolveDID: resolve, FetchStatusList: get,
	DocumentLoader: vcctx.New(vcctx.Options{Cache: cache, Client: http.DefaultClient}),
	FetchSchema:    vcctx.NewSchemas(vcctx.Options{Cache: cache, Client: http.DefaultClient}).Get,
})
```

Leave out `fetch` (or `Client`) and the loader is offline. A claim whose
context is then missing comes back `unknown` with the reason
`context_unavailable`; it is never mistaken for a bad signature. On the command
line, `--cache <dir>` names the cache and `--offline` forbids the network:

```sh
node packages/vc/dist/cli/main.js verify vectors/claims/gcb-012.json --offline   # valid
```

The outcome also says whether the subject matches the schema the claim names
(`schemaValid`). That is information for whoever wants it. It never changes the
answer: signature, revocation and dates decide that.

### Working with claim schemas

```ts
import { assertNoDroppedTerms, contextFromSchema, contextUrl, coreSchema, labelFor, namespaceOf, validateSchema, validateSubject } from '@vemphy/vc/schema'

validateSchema(draft)                          // [] when the draft may be published, else [{ field, message }]
validateSubject(coreSchema('Attestation', 1)!, subject)
labelFor(schema, 'holderName', ['fr-CA', 'en']) // the best language the schema has, else English

const ref = { issuer: 'gcb', name: 'StaffIdCard', version: 1 }
const context = contextFromSchema(schema, namespaceOf(ref))  // served at contextUrl(ref)
await assertNoDroppedTerms(schema, context, namespaceOf(ref))
```

```go
s, err := schema.Parse(raw)                     // refuses anything outside the rules, then compiles
problems := s.ValidateSubject(subjectJSON)      // nil, or one problem per failing field
label, _ := s.Label("holderName", "fr-CA", "en")

ref := schema.Ref{Issuer: "gcb", Name: "StaffIdCard", Version: 1}
context := schema.GenerateContext(s, ref.Namespace()) // the same bytes the TypeScript side produces
err = canon.AssertNoDroppedTerms(s, context, ref.Namespace())
document, _ := schema.Document(s, ref.SchemaURL())    // what is served at the schema URL

for _, core := range schema.Core() { /* core.Ref, core.Schema */ }
```

### What a claim schema may contain

One flat object of at most 30 fields. A field is text (`maxLength` required,
at most 2000), a date, a date and time, an email address, a link, a choice
from a list, a whole number with bounds, or a yes/no. No nesting, no arrays,
no `$ref`. Every field carries an `x-vemphy` block with its label (in one or
more languages), whether the issuer may show it to someone verifying, whether
it is personal data, and its order. The rules are themselves a JSON Schema:
[`schemas/meta/vemphy-claim-schema.json`](packages/vc/schemas/meta/vemphy-claim-schema.json).

Three things are stricter than JSON Schema on purpose, so that the two
languages, and yours, cannot disagree:

- **No floating-point numbers.** JSON-LD canonicalisation rounds them, and the
  two libraries round differently, so a number could change without breaking
  the signature. An amount is a string such as `"12500.50"`, marked
  `"kind": "decimal"`, beside a `currency`.
- **Formats are defined here**, not borrowed from a validator library. See
  [`formats.ts`](packages/vc/src/schema/formats.ts) and [`formats.go`](vc-go/schema/formats.go).
- **Patterns use only syntax that means the same in ECMAScript and RE2.**
  No lookarounds, backreferences, `\s`, `\w`, `\b` or `.`; write a character
  class. Both libraries run patterns on RE2, which cannot be made to backtrack.

A context is generated from a schema, never written by hand. Every field is
defined in it by name. JSON-LD silently drops a field no context defines, and
a dropped field is not covered by the signature; `assertNoDroppedTerms`
(`canon.AssertNoDroppedTerms` in Go) expands a sample claim and fails unless
every field survives, and canonicalisation runs in safe mode as a second guard.

## How the two implementations are kept in step

Both verify every file in `vectors/claims` and must produce the result and
reason recorded in [`vectors/expected.json`](vectors/expected.json). Both
reproduce the canonical N-Quads in `vectors/canon` byte for byte, and both
reproduce the test vector published in the W3C EdDSA specification
(`vectors/w3c`), so they agree with the standard and not only with each other.

Both refuse every schema in `vectors/schemas/invalid`, agree on every subject in
`vectors/schemas/subjects` and every pattern in `vectors/patterns.json`, and
generate the contexts and schema documents in `vectors/cache` byte for byte.

[`scripts/interop.sh`](scripts/interop.sh) then generates a key neither side
has seen: TypeScript signs and Go verifies, Go signs and TypeScript verifies,
and the two signatures over the same document must be identical. It also makes
up a claim type on the spot and requires both to generate the same context. CI runs all
of it on every push, regenerates the vectors, and fails on any difference.

`vectors/keys/test-seeds.json` holds the private seeds the vectors were signed
with. They are test material, published on purpose, and must never be used for
anything else.

## Layout

```
packages/vc/schemas/  core types · the meta-schema · the claim envelope
packages/vc/src/      code · schema · context · canon · proof · did · status · verify
packages/vc/cli/      the vemphy-vc command
vc-go/                code · schema · vcctx · canon · proof · did · multibase · status · verify
vectors/              claims · keys · status · canon · schemas · cache · w3c · codes.json · patterns.json · expected.json
docs/                 designs and implementation plans
```

## Licence

Apache-2.0.
