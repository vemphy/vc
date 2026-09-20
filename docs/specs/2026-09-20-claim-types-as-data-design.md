# Claim types as data — design for `vc` 0.2.0

Date: 2026-09-20. Status: approved.

## Why

In 0.1.0 the three claim types are compiled into the package: Zod schemas in
TypeScript, hand-written checks in Go, and one shared JSON-LD context,
`https://vemphy.com/ns/claims/v1`. A new type needs a release of this
repository and a deploy of everything that uses it.

From 0.2.0 a claim type is a document. An issuer can define one and use it the
same day. This repository's part is to say what such a document may contain,
to check it the same way in both languages, to turn it into a JSON-LD context,
and to keep verifying every claim ever issued, offline included.

## Three kinds of type

- **Core types** are curated by Vemphy and open to every issuer. Their schemas
  live in this repository under `packages/vc/schemas/core/`.
- **Custom types** belong to one issuer. This repository never sees them ahead
  of time; a verifier meets them as a context URL and a schema URL in a claim.
- **`Attestation`** is a core type for a one-off statement: `subjectName`,
  `title`, `statement`, and an optional `reference`.

Core types at this release, all at version 1: `BankReferenceLetter`,
`BankBalanceLetter`, `SalaryConfirmation`, `EmploymentLetter`,
`DegreeCertificate`, `InsuranceCertificate`, `Attestation`.

## The claim schema

One schema language everywhere: JSON Schema 2020-12, a restricted subset. A
claim schema describes `credentialSubject` and nothing else.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "x-vemphy": { "name": "StaffIdCard", "displayName": { "en": "Staff ID card" } },
  "properties": {
    "holderName": {
      "type": "string", "minLength": 1, "maxLength": 200,
      "x-vemphy": { "label": { "en": "Name" }, "disclosable": true, "pii": true, "order": 1 }
    }
  },
  "required": ["holderName"]
}
```

Rules, checked by `schemas/meta/vemphy-claim-schema.json` and, where JSON
Schema cannot say it, by code that is the same in both languages:

- The root is `type: object`, `additionalProperties: false`, 1–30 properties,
  and carries `x-vemphy.name` (PascalCase, 2–40 characters) and
  `x-vemphy.displayName` (`en` required).
- Every property is a leaf. One of:
  - `string` with `maxLength` (required, at most 2000), optional `minLength`
    and `pattern`;
  - `string` with `format`: `date`, `date-time`, `email` or `uri`;
  - `string` with `enum`: 1–50 distinct values, each 1–100 characters;
  - `integer` with `minimum` and `maximum`, both required and both within
    ±(2^53 − 1);
  - `boolean`.
- There is no `number`. The two JSON-LD libraries write a small decimal
  differently (`5e-7` is `"0"` in one and `"5.0E-7"` in the other), and both
  round to 15 significant digits, so `0.30000000000000004` and `0.3` sign the
  same. An amount is a string such as `"12500.50"` with a pattern, marked
  `x-vemphy.kind: "decimal"`, next to a `currency` enum. The signed bytes then
  carry the amount exactly as the issuer wrote it.
- No nested objects, arrays, `$ref`, `oneOf`, `anyOf`, `allOf`, `not`, `if`.
  Rules that span two fields cannot be written. Leaf-only keeps a later move
  to selective disclosure mechanical.
- Property keys match `^[a-z][a-zA-Z0-9]{1,39}$` and are not a term of the
  VC 2.0 context. That context is protected, so redefining `name` or
  `description` fails expansion just as `id` or `proof` would. The reserved
  list in the meta-schema is generated from the bundled context, and a test
  fails if they drift. The type name is held to the same rule.
- Every name in `required` is a property.
- Every property carries `x-vemphy`:
  `label` (`en` required; other keys are language tags), `disclosable`, `pii`,
  `order` (unique within the schema), and optionally `kind`
  (`decimal` or `multiline`, on plain strings only) and `enumLabels`
  (on enums only: a map from enum value to a label object shaped like
  `label`; every key must be an enum value).

### Patterns

JavaScript `RegExp` and Go RE2 are different dialects. They disagree about
lookarounds and backreferences, and more quietly about `\s`, `\w`, `\b` and
`.`. A pattern is accepted only if it is at most 200 characters and uses this
syntax:

- literal characters, and the escapes `\\ \. \- \/ \( \) \[ \] \{ \} \* \+ \? \| \^ \$ \t \n \r`;
- `\d`, which is `[0-9]` in both;
- character classes `[...]` and `[^...]` of literals, ranges, `\d` and the
  escapes above;
- `^`, `$`, `|`, groups `(...)` and `(?:...)`;
- quantifiers `*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}` with n, m ≤ 1000, never
  lazy or possessive.

Both libraries run patterns on RE2 (Go's `regexp`; `re2js` in TypeScript), so
the dialect is the same on both sides and matching takes linear time. That
matters because a verifier may compile a pattern it has just fetched. The
syntax limit remains because a published schema is also read by other
people's validators, which follow ECMA-262.

### Formats

JSON Schema leaves `format` loosely defined and the two validator libraries
differ. Vemphy defines the four formats, implements each twice, and registers
them with both validators as custom formats. `ajv-formats` is not used.

| Format | Accepted |
|---|---|
| `date` | `YYYY-MM-DD`, a real calendar date, year 0001–9999 |
| `date-time` | `YYYY-MM-DDThh:mm:ss`, optional `.` and 1–9 digits, then `Z` or `±hh:mm`. Capital `T` and `Z`. Seconds 00–59 |
| `email` | `local@domain`, ASCII, at most 254 characters, local part at most 64 of `A-Za-z0-9._%+-` with no leading, trailing or doubled dot; domain of two or more labels of `A-Za-z0-9-`, none starting or ending with `-` |
| `uri` | `http://` or `https://`, then printable ASCII with no spaces, at most 2000 characters |

Lengths count Unicode code points in both languages.

## Contexts

Every published version of every type has its own context, which never
changes:

- core: `https://vemphy.com/ns/core/<TypeName>/v<n>`
- custom: `https://vemphy.com/ns/i/<slug>/<TypeName>/v<n>`

`https://vemphy.com/ns/claims/v1` stays exactly as published in 0.1.0 and is
never edited. It remains bundled so that claims issued under it keep
verifying. Nothing new is issued under it.

Why one file per version and not one growing file: a verifier caches a
context for ever and this package ships copies for offline use. Both are only
safe if the bytes at a URL never change. A signature covers the identifiers a
context maps field names to; a context that changed would turn valid claims
into `unknown`.

`contextFromSchema(schema, namespace)` and Go's `GenerateContext` build the
context. `namespace` is the context URL followed by `#`.

```json
{ "@context": {
    "@protected": true,
    "StaffIdCard": "https://vemphy.com/ns/i/gcb/StaffIdCard/v1#StaffIdCard",
    "holderName": "https://vemphy.com/ns/i/gcb/StaffIdCard/v1#holderName",
    "issuedOn": { "@id": "https://vemphy.com/ns/i/gcb/StaffIdCard/v1#issuedOn",
                  "@type": "http://www.w3.org/2001/XMLSchema#date" } } }
```

`date` maps to `xsd:date`, `date-time` to `xsd:dateTime`, `integer` to
`xsd:integer`, `boolean` to `xsd:boolean`; everything else is a plain string.
Every property is defined explicitly. The VC 2.0 context has no `@vocab`
fallback, and nothing here adds one.

The output is canonical JSON: keys sorted, no whitespace, ASCII only. The two
generators must agree byte for byte on every vector schema.

### No dropped terms

JSON-LD expansion drops a term that no context defines, and a dropped field
is a field the signature does not cover. Two guards:

1. `assertNoDroppedTerms(schema, context)` builds a sample claim with every
   property present, expands it, and fails unless every key appears in the
   output under the expected identifier. It runs over every core and vector
   schema in CI, and the registry runs it before it publishes a type.
2. Canonicalisation stays in safe mode, which refuses an undefined term, so a
   claim with a field outside its context cannot be signed or verified at all.

## The claim

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://vemphy.com/ns/i/gcb/StaffIdCard/v1"],
  "type": ["VerifiableCredential", "StaffIdCard"],
  "credentialSchema": { "id": "https://vemphy.com/schemas/i/gcb/StaffIdCard/v1.json", "type": "JsonSchema" }
}
```

The shape check accepts, as the second context:

- `claims/v1`, with one of the three 0.1.0 types and no `credentialSchema`;
- `ns/core/<T>/v<n>`, with type `T` and `credentialSchema.id`
  `https://vemphy.com/schemas/core/<T>/v<n>.json`;
- `ns/i/<slug>/<T>/v<n>`, the same way, where `<slug>` is the issuer of the
  claim. An issuer cannot sign against another issuer's vocabulary.

The document at the schema URL follows the W3C "VC JSON Schema" reading, in
which a `JsonSchema` validates the whole credential: it is
`{ "$schema", "$id", "type": "object", "required": ["credentialSubject"],
"properties": { "credentialSubject": <the claim schema> } }`.
`credentialSchemaDocument(schema, url)` wraps and `subjectSchemaFrom(document)`
unwraps.

The envelope (credential, proof, status entry, status list credential, DID
document) is described by JSON Schemas under `schemas/envelope/`, shared by
both languages. The handful of rules that span fields (everything names the
same issuer; `validUntil` is after `validFrom`) stay as small functions.
Zod leaves the package.

## Verification

Signature, status and dates decide the four words, as before. The subject is
no longer checked against a compiled schema on the way. When
`credentialSchema` is present and `fetchSchema` can produce the document (core
schemas are bundled), the verifier checks that the document is a legitimate
claim schema, validates the subject, and reports `schemaValid: true | false`
and a `schema` entry in `checks`. It never changes `result`. For a `claims/v1`
claim the bundled version 1 core schema of the same name is used.

## Loading documents

`documentLoader({ allowlist, cache, bundled, fetch })`:

- serves bundled documents first: the VC 2.0 context, `claims/v1`, and every
  core context, generated from the core schemas at build time and checked in;
- then the cache; contexts are immutable, so entries never expire;
- then the network, only for a URL on the allowlist
  (`https://www.w3.org/ns/credentials/v2`, `https://w3id.org/security/*`,
  `https://vemphy.com/ns/*` by default). Anything else is refused before any
  request is made. Responses over 64 KB or without an `@context` are refused.

With no `fetch`, the loader is offline, and a missing document is a clear
error: the claim is `unknown` with reason `context_unavailable`. The CLI gains
`--cache <dir>` and `--offline`; schemas use the same loader with
`https://vemphy.com/schemas/*`.

`vcctx` in Go mirrors this.

## API

TypeScript: `validateSchema`, `validateSubject`, `labelFor`,
`contextFromSchema`, `assertNoDroppedTerms`, `credentialSchemaDocument`,
`subjectSchemaFrom`, `coreSchemas`, `documentLoader`. The `./schema` entry
point and every Zod export are removed; this is a breaking change, made in a
0.x minor release.

Go: package `schema` with `Validate`, `Compile`/`(*Validator).Subject`,
`LabelFor`, `GenerateContext`, `AssertNoDroppedTerms`, `Document`,
`SubjectSchemaFrom`, `Core`; validator
`github.com/santhosh-tekuri/jsonschema/v6`. TypeScript uses `ajv` 8
(2020-12 build). Go cannot embed files from outside its module, so
`vc-go/schema/` holds copies of `schemas/`, and CI fails if they differ.

## Vectors and CI

- `vectors/schemas/valid/` — core and custom schemas; `invalid/` — one schema
  per rule above, each with the rule it breaks; `subjects/` — accept and
  reject fixtures per schema, including every format and pattern edge.
- `vectors/contexts/` — the expected context for each valid schema.
- Claims: a custom type (`gcb` `StaffIdCard` v1 and v2, so a version 1 claim
  exists beside a version 2), an `Attestation`, new core types, a claim using
  another issuer's context (`unknown`, `malformed`), a claim whose subject
  breaks its schema but is correctly signed (`valid`, `schemaValid: false`).
- Interop CI: both meta-validators agree on every schema; both subject
  validators agree on every fixture; both context generators agree byte for
  byte; the dropped-terms check passes in both; canonical forms and signatures
  match on the new claims; the CLI verifies the custom claim offline from a
  cache and fails closed without one; a context outside the allowlist is
  refused before any request.
