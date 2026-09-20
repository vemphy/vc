# @vemphy/vc

Verify a Vemphy claim. No account, no API key, and no call to Vemphy beyond
fetching the issuer's public key and status list.

A Vemphy claim is a [W3C Verifiable Credential 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
signed by the issuer — a bank, a university, an employer — with a Data
Integrity proof (`eddsa-rdfc-2022`). This package checks that signature, the
issuer's key, revocation and the validity dates, and gives one of four answers.

```sh
npm install @vemphy/vc
```

## Verify a claim

```ts
import { didToUrl, verifyCredential } from '@vemphy/vc'

const getJson = (url: string) => fetch(url).then((response) => response.json())

const { result } = await verifyCredential(claim, {
  now: new Date(),
  resolveDid: (did) => getJson(didToUrl(did)),
  fetchStatusList: getJson,
})
// result: 'valid' | 'revoked' | 'expired' | 'unknown'
```

`claim` is the credential as parsed JSON. `verifyCredential` never throws and
never reads the clock or the network itself: the time and both fetchers are
yours, so you can cache, proxy, log or pin them as your environment requires.

## The four answers

| Result | Meaning |
|---|---|
| `valid` | Signed by the issuer named in it, with a key that was in good standing when it signed; not revoked; within its validity dates. |
| `revoked` | The issuer has withdrawn it. |
| `expired` | It is outside its validity dates. |
| `unknown` | Nothing can be confirmed about this document. Treat it as unverified. |

`unknown` covers every case where the checks could not be completed, including
a document that does not match its signature, a key that cannot be found, and
a status list that is unreachable or out of date. The outcome also carries a
`reason` and the list of `checks` made, for your logs:

```ts
const outcome = await verifyCredential(claim, deps)
// { result: 'unknown', reason: 'status_list_unverifiable', checks: [{ name: 'shape', ok: true }, …] }
```

Reasons: `malformed`, `did_unresolvable`, `key_not_found`,
`key_window_violation`, `signature_failure`, `status_list_unverifiable`.
Show people the result word; keep the reason for operators.

## From the command line

```sh
npx @vemphy/vc verify claim.json
npx @vemphy/vc verify claim.json --did-doc did.json --status-list list.json --now 2026-06-01T12:00:00Z
npx @vemphy/vc verify claim.json --verbose
```

It prints the one word. The exit status is `0` for `valid`, `1` for anything
else and `2` for a usage error. With `--did-doc` and `--status-list` nothing is
fetched, so a claim can be checked on a machine with no network access.

## Codes

Every claim has a short code such as `GCB-7K2M-9QXD`, printed on the document
next to a QR code. The last character is a check character covering the whole
code, so a mistyped code is caught before anything is looked up.

```ts
import { parseCode } from '@vemphy/vc/code'

parseCode('gcb 7k2m 9qxd')       // { ok: true, code: 'GCB-7K2M-9QXD', slug: 'GCB', … }
parseCode('GCB-7K2N-9QXD')       // { ok: false, error: 'check', suspects: [7, 2] }
parseCode('https://vemphy.com/v/GCB-7K2M-9QXD')
```

`@vemphy/vc/code` has no dependencies and is under 5 kB unminified, so it can go
in a browser bundle on its own. Input is case-insensitive; spaces and hyphens
are ignored; `O` is read as `0`, and `I` and `L` as `1`. `suspects` lists the
positions most likely to have been mistyped, best first, and may be empty.

## Schemas

```ts
import { subjectSchemas, credentialSchema, defaultDisclosure, jsonSchemaFor } from '@vemphy/vc/schema'

subjectSchemas.BankReferenceLetter.safeParse(formValues)
jsonSchemaFor('DegreeCertificate') // JSON Schema 2020-12
```

[zod](https://zod.dev) schemas for the three claim types —
`BankReferenceLetter`, `DegreeCertificate`, `EmploymentLetter` — and for the
credential around them. They are the schemas `verifyCredential` applies, so a
form validated with them cannot produce a claim the verifier will refuse. They
reject unknown fields: a field the JSON-LD context does not define would be
left out of what gets signed.

## What is checked, in order

1. **Shape.** Exactly the two known contexts, one known claim type, no unknown members.
2. **Issuer key.** The issuer's DID document is resolved (`did:web:vemphy.com:i:<slug>`)
   and the signing key is found in it, controlled by that issuer.
3. **Key window.** The key was not revoked or expired when the proof was created.
   Claims signed before a key was rotated out or revoked keep verifying.
4. **Signature.** RDFC-1.0 canonicalization, SHA-256, Ed25519.
5. **Status list.** A signed, short-lived credential from the same issuer. Its
   own signature and validity are checked; a list that is out of date is not trusted.
6. **Revocation**, then 7. **validity dates**.

The signature comes before revocation and dates, so a document that has been
altered never yields anything but `unknown`.

JSON-LD contexts are bundled. Canonicalization never fetches one, and a claim
that names any other context is refused.

## Signing

`createProof` and `memorySigner` exist for tests and for issuers who hold
their own keys. `Signer` receives the 64-byte hash to sign and nothing else,
so it can be implemented over a KMS or an HSM.

## Go

The same verifier, tested against the same vectors:
`go get github.com/vemphy/vc/vc-go`. See the [repository](https://github.com/vemphy/vc).

Apache-2.0.
