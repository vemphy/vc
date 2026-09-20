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

Issuer identifiers are `did:web:vemphy.com:i:<slug>`. Claims use two JSON-LD
contexts, both bundled here: the W3C credentials context and
[`https://vemphy.com/ns/claims/v1`](packages/vc/src/context/claims-v1.json).
The claims context is append-only: a term, once published, is never changed.

## How the two implementations are kept in step

Both verify every file in `vectors/claims` and must produce the result and
reason recorded in [`vectors/expected.json`](vectors/expected.json). Both
reproduce the canonical N-Quads in `vectors/canon` byte for byte, and both
reproduce the test vector published in the W3C EdDSA specification
(`vectors/w3c`), so they agree with the standard and not only with each other.

[`scripts/interop.sh`](scripts/interop.sh) then generates a key neither side
has seen: TypeScript signs and Go verifies, Go signs and TypeScript verifies,
and the two signatures over the same document must be identical. CI runs all
of it on every push, regenerates the vectors, and fails on any difference.

`vectors/keys/test-seeds.json` holds the private seeds the vectors were signed
with. They are test material, published on purpose, and must never be used for
anything else.

## Layout

```
packages/vc/src/   code · schema · context · canon · proof · did · status · verify
packages/vc/cli/   the vemphy-vc command
vc-go/             code · vcctx · canon · proof · did · multibase · status · verify
vectors/           claims · keys · status · canon · w3c · codes.json · expected.json
docs/              design and implementation plan
```

## Licence

Apache-2.0.
