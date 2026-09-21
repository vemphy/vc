import { readdirSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { dirCache } from '../cli/cache.js'
import { documentLoader, schemaLoader } from './context/loader.js'
import { slugOf } from './did.js'
import { verifyCredential, type VerifyDeps } from './verify.js'

const root = new URL('../../../vectors/', import.meta.url)
const read = (path: string) => JSON.parse(readFileSync(new URL(path, root), 'utf8'))

const expected = read('expected.json') as { now: string; vectors: Record<string, { result: string; reason?: string; schemaValid?: boolean }> }

// vectors/cache is what a verifier's cache holds once it has met the issuers' own types.
const cache = dirCache(new URL('cache/', root).pathname)

// Resolvers backed by the vectors directory. Nothing here touches the network: neither loader is given a fetch.
const deps = (overrides: Partial<VerifyDeps> = {}): VerifyDeps => ({
  now: new Date(expected.now),
  documentLoader: documentLoader({ cache }),
  fetchSchema: schemaLoader({ cache }),
  resolveDid: async (did) => read(`keys/${slugOf(did)}.did.json`),
  fetchStatusList: async (url) => {
    const match = /^https:\/\/vemphy\.com\/i\/([a-z]+)\/status\/(\d+)$/.exec(url)
    if (!match) throw new Error(`unexpected status list URL ${url}`)
    return read(`status/${match[1]}-${match[2]}.json`)
  },
  ...overrides,
})

describe('vectors', () => {
  it('cover every file in vectors/claims', () => {
    const files = readdirSync(new URL('claims/', root)).map((f) => f.replace(/\.json$/, '')).sort()
    expect(files).toEqual(Object.keys(expected.vectors).sort())
  })

  it.each(Object.entries(expected.vectors))('%s', async (name, want) => {
    const outcome = await verifyCredential(read(`claims/${name}.json`), deps())
    expect(outcome.result).toBe(want.result)
    expect(outcome.reason).toBe(want.reason)
    expect(outcome.schemaValid).toBe(want.schemaValid)
  })
})

describe("an issuer's own types", () => {
  const custom = () => read('claims/gcb-012.json')

  it('cannot be verified offline without their context, and say so', async () => {
    const bundledOnly = deps({ documentLoader: documentLoader() })
    expect(await verifyCredential(custom(), bundledOnly)).toMatchObject({ result: 'unknown', reason: 'context_unavailable' })
  })

  it('fetch a context once, from vemphy.com, and keep it', async () => {
    const requested: string[] = []
    const fetch = (async (url: string) => {
      requested.push(url)
      return new Response(JSON.stringify(await cache.get(url)))
    }) as typeof globalThis.fetch
    const online = deps({ documentLoader: documentLoader({ cache: (await import('./context/loader.js')).memoryCache(), fetch }) })
    expect((await verifyCredential(custom(), online)).result).toBe('valid')
    expect((await verifyCredential(custom(), online)).result).toBe('valid')
    expect(requested).toEqual(['https://vemphy.com/ns/i/gcb/StaffIdCard/v1'])
  })

  it('verify without their schema; schemaValid is then absent', async () => {
    const outcome = await verifyCredential(custom(), deps({ fetchSchema: async () => Promise.reject(new Error('offline')) }))
    expect(outcome.result).toBe('valid')
    expect(outcome.schemaValid).toBeUndefined()
  })

  it('are never checked against a schema document that breaks the rules', async () => {
    const document = await cache.get('https://vemphy.com/schemas/i/gcb/StaffIdCard/v1.json')
    const hostile = structuredClone(document) as any
    hostile.properties.credentialSubject.properties.holderName.pattern = '^(?=a)(a+)+$'
    const outcome = await verifyCredential(custom(), deps({ fetchSchema: async () => hostile }))
    expect(outcome).toMatchObject({ result: 'valid', schemaValid: false })
  })

  it('keep the answer when the subject does not match the schema', async () => {
    expect(await verifyCredential(read('claims/gcb-016.json'), deps())).toMatchObject({ result: 'valid', schemaValid: false })
  })
})

describe('verifyCredential', () => {
  const good = () => read('claims/gcb-001.json')

  it('reports every check it made, in order', async () => {
    const outcome = await verifyCredential(good(), deps())
    expect(outcome).toEqual({
      result: 'valid',
      schemaValid: true,
      checks: ['shape', 'context', 'did', 'key', 'key_window', 'signature', 'status_list', 'not_revoked', 'validity_period'].map(
        (name) => ({ name, ok: true }),
      ),
    })
  })

  it('stops at the first check that does not hold', async () => {
    const outcome = await verifyCredential(read('claims/gcb-002.json'), deps())
    expect(outcome.checks.at(-1)).toEqual({ name: 'signature', ok: false })
    expect(outcome.checks.map((c) => c.name)).not.toContain('status_list')
  })

  it.each([null, undefined, 42, 'text', [], {}])('answers unknown for %j and does not throw', async (input) => {
    expect(await verifyCredential(input, deps())).toMatchObject({ result: 'unknown', reason: 'malformed' })
  })

  it('answers unknown when the DID cannot be resolved', async () => {
    const failing = deps({ resolveDid: async () => Promise.reject(new Error('offline')) })
    expect(await verifyCredential(good(), failing)).toMatchObject({ result: 'unknown', reason: 'did_unresolvable' })
  })

  it('answers unknown when the DID document is for someone else', async () => {
    const wrong = deps({ resolveDid: async () => read('keys/ug.did.json') })
    expect(await verifyCredential(good(), wrong)).toMatchObject({ result: 'unknown', reason: 'did_unresolvable' })
  })

  it('answers unknown when the status list cannot be fetched', async () => {
    const failing = deps({ fetchStatusList: async () => Promise.reject(new Error('offline')) })
    expect(await verifyCredential(good(), failing)).toMatchObject({ result: 'unknown', reason: 'status_list_unverifiable' })
  })

  it("does not accept another issuer's status list, or an altered one", async () => {
    const swapped = deps({ fetchStatusList: async () => read('status/ug-1.json') })
    expect(await verifyCredential(good(), swapped)).toMatchObject({ reason: 'status_list_unverifiable' })

    // Clearing the revocation bit by replacing the list with an empty one breaks the list's signature.
    const cleared = deps({
      fetchStatusList: async () => {
        const list = read('status/gcb-1.json')
        list.credentialSubject.encodedList = read('status/gcb-2.json').credentialSubject.encodedList
        return list
      },
    })
    expect(await verifyCredential(read('claims/gcb-004.json'), cleared)).toMatchObject({
      result: 'unknown',
      reason: 'status_list_unverifiable',
    })
  })

  it("refuses a credential that claims Vemphy's own apex DID as its issuer", async () => {
    // Vemphy is not an issuer of claims: its apex key signs the issuer
    // directory and nothing else. verifyCredential passes a credential's own
    // `issuer` straight to the issuer-DID pattern, so this must stay refused
    // even though the rest of the document is otherwise well formed —
    // widening that pattern to admit the apex would let this verify as an
    // ordinary claim.
    const claimingApex = { ...good(), issuer: 'did:web:vemphy.com' }
    expect(await verifyCredential(claimingApex, deps())).toMatchObject({ result: 'unknown', reason: 'malformed' })
  })

  it('answers expired before validFrom and from validUntil onwards', async () => {
    const at = (now: string) => verifyCredential(good(), deps({ now: new Date(now), fetchStatusList: freshList(now) }))
    expect((await at('2026-05-04T08:59:59Z')).result).toBe('expired')
    expect((await at('2026-05-04T09:00:00Z')).result).toBe('valid')
    expect((await at('2026-08-04T08:59:59Z')).result).toBe('valid')
    expect((await at('2026-08-04T09:00:00Z')).result).toBe('expired')
  })
})

// The committed status list is only valid around expected.now. For other instants the tests
// need a list that is current, which means signing one with the test key.
function freshList(now: string): VerifyDeps['fetchStatusList'] {
  return async () => {
    const { createProof, memorySigner } = await import('./proof.js')
    const { hexToBytes } = await import('@noble/hashes/utils.js')
    const { proof: _, ...unsigned } = read('status/gcb-1.json')
    const at = Date.parse(now)
    unsigned.validFrom = new Date(at - 60_000).toISOString().replace('.000', '')
    unsigned.validUntil = new Date(at + 60_000).toISOString().replace('.000', '')
    const vm = 'did:web:vemphy.com:i:gcb#key-2'
    const signer = await memorySigner(hexToBytes(read('keys/test-seeds.json').seeds[vm]), vm)
    return createProof(unsigned, signer, { created: unsigned.validFrom })
  }
}
