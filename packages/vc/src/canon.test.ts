import { readFileSync } from 'node:fs'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { canonicalize } from './canon.js'
import { CLAIMS_V1, CREDENTIALS_V2, staticLoader, UnknownContextError } from './context/loader.js'

const vector = (name: string) => readFileSync(new URL(`../../../vectors/canon/${name}`, import.meta.url), 'utf8')
const minimal = () => JSON.parse(vector('minimal.json')) as Record<string, unknown>

afterEach(() => vi.restoreAllMocks())

describe('staticLoader', () => {
  it('serves the two bundled contexts', async () => {
    const load = staticLoader()
    expect((await load(CREDENTIALS_V2)).document).toHaveProperty('@context')
    expect((await load(CLAIMS_V1)).document).toHaveProperty('@context')
  })

  it('refuses anything else', async () => {
    await expect(staticLoader()('https://example.com/ctx')).rejects.toBeInstanceOf(UnknownContextError)
    await expect(staticLoader()('constructor')).rejects.toBeInstanceOf(UnknownContextError)
  })

  it('does not let extra documents replace a bundled context', async () => {
    const load = staticLoader({ [CLAIMS_V1]: { '@context': {} } })
    expect((await load(CLAIMS_V1)).document).toEqual((await staticLoader()(CLAIMS_V1)).document)
  })
})

describe('canonicalize', () => {
  it('reproduces the committed N-Quads', async () => {
    expect(await canonicalize(minimal())).toBe(vector('minimal.nq'))
  })

  it('does not depend on key order', async () => {
    const doc = minimal()
    const reversed = Object.fromEntries(Object.entries(doc).reverse())
    reversed.credentialSubject = Object.fromEntries(Object.entries(doc.credentialSubject as object).reverse())
    expect(await canonicalize(reversed)).toBe(vector('minimal.nq'))
  })

  it('rejects a property no context defines', async () => {
    const doc = minimal()
    ;(doc.credentialSubject as Record<string, unknown>).balance = '1000'
    await expect(canonicalize(doc)).rejects.toThrow()
  })

  it('rejects a type no context defines', async () => {
    const doc = minimal()
    doc.type = ['VerifiableCredential', 'NotDefinedAnywhere']
    await expect(canonicalize(doc)).rejects.toThrow()
  })

  it('rejects a relative id', async () => {
    const doc = minimal()
    doc.id = 'not-an-iri'
    await expect(canonicalize(doc)).rejects.toThrow()
  })

  it('rejects an unknown context without fetching it', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const doc = minimal()
    ;(doc['@context'] as string[]).push('https://example.com/ctx')
    await expect(canonicalize(doc)).rejects.toThrow(/example\.com/)
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
