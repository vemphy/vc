import { describe, expect, it, vi } from 'vitest'
import { BUNDLED_CONTEXTS, CREDENTIALS_V2, documentLoader, DocumentUnavailableError, memoryCache, UnknownContextError } from './loader.js'

const context = { '@context': { '@protected': true } }
const respond = (body: unknown, init?: ResponseInit) => vi.fn(async () => new Response(typeof body === 'string' ? body : JSON.stringify(body), init))

describe('documentLoader', () => {
  it('serves bundled documents without a cache or a network', async () => {
    const load = documentLoader()
    expect((await load(CREDENTIALS_V2)).document).toBe(BUNDLED_CONTEXTS[CREDENTIALS_V2])
    expect((await load('https://vemphy.com/ns/core/Attestation/v1')).document).toBeDefined()
    expect((await load('https://vemphy.com/ns/claims/v1')).document).toBeDefined()
  })

  it('refuses an origin that is not on the allowlist before any request is made', async () => {
    const fetch = respond(context)
    const load = documentLoader({ fetch })
    for (const url of [
      'https://example.com/ns/v1',
      'http://vemphy.com/ns/i/gcb/StaffIdCard/v1',
      'https://vemphy.com.example.com/ns/x',
      'https://vemphy.com/other',
      'https://www.w3.org/ns/credentials/v2/extra',
    ]) {
      await expect(load(url)).rejects.toBeInstanceOf(UnknownContextError)
    }
    expect(fetch).not.toHaveBeenCalled()
  })

  it('does not look in the cache for a URL it would refuse', async () => {
    const cache = memoryCache()
    await cache.set('https://example.com/ns/v1', context)
    await expect(documentLoader({ cache })('https://example.com/ns/v1')).rejects.toBeInstanceOf(UnknownContextError)
  })

  it('fetches an allowed URL once and then answers from the cache', async () => {
    const fetch = respond(context)
    const load = documentLoader({ cache: memoryCache(), fetch })
    const url = 'https://vemphy.com/ns/i/gcb/StaffIdCard/v1'
    expect((await load(url)).document).toEqual(context)
    expect((await load(url)).document).toEqual(context)
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('is offline without a fetch, and says which document is missing', async () => {
    const load = documentLoader()
    await expect(load('https://vemphy.com/ns/i/gcb/StaffIdCard/v1')).rejects.toBeInstanceOf(DocumentUnavailableError)
    await expect(load('https://vemphy.com/ns/i/gcb/StaffIdCard/v1')).rejects.toThrow(/StaffIdCard\/v1.*offline/)
  })

  it.each([
    ['an error status', respond('no', { status: 404 })],
    ['something that is not JSON', respond('<html>')],
    ['JSON with no @context', respond({ hello: 'world' })],
    ['a document over 64 KB', respond({ '@context': {}, padding: 'x'.repeat(70_000) })],
    ['a network error', vi.fn(async () => Promise.reject(new Error('offline')))],
  ])('does not keep %s', async (_, fetch) => {
    const cache = memoryCache()
    const load = documentLoader({ cache, fetch: fetch as never })
    const url = 'https://vemphy.com/ns/i/gcb/StaffIdCard/v1'
    await expect(load(url)).rejects.toBeInstanceOf(DocumentUnavailableError)
    expect(await cache.get(url)).toBeUndefined()
  })

  it('never lets a caller replace a bundled context through the cache', async () => {
    const cache = memoryCache()
    await cache.set(CREDENTIALS_V2, context)
    expect((await documentLoader({ cache })(CREDENTIALS_V2)).document).toBe(BUNDLED_CONTEXTS[CREDENTIALS_V2])
  })
})
