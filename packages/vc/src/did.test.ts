import { describe, expect, it } from 'vitest'
import { didToUrl, findKey, parseDidDocument, slugOf } from './did.js'

const DID = 'did:web:vemphy.com:i:gcb'
const KEY = 'z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2'

const document = () => ({
  '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
  id: DID,
  verificationMethod: [
    { id: `${DID}#key-1`, type: 'Multikey', controller: DID, publicKeyMultibase: KEY, revoked: '2026-03-01T00:00:00Z' },
    { id: `${DID}#key-2`, type: 'Multikey', controller: DID, publicKeyMultibase: KEY },
    { id: `${DID}#key-3`, type: 'Multikey', controller: 'did:web:vemphy.com:i:ug', publicKeyMultibase: KEY },
  ],
  assertionMethod: [`${DID}#key-2`],
})

describe('did:web', () => {
  it('maps an issuer DID to its document URL', () => {
    expect(didToUrl(DID)).toBe('https://vemphy.com/i/gcb/did.json')
    expect(slugOf(DID)).toBe('gcb')
  })

  it.each([
    'did:web:example.com:i:gcb',
    'did:web:vemphy.com',
    'did:web:vemphy.com:i:GCB',
    'did:web:vemphy.com:i:gcb:extra',
    'did:web:vemphy.com%3A8443:i:gcb',
    'did:web:vemphy.com:i:g%63b',
    'did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2',
  ])('refuses %s', (did) => {
    expect(() => didToUrl(did)).toThrow()
  })
})

describe('DID documents', () => {
  it('refuses a document for another DID', () => {
    expect(() => parseDidDocument(document(), 'did:web:vemphy.com:i:ug')).toThrow()
    expect(() => parseDidDocument({ id: DID }, DID)).toThrow()
  })

  it('finds an active key', () => {
    const key = findKey(parseDidDocument(document(), DID), `${DID}#key-2`)
    expect(key?.publicKey).toHaveLength(32)
    expect(key?.inAssertionMethod).toBe(true)
    expect(key?.revoked).toBeUndefined()
  })

  it('reports a revoked key with its date and outside assertionMethod', () => {
    const key = findKey(parseDidDocument(document(), DID), `${DID}#key-1`)
    expect(key?.revoked).toEqual(new Date('2026-03-01T00:00:00Z'))
    expect(key?.inAssertionMethod).toBe(false)
  })

  it('ignores a key controlled by someone else, a missing key and a foreign key id', () => {
    const doc = parseDidDocument(document(), DID)
    expect(findKey(doc, `${DID}#key-3`)).toBeUndefined()
    expect(findKey(doc, `${DID}#key-9`)).toBeUndefined()
    expect(findKey(doc, 'did:web:vemphy.com:i:ug#key-1')).toBeUndefined()
  })
})
