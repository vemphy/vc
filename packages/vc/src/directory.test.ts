import { hexToBytes } from '@noble/hashes/utils.js'
import { readdirSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { APEX_DID } from './did.js'
import { directoryIssuer, DirectoryExpiredError, verifyDirectory, type VerifyDirectoryDeps } from './directory.js'
import { createProof, memorySigner } from './proof.js'

const root = new URL('../../../vectors/', import.meta.url)
const read = (path: string) => JSON.parse(readFileSync(new URL(path, root), 'utf8'))

const expected = read('expected.json') as { now: string; directories: Record<string, { result: string; note: string }> }

// Resolvers backed by the vectors directory. Nothing here touches the network.
const deps = (overrides: Partial<VerifyDirectoryDeps> = {}): VerifyDirectoryDeps => ({
  now: new Date(expected.now),
  resolveApex: async () => read('keys/apex.did.json'),
  ...overrides,
})

describe('vectors', () => {
  it('cover every file in vectors/directory', () => {
    const files = readdirSync(new URL('directory/', root))
      .map((f) => f.replace(/\.json$/, ''))
      .sort()
    expect(files).toEqual(Object.keys(expected.directories).sort())
  })

  it.each(Object.entries(expected.directories))('%s', async (name, want) => {
    const raw = read(`directory/${name}.json`)
    if (want.result === 'valid') {
      const directory = await verifyDirectory(raw, deps())
      expect(directory.entries).toHaveLength(3)
      expect(directoryIssuer(directory, 'gcb')).toEqual({ slug: 'gcb', legalName: 'GCB Bank PLC', did: 'did:web:vemphy.com:i:gcb', status: 'active' })
    } else if (want.result === 'expired') {
      await expect(verifyDirectory(raw, deps())).rejects.toBeInstanceOf(DirectoryExpiredError)
    } else {
      // Everything that is not a stale directory is refused as not trustworthy: wrong key,
      // wrong key window or a broken signature, never told apart from one another by result.
      await expect(verifyDirectory(raw, deps())).rejects.not.toBeInstanceOf(DirectoryExpiredError)
    }
  })
})

describe('verifyDirectory', () => {
  const good = () => read('directory/good.json')

  it('reports the entries and validUntil of a directory in good order', async () => {
    const directory = await verifyDirectory(good(), deps())
    expect(directory.validUntil).toEqual(new Date('2026-06-01T12:32:00Z'))
    expect(directoryIssuer(directory, 'ug')?.legalName).toBe('University of Ghana')
    expect(directoryIssuer(directory, 'zzz')).toBeUndefined()
  })

  it('refuses anything that is not a Verifiable Credential at all', async () => {
    await expect(verifyDirectory({ hello: 'world' }, deps())).rejects.toThrow()
    await expect(verifyDirectory(null, deps())).rejects.toThrow()
    await expect(verifyDirectory('a string', deps())).rejects.toThrow()
  })

  it('refuses a directory not issued by the apex DID, even before a key is looked up', async () => {
    const wrongIssuer = { ...good(), issuer: 'did:web:vemphy.com:i:gcb' }
    await expect(verifyDirectory(wrongIssuer, deps())).rejects.toThrow(/is not/)
  })

  it('refuses a genuinely, validly signed directory-shaped document issued by a real bank', async () => {
    // Vemphy's apex key signs the issuer directory and nothing else. A bank
    // signing something shaped exactly like the directory, with its own
    // perfectly good key, must still be refused: a receiver must never read
    // it as Vemphy's own directory.
    const { proof: _proof, ...unsigned } = good()
    const seeds = read('keys/test-seeds.json').seeds as Record<string, string>
    const vm = 'did:web:vemphy.com:i:gcb#key-2'
    const signer = await memorySigner(hexToBytes(seeds[vm]!), vm)
    const impersonating = await createProof({ ...unsigned, issuer: 'did:web:vemphy.com:i:gcb' }, signer, { created: '2026-06-01T11:32:00Z' })
    await expect(verifyDirectory(impersonating, deps())).rejects.toThrow(/is not/)
  })

  it('refuses a proof made with a key that is not in the apex DID document', async () => {
    const unknownKey = { ...good(), proof: { ...good().proof, verificationMethod: `${APEX_DID}#key-9` } }
    await expect(verifyDirectory(unknownKey, deps())).rejects.toThrow()
  })

  it('refuses when the apex DID document cannot be resolved as one', async () => {
    // A document for an issuer, not Vemphy's own, must not stand in for the apex document.
    const wrongDocument = deps({ resolveApex: async () => read('keys/gcb.did.json') })
    await expect(verifyDirectory(good(), wrongDocument)).rejects.toThrow()
  })

  it("tells a stale directory apart from one that was never trustworthy", async () => {
    const expiredDoc = read('directory/expired.json')
    const alteredDoc = read('directory/altered-status.json')
    await expect(verifyDirectory(expiredDoc, deps())).rejects.toBeInstanceOf(DirectoryExpiredError)
    await expect(verifyDirectory(alteredDoc, deps())).rejects.not.toBeInstanceOf(DirectoryExpiredError)
  })
})
