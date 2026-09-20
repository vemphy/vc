import { readFileSync } from 'node:fs'
import { bytesToHex } from '@noble/hashes/utils.js'
import { describe, expect, it } from 'vitest'
import { canonicalize } from './canon.js'
import { staticLoader } from './context/loader.js'
import { decodeBase58btc, decodeMultikey } from './multibase.js'
import { createProof, hashForProof, memorySigner, verifyProof } from './proof.js'

const read = (name: string) => JSON.parse(readFileSync(new URL(`../../../vectors/w3c/${name}`, import.meta.url), 'utf8'))

// The test vector published in the W3C Data Integrity EdDSA Cryptosuites specification.
const w3c = read('eddsa-rdfc-2022.json')
const loader = staticLoader({ 'https://www.w3.org/ns/credentials/examples/v2': read('examples-v2.json') })

// secretKeyMultibase is a two-byte multicodec prefix followed by the 32-byte seed.
const seed = decodeBase58btc(w3c.secretKeyMultibase).slice(2)
const publicKey = decodeMultikey(w3c.publicKeyMultibase)

describe('W3C eddsa-rdfc-2022 known answers', () => {
  it('canonicalizes the document and the proof options as published', async () => {
    expect(await canonicalize(w3c.unsigned, loader)).toBe(w3c.canonicalDocument)
    expect(await canonicalize(w3c.proofOptions, loader)).toBe(w3c.canonicalProofOptions)
  })

  it('produces the published 64-byte hash', async () => {
    const { '@context': _, ...options } = w3c.proofOptions
    expect(bytesToHex(await hashForProof(w3c.unsigned, options, loader))).toBe(w3c.combinedHashHex)
  })

  it('derives the published public key from the secret key', async () => {
    const signer = await memorySigner(seed, w3c.proofOptions.verificationMethod)
    expect(signer.publicKey).toEqual(publicKey)
  })

  it('produces the published proofValue', async () => {
    const signer = await memorySigner(seed, w3c.proofOptions.verificationMethod)
    const signed = await createProof(w3c.unsigned, signer, { created: w3c.proofOptions.created }, loader)
    expect(signed.proof.proofValue).toBe(w3c.signed.proof.proofValue)
    expect(signed).toEqual(w3c.signed)
  })

  it('verifies the published credential', async () => {
    expect(await verifyProof(w3c.signed, publicKey, loader)).toBe(true)
  })
})

describe('verifyProof', () => {
  const tampered = (mutate: (c: any) => void) => {
    const copy = structuredClone(w3c.signed)
    mutate(copy)
    return copy
  }

  it.each([
    ['a changed subject value', (c: any) => (c.credentialSubject.alumniOf = 'The School of Exampless')],
    ['a changed issuer', (c: any) => (c.issuer = 'https://vc.example/issuers/5679')],
    ['a changed proof date', (c: any) => (c.proof.created = '2023-02-24T23:36:39Z')],
    ['a changed verification method', (c: any) => (c.proof.verificationMethod += 'x')],
    ['a removed member', (c: any) => delete c.description],
  ])('is false after %s', async (_, mutate) => {
    expect(await verifyProof(tampered(mutate), publicKey, loader)).toBe(false)
  })

  it('is false for another key', async () => {
    const other = await memorySigner(new Uint8Array(32).fill(7), 'did:example:other#key-1')
    expect(await verifyProof(w3c.signed, other.publicKey, loader)).toBe(false)
  })

  it.each([
    ['no proof', (c: any) => delete c.proof],
    ['a list of proofs', (c: any) => (c.proof = [c.proof])],
    ['a proofValue in another base', (c: any) => (c.proof.proofValue = 'u' + c.proof.proofValue.slice(1))],
    ['a truncated proofValue', (c: any) => (c.proof.proofValue = c.proof.proofValue.slice(0, 40))],
    ['a proofValue that is not text', (c: any) => (c.proof.proofValue = 42)],
  ])('is false for %s', async (_, mutate) => {
    expect(await verifyProof(tampered(mutate), publicKey, loader)).toBe(false)
  })
})

describe('createProof', () => {
  it('refuses a document that is already signed', async () => {
    const signer = await memorySigner(seed, 'did:example:x#key-1')
    await expect(createProof(w3c.signed, signer, { created: '2026-01-01T00:00:00Z' }, loader)).rejects.toThrow()
  })
})
