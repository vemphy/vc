import * as ed from '@noble/ed25519'
import { sha256 } from '@noble/hashes/sha2.js'
import { canonicalize } from './canon.js'
import type { DocumentLoader } from './context/loader.js'
import { decodeBase58btc, encodeBase58btc } from './multibase.js'

/**
 * Something that can sign on behalf of one verification method.
 *
 * It is given the 64-byte Data Integrity hash, never the document and never a
 * key, so an implementation can sit in front of a KMS or an HSM.
 */
export interface Signer {
  readonly verificationMethod: string
  sign(hash: Uint8Array): Promise<Uint8Array>
}

/** Holds an Ed25519 seed in memory. For tests, and for issuers who keep their own keys. */
export async function memorySigner(
  seed: Uint8Array,
  verificationMethod: string,
): Promise<Signer & { publicKey: Uint8Array }> {
  if (seed.length !== 32) throw new Error('an Ed25519 seed is 32 bytes')
  const publicKey = await ed.getPublicKeyAsync(seed)
  return { verificationMethod, publicKey, sign: (hash) => ed.signAsync(hash, seed) }
}

type JsonObject = Record<string, unknown>

const encoder = new TextEncoder()
const digest = (text: string) => sha256(encoder.encode(text))

/**
 * The bytes that are signed: SHA-256 of the canonical proof options followed
 * by SHA-256 of the canonical document. The proof options are the proof
 * without its value, read in the document's own context.
 */
export async function hashForProof(
  unsigned: JsonObject,
  proofOptions: JsonObject,
  loader?: DocumentLoader,
): Promise<Uint8Array> {
  const options = { ...proofOptions, '@context': unsigned['@context'] }
  const [optionsNQuads, documentNQuads] = await Promise.all([
    canonicalize(options, loader),
    canonicalize(unsigned, loader),
  ])
  const out = new Uint8Array(64)
  out.set(digest(optionsNQuads))
  out.set(digest(documentNQuads), 32)
  return out
}

/** Signs a document. `created` comes from the caller; this module never reads a clock. */
export async function createProof<T extends JsonObject>(
  unsigned: T,
  signer: Signer,
  options: { created: string },
  loader?: DocumentLoader,
): Promise<T & { proof: JsonObject }> {
  if ('proof' in unsigned) throw new Error('document already has a proof')
  const proofOptions = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-rdfc-2022',
    created: options.created,
    verificationMethod: signer.verificationMethod,
    proofPurpose: 'assertionMethod',
  }
  const signature = await signer.sign(await hashForProof(unsigned, proofOptions, loader))
  if (signature.length !== 64) throw new Error('an Ed25519 signature is 64 bytes')
  return { ...unsigned, proof: { ...proofOptions, proofValue: encodeBase58btc(signature) } }
}

/**
 * Checks a document's signature against a public key. Returns false for a
 * signature that does not match; throws only when the document cannot be
 * canonicalized.
 */
export async function verifyProof(signed: JsonObject, publicKey: Uint8Array, loader?: DocumentLoader): Promise<boolean> {
  const { proof, ...unsigned } = signed
  if (typeof proof !== 'object' || proof === null || Array.isArray(proof)) return false
  const { proofValue, ...proofOptions } = proof as JsonObject
  if (typeof proofValue !== 'string') return false

  let signature: Uint8Array
  try {
    signature = decodeBase58btc(proofValue)
  } catch {
    return false
  }
  if (signature.length !== 64) return false

  const hash = await hashForProof(unsigned, proofOptions, loader)
  try {
    return await ed.verifyAsync(signature, hash, publicKey)
  } catch {
    return false
  }
}
