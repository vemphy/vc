import { base58 } from '@scure/base'

// Multicodec prefix for an Ed25519 public key (0xed), varint-encoded.
const ED25519_PUB = Uint8Array.of(0xed, 0x01)
const ED25519_KEY_LENGTH = 32

/** Multibase base58btc: the letter z followed by the base58 text. */
export function encodeBase58btc(bytes: Uint8Array): string {
  return 'z' + base58.encode(bytes)
}

export function decodeBase58btc(text: string): Uint8Array {
  if (!text.startsWith('z')) throw new Error('not multibase base58btc')
  return base58.decode(text.slice(1))
}

/** An Ed25519 public key as a Multikey publicKeyMultibase value (z6Mk...). */
export function encodeMultikey(publicKey: Uint8Array): string {
  if (publicKey.length !== ED25519_KEY_LENGTH) throw new Error('an Ed25519 public key is 32 bytes')
  const out = new Uint8Array(ED25519_PUB.length + publicKey.length)
  out.set(ED25519_PUB)
  out.set(publicKey, ED25519_PUB.length)
  return encodeBase58btc(out)
}

export function decodeMultikey(text: string): Uint8Array {
  const bytes = decodeBase58btc(text)
  if (bytes[0] !== ED25519_PUB[0] || bytes[1] !== ED25519_PUB[1]) throw new Error('not an Ed25519 Multikey')
  if (bytes.length !== ED25519_PUB.length + ED25519_KEY_LENGTH) throw new Error('an Ed25519 public key is 32 bytes')
  return bytes.slice(ED25519_PUB.length)
}
