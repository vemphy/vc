import { describe, expect, it } from 'vitest'
import { decodeBase58btc, decodeMultikey, encodeBase58btc, encodeMultikey } from './multibase.js'

// The public key used by the W3C eddsa-rdfc-2022 test vectors.
const W3C_KEY = 'z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2'

describe('multikey', () => {
  it('round-trips the W3C test key', () => {
    const key = decodeMultikey(W3C_KEY)
    expect(key).toHaveLength(32)
    expect(encodeMultikey(key)).toBe(W3C_KEY)
  })

  it('rejects another multicodec, a short key and another multibase', () => {
    const secp = encodeBase58btc(Uint8Array.of(0xe7, 0x01, ...new Uint8Array(32)))
    expect(() => decodeMultikey(secp)).toThrow()
    expect(() => decodeMultikey(encodeBase58btc(Uint8Array.of(0xed, 0x01, 1, 2, 3)))).toThrow()
    expect(() => decodeMultikey('u' + W3C_KEY.slice(1))).toThrow()
    expect(() => encodeMultikey(new Uint8Array(31))).toThrow()
  })

  it('keeps leading zero bytes', () => {
    const bytes = Uint8Array.of(0, 0, 7)
    expect(decodeBase58btc(encodeBase58btc(bytes))).toEqual(bytes)
  })
})
