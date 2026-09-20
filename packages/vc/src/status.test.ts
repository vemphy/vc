import { readFileSync } from 'node:fs'
import { gzipSync } from 'node:zlib'
import { base64urlnopad } from '@scure/base'
import { describe, expect, it } from 'vitest'
import { decodeList, encodeList, getBit, LIST_BITS, setBit } from './status.js'

const empty = () => new Uint8Array(LIST_BITS / 8)

describe('status list bits', () => {
  it('numbers bits from the most significant bit of the first byte', () => {
    const bits = empty()
    setBit(bits, 0)
    setBit(bits, LIST_BITS - 1)
    setBit(bits, 9)
    expect(bits[0]).toBe(0x80)
    expect(bits[1]).toBe(0x40)
    expect(bits.at(-1)).toBe(0x01)
    expect(getBit(bits, 0)).toBe(true)
    expect(getBit(bits, 1)).toBe(false)
    expect(getBit(bits, 9)).toBe(true)
    expect(getBit(bits, LIST_BITS - 1)).toBe(true)
  })

  it.each([-1, LIST_BITS, 1.5, Number.NaN])('refuses index %s', (index) => {
    expect(() => getBit(empty(), index)).toThrow(RangeError)
    expect(() => setBit(empty(), index)).toThrow(RangeError)
  })
})

describe('encodedList', () => {
  it('round-trips', async () => {
    const bits = empty()
    setBit(bits, 94_567)
    const encoded = await encodeList(bits)
    expect(encoded).toMatch(/^u[A-Za-z0-9_-]+$/)
    expect(await decodeList(encoded)).toEqual(bits)
  })

  it.each(['encoding.json', 'encoding-go.json'])('decodes the list in vectors/status/%s', async (file) => {
    const fixture = JSON.parse(readFileSync(new URL(`../../../vectors/status/${file}`, import.meta.url), 'utf8'))
    const bits = await decodeList(fixture.encodedList)
    const set = Array.from({ length: LIST_BITS }, (_, i) => i).filter((i) => getBit(bits, i))
    expect(set).toEqual(fixture.set)
  })

  it('encodes the same list to the same text', async () => {
    expect(await encodeList(empty())).toBe(await encodeList(empty()))
  })

  it('refuses a list of the wrong size', async () => {
    const short = 'u' + base64urlnopad.encode(gzipSync(new Uint8Array(100)))
    await expect(decodeList(short)).rejects.toThrow()
    await expect(encodeList(new Uint8Array(100))).rejects.toThrow()
  })

  it('stops decompressing an oversized list', async () => {
    const bomb = 'u' + base64urlnopad.encode(gzipSync(new Uint8Array(10 * 1024 * 1024)))
    expect(bomb.length).toBeLessThan(20_000)
    await expect(decodeList(bomb)).rejects.toThrow(/larger/)
  })

  it('refuses another multibase and input that is not gzip', async () => {
    await expect(decodeList('z' + 'abc')).rejects.toThrow()
    await expect(decodeList('u' + base64urlnopad.encode(new Uint8Array(64)))).rejects.toThrow()
  })
})
