import { base64urlnopad } from '@scure/base'
import { LIST_BITS } from './constants.js'

export { LIST_BITS }

const LIST_BYTES = LIST_BITS / 8

/**
 * Decodes an `encodedList`: multibase base64url (the letter u) around gzip.
 * Decompression stops as soon as the output passes the expected size, so a
 * small input cannot be used to exhaust memory.
 */
export async function decodeList(encodedList: string): Promise<Uint8Array> {
  if (!encodedList.startsWith('u')) throw new Error('status list is not multibase base64url')
  const compressed = base64urlnopad.decode(encodedList.slice(1))
  const bits = await gunzip(compressed, LIST_BYTES)
  if (bits.length !== LIST_BYTES) throw new Error(`status list is ${bits.length} bytes, expected ${LIST_BYTES}`)
  return bits
}

export async function encodeList(bits: Uint8Array): Promise<string> {
  if (bits.length !== LIST_BYTES) throw new Error(`status list must be ${LIST_BYTES} bytes`)
  const compressed = await collect(blobStream(bits).pipeThrough(new CompressionStream('gzip')), Infinity)
  // The gzip header records a timestamp and the operating system. Both are
  // cleared so that the same list always encodes to the same text.
  compressed.fill(0, 4, 9)
  compressed[9] = 0xff
  return 'u' + base64urlnopad.encode(compressed)
}

/** Bit 0 is the most significant bit of the first byte. */
export function getBit(bits: Uint8Array, index: number): boolean {
  return (bits[byteOf(bits, index)]! & (0x80 >> (index & 7))) !== 0
}

export function setBit(bits: Uint8Array, index: number): void {
  bits[byteOf(bits, index)]! |= 0x80 >> (index & 7)
}

function byteOf(bits: Uint8Array, index: number): number {
  if (!Number.isInteger(index) || index < 0 || index >= bits.length * 8) {
    throw new RangeError(`status index ${index} is outside the list`)
  }
  return index >> 3
}

function blobStream(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new Blob([bytes as Uint8Array<ArrayBuffer>]).stream()
}

function gunzip(bytes: Uint8Array, limit: number): Promise<Uint8Array> {
  return collect(blobStream(bytes).pipeThrough(new DecompressionStream('gzip')), limit)
}

async function collect(stream: ReadableStream<Uint8Array>, limit: number): Promise<Uint8Array> {
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.length
    if (total > limit) {
      await reader.cancel()
      throw new Error('status list is larger than expected')
    }
    chunks.push(value)
  }
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}
