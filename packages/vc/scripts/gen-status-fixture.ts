// Writes vectors/status/encoding.json: a list encoded by the TypeScript side for the Go tests to decode.
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { encodeList, LIST_BITS, setBit } from '../src/status.js'

const set = [0, 9, 94_567, LIST_BITS - 1]
const bits = new Uint8Array(LIST_BITS / 8)
for (const index of set) setBit(bits, index)

const out = fileURLToPath(new URL('../../../vectors/status/encoding.json', import.meta.url))
writeFileSync(out, JSON.stringify({ set, encodedList: await encodeList(bits) }, null, 2) + '\n')
console.log(`wrote ${out}`)
