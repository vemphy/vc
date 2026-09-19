// Writes vectors/codes.json from the TypeScript implementation. The Go tests replay it.
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { formatCode, isIssuable, parseCode } from '../src/code.js'

const inputs = [
  'GCB-7K2M-9QXD', 'gcb 7k2m 9qxd', 'GCB7K2M9QXD', ' gcb-7k2m-9qxd\n',
  'https://vemphy.com/v/GCB-7K2M-9QXD', 'https://vemphy.com/v/gcb-7k2m-9qxd?utm=x', 'vemphy.com/v/GCB-7K2M-9QXD',
  'GCB-OOOO-OOOI', 'gcb-oooo-oool', 'G0B-0000-0001', 'GC8-7K2M-9QXD',
  '', 'GCB-7K2M-9QX', 'TOOLONG-0000-0001', 'G-0000-0001', 'GCB-7K2M-9QXDD', 'GCB-7U2M-9QXD',
  'GCD-7K2M-9QXD', 'GCB-7K2N-9QXD', 'GCB-7KZM-9QXD', 'GCB-7K2M-9QXO', 'GCB-1K2M-9QXD', 'GCB-7K2M-9QVD', 'UG-3N7P-1D9B', 'KNVS-9X8W-7V6T', 'GCB-7K2M-9QKD', 'GCB-7K2M-9QXE', 'https://vemphy.com/v/%E0%A4%A',
  formatCode('GCB', '000000Z'), formatCode('GCB', '0000000'),
  formatCode('UG', '0000000'), formatCode('UG', 'ZZZZZZZ'), formatCode('LOU', '1A2B3C4'),
  formatCode('KNUS', '9X8W7V6'), formatCode('AB', 'HJKMNPQ'), formatCode('EMP', '5T4S3R2'),
  formatCode('GCB', 'QQQQQQQ'), formatCode('UG', '3N7P1D9'), formatCode('KNUS', '0000001'),
]

const cases = inputs.map((input) => {
  const result = parseCode(input)
  return result.ok ? { input, result, issuable: isIssuable(input) } : { input, result }
})

const out = fileURLToPath(new URL('../../../vectors/codes.json', import.meta.url))
writeFileSync(out, JSON.stringify(cases, null, 2) + '\n')
console.log(`wrote ${cases.length} cases to ${out}`)
